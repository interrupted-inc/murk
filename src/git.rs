// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Git integration helpers (merge driver setup, worktree layout).

use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// The `.gitattributes` line that enables the merge driver.
const GITATTRIBUTES_LINE: &str = "*.murk merge=murk";

/// Git config keys for the merge driver.
const GIT_CONFIG_MERGE_NAME: &str = "merge.murk.name";
const GIT_CONFIG_MERGE_DRIVER: &str = "merge.murk.driver";

/// A `git` command that runs no code from the repository it is pointed at, with
/// murk's key variables removed from its environment.
///
/// The only way murk spawns git. A repository's own `.git/config` is not
/// trusted: a working tree unpacked from an archive, a shared volume, or a CI
/// cache carries whatever config its author wrote, and several keys name a
/// program git runs. `core.fsmonitor` runs on any index refresh (`check-ignore`
/// does one), hooks run on writes, and a pager runs on terminal output, so all
/// three are switched off here. The signature programs (`gpg.*`) are refused per
/// call in [`last_commit_signature`], since overriding them would also override
/// the user's own choice. Repository-format settings are still read; git needs
/// them to open the repository at all.
///
/// None of the spawned git commands needs the key either. The merge driver is
/// unaffected: git invokes `murk merge-driver` with the user's environment, not
/// with the one murk hands git here.
pub fn git_command() -> Command {
    let mut cmd = Command::new("git");
    cmd.args([
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    cmd.env("GIT_OPTIONAL_LOCKS", "0");
    crate::env::strip_key_env(&mut cmd);
    cmd
}

/// A step completed during merge driver setup.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeDriverSetupStep {
    /// `.gitattributes` already contained the merge driver entry.
    GitattributesAlreadyExists,
    /// Appended the merge driver entry to an existing `.gitattributes`.
    GitattributesAppended,
    /// Created a new `.gitattributes` file with the merge driver entry.
    GitattributesCreated,
    /// Configured `git config merge.murk.*`.
    GitConfigured,
}

/// Configure git to use murk's custom merge driver for `.murk` files.
///
/// 1. Ensures `.gitattributes` contains `*.murk merge=murk`.
/// 2. Runs `git config merge.murk.name` and `git config merge.murk.driver`.
///
/// Returns the steps that were performed.
pub fn setup_merge_driver() -> Result<Vec<MergeDriverSetupStep>, String> {
    let mut steps = Vec::new();

    // 1. Write .gitattributes entry.
    let gitattributes = Path::new(".gitattributes");
    let merge_line = GITATTRIBUTES_LINE;

    crate::env::reject_symlink(gitattributes, ".gitattributes")?;

    if gitattributes.exists() {
        let contents = fs::read_to_string(gitattributes)
            .map_err(|e| format!("reading .gitattributes: {e}"))?;
        if contents.contains(merge_line) {
            steps.push(MergeDriverSetupStep::GitattributesAlreadyExists);
        } else {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(gitattributes)
                .map_err(|e| format!("writing .gitattributes: {e}"))?;
            writeln!(file, "{merge_line}").map_err(|e| format!("writing .gitattributes: {e}"))?;
            steps.push(MergeDriverSetupStep::GitattributesAppended);
        }
    } else {
        fs::write(gitattributes, format!("{merge_line}\n"))
            .map_err(|e| format!("writing .gitattributes: {e}"))?;
        steps.push(MergeDriverSetupStep::GitattributesCreated);
    }

    // 2. Configure git merge driver.
    let configs = [
        (GIT_CONFIG_MERGE_NAME, "murk vault merge"),
        (GIT_CONFIG_MERGE_DRIVER, "murk merge-driver %O %A %B %P"),
    ];
    for (key, value) in &configs {
        let status = git_command()
            .args(["config", key, value])
            .status()
            .map_err(|e| format!("running git config: {e}"))?;
        if !status.success() {
            return Err(format!("git config {key} failed (are you in a git repo?)"));
        }
    }
    steps.push(MergeDriverSetupStep::GitConfigured);

    Ok(steps)
}

/// Who signed a commit, as git reports it for the signature it checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSigner {
    /// git's `%GK`: the signing key's id for gpg, its `SHA256:` fingerprint
    /// for an ssh key. Empty when git reports none.
    pub key: String,
    /// git's `%GF`: the signing key's fingerprint. For an ssh key this is the
    /// `ssh-keygen -l` form ([`crate::signing::ssh_ed25519_fingerprint`]).
    /// Empty when git reports none.
    pub fingerprint: String,
}

impl CommitSigner {
    /// What names the key: its fingerprint, else its key id. `None` when git
    /// reported neither.
    pub fn id(&self) -> Option<&str> {
        [self.fingerprint.as_str(), self.key.as_str()]
            .into_iter()
            .find(|s| !s.is_empty())
    }
}

/// Signature status of the most recent commit that modified `path`.
///
/// The vault signature authenticates *content*; a signed commit authenticates
/// *who landed it* — together they anchor integrity in git (see `THREAT_MODEL`).
/// `murk verify` surfaces this so a team can confirm the vault's history is
/// signed, not just its bytes. A signature by *some* key proves nothing about
/// whether that key belongs to a person the vault trusts, so the signer is
/// carried along for the caller to compare with the vault's signers.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitSignature {
    /// git checked the signature and it is valid (`G`, or `U`: valid, but git
    /// has no standing for the key). It says nothing about who the key is.
    Verified(CommitSigner),
    /// A signature is present but git does not vouch for it: `status` is `E`
    /// (it could not be checked, e.g. the key is unknown or the verifier is
    /// missing), `X` (the signature has expired) or `Y` (the key has expired).
    Unverified { status: char, signer: CommitSigner },
    /// A bad signature — the commit was altered or the signature doesn't match.
    Bad,
    /// The commit carries no signature.
    Unsigned,
    /// Not checked: the repository's own config sets `gpg.*`. Verifying would
    /// run the program that config names, and an allowed-signers file it names
    /// would let the repository vouch for its own signer.
    RepoConfigured,
}

/// The principal name in the allowed-signers file handed to git. git only
/// needs *a* principal to report a key as listed; the name is never shown.
const ALLOWED_SIGNERS_PRINCIPAL: &str = "murk-trusted-signer";

/// Write `keys` (ssh-ed25519 public key lines) as an allowed-signers file in a
/// fresh temporary directory, for `gpg.ssh.allowedSignersFile`. The directory
/// goes away when the returned handle is dropped. `None` when it cannot be
/// written. Keys that are not ssh-ed25519 are left out.
fn write_allowed_signers(keys: &[String]) -> Option<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("murk-allowed-signers-")
        .tempdir()
        .ok()?;
    let path = dir.path().join("allowed_signers");
    let mut contents = String::new();
    for key in keys
        .iter()
        .filter_map(|k| crate::signing::ssh_ed25519_key_line(k))
    {
        contents.push_str(ALLOWED_SIGNERS_PRINCIPAL);
        contents.push_str(" namespaces=\"git\" ");
        contents.push_str(&key);
        contents.push('\n');
    }
    fs::write(&path, contents).ok()?;
    Some((dir, path))
}

/// Return the signature status of the last commit touching `path`, or `None`
/// when git is unavailable, the repo has no such commit, or the path is
/// untracked — i.e. there is no git anchor to check.
///
/// `trusted_ssh_signers` are the ssh-ed25519 keys the caller trusts to sign
/// commits. They go to git as the allowed-signers list for this one call
/// (`-c gpg.ssh.allowedSignersFile`), which makes the check independent of
/// the user's git config: without such a file git cannot check an ssh
/// signature at all and reports a signed commit as unsigned, and a user's own
/// list would decide what `G` means. With it, a valid ssh signature by one of
/// these keys is `G` and a valid one by any other key is `U`. A
/// `gpg.ssh.revocationFile` the user configured still applies.
///
/// Signature verification is governed entirely by `gpg.*` config, so only the
/// user's global and system config may set it; see
/// [`CommitSignature::RepoConfigured`].
pub fn last_commit_signature(
    path: &str,
    trusted_ssh_signers: &[String],
) -> Option<CommitSignature> {
    // No commit for this path (untracked / no history): no anchor to check.
    last_commit_field(path, "%H")?;
    if repo_sets_gpg_config()? {
        return Some(CommitSignature::RepoConfigured);
    }
    let allowed = write_allowed_signers(trusted_ssh_signers);
    let mut cmd = git_command();
    if let Some((_, file)) = &allowed {
        let mut setting = std::ffi::OsString::from("gpg.ssh.allowedSignersFile=");
        setting.push(file);
        cmd.arg("-c").arg(setting);
    }
    let output = cmd
        .args([
            "log",
            "-1",
            // `log.showSignature` would print the verifier's output into ours.
            "--no-show-signature",
            "--format=%G?%x00%GK%x00%GF",
            "--",
        ])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_commit_signature(String::from_utf8(output.stdout).ok()?.trim_end())
}

/// Parse `%G?%x00%GK%x00%GF` output: `None` for no commit (an empty line) or a
/// status git does not define.
fn parse_commit_signature(line: &str) -> Option<CommitSignature> {
    let mut fields = line.split('\0');
    let status = fields.next()?;
    let mut signer = move || CommitSigner {
        key: fields.next().unwrap_or_default().to_string(),
        fingerprint: fields.next().unwrap_or_default().to_string(),
    };
    let mut chars = status.chars();
    let (Some(code), None) = (chars.next(), chars.next()) else {
        return None;
    };
    match code {
        'G' | 'U' => Some(CommitSignature::Verified(signer())),
        // X (expired signature), Y (expired key), E (cannot check) all mean "a
        // signature exists but we can't vouch for it".
        'X' | 'Y' | 'E' => Some(CommitSignature::Unverified {
            status: code,
            signer: signer(),
        }),
        'B' | 'R' => Some(CommitSignature::Bad),
        'N' => Some(CommitSignature::Unsigned),
        _ => None,
    }
}

/// `git log -1 --format=<format> -- <path>`, trimmed; `None` when git fails or
/// no commit touches `path`. `--no-show-signature` keeps a repository's
/// `log.showSignature` from verifying signatures where the format does not ask.
fn last_commit_field(path: &str, format: &str) -> Option<String> {
    let output = git_command()
        .args([
            "log",
            "-1",
            "--no-show-signature",
            &format!("--format={format}"),
            "--",
            path,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let field = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!field.is_empty()).then_some(field)
}

/// Whether the repository's own config (local or per-worktree scope, including
/// files it includes) sets any `gpg.*` key. `None` when git cannot answer.
fn repo_sets_gpg_config() -> Option<bool> {
    let output = git_command()
        .args(["config", "--show-scope", "--get-regexp", r"^gpg\."])
        .output()
        .ok()?;
    match output.status.code() {
        // `--get-regexp` exits 1 when nothing matches.
        Some(1) => Some(false),
        Some(0) => Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.starts_with("local\t") || line.starts_with("worktree\t")),
        ),
        _ => None,
    }
}

/// Read the vault file at `vault_path` as it was in git revision `git_ref`.
///
/// Returns `Ok(None)` only when git proves the file is absent from that
/// revision; every other failure (not a repository, unknown revision, a
/// non-file entry, a git error) is an `Err`, so a caller never mistakes a
/// failed lookup for an empty vault.
///
/// `git_ref` is untrusted input. It is refused if it starts with `-`, resolved
/// to a commit id with `rev-parse --verify --end-of-options` first, and only
/// that hex id reaches the later commands, so it can never be read as a git
/// option. The path is resolved against the repository that holds the vault
/// file, so it works from a subdirectory and with a vault outside the current
/// directory.
pub fn vault_at_revision(git_ref: &str, vault_path: &str) -> Result<Option<String>, String> {
    if git_ref.is_empty() || git_ref.starts_with('-') {
        return Err(format!("invalid git revision {git_ref:?}"));
    }
    let path = Path::new(vault_path);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid vault path {vault_path}"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let git = |args: &[&str]| {
        git_command()
            .args(args)
            .current_dir(dir)
            .output()
            .map_err(|e| format!("running git: {e}"))
    };

    let out = git(&["rev-parse", "--show-prefix"])?;
    if !out.status.success() {
        return Err(format!("{} is not inside a git repository", dir.display()));
    }
    let prefix = String::from_utf8(out.stdout)
        .map_err(|_| format!("{} has a non-UTF-8 path", dir.display()))?;
    let tree_path = format!("{}{file_name}", prefix.trim_end_matches('\n'));

    let out = git(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &format!("{git_ref}^{{commit}}"),
    ])?;
    let commit = String::from_utf8(out.stdout).unwrap_or_default();
    let commit = commit.trim_end_matches('\n');
    if !out.status.success() || commit.is_empty() || !commit.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if git_ref == "HEAD" && head_is_unborn(&git)? {
            return Ok(None);
        }
        return Err(format!("{git_ref} does not name a git commit"));
    }

    // `ls-tree` exits 0 with no output when the path is absent: that is the
    // only outcome treated as "no vault at this revision".
    let out = git(&[
        "--literal-pathspecs",
        "ls-tree",
        "-z",
        "--full-tree",
        commit,
        "--",
        &tree_path,
    ])?;
    if !out.status.success() {
        return Err(format!(
            "git ls-tree {git_ref} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.is_empty() {
        return Ok(None);
    }
    // One entry: "<mode> <type> <id>\t<path>\0".
    let entry = String::from_utf8_lossy(&out.stdout);
    let mut fields = entry.split(['\t', '\0']).next().unwrap_or("").split(' ');
    let (mode, kind, id) = (fields.next(), fields.next(), fields.next());
    let id = match (mode, kind, id) {
        (Some("100644" | "100755"), Some("blob"), Some(id))
            if id.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            id
        }
        _ => return Err(format!("{tree_path} at {git_ref} is not a regular file")),
    };

    let out = git(&["cat-file", "blob", id])?;
    if !out.status.success() {
        return Err(format!(
            "reading {tree_path} at {git_ref}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .map(Some)
        .map_err(|_| format!("{tree_path} at {git_ref} is not UTF-8"))
}

/// Whether HEAD is unborn: it names a branch that does not exist at all, as in
/// a repository with no commits yet. A branch that exists but points at a
/// missing or corrupt object is not unborn, so a broken repository never reads
/// as "no vault here". `for-each-ref` lists a broken ref (and exits 0), and
/// prints nothing only when no such ref exists.
fn head_is_unborn(
    git: &impl Fn(&[&str]) -> Result<std::process::Output, String>,
) -> Result<bool, String> {
    let out = git(&["symbolic-ref", "--quiet", "HEAD"])?;
    if !out.status.success() {
        return Ok(false);
    }
    let target = String::from_utf8(out.stdout).unwrap_or_default();
    let target = target.trim_end_matches('\n');
    if !target.starts_with("refs/") {
        return Ok(false);
    }
    let out = git(&["for-each-ref", "--format=%(refname)", target])?;
    Ok(out.status.success() && out.stdout.is_empty())
}

/// The working tree containing `path`: the nearest ancestor holding a `.git`
/// entry. `None` when `path` is not inside a checkout.
///
/// Lexical only — no `git` subprocess and no symlink resolution, so the answer
/// is a prefix of the path handed in. Key lookup hashes the literal vault path
/// (see `env::key_file_path`), and this must agree with it.
pub fn worktree_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Every *other* working tree of the repository `root` belongs to: the main
/// checkout first, then linked worktrees in a stable order. Empty when `root`
/// is not a checkout, the repository has no other working tree, or the git
/// metadata is unreadable.
///
/// Read straight off the git directory rather than through `git worktree list`:
/// key resolution runs on every decrypt, and a secrets tool should not spawn a
/// binary off `PATH` to answer it.
///
/// Membership is checked in **both** directions, because a `.git` entry is just
/// a file anyone can write and the caller uses the answer to decide whose key a
/// vault may borrow. `root` must be a checkout the repository itself records —
/// so a planted `.git` pointer into someone else's repository lists nothing —
/// and every candidate must resolve back to the same common directory — so a
/// planted `.git` *directory* naming a foreign checkout as its worktree is
/// ignored too. Anything unverified is dropped: this fails closed.
pub fn sibling_worktrees(root: &Path) -> Vec<PathBuf> {
    let Some(common) = common_dir(root) else {
        return Vec::new();
    };

    // The main working tree is the parent of `<checkout>/.git`. A bare
    // repository — the `.bare` + worktrees layout — has no working tree of its
    // own, and its parent directory is not a checkout, so require the name.
    let main = if common.file_name() == Some(std::ffi::OsStr::new(".git")) {
        common.parent().map(Path::to_path_buf)
    } else {
        None
    };

    // Linked worktrees: `<common>/worktrees/<id>/gitdir` holds the path of that
    // checkout's own `.git` file.
    let mut linked: Vec<PathBuf> = match fs::read_dir(common.join("worktrees")) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|entry| {
                let gitdir = fs::read_to_string(entry.path().join("gitdir")).ok()?;
                Path::new(gitdir.trim()).parent().map(Path::to_path_buf)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    linked.sort();

    if main.as_deref() != Some(root) && !linked.iter().any(|checkout| checkout == root) {
        return Vec::new();
    }

    main.into_iter()
        .chain(linked)
        .filter(|checkout| {
            checkout != root && common_dir(checkout).as_deref() == Some(common.as_path())
        })
        .collect()
}

/// What the checkout containing a vault has checked out, read from its HEAD
/// file (no `git` process). The rollback check is per branch: switching to an
/// older branch is normal, a branch going backwards is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// The vault is not in a git checkout.
    NotARepo,
    /// A branch is checked out (`refs/heads/<name>`).
    Branch(String),
    /// A detached HEAD (a rebase, bisect, or CI checkout of a commit).
    Detached,
}

/// The HEAD state of the checkout holding `abs_vault`.
pub fn head_state(abs_vault: &Path) -> HeadState {
    let Some(root) = abs_vault.parent().and_then(worktree_root) else {
        return HeadState::NotARepo;
    };
    let dotgit = root.join(".git");
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        match fs::read_to_string(&dotgit)
            .ok()
            .and_then(|p| Some(root.join(p.trim().strip_prefix("gitdir:")?.trim())))
        {
            Some(dir) => dir,
            None => return HeadState::Detached,
        }
    };
    match fs::read_to_string(gitdir.join("HEAD")) {
        Ok(head) => match head.trim().strip_prefix("ref: refs/heads/") {
            Some(branch) => HeadState::Branch(branch.to_string()),
            None => HeadState::Detached,
        },
        Err(_) => HeadState::Detached,
    }
}

/// Whether the commit checked out in the checkout holding `abs_vault` is in
/// the history of local branch `branch` (equal to its tip or an ancestor of
/// it), and the vault file is exactly the one committed at HEAD — so the vault
/// being read is that commit's, not an uncommitted copy of another. False when
/// git fails, the branch does not exist, or the name could be read as an
/// option.
pub fn committed_vault_in_history_of(abs_vault: &Path, branch: &str) -> bool {
    let (Some(dir), Some(name)) = (abs_vault.parent(), abs_vault.file_name()) else {
        return false;
    };
    if branch.starts_with('-') || worktree_root(dir).is_none() {
        return false;
    }
    let quiet = |cmd: &mut Command| {
        cmd.current_dir(dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    quiet(
        git_command()
            .args(["merge-base", "--is-ancestor", "HEAD"])
            .arg(format!("refs/heads/{branch}")),
    ) && quiet(
        git_command()
            .args(["cat-file", "-e"])
            .arg(format!("HEAD:./{}", name.to_string_lossy())),
    ) && quiet(
        git_command()
            .args(["diff", "--quiet", "HEAD", "--"])
            .arg(name),
    )
}

/// A path naming a vault the same way from every worktree of its repository:
/// the repository's common git directory joined with the vault's path inside
/// the checkout. `None` when the vault is not inside a git checkout.
///
/// The trust pin is keyed on this, so trusting a vault once covers every
/// worktree of the repository (an agent's throwaway checkout included).
pub(crate) fn repository_vault_identity(abs_vault: &Path) -> Option<PathBuf> {
    let root = worktree_root(abs_vault.parent()?)?;
    let relative = abs_vault.strip_prefix(&root).ok()?;
    let common = common_dir(&root)?;
    let common = fs::canonicalize(&common).unwrap_or(common);
    Some(common.join("murk-vault").join(relative))
}

/// The repository's common directory (the shared `.git` holding `objects/` and
/// `worktrees/`) for the checkout at `root`.
///
/// Resolved lexically, never through `fs::canonicalize`. Two callers compare
/// these values against each other — [`sibling_worktrees`] checks membership in
/// both directions — so both sides must live in one coordinate system. A
/// canonicalized path is a *different spelling* of the same directory: on
/// Windows it gains a `\\?\` verbatim prefix that no lexical path ever has, so
/// every genuine sibling compared unequal and worktree discovery rejected
/// everything. Lexical also matches how key lookup hashes a vault path
/// (`env::key_file_path`), which likewise does not resolve symlinks.
fn common_dir(root: &Path) -> Option<PathBuf> {
    let dotgit = root.join(".git");
    if dotgit.is_dir() {
        return Some(dotgit);
    }
    // A linked worktree's `.git` is a file pointing at `<common>/worktrees/<id>`,
    // which in turn records the common dir relative to itself.
    let pointer = fs::read_to_string(&dotgit).ok()?;
    let gitdir = root.join(pointer.trim().strip_prefix("gitdir:")?.trim());
    let common = match fs::read_to_string(gitdir.join("commondir")) {
        Ok(rel) => gitdir.join(rel.trim()),
        Err(_) => gitdir,
    };
    // Resolve the `../..` hop `commondir` spells it with, so the `.git` name
    // check in `sibling_worktrees` sees the directory itself.
    Some(lexical_normalize(&common))
}

/// Resolve `.` and `..` components textually, without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::CWD_LOCK;

    #[test]
    fn setup_merge_driver_creates_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_setup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Init a git repo so git config works.
        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesCreated));
        assert!(steps.contains(&MergeDriverSetupStep::GitConfigured));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_appends_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.txt text\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAppended));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.txt text"));
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_already_exists() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_exists");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.murk merge=murk\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAlreadyExists));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn last_commit_signature_unsigned_commit() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(dir.join("vault.murk"), "data\n").unwrap();
        Command::new("git")
            .args(["add", "vault.murk"])
            .current_dir(dir)
            .output()
            .unwrap();
        // Explicit identity + gpgsign=false so the commit lands unsigned
        // regardless of the runner's global git config.
        Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "add vault",
            ])
            .current_dir(dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("vault.murk", &[]);
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, Some(CommitSignature::Unsigned));
    }

    #[test]
    fn last_commit_signature_untracked_path_is_none() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        // A commit exists, but for a *different* file — so `git log` succeeds
        // with empty output for the queried path: the "no anchor" branch.
        std::fs::write(dir.join("other.txt"), "x\n").unwrap();
        Command::new("git")
            .args(["add", "other.txt"])
            .current_dir(dir)
            .output()
            .unwrap();
        let commit = Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "seed",
            ])
            .current_dir(dir)
            .output()
            .unwrap();
        // If the seed commit fails, `git log` would error (not return empty) and
        // the None below would come from the wrong branch — assert it landed.
        assert!(
            commit.status.success(),
            "seed commit must succeed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("never-committed.murk", &[]);
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, None);
    }

    #[test]
    fn commit_signature_status_maps_to_what_git_vouches_for() {
        let signer = |key: &str, fp: &str| CommitSigner {
            key: key.into(),
            fingerprint: fp.into(),
        };
        let fp = "SHA256:abc";
        let line = |status: &str| format!("{status}\0{fp}\0{fp}");
        // G and U both mean the signature checked out; neither says whose key it is.
        for status in ["G", "U"] {
            assert_eq!(
                parse_commit_signature(&line(status)),
                Some(CommitSignature::Verified(signer(fp, fp))),
                "{status}"
            );
        }
        // X, Y and E are signatures git cannot vouch for, and keep their status.
        for status in ['X', 'Y', 'E'] {
            assert_eq!(
                parse_commit_signature(&line(&status.to_string())),
                Some(CommitSignature::Unverified {
                    status,
                    signer: signer(fp, fp)
                }),
                "{status}"
            );
        }
        assert_eq!(
            parse_commit_signature(&line("B")),
            Some(CommitSignature::Bad)
        );
        assert_eq!(
            parse_commit_signature(&line("R")),
            Some(CommitSignature::Bad)
        );
        assert_eq!(
            parse_commit_signature("N\0\0"),
            Some(CommitSignature::Unsigned)
        );
        // No commit touches the path, or a status git does not define.
        assert_eq!(parse_commit_signature(""), None);
        assert_eq!(parse_commit_signature(&line("Z")), None);
        assert_eq!(parse_commit_signature(&line("GG")), None);
    }

    #[test]
    fn commit_signer_id_prefers_the_fingerprint() {
        let both = CommitSigner {
            key: "KEYID".into(),
            fingerprint: "FINGERPRINT".into(),
        };
        assert_eq!(both.id(), Some("FINGERPRINT"));
        let key_only = CommitSigner {
            key: "KEYID".into(),
            fingerprint: String::new(),
        };
        assert_eq!(key_only.id(), Some("KEYID"));
        let neither = CommitSigner {
            key: String::new(),
            fingerprint: String::new(),
        };
        assert_eq!(neither.id(), None);
    }

    #[test]
    fn allowed_signers_file_lists_only_ssh_ed25519_keys_without_comments() {
        let key = crate::testutil::SSH_ED25519_PK;
        let keys = vec![
            format!("{key} someone@host"),
            "ssh-rsa AAAAB3xyz".to_string(),
            "age1abc".to_string(),
        ];
        let (dir, path) = write_allowed_signers(&keys).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("murk-trusted-signer namespaces=\"git\" {key}\n")
        );
        drop(dir);
        assert!(!path.exists(), "the temporary directory is removed");
    }

    #[test]
    fn setup_merge_driver_outside_repo_errors() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // No `git init`: `git config` has no repo to write to and must fail,
        // surfacing the "are you in a git repo?" guidance rather than silently
        // claiming the merge driver was configured.
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = setup_merge_driver();
        std::env::set_current_dir(original_dir).unwrap();

        let err = result.unwrap_err();
        assert!(
            err.contains("git config") && err.contains("failed"),
            "expected git-config failure guidance, got: {err}"
        );
    }

    // ── worktree layout ──

    /// Create a repo with one commit at `dir` and return its canonical path.
    /// `git worktree add` records canonical paths, so the fixture must use them
    /// too or the comparisons below drift on macOS (`/var` → `/private/var`).
    fn init_repo_with_commit(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let dir = crate::testutil::real_path(dir);
        git_in(&dir, &["init"]);
        std::fs::write(dir.join("README"), "x\n").unwrap();
        git_in(&dir, &["add", "README"]);
        git_in(&dir, &["commit", "-m", "init"]);
        dir
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn worktree_root_finds_nearest_checkout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("main"));
        let nested = main.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(worktree_root(&nested), Some(main.clone()));
        assert_eq!(worktree_root(&main), Some(main));
    }

    #[test]
    fn worktree_root_outside_a_repo_is_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = crate::testutil::real_path(tmp.path());
        assert_eq!(worktree_root(&dir), None);
    }

    #[test]
    fn sibling_worktrees_sees_main_and_linked_checkouts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("main"));
        let root = crate::testutil::real_path(tmp.path());
        let first = root.join("wt-a");
        let second = root.join("wt-b");
        git_in(
            &main,
            &["worktree", "add", "--detach", first.to_str().unwrap()],
        );
        git_in(
            &main,
            &["worktree", "add", "--detach", second.to_str().unwrap()],
        );

        // From the main checkout: only the linked worktrees, sorted.
        assert_eq!(
            sibling_worktrees(&main),
            vec![first.clone(), second.clone()]
        );
        // From a linked worktree: the main checkout first, then the other link.
        // Main first is what makes the original checkout's key win when several
        // worktrees have one stored.
        assert_eq!(
            sibling_worktrees(&first),
            vec![main.clone(), second.clone()]
        );
        // A checkout never lists itself.
        assert!(!sibling_worktrees(&second).contains(&second));
    }

    #[test]
    fn sibling_worktrees_of_a_lone_repo_is_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("solo"));
        let found = sibling_worktrees(&main);
        assert!(found.is_empty(), "{found:?}");

        let bare = crate::testutil::real_path(tmp.path()).join("not-a-repo");
        std::fs::create_dir_all(&bare).unwrap();
        let found = sibling_worktrees(&bare);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn sibling_worktrees_of_a_bare_repo_layout_skips_the_container() {
        // The `.bare` + worktrees layout has no main working tree, so the
        // parent of the common dir is a plain directory, not a checkout — it
        // must not be offered as a sibling.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let seed = init_repo_with_commit(&root.join("seed"));
        let bare = root.join("proj").join(".bare");
        std::fs::create_dir_all(root.join("proj")).unwrap();
        git_in(
            &root,
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );

        let checkout = root.join("proj").join("main");
        git_in(
            &bare,
            &["worktree", "add", "--detach", checkout.to_str().unwrap()],
        );

        assert_eq!(sibling_worktrees(&checkout), Vec::<PathBuf>::new());
    }

    #[test]
    fn bare_repo_worktrees_still_see_each_other() {
        // The layout agent harnesses use: a bare repo plus N checkouts, none of
        // which is a main working tree. They are still siblings.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let seed = init_repo_with_commit(&root.join("seed"));
        let bare = root.join("proj").join(".bare");
        std::fs::create_dir_all(root.join("proj")).unwrap();
        git_in(
            &root,
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );

        let first = root.join("proj").join("a");
        let second = root.join("proj").join("b");
        git_in(
            &bare,
            &["worktree", "add", "--detach", first.to_str().unwrap()],
        );
        git_in(
            &bare,
            &["worktree", "add", "--detach", second.to_str().unwrap()],
        );

        assert_eq!(sibling_worktrees(&first), vec![second]);
    }

    #[test]
    fn planted_git_pointer_into_another_repo_lists_nothing() {
        // A directory is not a worktree just because it says so. Anyone who can
        // drop a `.git` file — an unpacked tarball, an agent writing files —
        // could otherwise nominate a victim repository and borrow its key.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let main = init_repo_with_commit(&root.join("main"));
        let real = root.join("real-wt");
        git_in(
            &main,
            &["worktree", "add", "--detach", real.to_str().unwrap()],
        );

        // Point at the registered worktree's own git dir: maximally plausible,
        // and still not a checkout git knows about.
        let stolen = std::fs::read_to_string(real.join(".git")).unwrap();
        let evil = root.join("evil");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(evil.join(".git"), stolen).unwrap();

        assert_eq!(sibling_worktrees(&evil), Vec::<PathBuf>::new());
        // The genuine worktree is unaffected.
        assert_eq!(sibling_worktrees(&real), vec![main]);
    }

    #[test]
    fn planted_git_dir_naming_a_foreign_checkout_lists_nothing() {
        // The mirror image: a real (attacker-owned) repository whose
        // `worktrees/` entry names someone else's checkout. That checkout
        // points at its own common dir, so it is not a sibling.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let victim = init_repo_with_commit(&root.join("victim"));
        let evil = init_repo_with_commit(&root.join("evil"));

        let forged = evil.join(".git").join("worktrees").join("x");
        std::fs::create_dir_all(&forged).unwrap();
        std::fs::write(
            forged.join("gitdir"),
            format!("{}\n", victim.join(".git").display()),
        )
        .unwrap();

        assert_eq!(sibling_worktrees(&evil), Vec::<PathBuf>::new());
    }
}
