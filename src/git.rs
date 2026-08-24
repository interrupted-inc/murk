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
        (GIT_CONFIG_MERGE_DRIVER, "murk merge-driver %O %A %B"),
    ];
    for (key, value) in &configs {
        let status = Command::new("git")
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

/// Signature status of the most recent commit that modified `path`.
///
/// The vault signature authenticates *content*; a signed commit authenticates
/// *who landed it* — together they anchor integrity in git (see `THREAT_MODEL`).
/// `murk verify` surfaces this so a team can confirm the vault's history is
/// signed, not just its bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitSignature {
    /// A good, verified signature.
    Good,
    /// A signature is present but git could not validate it (unknown/expired key).
    Unverified,
    /// A bad signature — the commit was altered or the signature doesn't match.
    Bad,
    /// The commit carries no signature.
    Unsigned,
}

/// Return the signature status of the last commit touching `path`, or `None`
/// when git is unavailable, the repo has no such commit, or the path is
/// untracked — i.e. there is no git anchor to check.
pub fn last_commit_signature(path: &str) -> Option<CommitSignature> {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%G?", "--", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    match String::from_utf8(output.stdout).ok()?.trim() {
        "G" => Some(CommitSignature::Good),
        // U (good, unknown validity), X (expired), Y (expired key), E (cannot
        // check) all mean "a signature exists but we can't fully vouch for it".
        "U" | "X" | "Y" | "E" => Some(CommitSignature::Unverified),
        "B" | "R" => Some(CommitSignature::Bad),
        "N" => Some(CommitSignature::Unsigned),
        // Empty: no commit for this path (untracked / no history) — no anchor.
        _ => None,
    }
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

/// The repository's common directory (the shared `.git` holding `objects/` and
/// `worktrees/`) for the checkout at `root`.
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
    // Canonicalize so the `.git` name check below sees the real directory, not
    // the `../..` hop that `commondir` spells it with.
    Some(fs::canonicalize(&common).unwrap_or_else(|_| lexical_normalize(&common)))
}

/// Resolve `.` and `..` components textually, without touching the filesystem.
/// Only a fallback for when a git directory cannot be canonicalized.
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
        let sig = last_commit_signature("vault.murk");
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
        let sig = last_commit_signature("never-committed.murk");
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, None);
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
        let dir = std::fs::canonicalize(dir).unwrap();
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
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(worktree_root(&dir), None);
    }

    #[test]
    fn sibling_worktrees_sees_main_and_linked_checkouts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("main"));
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
        assert!(sibling_worktrees(&main).is_empty());

        let bare = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("not-a-repo");
        std::fs::create_dir_all(&bare).unwrap();
        assert!(sibling_worktrees(&bare).is_empty());
    }

    #[test]
    fn sibling_worktrees_of_a_bare_repo_layout_skips_the_container() {
        // The `.bare` + worktrees layout has no main working tree, so the
        // parent of the common dir is a plain directory, not a checkout — it
        // must not be offered as a sibling.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
