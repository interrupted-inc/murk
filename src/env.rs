// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment and `.env` file handling.

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use age::secrecy::SecretString;
use zeroize::Zeroizing;

/// Shell-escape a string using single quotes, safe for embedding in shell scripts.
/// If the value is a simple identifier (alphanumeric, `-`, `_`, `.`, `/`), returns it bare.
fn shell_escape(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Reject symlinks at the given path to prevent symlink-clobber attacks.
/// Returns Ok(()) if the path does not exist or is not a symlink.
pub(crate) fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    if path.is_symlink() {
        return Err(format!(
            "{label} is a symlink — refusing to follow for security"
        ));
    }
    Ok(())
}

/// The mode bits (`& 0o777`) of the file at `path` if it is readable by group
/// or others, else `None`. Always `None` on non-Unix platforms, where file
/// modes are not enforced, and when the file cannot be stat'd.
pub fn secret_file_loose_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(path).ok()?.mode();
        (mode & WORLD_READABLE_MASK != 0).then_some(mode & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Read a file, rejecting symlinks and (on Unix) group/world-readable permissions.
/// The contents are a key, so they come back in a [`Zeroizing`] buffer; callers
/// build their `SecretString` with `SecretString::from(&str)`, an exact-size
/// copy, because `From<String>` shrinks the buffer and frees the original
/// un-wiped.
fn read_secret_file(path: &Path, label: &str) -> Result<Zeroizing<String>, String> {
    reject_symlink(path, label)?;

    if let Some(mode) = secret_file_loose_mode(path) {
        return Err(format!(
            "{label} is readable by others (mode {mode:o}). Run: chmod 600 {}",
            path.display()
        ));
    }

    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read {label}: {e}"))
}

/// Environment variable for the secret key.
pub const ENV_MURK_KEY: &str = "MURK_KEY";
/// Environment variable for the secret key file path.
pub const ENV_MURK_KEY_FILE: &str = "MURK_KEY_FILE";

/// Remove the key variables from a child's environment. murk's subprocesses —
/// the editor, the `exec` child, `git` — go through this, so the key never
/// leaks into a program (or its hooks, filters, and helpers) that has no use
/// for it.
pub fn strip_key_env(cmd: &mut std::process::Command) {
    cmd.env_remove(ENV_MURK_KEY);
    cmd.env_remove(ENV_MURK_KEY_FILE);
}

/// File mode for `.env`: owner read/write only.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// Bitmask for group/other permission bits.
#[cfg(unix)]
const WORLD_READABLE_MASK: u32 = 0o077;

/// Resolve the secret key, checking in order:
/// 1. `MURK_KEY` or `MURK_KEY_FILE` env var (never both — see [`env_key`])
/// 2. `~/.config/murk/keys/<vault-hash>` (automatic lookup for default vault)
///
/// Returns the key wrapped in `SecretString` so it is zeroized on drop.
pub fn resolve_key() -> Result<SecretString, String> {
    resolve_key_for_vault(".murk")
}

/// Where the resolved key came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// From `MURK_KEY` environment variable.
    EnvVar,
    /// From `MURK_KEY_FILE` environment variable (path).
    EnvFile(std::path::PathBuf),
    /// Auto-discovered at `~/.config/murk/keys/<hash>`.
    Auto(std::path::PathBuf),
}

impl KeySource {
    /// Human-readable description for display.
    pub fn describe(&self) -> String {
        match self {
            KeySource::EnvVar => "MURK_KEY environment variable".into(),
            KeySource::EnvFile(p) => format!("MURK_KEY_FILE {}", p.display()),
            KeySource::Auto(p) => p.display().to_string(),
        }
    }
}

/// A key the environment names directly.
enum EnvKey {
    /// Inline key material from `MURK_KEY`.
    Inline(String),
    /// A key file path from `MURK_KEY_FILE`.
    File(std::path::PathBuf),
}

/// Read `MURK_KEY` / `MURK_KEY_FILE`, treating an empty value as unset.
///
/// Setting both is an error rather than a precedence rule: a key that arrives
/// from somewhere unexpected (a dotenv file a tool loads, an inherited shell
/// variable) must not silently outrank or be outranked by the one the caller
/// meant. Callers that hand a child a key in one variable blank the other.
///
/// This is the single place that reads the key environment variables — see
/// `tests/invariants.rs`.
fn env_key() -> Result<Option<EnvKey>, String> {
    let key = env::var(ENV_MURK_KEY).ok().filter(|v| !v.is_empty());
    let file = env::var(ENV_MURK_KEY_FILE).ok().filter(|v| !v.is_empty());
    match (key, file) {
        (Some(_), Some(_)) => Err([
            "MURK_KEY and MURK_KEY_FILE are both set",
            "murk will not pick one: they may name different keys",
            "unset one of them (`unset MURK_KEY` or `unset MURK_KEY_FILE`)",
        ]
        .join("\n")),
        (Some(k), None) => Ok(Some(EnvKey::Inline(k))),
        (None, Some(path)) => Ok(Some(EnvKey::File(path.into()))),
        (None, None) => Ok(None),
    }
}

/// Resolve the secret key and report where it came from.
///
/// Checks, in order:
/// 1. `MURK_KEY` env var (explicit key) or `MURK_KEY_FILE` env var (path to a
///    key file); setting both is an error (see [`env_key`])
/// 2. `~/.config/murk/keys/<hash-of-vault-path>`, for this checkout or a
///    sibling git worktree of it (automatic lookup — see [`discover_key_file`])
///
/// `.env` is **not** consulted at runtime. It is a write-only convenience that
/// `murk init` populates with a `MURK_KEY_FILE` reference for direnv to export.
/// Reading `.env` at runtime would let a copied vault in another repo borrow
/// whichever key happened to be referenced in the current working directory's
/// `.env` — a confused-deputy path that defeats per-vault key isolation.
pub fn resolve_key_with_source(vault_path: &str) -> Result<(SecretString, KeySource), String> {
    match env_key()? {
        Some(EnvKey::Inline(k)) => return Ok((SecretString::from(k), KeySource::EnvVar)),
        // File paths return full contents (not trimmed) so that plugin identity
        // files — which contain a `# public key: age1...` header above an
        // `AGE-PLUGIN-...-1...` pointer — round-trip intact through parse_identity.
        Some(EnvKey::File(path)) => {
            let contents = read_secret_file(&path, "MURK_KEY_FILE")?;
            return Ok((
                SecretString::from(contents.as_str()),
                KeySource::EnvFile(path),
            ));
        }
        None => {}
    }
    if let Some(path) = auto_key_file(vault_path) {
        let contents = read_secret_file(&path, "key file")?;
        return Ok((SecretString::from(contents.as_str()), KeySource::Auto(path)));
    }
    // One short summary line, then one action per line. The CLI renders each
    // trailing line as an indented `hint` (see `main::die`), so this must stay
    // plain text — and each line must fit a narrow terminal on its own, which
    // the previous single 330-character paragraph did not.
    Err([
        "MURK_KEY not set",
        "run `murk init` to generate a key",
        "or point MURK_KEY_FILE at an existing key file",
        "or ask a recipient to authorize your public key",
        "a key in .env needs `direnv allow` — murk does not read .env itself",
    ]
    .join("\n"))
}

/// Where [`resolve_key_with_source`] would take the key from for `vault_path`,
/// without reading it — `Ok(None)` when no source is configured, and the same
/// error as the resolver when both key variables are set (see [`env_key`]). A
/// file source is reported even when the file is missing, unreadable or has
/// loose permissions, so callers can inspect its location (e.g. `murk doctor`'s
/// inside-the-repo check) independently of whether the key itself would load.
pub fn locate_key(vault_path: &str) -> Result<Option<KeySource>, String> {
    match env_key()? {
        Some(EnvKey::Inline(k)) => {
            // Only the source matters here; wipe the key material on drop.
            drop(Zeroizing::new(k));
            Ok(Some(KeySource::EnvVar))
        }
        Some(EnvKey::File(path)) => Ok(Some(KeySource::EnvFile(path))),
        None => Ok(auto_key_file(vault_path).map(KeySource::Auto)),
    }
}

/// The operator's stored key file for `vault_path`, if auto-discovery is on.
///
/// Auto-discovery is disabled in strict mode (an explicit MURK_STRICT, or an
/// agent context via MURK_AGENT) so an agent never silently falls back to the
/// operator's personal key in ~/.config/murk/keys — it must present an explicit
/// MURK_KEY/MURK_KEY_FILE (its grant key) or fail closed. `murk agent exec` sets
/// MURK_AGENT=1 and MURK_STRICT=1 for the child, so this holds without the agent
/// having to opt in.
fn auto_key_file(vault_path: &str) -> Option<std::path::PathBuf> {
    if crate::hardening::strict_mode() {
        return None;
    }
    discover_key_file(vault_path)
}

/// Resolve the secret key for a specific vault.
pub fn resolve_key_for_vault(vault_path: &str) -> Result<SecretString, String> {
    resolve_key_with_source(vault_path).map(|(k, _)| k)
}

/// Read a key the environment supplied directly — `MURK_KEY`, or the file at
/// `MURK_KEY_FILE` — and nothing else. Unlike [`resolve_key_with_source`] this
/// does NOT fall back to auto-discovery in `~/.config/murk/keys`: it answers only
/// "did the current environment hand us a key?". `murk init` uses it to reuse an
/// already-present identity instead of generating a new one, which is why it must
/// ignore the stored key it would otherwise be about to create.
///
/// Returns `Ok(None)` when neither variable is set, and an error when both are
/// (see [`env_key`]). The value comes back in a `SecretString` (zeroized on
/// drop) and is trimmed — init later writes it back as a single-line key file;
/// the runtime path deliberately does not trim, to keep plugin identity files
/// intact. The [`KeySource`] says which variable supplied it.
pub fn key_from_env_only() -> Result<Option<(SecretString, KeySource)>, String> {
    match env_key()? {
        Some(EnvKey::Inline(k)) => Ok(Some((SecretString::from(k), KeySource::EnvVar))),
        Some(EnvKey::File(path)) => {
            let contents = read_secret_file(&path, "MURK_KEY_FILE")?;
            Ok(Some((
                SecretString::from(contents.trim()),
                KeySource::EnvFile(path),
            )))
        }
        None => Ok(None),
    }
}

/// Read a key file from `~/.config/murk/keys` with the same symlink and
/// permission checks as the runtime resolver, trimmed like
/// [`key_from_env_only`]. `murk init` uses it to reuse a stored identity
/// instead of generating a new one over it.
pub(crate) fn read_stored_key(path: &Path) -> Result<SecretString, String> {
    let key = read_secret_file(path, "key file")?.trim().to_string();
    Ok(SecretString::from(key))
}

/// The loose-permission warning for a `.env` mode, if it is group/other-readable
/// (Unix only). `None` when the mode is owner-only.
#[cfg(unix)]
fn world_readable_warning(mode: u32) -> Option<String> {
    (mode & WORLD_READABLE_MASK != 0).then(|| {
        format!(
            "\x1b[1;33mwarning:\x1b[0m .env is readable by others (mode {:o}). Run: \x1b[1mchmod 600 .env\x1b[0m",
            mode & 0o777
        )
    })
}

/// The warning to show when `.env` in the cwd has loose permissions, else `None`.
/// Always `None` on non-Unix platforms, where file modes are not enforced.
pub fn env_permission_warning() -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env_path = Path::new(".env");
        if env_path.exists()
            && let Ok(meta) = fs::metadata(env_path)
        {
            return world_readable_warning(meta.permissions().mode());
        }
    }
    None
}

/// Check whether `.env` already contains a `MURK_KEY` line.
pub fn dotenv_has_murk_key() -> bool {
    let env_path = Path::new(".env");
    if !env_path.exists() {
        return false;
    }
    let contents = fs::read_to_string(env_path).unwrap_or_default();
    contents.lines().any(|l| {
        l.starts_with("MURK_KEY=")
            || l.starts_with("export MURK_KEY=")
            || l.starts_with("MURK_KEY_FILE=")
            || l.starts_with("export MURK_KEY_FILE=")
    })
}

/// Write a MURK_KEY to `.env`, removing any existing MURK_KEY lines.
/// On Unix, sets file permissions to 600 atomically at creation time to
/// prevent a TOCTOU window where the secret key is world-readable.
/// On non-Unix platforms, permissions are not hardened.
pub fn write_key_to_dotenv(secret_key: &str) -> Result<(), String> {
    let env_path = Path::new(".env");
    reject_symlink(env_path, ".env")?;

    // Read existing content (minus any MURK_KEY lines).
    let existing = if env_path.exists() {
        let contents = fs::read_to_string(env_path).map_err(|e| format!("reading .env: {e}"))?;
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|l| !l.starts_with("MURK_KEY=") && !l.starts_with("export MURK_KEY="))
            .collect();
        filtered.join("\n") + "\n"
    } else {
        String::new()
    };

    let full_content = format!("{existing}export MURK_KEY={secret_key}\n");

    write_secret_file(
        env_path,
        full_content.as_bytes(),
        "opening .env",
        "writing .env",
    )
}

/// Create or truncate `path` and write `contents`. On Unix the file is created
/// `0600` atomically (no window where it is world-readable) and opened with
/// `O_NOFOLLOW`, so a symlink planted after the caller's check is refused. An
/// existing file is set to `0600` before anything is written to it: `mode()`
/// only applies at creation, and the file is about to hold a secret. On
/// non-Unix platforms permissions are not hardened. Errors are prefixed with
/// `open_context` or `write_context` depending on which step failed.
fn write_secret_file(
    path: &Path,
    contents: &[u8],
    open_context: &str,
    write_context: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("{open_context}: {e}"))?;
        file.set_permissions(fs::Permissions::from_mode(SECRET_FILE_MODE))
            .map_err(|e| format!("{open_context}: {e}"))?;
        file.write_all(contents)
            .map_err(|e| format!("{write_context}: {e}"))
    }
    #[cfg(not(unix))]
    {
        let _ = open_context;
        fs::write(path, contents).map_err(|e| format!("{write_context}: {e}"))
    }
}

/// The absolute — but *lexical* — path of `vault_path`: cwd-joined when
/// relative, with symlinks left unresolved. Using the literal path is important
/// for security: a symlink `.murk` pointing at another project's vault must not
/// resolve to that project's key file.
fn absolute_vault_path(vault_path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::Path::new(vault_path);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    Ok(std::env::current_dir()
        .map_err(|e| format!("cannot resolve vault path: {e}"))?
        .join(p))
}

/// Truncated SHA-256 of an absolute vault path — the filename a vault's key is
/// stored under, in both `keys/` and `agent-keys/`.
fn vault_hash(abs_path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
    hash.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Compute the key file path for a vault: `~/.config/murk/keys/<hash>`.
///
/// This is where `murk init` *writes* a key, keyed on the vault's own path.
/// Reads go through [`discover_key_file`], which also accepts the key stored
/// for the same vault in a sibling git worktree.
pub fn key_file_path(vault_path: &str) -> Result<std::path::PathBuf, String> {
    let abs_path = absolute_vault_path(vault_path)?;
    Ok(dirs_path()?.join(vault_hash(&abs_path)))
}

/// Find a stored key for `vault_path`, or `None` when the operator has none.
///
/// Checks this checkout's own `keys/<hash>` first, then the same vault path in
/// every sibling git worktree of the same repository — main checkout first,
/// then linked worktrees in a stable order.
///
/// The fallback exists because the hash covers an absolute path, and a worktree
/// puts the very same vault at a different one. The committed vault travels
/// into a worktree for free; without this, the key pointer is the one thing
/// that does not, and every throwaway checkout has to be re-provisioned by
/// hand. A sibling worktree is the same repository, same vault file, same
/// operator, and the key is read from the operator's own `0700` config dir —
/// so this widens *where murk looks*, not *whose key it will use*. Strict and
/// agent contexts skip auto-discovery entirely (see
/// [`resolve_key_with_source`]) and are unaffected.
pub fn discover_key_file(vault_path: &str) -> Option<std::path::PathBuf> {
    let own = key_file_path(vault_path).ok()?;
    if own.exists() {
        return Some(own);
    }

    let abs_path = absolute_vault_path(vault_path).ok()?;
    let root = crate::git::worktree_root(abs_path.parent()?)?;
    let relative = abs_path.strip_prefix(&root).ok()?;
    let keys_dir = dirs_path().ok()?;

    crate::git::sibling_worktrees(&root)
        .into_iter()
        .map(|worktree| keys_dir.join(vault_hash(&worktree.join(relative))))
        .find(|key| key.exists())
}

/// Compute the file path for an agent grant key:
/// `~/.config/murk/agent-keys/<vault-hash>-<name>`.
///
/// Grant keys live in a separate `agent-keys/` directory, not in
/// `~/.config/murk/keys/`, so they are never surfaced by key auto-discovery
/// (which only looks up `keys/<vault-hash>`). The vault hash prefix keeps a
/// grant named the same across two vaults from colliding.
pub fn agent_key_file_path(vault_path: &str, name: &str) -> Result<std::path::PathBuf, String> {
    let short_hash = vault_hash(&absolute_vault_path(vault_path)?);
    Ok(agent_keys_dir()?.join(format!("{short_hash}-{name}")))
}

/// Collapse a leading `$HOME` in `path` to `~` for display. Grant key paths live
/// under `~/.config/murk/agent-keys/`, so the absolute form eats 30+ columns of
/// every line that prints one — and a shell expands `~` back, so a printed
/// command stays copy-pasteable.
pub fn home_short(path: &str) -> String {
    match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(home) => shorten_home(path, &home),
        Err(_) => path.to_string(),
    }
}

/// The pure prefix rule behind [`home_short`], split out so it can be tested
/// without mutating the process environment (same shape as
/// `hardening::effective_strict_from`). Only a whole path component matches, so
/// `/home/mickeybob` keeps its full path when `$HOME` is `/home/mickey`.
fn shorten_home(path: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path.to_string();
    }
    match path.strip_prefix(home) {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

/// Return `~/.config/murk/agent-keys/`, creating it if needed (dir `0700`).
pub fn agent_keys_dir() -> Result<std::path::PathBuf, String> {
    config_subdir("agent-keys", "agent key directory")
}

/// Return `~/.config/murk/keys/`, creating it if needed (dir `0700`).
fn dirs_path() -> Result<std::path::PathBuf, String> {
    config_subdir("keys", "key directory")
}

/// Return `~/.config/murk/<name>/`, creating it if needed. On Unix both it and
/// `~/.config/murk` are set to `0700`. `what` names the directory in the
/// creation error.
fn config_subdir(name: &str, what: &str) -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine home directory")?;
    let dir = std::path::Path::new(&home)
        .join(".config")
        .join("murk")
        .join(name);
    fs::create_dir_all(&dir).map_err(|e| format!("creating {what}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = dir.parent().unwrap(); // ~/.config/murk
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("setting permissions on {}: {e}", parent.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("setting permissions on {}: {e}", dir.display()))?;
    }

    Ok(dir)
}

/// Store a secret key at `path`, replacing any file already there.
///
/// [`stage_key_file`] then [`StagedKeyFile::commit`]: the key goes to a `0600`
/// temporary file in the same directory, which is renamed over `path`. An
/// existing file is never truncated and rewritten in place, so it cannot hand
/// its own mode (or its other hard links) to the key. A symlink at `path` is
/// refused; the rename replaces the directory entry and never follows one.
pub fn write_key_to_file(path: &Path, secret_key: &str) -> Result<(), String> {
    stage_key_file(path, secret_key, true)?
        .commit()
        .map_err(|e| e.reason)
}

/// A secret key written to a `0600` temporary file beside its destination and
/// not yet renamed into place. Dropping it deletes the temporary file, so a
/// caller that fails between staging and [`commit`](Self::commit) leaves the
/// destination exactly as it was.
pub struct StagedKeyFile {
    tmp: tempfile::NamedTempFile,
    target: std::path::PathBuf,
    existing: Existing,
}

/// What [`StagedKeyFile::commit`] may do to a file already at the destination.
enum Existing {
    /// Leave it: the rename is exclusive.
    Refuse,
    /// Replace the file that was there at staging (`None`: there was none),
    /// and nothing else.
    Replace(Option<FileStamp>),
}

/// Enough of a file's metadata to tell whether it was replaced or rewritten.
#[derive(PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    inode: (u64, u64),
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = fs::symlink_metadata(path).ok()?;
    Some(FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        },
    })
}

/// Write `secret_key` to a `0600` temporary file in `path`'s directory, ready
/// to be renamed over `path` by [`StagedKeyFile::commit`]. Staging is where an
/// unwritable directory fails, before the caller commits to anything else.
///
/// With `replace`, the commit replaces the file that is at `path` now, and
/// only that file: if it changes in between, the commit refuses. Without it,
/// the commit refuses any file at `path`.
pub fn stage_key_file(
    path: &Path,
    secret_key: &str,
    replace: bool,
) -> Result<StagedKeyFile, String> {
    reject_symlink(path, &path.display().to_string())?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut tmp =
        tempfile::NamedTempFile::new_in(dir).map_err(|e| format!("writing key file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(SECRET_FILE_MODE))
            .map_err(|e| format!("writing key file: {e}"))?;
    }
    tmp.write_all(secret_key.as_bytes())
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| format!("writing key file: {e}"))?;
    Ok(StagedKeyFile {
        tmp,
        target: path.to_path_buf(),
        existing: if replace {
            Existing::Replace(file_stamp(path))
        } else {
            Existing::Refuse
        },
    })
}

/// A [`StagedKeyFile`] that could not be renamed into place. The destination
/// is untouched. Dropping this deletes the staged key; [`keep`](Self::keep)
/// leaves it on disk instead, for a key that must not be lost.
pub struct UncommittedKeyFile {
    pub reason: String,
    /// A file was at the destination and replacing it was not allowed (see
    /// [`stage_key_file`]'s `replace`).
    pub already_exists: bool,
    staged: Box<StagedKeyFile>,
}

impl UncommittedKeyFile {
    /// Keep the staged key file (`0600`, beside the destination) and return
    /// its path.
    pub fn keep(self) -> Result<std::path::PathBuf, String> {
        self.staged
            .tmp
            .keep()
            .map(|(_, path)| path)
            .map_err(|e| format!("keeping the staged key file: {}", e.error))
    }
}

impl StagedKeyFile {
    /// Where [`commit`](Self::commit) puts the key.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Rename the staged key over its destination. Refused, with the
    /// destination left alone, when it is a symlink, when a file appeared there
    /// and replacing was not allowed, or when the file to be replaced changed
    /// since staging.
    pub fn commit(self) -> Result<(), UncommittedKeyFile> {
        let shown = self.target.display().to_string();
        let refuse = |staged, reason: String| {
            Err(UncommittedKeyFile {
                reason,
                already_exists: false,
                staged: Box::new(staged),
            })
        };
        if let Err(reason) = reject_symlink(&self.target, &shown) {
            return refuse(self, reason);
        }
        if let Existing::Replace(stamp) = &self.existing
            && *stamp != file_stamp(&self.target)
        {
            return refuse(
                self,
                format!("{shown} changed while the key was being written — left it untouched"),
            );
        }
        let Self {
            tmp,
            target,
            existing,
        } = self;
        let persisted = match &existing {
            Existing::Replace(_) => tmp.persist(&target),
            Existing::Refuse => tmp.persist_noclobber(&target),
        };
        persisted.map(drop).map_err(|e| {
            let already_exists = e.error.kind() == std::io::ErrorKind::AlreadyExists;
            let reason = if already_exists {
                format!("{shown} already exists — refusing to overwrite it")
            } else {
                format!("writing key file {shown}: {}", e.error)
            };
            UncommittedKeyFile {
                reason,
                already_exists,
                staged: Box::new(StagedKeyFile {
                    tmp: e.file,
                    target,
                    existing,
                }),
            }
        })
    }
}

/// Write a MURK_KEY_FILE reference to `.env`, removing any existing MURK_KEY/MURK_KEY_FILE lines.
pub fn write_key_ref_to_dotenv(key_file_path: &std::path::Path) -> Result<(), String> {
    let env_path = Path::new(".env");
    reject_symlink(env_path, ".env")?;

    let existing = if env_path.exists() {
        let contents = fs::read_to_string(env_path).map_err(|e| format!("reading .env: {e}"))?;
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|l| {
                !l.starts_with("MURK_KEY=")
                    && !l.starts_with("export MURK_KEY=")
                    && !l.starts_with("MURK_KEY_FILE=")
                    && !l.starts_with("export MURK_KEY_FILE=")
            })
            .collect();
        filtered.join("\n") + "\n"
    } else {
        String::new()
    };

    let full_content = format!(
        "{existing}export MURK_KEY_FILE='{}'\n",
        key_file_path.display().to_string().replace('\'', "'\\''")
    );

    write_secret_file(
        env_path,
        full_content.as_bytes(),
        "opening .env",
        "writing .env",
    )
}

/// Status of `.envrc` after writing.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvrcStatus {
    /// `.envrc` already contained `murk export`.
    AlreadyPresent,
    /// Appended murk export line to existing `.envrc`.
    Appended,
    /// Created a new `.envrc` file.
    Created,
}

/// Write a `.envrc` file for direnv integration.
///
/// If `.envrc` exists and already contains `murk export`, returns `AlreadyPresent`.
/// If it exists but doesn't, appends the line. Otherwise creates the file.
pub fn write_envrc(vault_name: &str) -> Result<EnvrcStatus, String> {
    let envrc = Path::new(".envrc");
    reject_symlink(envrc, ".envrc")?;
    let safe_vault_name = shell_escape(vault_name);
    let murk_line = format!("eval \"$(murk export --vault {safe_vault_name})\"");

    if envrc.exists() {
        let contents = fs::read_to_string(envrc).map_err(|e| format!("reading .envrc: {e}"))?;
        if contents.contains("murk export") {
            return Ok(EnvrcStatus::AlreadyPresent);
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(envrc)
            .map_err(|e| format!("writing .envrc: {e}"))?;
        writeln!(file, "\n{murk_line}").map_err(|e| format!("writing .envrc: {e}"))?;
        Ok(EnvrcStatus::Appended)
    } else {
        write_secret_file(
            envrc,
            format!("{murk_line}\n").as_bytes(),
            "writing .envrc",
            "writing .envrc",
        )?;
        Ok(EnvrcStatus::Created)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use age::secrecy::ExposeSecret;

    use crate::testutil::{CWD_LOCK, ENV_LOCK};

    /// Helper: acquire both locks and cd to a clean temp dir.
    /// Returns guards and the previous cwd. The cwd is restored on drop
    /// via the returned `prev` path — callers must restore manually before
    /// asserting so panics don't leave cwd changed.
    fn resolve_key_sandbox(
        name: &str,
    ) -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = std::env::temp_dir().join(format!("murk_test_{name}"));
        let _ = std::fs::create_dir_all(&tmp);
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        (env, cwd, tmp, prev)
    }

    fn resolve_key_sandbox_teardown(tmp: &std::path::Path, prev: &std::path::Path) {
        std::env::set_current_dir(prev).unwrap();
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn resolve_key_from_env() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("from_env");
        let key = "AGE-SECRET-KEY-1TEST";
        unsafe { env::set_var("MURK_KEY", key) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        assert_eq!(secret.expose_secret(), key);
    }

    #[test]
    fn resolve_key_from_file() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("from_file");
        unsafe { env::remove_var("MURK_KEY") };

        let path = std::env::temp_dir().join("murk_test_key_file");
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                std::io::Write::write_all(&mut f, b"AGE-SECRET-KEY-1FROMFILE\n").unwrap();
            }
            #[cfg(not(unix))]
            std::fs::write(&path, "AGE-SECRET-KEY-1FROMFILE\n").unwrap();
        }

        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        // File contents pass through unmodified so plugin identity files
        // (multi-line with `# public key:` header) round-trip intact.
        assert_eq!(secret.expose_secret().trim(), "AGE-SECRET-KEY-1FROMFILE");
    }

    #[test]
    fn resolve_key_file_not_found() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("file_not_found");
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::set_var("MURK_KEY_FILE", "/nonexistent/path/murk_key") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn resolve_key_neither_set() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("neither_set");
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[test]
    fn resolve_key_empty_string_treated_as_unset() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("empty_string");
        unsafe { env::set_var("MURK_KEY", "") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[test]
    fn murk_key_and_key_file_together_are_rejected() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("both");
        let path = std::env::temp_dir().join("murk_test_key_both");
        std::fs::write(&path, "AGE-SECRET-KEY-1FILE\n").unwrap();

        unsafe { env::set_var("MURK_KEY", "AGE-SECRET-KEY-1DIRECT") };
        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let resolved = resolve_key();
        let env_only = key_from_env_only();
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();
        resolve_key_sandbox_teardown(&tmp, &prev);

        // Neither the runtime path nor init's env-only read picks a winner.
        assert!(resolved.unwrap_err().contains("both set"));
        assert!(env_only.err().unwrap().contains("both set"));
    }

    #[cfg(unix)]
    #[test]
    fn key_from_env_only_rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { env::remove_var("MURK_KEY") };

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("loose.key");
        std::fs::write(&path, "AGE-SECRET-KEY-1LOOSE\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = key_from_env_only();
        unsafe { env::remove_var("MURK_KEY_FILE") };

        assert!(
            result.is_err(),
            "a group/world-readable MURK_KEY_FILE must be refused, matching \
             resolve_key_with_source's read_secret_file check"
        );
        assert!(result.unwrap_err().contains("readable by others"));
    }

    #[test]
    fn key_from_env_only_trims_and_accepts_tight_permissions() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { env::remove_var("MURK_KEY") };

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tight.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut f, b"  AGE-SECRET-KEY-1TIGHT  \n").unwrap();
        }
        #[cfg(not(unix))]
        std::fs::write(&path, "  AGE-SECRET-KEY-1TIGHT  \n").unwrap();

        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = key_from_env_only();
        unsafe { env::remove_var("MURK_KEY_FILE") };

        let (key, _source) = result.unwrap().unwrap();
        assert_eq!(key.expose_secret(), "AGE-SECRET-KEY-1TIGHT");
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_warning_flags_group_and_other_bits() {
        // Owner-only mode: no warning.
        assert_eq!(world_readable_warning(0o600), None);
        // Group- or world-readable modes: a warning naming the octal mode.
        for mode in [0o644, 0o640, 0o604, 0o666] {
            let msg =
                world_readable_warning(mode).unwrap_or_else(|| panic!("mode {mode:o} should warn"));
            assert!(msg.contains("readable by others"));
            assert!(
                msg.contains(&format!("{mode:o}")),
                "warning should name the octal mode {mode:o}: {msg}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn env_permission_warning_matches_dotenv_mode() {
        use std::os::unix::fs::PermissionsExt;

        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = std::env::temp_dir().join("murk_test_perms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        // No .env at all: no warning.
        assert_eq!(env_permission_warning(), None);

        // Secure .env (0o600): no warning.
        std::fs::write(&env_path, "KEY=val\n").unwrap();
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(env_permission_warning(), None);

        // Loose .env (0o644): warns.
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            env_permission_warning().is_some_and(|m| m.contains("readable by others")),
            "a group/world-readable .env must produce a warning"
        );

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_key_does_not_read_dotenv() {
        // Even if .env sits in CWD with an inline
        // MURK_KEY, resolve_key_with_source must not pick it up. The runtime
        // only trusts the environment and the vault-keyed auto lookup.
        //
        // Lock order: ENV_LOCK before CWD_LOCK, matching every other test
        // that grabs both. Reversing the order deadlocks against parallel
        // tests that hold ENV_LOCK while waiting for CWD_LOCK.
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_resolve_ignores_dotenv");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".env"),
            "MURK_KEY=AGE-SECRET-KEY-1SHOULDNEVERBEREAD\n",
        )
        .unwrap();

        // Preserve and clear any ambient key env so we see the true fallback.
        let prev_key = env::var(ENV_MURK_KEY).ok();
        let prev_keyfile = env::var(ENV_MURK_KEY_FILE).ok();
        unsafe {
            env::remove_var(ENV_MURK_KEY);
            env::remove_var(ENV_MURK_KEY_FILE);
        }

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        // Use a vault_path that won't match any auto key file on this machine.
        let result = resolve_key_with_source("nonexistent-vault-for-test.murk");
        std::env::set_current_dir(original_dir).unwrap();

        unsafe {
            if let Some(v) = prev_key {
                env::set_var(ENV_MURK_KEY, v);
            }
            if let Some(v) = prev_keyfile {
                env::set_var(ENV_MURK_KEY_FILE, v);
            }
        }

        assert!(
            result.is_err(),
            "resolve_key_with_source must not fall back to .env"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_key_agent_context_disables_auto_fallback() {
        // Regression test: agent context (MURK_AGENT=1) must
        // not silently fall back to the operator's stored key in
        // ~/.config/murk/keys, even when a valid key sits at the
        // auto-discovery path. This is a security fix, not a convenience
        // knob: MURK_STRICT=0 must NOT be able to override agent context
        // back off, or a child process could regain the operator's key.
        //
        // Lock order: ENV_LOCK before CWD_LOCK, matching every other test
        // that grabs both.
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let prev_home = env::var_os("HOME");
        let prev_key = env::var(ENV_MURK_KEY).ok();
        let prev_keyfile = env::var(ENV_MURK_KEY_FILE).ok();
        let prev_agent = env::var("MURK_AGENT").ok();
        let prev_strict = env::var("MURK_STRICT").ok();

        let home = std::env::temp_dir().join("murk_test_agent_fallback_home");
        let vault_dir = std::env::temp_dir().join("murk_test_agent_fallback_vault");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&vault_dir);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&vault_dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        unsafe {
            env::remove_var(ENV_MURK_KEY);
            env::remove_var(ENV_MURK_KEY_FILE);
            env::remove_var("MURK_AGENT");
            env::remove_var("MURK_STRICT");
            env::set_var("HOME", &home);
        }
        std::env::set_current_dir(&vault_dir).unwrap();

        let vault_path = "auto-fallback-test.murk";
        let key = "AGE-SECRET-KEY-1AUTOFALLBACK";
        let auto_path = key_file_path(vault_path).unwrap();
        write_key_to_file(&auto_path, key).unwrap();

        // No agent context, no explicit strict setting: auto fallback works.
        let plain = resolve_key_with_source(vault_path);

        // Agent context with no explicit MURK_STRICT: fail closed, no fallback.
        unsafe { env::set_var("MURK_AGENT", "1") };
        let agent = resolve_key_with_source(vault_path);

        // MURK_STRICT=0 must NOT override agent context: still fails closed.
        unsafe { env::set_var("MURK_STRICT", "0") };
        let agent_with_explicit_off = resolve_key_with_source(vault_path);

        std::env::set_current_dir(&original_dir).unwrap();
        unsafe {
            match prev_home {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
            match prev_key {
                Some(v) => env::set_var(ENV_MURK_KEY, v),
                None => env::remove_var(ENV_MURK_KEY),
            }
            match prev_keyfile {
                Some(v) => env::set_var(ENV_MURK_KEY_FILE, v),
                None => env::remove_var(ENV_MURK_KEY_FILE),
            }
            match prev_agent {
                Some(v) => env::set_var("MURK_AGENT", v),
                None => env::remove_var("MURK_AGENT"),
            }
            match prev_strict {
                Some(v) => env::set_var("MURK_STRICT", v),
                None => env::remove_var("MURK_STRICT"),
            }
        }
        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&vault_dir).ok();

        let (_, source) = plain.expect("auto fallback should succeed without agent/strict context");
        assert_eq!(source, KeySource::Auto(auto_path.clone()));

        assert!(
            agent.is_err(),
            "MURK_AGENT=1 must disable the stored-key auto fallback"
        );

        assert!(
            agent_with_explicit_off.is_err(),
            "MURK_STRICT=0 must not re-enable auto fallback while MURK_AGENT is set"
        );
    }

    #[test]
    fn dotenv_has_murk_key_true() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_has_key_true");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "MURK_KEY=test\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dotenv_has_murk_key_false() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_has_key_false");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "OTHER=val\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(!dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dotenv_has_murk_key_no_file() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_has_key_nofile");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(!dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_key_to_dotenv_creates_new() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_write_key_new");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_to_dotenv("AGE-SECRET-KEY-1NEW").unwrap();

        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(contents.contains("export MURK_KEY=AGE-SECRET-KEY-1NEW"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_key_to_dotenv_replaces_existing() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_write_key_replace");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".env"),
            "OTHER=keep\nMURK_KEY=old\nexport MURK_KEY=also_old\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_to_dotenv("AGE-SECRET-KEY-1REPLACED").unwrap();

        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(contents.contains("OTHER=keep"));
        assert!(contents.contains("export MURK_KEY=AGE-SECRET-KEY-1REPLACED"));
        assert!(!contents.contains("MURK_KEY=old"));
        assert!(!contents.contains("also_old"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_key_to_dotenv_permissions_are_600() {
        use std::os::unix::fs::PermissionsExt;

        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = std::env::temp_dir().join("murk_test_write_key_perms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        // Create new .env — should be 0o600 from the start.
        write_key_to_dotenv("AGE-SECRET-KEY-1PERMTEST").unwrap();
        let meta = std::fs::metadata(dir.join(".env")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SECRET_FILE_MODE,
            "new .env should be created with mode 600"
        );

        // Replace existing — should still be 0o600.
        write_key_to_dotenv("AGE-SECRET-KEY-1PERMTEST2").unwrap();
        let meta = std::fs::metadata(dir.join(".env")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SECRET_FILE_MODE,
            "rewritten .env should maintain mode 600"
        );

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_creates_new() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_envrc_new");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::Created);

        let contents = std::fs::read_to_string(dir.join(".envrc")).unwrap();
        assert!(contents.contains("murk export --vault .murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_appends() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_envrc_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".envrc"), "existing content\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::Appended);

        let contents = std::fs::read_to_string(dir.join(".envrc")).unwrap();
        assert!(contents.contains("existing content"));
        assert!(contents.contains("murk export"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_already_present() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_envrc_present");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".envrc"),
            "eval \"$(murk export --vault .murk)\"\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::AlreadyPresent);

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reject_symlink_ok_for_regular_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("regular.txt");
        std::fs::write(&path, "content").unwrap();
        assert!(reject_symlink(&path, "test").is_ok());
    }

    #[test]
    fn reject_symlink_ok_for_nonexistent() {
        let path = std::path::Path::new("/tmp/does_not_exist_murk_test");
        assert!(reject_symlink(path, "test").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_rejects_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("/tmp/target", &link).unwrap();
        let result = reject_symlink(&link, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
    }

    #[test]
    fn staging_without_replace_never_replaces_an_existing_key_file() {
        // Another `murk init` stored a key after this one's discovery check.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "AGE-SECRET-KEY-1FIRST\n").unwrap();

        let Err(err) = stage_key_file(&path, "AGE-SECRET-KEY-1SECOND", false)
            .unwrap()
            .commit()
        else {
            panic!("an existing key file must not be replaced");
        };

        assert!(err.already_exists, "{}", err.reason);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"AGE-SECRET-KEY-1FIRST\n",
            "existing key file was modified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staging_creates_a_0600_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("key");

        stage_key_file(&path, "AGE-SECRET-KEY-1NEW", false)
            .unwrap()
            .commit()
            .unwrap_or_else(|e| panic!("{}", e.reason));

        assert_eq!(std::fs::read(&path).unwrap(), b"AGE-SECRET-KEY-1NEW");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("loose.key");
        std::fs::write(&path, "secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = read_secret_file(&path, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("readable by others"));
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_accepts_600() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tight.key");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, b"secret").unwrap();
        let result = read_secret_file(&path, "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "secret");
    }

    /// A staged key replaces only the file it was staged against: one that
    /// was rewritten, or that appeared, in the meantime is left untouched, and
    /// the staged key can still be kept rather than lost.
    #[test]
    fn staged_key_never_replaces_a_file_that_changed() {
        let dir = tempfile::TempDir::new().unwrap();
        let rewritten = dir.path().join("rewritten");
        std::fs::write(&rewritten, "AGE-SECRET-KEY-1OLD\n").unwrap();
        let staged = stage_key_file(&rewritten, "AGE-SECRET-KEY-1NEW", true).unwrap();
        std::fs::write(&rewritten, "AGE-SECRET-KEY-1SOMEONE-ELSE\n").unwrap();
        let refused = staged.commit().expect_err("a changed file is not replaced");
        assert!(refused.reason.contains("changed"), "{}", refused.reason);
        assert_eq!(
            std::fs::read_to_string(&rewritten).unwrap(),
            "AGE-SECRET-KEY-1SOMEONE-ELSE\n"
        );
        let kept = refused.keep().unwrap();
        assert_eq!(
            std::fs::read_to_string(kept).unwrap(),
            "AGE-SECRET-KEY-1NEW"
        );

        let appeared = dir.path().join("appeared");
        let staged = stage_key_file(&appeared, "AGE-SECRET-KEY-1NEW", true).unwrap();
        std::fs::write(&appeared, "AGE-SECRET-KEY-1SOMEONE-ELSE\n").unwrap();
        assert!(staged.commit().is_err());
        assert_eq!(
            std::fs::read_to_string(&appeared).unwrap(),
            "AGE-SECRET-KEY-1SOMEONE-ELSE\n"
        );

        // Unchanged, the same staging replaces it.
        let staged = stage_key_file(&appeared, "AGE-SECRET-KEY-1NEW", true).unwrap();
        assert!(staged.commit().is_ok(), "an unchanged file is replaced");
        assert_eq!(
            std::fs::read_to_string(&appeared).unwrap(),
            "AGE-SECRET-KEY-1NEW"
        );
    }

    #[test]
    fn shell_escape_bare_identifiers() {
        assert_eq!(shell_escape(".murk"), ".murk");
        assert_eq!(shell_escape("my-vault.murk"), "my-vault.murk");
        assert_eq!(
            shell_escape("/home/user/.config/murk/key"),
            "/home/user/.config/murk/key"
        );
    }

    #[test]
    fn shell_escape_quotes_special_chars() {
        assert_eq!(shell_escape("my vault"), "'my vault'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
        assert_eq!(shell_escape("val'ue"), "'val'\\''ue'");
    }

    #[test]
    fn write_envrc_escapes_vault_name() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_envrc_escape");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc("my vault.murk").unwrap();
        assert_eq!(status, EnvrcStatus::Created);

        let contents = std::fs::read_to_string(dir.join(".envrc")).unwrap();
        assert!(contents.contains("'my vault.murk'"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_source_describe_renders_each_variant() {
        assert_eq!(
            KeySource::EnvVar.describe(),
            "MURK_KEY environment variable"
        );
        let p = std::path::PathBuf::from("/keys/env-file");
        let env_file = KeySource::EnvFile(p.clone()).describe();
        assert!(env_file.contains("MURK_KEY_FILE"));
        assert!(env_file.contains("/keys/env-file"));
        assert_eq!(
            KeySource::Auto(p.clone()).describe(),
            p.display().to_string()
        );
    }

    #[test]
    fn dotenv_has_murk_key_detects_key_file_variants() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let original_dir = std::env::current_dir().unwrap();
        // A bare MURK_KEY_FILE= line and an `export`-prefixed one both count.
        for line in ["MURK_KEY_FILE=/path\n", "export MURK_KEY_FILE=/path\n"] {
            let dir = std::env::temp_dir().join("murk_test_has_keyfile");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(".env"), line).unwrap();
            std::env::set_current_dir(&dir).unwrap();
            assert!(dotenv_has_murk_key(), "line {line:?} should be detected");
            std::env::set_current_dir(&original_dir).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn write_key_ref_to_dotenv_creates_new() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_write_ref_new");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_ref_to_dotenv(std::path::Path::new("/keys/vault-key")).unwrap();
        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        std::env::set_current_dir(&original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(contents.contains("export MURK_KEY_FILE='/keys/vault-key'"));
    }

    #[test]
    fn write_key_ref_to_dotenv_strips_all_key_lines_and_keeps_others() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_write_ref_replace");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".env"),
            "KEEP=1\n\
             MURK_KEY=oldinline\n\
             export MURK_KEY=oldinline2\n\
             MURK_KEY_FILE=/oldfile\n\
             export MURK_KEY_FILE=/oldfile2\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_ref_to_dotenv(std::path::Path::new("/keys/new-key")).unwrap();
        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        std::env::set_current_dir(&original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        // Unrelated line is preserved.
        assert!(
            contents.contains("KEEP=1"),
            "unrelated line dropped: {contents:?}"
        );
        // Exactly the new reference remains.
        assert!(contents.contains("export MURK_KEY_FILE='/keys/new-key'"));
        // Every prior key/key-file line (all four forms) is stripped.
        assert!(
            !contents.contains("oldinline"),
            "inline key survived: {contents:?}"
        );
        assert!(
            !contents.contains("/oldfile"),
            "old key-file survived: {contents:?}"
        );
    }

    #[test]
    fn write_key_ref_to_dotenv_escapes_single_quotes() {
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_write_ref_escape");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_ref_to_dotenv(std::path::Path::new("/keys/a'b")).unwrap();
        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        std::env::set_current_dir(&original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        // A `'` in the path is escaped so the quoted assignment can't break out.
        assert!(
            contents.contains("export MURK_KEY_FILE='/keys/a'\\''b'"),
            "single quote not escaped: {contents:?}"
        );
    }

    #[test]
    fn config_key_paths_live_under_home_config_murk() {
        // key_file_path / agent_key_file_path / agent_keys_dir must all resolve
        // beneath ~/.config/murk — a stubbed empty path (mutant) would break the
        // per-vault key isolation these paths encode.
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let prev_home = std::env::var_os("HOME");
        let home = std::env::temp_dir().join("murk_test_config_paths_home");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        unsafe { std::env::set_var("HOME", &home) };

        let keys_root = home.join(".config").join("murk").join("keys");
        let agent_root = home.join(".config").join("murk").join("agent-keys");

        let key_path = key_file_path("/project/.murk").unwrap();
        let agent_path = agent_key_file_path("/project/.murk", "cursor").unwrap();
        let agent_dir = agent_keys_dir().unwrap();

        unsafe {
            match &prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&home);

        assert!(
            key_path.starts_with(&keys_root),
            "key_file_path {key_path:?} not under {keys_root:?}"
        );
        assert_eq!(agent_dir, agent_root);
        assert!(
            agent_path.starts_with(&agent_root),
            "agent_key_file_path {agent_path:?} not under {agent_root:?}"
        );
        // The grant key file is named for the grant, keeping distinct grants apart.
        assert!(
            agent_path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-cursor")),
            "agent key file {agent_path:?} should end with the grant name"
        );
    }

    #[test]
    fn vault_hash_is_truncated_sha256_of_the_path() {
        // The key filename scheme is on-disk state: changing it orphans every
        // operator's stored key. Pinned against
        // `printf '%s' /project/.murk | shasum -a 256 | cut -c1-16`.
        assert_eq!(vault_hash(Path::new("/project/.murk")), "55cdcbc361a1e937");
        assert_eq!(vault_hash(Path::new("/other/.murk")), "5db2a3f97067d5c8");
    }

    #[test]
    fn vault_key_file_is_keyed_on_absolute_lexical_path() {
        // Which key file a vault uses must depend only on where the vault sits:
        // relative and absolute spellings of one vault share a key, two vaults
        // never do, and a symlinked vault does not borrow its target's key.
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let prev_home = std::env::var_os("HOME");
        let original_dir = std::env::current_dir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };
        std::env::set_current_dir(project.path()).unwrap();

        // current_dir, not project.path(): macOS reports /var temp dirs as
        // /private/var once they are the cwd.
        let cwd = std::env::current_dir().unwrap();
        let abs = cwd.join("proj.murk");
        let abs_str = abs.to_str().unwrap().to_string();
        let other = cwd.join("other").join("proj.murk");

        let resolved_rel = absolute_vault_path("proj.murk");
        let resolved_abs = absolute_vault_path(&abs_str);
        let key_rel = key_file_path("proj.murk");
        let key_abs = key_file_path(&abs_str);
        let key_other = key_file_path(other.to_str().unwrap());
        let agent_rel = agent_key_file_path("proj.murk", "cursor");

        #[cfg(unix)]
        let (key_real, key_link) = {
            std::fs::create_dir_all(cwd.join("a")).unwrap();
            std::fs::create_dir_all(cwd.join("b")).unwrap();
            std::fs::write(cwd.join("a").join(".murk"), "").unwrap();
            std::os::unix::fs::symlink(cwd.join("a").join(".murk"), cwd.join("b").join(".murk"))
                .unwrap();
            (key_file_path("a/.murk"), key_file_path("b/.murk"))
        };

        std::env::set_current_dir(&original_dir).unwrap();
        unsafe {
            match &prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        let keys_root = home.path().join(".config").join("murk").join("keys");
        let agent_root = home.path().join(".config").join("murk").join("agent-keys");
        let hash = vault_hash(&abs);

        assert_eq!(resolved_rel.unwrap(), abs);
        assert_eq!(resolved_abs.unwrap(), abs);
        assert_eq!(key_rel.unwrap(), keys_root.join(&hash));
        assert_eq!(key_abs.unwrap(), keys_root.join(&hash));
        assert_eq!(key_other.unwrap(), keys_root.join(vault_hash(&other)));
        assert_ne!(vault_hash(&other), hash);
        assert_eq!(
            agent_rel.unwrap(),
            agent_root.join(format!("{hash}-cursor"))
        );
        #[cfg(unix)]
        assert_ne!(
            key_link.unwrap(),
            key_real.unwrap(),
            "a symlinked vault must not resolve to its target's key file"
        );
    }

    #[test]
    fn home_short_collapses_the_process_home() {
        // The env-reading wrapper a grant handoff prints through; the prefix
        // rule itself is covered by shorten_home_collapses_only_whole_components.
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/home/mickey") };

        let inside = home_short("/home/mickey/.config/murk/agent-keys/ab-codex");
        let outside = home_short("/etc/murk/k");

        unsafe {
            match &prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        assert_eq!(inside, "~/.config/murk/agent-keys/ab-codex");
        assert_eq!(outside, "/etc/murk/k");
    }

    #[test]
    fn shorten_home_collapses_only_whole_components() {
        // The display path a grant handoff prints: $HOME becomes `~`, and a
        // shell expands it back, so the printed command stays runnable.
        assert_eq!(
            shorten_home(
                "/home/mickey/.config/murk/agent-keys/ab-codex",
                "/home/mickey"
            ),
            "~/.config/murk/agent-keys/ab-codex"
        );
        // Exactly $HOME.
        assert_eq!(shorten_home("/home/mickey", "/home/mickey"), "~");
        // A trailing slash on $HOME must not leave a doubled separator.
        assert_eq!(shorten_home("/home/mickey/k", "/home/mickey/"), "~/k");
        // Sibling directories that merely share a prefix keep their full path —
        // collapsing these would print a path pointing at the wrong user.
        assert_eq!(
            shorten_home("/home/mickeybob/k", "/home/mickey"),
            "/home/mickeybob/k"
        );
        // Unrelated paths, and an empty $HOME, are passed through untouched.
        assert_eq!(shorten_home("/etc/murk/k", "/home/mickey"), "/etc/murk/k");
        assert_eq!(shorten_home("/home/mickey/k", ""), "/home/mickey/k");
        assert_eq!(shorten_home("relative/k", "/home/mickey"), "relative/k");
    }
}
