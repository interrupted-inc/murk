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

/// Read a file, rejecting symlinks and (on Unix) group/world-readable permissions.
/// Returns the file contents as a string.
fn read_secret_file(path: &Path, label: &str) -> Result<String, String> {
    reject_symlink(path, label)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.mode();
            if mode & WORLD_READABLE_MASK != 0 {
                return Err(format!(
                    "{label} is readable by others (mode {:o}). Run: chmod 600 {}",
                    mode & 0o777,
                    path.display()
                ));
            }
        }
    }

    fs::read_to_string(path).map_err(|e| format!("cannot read {label}: {e}"))
}

/// Environment variable for the secret key.
pub const ENV_MURK_KEY: &str = "MURK_KEY";
/// Environment variable for the secret key file path.
pub const ENV_MURK_KEY_FILE: &str = "MURK_KEY_FILE";
/// Environment variable for the vault filename.
pub const ENV_MURK_VAULT: &str = "MURK_VAULT";

/// Keys to skip when importing from a .env file.
const IMPORT_SKIP: &[&str] = &[ENV_MURK_KEY, ENV_MURK_KEY_FILE, ENV_MURK_VAULT];

/// File mode for `.env`: owner read/write only.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// Bitmask for group/other permission bits.
#[cfg(unix)]
const WORLD_READABLE_MASK: u32 = 0o077;

/// Resolve the secret key, checking in order:
/// 1. `MURK_KEY` env var (explicit key)
/// 2. `MURK_KEY_FILE` env var (path to key file)
/// 3. `~/.config/murk/keys/<vault-hash>` (automatic lookup for default vault)
/// 4. `.env` file in cwd (backward compat)
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

/// Resolve the secret key and report where it came from.
///
/// Checks, in order:
/// 1. `MURK_KEY` env var (explicit key)
/// 2. `MURK_KEY_FILE` env var (path to a key file)
/// 3. `~/.config/murk/keys/<hash-of-vault-path>`, for this checkout or a
///    sibling git worktree of it (automatic lookup — see [`discover_key_file`])
///
/// `.env` is **not** consulted at runtime. It is a write-only convenience that
/// `murk init` populates with a `MURK_KEY_FILE` reference for direnv to export.
/// Reading `.env` at runtime would let a copied vault in another repo borrow
/// whichever key happened to be referenced in the current working directory's
/// `.env` — a confused-deputy path that defeats per-vault key isolation.
pub fn resolve_key_with_source(vault_path: &str) -> Result<(SecretString, KeySource), String> {
    if let Some(k) = env::var(ENV_MURK_KEY).ok().filter(|k| !k.is_empty()) {
        return Ok((SecretString::from(k), KeySource::EnvVar));
    }
    // File paths return full contents (not trimmed) so that plugin identity
    // files — which contain a `# public key: age1...` header above an
    // `AGE-PLUGIN-...-1...` pointer — round-trip intact through parse_identity.
    if let Ok(path) = env::var(ENV_MURK_KEY_FILE) {
        let p = std::path::Path::new(&path);
        let contents = read_secret_file(p, "MURK_KEY_FILE")?;
        return Ok((
            SecretString::from(contents),
            KeySource::EnvFile(p.to_path_buf()),
        ));
    }
    // Auto-discovery of the operator's stored key. Disabled in strict mode (an
    // explicit MURK_STRICT, or an agent context via MURK_AGENT) so an agent never
    // silently falls back to the operator's personal key in ~/.config/murk/keys —
    // it must present an explicit MURK_KEY/MURK_KEY_FILE (its grant key) or fail
    // closed. `murk agent exec` sets MURK_AGENT=1 and MURK_STRICT=1 for the child, so this holds
    // without the agent having to opt in.
    if !crate::hardening::strict_mode()
        && let Some(path) = discover_key_file(vault_path)
    {
        let contents = read_secret_file(&path, "key file")?;
        return Ok((SecretString::from(contents), KeySource::Auto(path)));
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
/// Returns `Ok(None)` when neither variable is set. The value comes back in a
/// `SecretString` (zeroized on drop) and is trimmed — init later writes it back
/// as a single-line key file; the runtime path deliberately does not trim,
/// to keep plugin identity files intact.
///
/// This is the single place, alongside [`resolve_key_with_source`], that reads
/// the key environment variables — see `tests/invariants.rs`.
pub fn key_from_env_only() -> Result<Option<SecretString>, String> {
    if let Some(k) = env::var(ENV_MURK_KEY).ok().filter(|k| !k.is_empty()) {
        return Ok(Some(SecretString::from(k)));
    }
    if let Ok(path) = env::var(ENV_MURK_KEY_FILE) {
        let p = std::path::Path::new(&path);
        let key = read_secret_file(p, "MURK_KEY_FILE")?.trim().to_string();
        return Ok(Some(SecretString::from(key)));
    }
    Ok(None)
}

/// Parse a .env file into key-value pairs.
/// Skips comments, blank lines, `MURK_*` keys, and strips quotes and `export` prefixes.
///
/// Values are wrapped in [`Zeroizing`] so that the plaintext is wiped from memory
/// as soon as the caller drops them.
pub fn parse_env(contents: &str) -> Vec<(String, Zeroizing<String>)> {
    let mut pairs = Vec::new();

    for line in contents.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        // Strip surrounding quotes.
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        if key.is_empty() || IMPORT_SKIP.contains(&key) {
            continue;
        }

        pairs.push((key.into(), Zeroizing::new(value.to_string())));
    }

    pairs
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

    // Write the file with restricted permissions from the start (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(env_path)
            .map_err(|e| format!("opening .env: {e}"))?;
        file.write_all(full_content.as_bytes())
            .map_err(|e| format!("writing .env: {e}"))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(env_path, &full_content).map_err(|e| format!("writing .env: {e}"))?;
    }

    Ok(())
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
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine home directory")?;
    let dir = std::path::Path::new(&home)
        .join(".config")
        .join("murk")
        .join("agent-keys");
    fs::create_dir_all(&dir).map_err(|e| format!("creating agent key directory: {e}"))?;

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

/// Return `~/.config/murk/keys/`, creating it if needed.
fn dirs_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine home directory")?;
    let dir = std::path::Path::new(&home)
        .join(".config")
        .join("murk")
        .join("keys");
    fs::create_dir_all(&dir).map_err(|e| format!("creating key directory: {e}"))?;

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

/// Write a secret key to a file with restricted permissions.
pub fn write_key_to_file(path: &std::path::Path, secret_key: &str) -> Result<(), String> {
    reject_symlink(path, &path.display().to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("writing key file: {e}"))?;
        file.write_all(secret_key.as_bytes())
            .map_err(|e| format!("writing key file: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, secret_key).map_err(|e| format!("writing key file: {e}"))?;
    }
    Ok(())
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(env_path)
            .map_err(|e| format!("opening .env: {e}"))?;
        file.write_all(full_content.as_bytes())
            .map_err(|e| format!("writing .env: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(env_path, &full_content).map_err(|e| format!("writing .env: {e}"))?;
    }

    Ok(())
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(SECRET_FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW)
                .open(envrc)
                .map_err(|e| format!("writing .envrc: {e}"))?;
            file.write_all(format!("{murk_line}\n").as_bytes())
                .map_err(|e| format!("writing .envrc: {e}"))?;
        }
        #[cfg(not(unix))]
        {
            fs::write(envrc, format!("{murk_line}\n"))
                .map_err(|e| format!("writing .envrc: {e}"))?;
        }
        Ok(EnvrcStatus::Created)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use age::secrecy::ExposeSecret;

    use crate::testutil::{CWD_LOCK, ENV_LOCK};

    #[test]
    fn parse_env_empty() {
        assert!(parse_env("").is_empty());
    }

    #[test]
    fn parse_env_comments_and_blanks() {
        let input = "# comment\n\n  # another\n";
        assert!(parse_env(input).is_empty());
    }

    /// Compare parsed pairs against plain `(key, value)` expectations by
    /// unwrapping the `Zeroizing` value wrappers.
    fn assert_pairs(pairs: Vec<(String, Zeroizing<String>)>, expected: &[(&str, &str)]) {
        let actual: Vec<(String, String)> =
            pairs.into_iter().map(|(k, v)| (k, (*v).clone())).collect();
        let want: Vec<(String, String)> = expected
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        assert_eq!(actual, want);
    }

    #[test]
    fn parse_env_basic() {
        assert_pairs(
            parse_env("FOO=bar\nBAZ=qux\n"),
            &[("FOO", "bar"), ("BAZ", "qux")],
        );
    }

    #[test]
    fn parse_env_double_quotes() {
        assert_pairs(
            parse_env("KEY=\"hello world\"\n"),
            &[("KEY", "hello world")],
        );
    }

    #[test]
    fn parse_env_single_quotes() {
        assert_pairs(parse_env("KEY='hello world'\n"), &[("KEY", "hello world")]);
    }

    #[test]
    fn parse_env_export_prefix() {
        assert_pairs(parse_env("export FOO=bar\n"), &[("FOO", "bar")]);
    }

    #[test]
    fn parse_env_skips_murk_keys() {
        let input = "MURK_KEY=secret\nMURK_KEY_FILE=/path\nMURK_VAULT=.murk\nKEEP=yes\n";
        assert_pairs(parse_env(input), &[("KEEP", "yes")]);
    }

    #[test]
    fn parse_env_equals_in_value() {
        assert_pairs(
            parse_env("URL=postgres://host?opt=1\n"),
            &[("URL", "postgres://host?opt=1")],
        );
    }

    #[test]
    fn parse_env_no_equals_skipped() {
        assert_pairs(parse_env("not-a-valid-line\nKEY=val\n"), &[("KEY", "val")]);
    }

    // ── New edge-case tests ──

    #[test]
    fn parse_env_empty_value() {
        assert_pairs(parse_env("KEY=\n"), &[("KEY", "")]);
    }

    #[test]
    fn parse_env_trailing_whitespace() {
        assert_pairs(parse_env("KEY=value   \n"), &[("KEY", "value")]);
    }

    #[test]
    fn parse_env_unicode_value() {
        assert_pairs(parse_env("KEY=hello🔐world\n"), &[("KEY", "hello🔐world")]);
    }

    #[test]
    fn parse_env_empty_key_skipped() {
        let pairs = parse_env("=value\n");
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_env_mixed_quotes_unmatched() {
        // Mismatched quotes are not stripped.
        assert_pairs(parse_env("KEY=\"hello'\n"), &[("KEY", "\"hello'")]);
    }

    #[test]
    fn parse_env_multiple_murk_vars() {
        // All three MURK_ vars are skipped, other vars kept.
        let input = "MURK_KEY=x\nMURK_KEY_FILE=y\nMURK_VAULT=z\nA=1\nB=2\n";
        assert_pairs(parse_env(input), &[("A", "1"), ("B", "2")]);
    }

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
    fn resolve_key_murk_key_takes_priority_over_file() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("priority");
        let direct_key = "AGE-SECRET-KEY-1DIRECT";
        let file_key = "AGE-SECRET-KEY-1FILE";

        let path = std::env::temp_dir().join("murk_test_key_priority");
        std::fs::write(&path, format!("{file_key}\n")).unwrap();

        unsafe { env::set_var("MURK_KEY", direct_key) };
        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        assert_eq!(secret.expose_secret(), direct_key);
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

        let key = result.unwrap().unwrap();
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
        assert_eq!(result.unwrap(), "secret");
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
    fn parse_env_comment_with_equals_is_skipped() {
        // A comment line that happens to contain `=` must still be dropped;
        // it must not be parsed into a `# FOO` key.
        assert!(parse_env("# FOO=bar\n").is_empty());
        assert!(parse_env("   # A=B\n").is_empty());
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
