// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::types::Vault;

/// Errors that can occur during vault file operations.
#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                write!(f, "vault file not found. Run `murk init` to create one")
            }
            VaultError::Io(e) => write!(f, "vault I/O error: {e}"),
            VaultError::Parse(msg) => write!(f, "vault parse error: {msg}"),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

/// Parse vault from a JSON string.
///
/// Rejects vaults with an unrecognized major version to prevent
/// silently misinterpreting a newer format.
pub fn parse(contents: &str) -> Result<Vault, VaultError> {
    let vault: Vault = serde_json::from_str(contents).map_err(|e| {
        VaultError::Parse(format!(
            "invalid vault JSON: {e}. Vault may be corrupted — restore from git"
        ))
    })?;

    // Accept any 2.x version (same major).
    let major = vault.version.split('.').next().unwrap_or("");
    if major != "2" {
        return Err(VaultError::Parse(format!(
            "unsupported vault version: {}. This build of murk supports version 2.x",
            vault.version
        )));
    }

    Ok(vault)
}

/// Read a .murk vault file.
///
/// Rejects symlinks at the vault path to prevent a local attacker from
/// redirecting vault operations to a different project's vault (and thus
/// triggering auto key-file lookup against the attacker-controlled path).
pub fn read(path: &Path) -> Result<Vault, VaultError> {
    Ok(read_with_raw(path)?.0)
}

/// Read a .murk vault file and return both the parsed vault and the raw bytes.
///
/// Use this when a caller needs the raw file contents (e.g. for computing a
/// content-addressed codename via `codename::from_bytes`) and must NOT bypass
/// the symlink rejection and version check that `read` enforces. Callers
/// should always prefer this or `read` over calling `fs::read(path)` directly.
pub fn read_with_raw(path: &Path) -> Result<(Vault, Vec<u8>), VaultError> {
    if path.is_symlink() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "vault file is a symlink — refusing to follow for security: {}",
                path.display()
            ),
        )));
    }
    let contents = fs::read_to_string(path)?;
    let vault = parse(&contents)?;
    Ok((vault, contents.into_bytes()))
}

/// An exclusive advisory lock on a vault file.
///
/// Holds a `.murk.lock` file with an exclusive flock for the duration of a
/// read-modify-write cycle. Dropped automatically when the guard goes out of scope.
#[derive(Debug)]
pub struct VaultLock {
    _file: File,
    _path: PathBuf,
}

/// Lock path for a given vault path (e.g. `.murk` → `.murk.lock`).
fn lock_path(vault_path: &Path) -> PathBuf {
    let mut p = vault_path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

/// Acquire an exclusive advisory lock on the vault file.
///
/// Returns a guard that releases the lock when dropped. Use this around
/// read-modify-write cycles to prevent concurrent writes from losing changes.
pub fn lock(vault_path: &Path) -> Result<VaultLock, VaultError> {
    let lp = lock_path(vault_path);

    // Open lock file without following symlinks (race-safe on Unix).
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lp)?
    };
    #[cfg(not(unix))]
    let file = {
        // Fallback: check-then-open (still has TOCTOU on non-Unix).
        if lp.is_symlink() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "lock file is a symlink — refusing to follow: {}",
                    lp.display()
                ),
            )));
        }
        File::create(&lp)?
    };
    file.lock_exclusive().map_err(|e| {
        VaultError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to acquire vault lock: {e}"),
        ))
    })?;
    Ok(VaultLock {
        _file: file,
        _path: lp,
    })
}

/// Write a vault to a .murk file as pretty-printed JSON.
///
/// Uses write-to-tempfile + rename for atomic writes — if the process is
/// killed mid-write, the original file remains intact.
pub fn write(path: &Path, vault: &Vault) -> Result<(), VaultError> {
    let json = serde_json::to_string_pretty(vault)
        .map_err(|e| VaultError::Parse(format!("failed to serialize vault: {e}")))?;

    // Write to a sibling temp file, fsync, then atomically rename.
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;

    // Restrict temp file permissions before writing plaintext JSON.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    tmp.write_all(json.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;

    // Fsync the parent directory so the rename is durable across power loss.
    #[cfg(unix)]
    {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SchemaEntry, SecretEntry, VAULT_VERSION};
    use std::collections::BTreeMap;

    fn test_vault() -> Vault {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DATABASE_URL".into(),
            SchemaEntry {
                description: "postgres connection string".into(),
                example: Some("postgres://user:pass@host/db".into()),
                tags: vec![],
                ..Default::default()
            },
        );

        Vault {
            version: VAULT_VERSION.into(),
            created: "2026-02-27T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1test".into()],
            schema,
            policy: None,
            secrets: BTreeMap::new(),
            meta: "encrypted-meta".into(),
        }
    }

    #[test]
    fn roundtrip_read_write() {
        let dir = std::env::temp_dir().join("murk_test_vault_v2");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: "encrypted-value".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        assert_eq!(read_vault.version, VAULT_VERSION);
        assert_eq!(read_vault.recipients[0], "age1test");
        assert!(read_vault.schema.contains_key("DATABASE_URL"));
        assert!(read_vault.secrets.contains_key("DATABASE_URL"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_is_sorted() {
        let dir = std::env::temp_dir().join("murk_test_sorted_v2");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.schema.insert(
            "ZZZ_KEY".into(),
            SchemaEntry {
                description: "last".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "AAA_KEY".into(),
            SchemaEntry {
                description: "first".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        write(&path, &vault).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        // BTreeMap ensures sorted output — AAA before DATABASE before ZZZ.
        let aaa_pos = contents.find("AAA_KEY").unwrap();
        let db_pos = contents.find("DATABASE_URL").unwrap();
        let zzz_pos = contents.find("ZZZ_KEY").unwrap();
        assert!(aaa_pos < db_pos);
        assert!(db_pos < zzz_pos);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_errors() {
        let result = read(Path::new("/tmp/null.murk"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_json() {
        let result = parse("not json at all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("vault parse error"));
        assert!(msg.contains("Vault may be corrupted"));
    }

    #[test]
    fn parse_empty_string() {
        let result = parse("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_valid_json() {
        let json = serde_json::to_string(&test_vault()).unwrap();
        let result = parse(&json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, VAULT_VERSION);
    }

    #[test]
    fn parse_rejects_unknown_major_version() {
        let mut vault = test_vault();
        vault.version = "99.0".into();
        let json = serde_json::to_string(&vault).unwrap();
        let result = parse(&json);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported vault version: 99.0"));
    }

    #[test]
    fn parse_accepts_minor_version_bump() {
        let mut vault = test_vault();
        vault.version = "2.1".into();
        let json = serde_json::to_string(&vault).unwrap();
        let result = parse(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn error_display_not_found() {
        let err = VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file",
        ));
        let msg = err.to_string();
        assert!(msg.contains("vault file not found"));
        assert!(msg.contains("murk init"));
    }

    #[test]
    fn error_display_io() {
        let err = VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        let msg = err.to_string();
        assert!(msg.contains("vault I/O error"));
    }

    #[test]
    fn error_display_parse() {
        let err = VaultError::Parse("bad data".into());
        assert!(err.to_string().contains("vault parse error: bad data"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::other("test");
        let vault_err: VaultError = io_err.into();
        assert!(matches!(vault_err, VaultError::Io(_)));
    }

    #[test]
    fn scoped_entries_roundtrip() {
        let dir = std::env::temp_dir().join("murk_test_scoped_rt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        let mut private = BTreeMap::new();
        private.insert("age1bob".into(), "encrypted-for-bob".into());

        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: "encrypted-value".into(),
                private,
                grouped: std::collections::BTreeMap::default(),
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        let entry = &read_vault.secrets["DATABASE_URL"];
        assert_eq!(entry.private["age1bob"], "encrypted-for-bob");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_creates_lock_file() {
        let dir = std::env::temp_dir().join("murk_test_lock_create");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("test.murk");

        let lock = lock(&vault_path).unwrap();
        assert!(lock_path(&vault_path).exists());

        drop(lock);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lock_rejects_symlink() {
        let dir = std::env::temp_dir().join("murk_test_lock_symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("test.murk");
        let lp = lock_path(&vault_path);

        // Create a symlink where the lock file would go.
        std::os::unix::fs::symlink("/tmp/evil", &lp).unwrap();

        let result = lock(&vault_path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // On Unix with O_NOFOLLOW, we get a "too many levels of symbolic links" error.
        assert!(
            msg.contains("symlink") || msg.contains("symbolic link"),
            "unexpected error: {msg}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_is_atomic() {
        let dir = std::env::temp_dir().join("murk_test_write_atomic");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let vault = test_vault();
        write(&path, &vault).unwrap();

        // File should exist and be valid JSON.
        let contents = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["version"], VAULT_VERSION);

        // Overwrite with a new vault — should atomically replace.
        let mut vault2 = test_vault();
        vault2.vault_name = "updated.murk".into();
        write(&path, &vault2).unwrap();
        let contents2 = fs::read_to_string(&path).unwrap();
        assert!(contents2.contains("updated.murk"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_entry_timestamps_roundtrip() {
        let dir = std::env::temp_dir().join("murk_test_timestamps");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.schema.insert(
            "TIMED_KEY".into(),
            SchemaEntry {
                description: "has timestamps".into(),
                created: Some("2026-03-29T00:00:00Z".into()),
                updated: Some("2026-03-29T12:00:00Z".into()),
                ..Default::default()
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();
        let entry = &read_vault.schema["TIMED_KEY"];
        assert_eq!(entry.created.as_deref(), Some("2026-03-29T00:00:00Z"));
        assert_eq!(entry.updated.as_deref(), Some("2026-03-29T12:00:00Z"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_entry_without_timestamps_roundtrips() {
        let dir = std::env::temp_dir().join("murk_test_no_timestamps");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.schema.insert(
            "LEGACY".into(),
            SchemaEntry {
                description: "no timestamps".into(),
                ..Default::default()
            },
        );

        write(&path, &vault).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        // Schema timestamps should be omitted from JSON when None.
        // Check that the LEGACY entry block doesn't contain timestamp fields.
        let legacy_block = &contents[contents.find("LEGACY").unwrap()..];
        let block_end = legacy_block.find('}').unwrap();
        let legacy_block = &legacy_block[..block_end];
        assert!(
            !legacy_block.contains("created"),
            "LEGACY entry should not have created timestamp"
        );
        assert!(
            !legacy_block.contains("updated"),
            "LEGACY entry should not have updated timestamp"
        );

        let read_vault = read(&path).unwrap();
        assert!(read_vault.schema["LEGACY"].created.is_none());
        assert!(read_vault.schema["LEGACY"].updated.is_none());

        fs::remove_dir_all(&dir).unwrap();
    }
}
