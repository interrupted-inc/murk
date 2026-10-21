// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::types::Vault;
use crate::validate::MAX_VAULT_BYTES;

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
/// Every vault loader goes through here, so this is where untrusted input is
/// checked: oversized input is refused before deserializing, and every field
/// of the result must pass the allowlists in [`crate::validate`] (including
/// the version, so a newer major format is never silently misinterpreted).
pub fn parse(contents: &str) -> Result<Vault, VaultError> {
    if contents.len() > MAX_VAULT_BYTES {
        return Err(oversized());
    }
    let vault: Vault = serde_json::from_str(contents).map_err(|e| {
        VaultError::Parse(format!(
            "invalid vault JSON: {e}. Vault may be corrupted — restore from git"
        ))
    })?;
    crate::validate::vault(&vault).map_err(VaultError::Parse)?;
    Ok(vault)
}

fn oversized() -> VaultError {
    VaultError::Parse(format!(
        "vault file size exceeds the {} MiB limit",
        MAX_VAULT_BYTES / (1024 * 1024)
    ))
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
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_VAULT_BYTES as u64 {
        return Err(oversized());
    }
    // Bounded read: a file that grows after the size check still cannot make
    // us buffer more than one byte past the limit (which `parse` then rejects).
    let mut contents = String::new();
    file.take(MAX_VAULT_BYTES as u64 + 1)
        .read_to_string(&mut contents)?;
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
/// Refuses a vault that [`parse`] would reject, so murk never commits a file
/// it (or another recipient) cannot load back.
///
/// Uses write-to-tempfile + rename for atomic writes — if the process is
/// killed mid-write, the original file remains intact.
pub fn write(path: &Path, vault: &Vault) -> Result<(), VaultError> {
    write_impl(path, vault, false)
}

/// Write a brand-new vault, refusing (with an `AlreadyExists` I/O error) if a
/// file appeared at `path` since the caller checked, for example from a
/// `git pull` while `murk init` waited at a prompt. Same atomicity as
/// [`write`]; the existing file is left untouched.
pub fn create(path: &Path, vault: &Vault) -> Result<(), VaultError> {
    write_impl(path, vault, true)
}

fn write_impl(path: &Path, vault: &Vault, create_new: bool) -> Result<(), VaultError> {
    crate::validate::vault(vault)
        .map_err(|e| VaultError::Parse(format!("refusing to write invalid vault: {e}")))?;
    let json = serde_json::to_string_pretty(vault)
        .map_err(|e| VaultError::Parse(format!("failed to serialize vault: {e}")))?;
    if json.len() + 1 > MAX_VAULT_BYTES {
        return Err(oversized());
    }

    // Write to a sibling temp file, fsync, then atomically rename (or, for a
    // new vault, link without replacing).
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
    if create_new {
        tmp.persist_noclobber(path).map_err(|e| e.error)?;
    } else {
        tmp.persist(path).map_err(|e| e.error)?;
    }

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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![crate::testutil::AGE_PK.into()],
            schema,
            policy: None,
            secrets: BTreeMap::new(),
            meta: "ZW5jcnlwdGVkLW1ldGE=".into(),
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
                shared: "ZW5jcnlwdGVk".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        assert_eq!(read_vault.version, VAULT_VERSION);
        assert_eq!(read_vault.recipients[0], crate::testutil::AGE_PK);
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
    fn parse_accepts_supported_2x_versions() {
        for v in ["2.0", "2.1", "2.10", "2.1.3"] {
            let mut vault = test_vault();
            vault.version = v.into();
            let json = serde_json::to_string(&vault).unwrap();
            assert!(parse(&json).is_ok(), "version {v} must load");
        }
    }

    /// `test_vault()` with every optional field populated, as JSON.
    fn full_vault_json() -> serde_json::Value {
        let mut vault = test_vault();
        let entry = vault.schema.get_mut("DATABASE_URL").unwrap();
        entry.tags = vec!["db".into()];
        entry.created = Some("2026-02-27T00:00:00Z".into());
        entry.updated = Some("2026-02-27T00:00:00Z".into());
        entry.expires_at = Some("2026-09-01T23:59:59Z".into());
        entry.revoked_at = Some("2026-03-01T00:00:00Z".into());
        entry.rotation_interval_days = Some(90);
        vault.policy = Some(crate::types::Policy {
            agent_allow_tags: vec!["db".into()],
        });
        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: String::new(),
                private: BTreeMap::from([(crate::testutil::SSH_ED25519_PK.into(), "Ym9i".into())]),
                grouped: BTreeMap::from([("prod".into(), "cHJvZA==".into())]),
            },
        );
        serde_json::to_value(&vault).unwrap()
    }

    #[test]
    fn parse_accepts_fully_populated_vault() {
        parse(&full_vault_json().to_string()).unwrap();
    }

    #[test]
    fn parse_rejects_invalid_fields_naming_them() {
        type Mutate = fn(&mut serde_json::Value);
        let cases: &[(&str, Mutate)] = &[
            ("unsupported vault version: 2.", |v| {
                v["version"] = "2.".into();
            }),
            ("unsupported vault version: 2", |v| {
                v["version"] = "2".into();
            }),
            ("unsupported vault version: 2.x", |v| {
                v["version"] = "2.x".into();
            }),
            ("unsupported vault version: 2.01", |v| {
                v["version"] = "2.01".into();
            }),
            ("unsupported vault version: 20.0", |v| {
                v["version"] = "20.0".into();
            }),
            ("unsupported vault version: 2.0-beta", |v| {
                v["version"] = "2.0-beta".into();
            }),
            ("created: not an RFC 3339 timestamp", |v| {
                v["created"] = "yesterday".into();
            }),
            ("schema.DATABASE_URL.expires_at: not an RFC 3339", |v| {
                v["schema"]["DATABASE_URL"]["expires_at"] = "2026-13-01T00:00:00Z".into();
            }),
            ("schema.DATABASE_URL.revoked_at: not an RFC 3339", |v| {
                v["schema"]["DATABASE_URL"]["revoked_at"] = "".into();
            }),
            ("schema.DATABASE_URL.rotation_interval_days", |v| {
                v["schema"]["DATABASE_URL"]["rotation_interval_days"] = 0.into();
            }),
            ("schema: invalid key name BAD-NAME", |v| {
                v["schema"]["BAD-NAME"] = serde_json::json!({"description": ""});
            }),
            ("secrets: invalid key name 1BAD", |v| {
                v["secrets"]["1BAD"] = serde_json::json!({"shared": ""});
            }),
            ("schema: invalid key name $(rm -rf ~)", |v| {
                v["schema"]["$(rm -rf ~)"] = serde_json::json!({"description": ""});
            }),
            (
                "recipients[1]: not a valid age, SSH, or plugin public key",
                |v| {
                    v["recipients"]
                        .as_array_mut()
                        .unwrap()
                        .push("age1bogus".into());
                },
            ),
            ("secrets.DATABASE_URL.scoped key: not a valid", |v| {
                v["secrets"]["DATABASE_URL"]["scoped"]["../../etc"] = "Ym9i".into();
            }),
            ("secrets.DATABASE_URL.grouped key", |v| {
                v["secrets"]["DATABASE_URL"]["grouped"]["no spaces"] = "cHJvZA==".into();
            }),
            ("secrets.DATABASE_URL.grouped key", |v| {
                v["secrets"]["DATABASE_URL"]["grouped"]["me"] = "cHJvZA==".into();
            }),
            ("secrets.DATABASE_URL.shared: not valid base64", |v| {
                v["secrets"]["DATABASE_URL"]["shared"] = "not base64!".into();
            }),
            ("meta: not valid base64", |v| v["meta"] = "abc".into()),
            (
                "schema.DATABASE_URL.description: contains control characters",
                |v| {
                    v["schema"]["DATABASE_URL"]["description"] = "\u{1b}]52;c;aGk=\u{7}".into();
                },
            ),
            (
                "schema.DATABASE_URL.tags[1]: contains control characters",
                |v| {
                    v["schema"]["DATABASE_URL"]["tags"]
                        .as_array_mut()
                        .unwrap()
                        .push("\u{1b}[2J".into());
                },
            ),
            (
                "policy.agent_allow_tags[0]: contains control characters",
                |v| {
                    v["policy"]["agent_allow_tags"][0] = "db\u{0}".into();
                },
            ),
            ("vault_name: contains control characters", |v| {
                v["vault_name"] = "\u{9b}31m".into();
            }),
        ];
        for (expected, mutate) in cases {
            let mut v = full_vault_json();
            mutate(&mut v);
            let err = parse(&v.to_string())
                .expect_err(&format!("expected rejection: {expected}"))
                .to_string();
            assert!(err.contains(expected), "want {expected:?}, got {err:?}");
        }
    }

    #[test]
    fn parse_errors_never_echo_raw_control_characters() {
        const ESC: &str = "\u{1b}]0;pwned\u{7}\u{1b}[2J";
        type Mutate = fn(&mut serde_json::Value);
        let cases: &[(&str, Mutate)] = &[
            (
                "secrets.DATABASE_URL.grouped key: invalid group name",
                |v| {
                    v["secrets"]["DATABASE_URL"]["grouped"][ESC] = "cHJvZA==".into();
                },
            ),
            ("secrets.DATABASE_URL.scoped key", |v| {
                v["secrets"]["DATABASE_URL"]["scoped"][ESC] = "Ym9i".into();
            }),
            ("schema: invalid key name", |v| {
                v["schema"][ESC] = serde_json::json!({"description": ""});
            }),
            ("secrets: invalid key name", |v| {
                v["secrets"][ESC] = serde_json::json!({"shared": ""});
            }),
            ("recipients[0]", |v| v["recipients"][0] = ESC.into()),
            ("unsupported vault version", |v| v["version"] = ESC.into()),
            ("created: not an RFC 3339", |v| v["created"] = ESC.into()),
        ];
        for (field, mutate) in cases {
            let mut v = full_vault_json();
            mutate(&mut v);
            let err = parse(&v.to_string())
                .expect_err(&format!("expected rejection: {field}"))
                .to_string();
            assert!(err.contains(field), "want {field:?}, got {err:?}");
            assert!(
                !err.chars().any(char::is_control),
                "raw control char in {err:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_oversized_input() {
        let big = " ".repeat(crate::validate::MAX_VAULT_BYTES + 1);
        let err = parse(&big).unwrap_err().to_string();
        assert!(err.contains("vault file size exceeds"), "{err}");
    }

    #[test]
    fn read_rejects_oversized_file_without_reading_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.murk");
        // Sparse: the size check must fire on metadata, not after buffering.
        File::create(&path)
            .unwrap()
            .set_len(crate::validate::MAX_VAULT_BYTES as u64 + 1)
            .unwrap();
        let err = read(&path).unwrap_err().to_string();
        assert!(err.contains("vault file size exceeds"), "{err}");
    }

    #[test]
    fn write_refuses_vault_that_would_not_load() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.murk");
        let mut vault = test_vault();
        vault.schema.insert(
            "BAD-NAME".into(),
            SchemaEntry {
                description: String::new(),
                ..Default::default()
            },
        );
        let err = write(&path, &vault).unwrap_err().to_string();
        assert!(err.contains("schema: invalid key name BAD-NAME"), "{err}");
        assert!(!path.exists(), "invalid vault must not reach disk");
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
        private.insert(crate::testutil::SSH_ED25519_PK.into(), "Ym9i".into());

        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: "ZW5jcnlwdGVk".into(),
                private,
                grouped: std::collections::BTreeMap::default(),
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        let entry = &read_vault.secrets["DATABASE_URL"];
        assert_eq!(entry.private[crate::testutil::SSH_ED25519_PK], "Ym9i");

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
