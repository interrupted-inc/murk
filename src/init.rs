// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault initialization logic.

use std::collections::{BTreeMap, HashMap};
// Only the tests touch the process environment directly; the runtime key read
// now goes through env::key_from_env_only (see tests/invariants.rs).
#[cfg(test)]
use std::env;

use crate::{crypto, encrypt_value, now_utc, types};
use age::secrecy::{ExposeSecret, SecretString};

/// Strip embedded credentials from a git remote URL.
///
/// Handles `https://user:pass@host/repo` → `https://host/repo` and
/// `https://token@host/repo` → `https://host/repo`.
/// SSH and other formats are returned as-is (no credentials to strip).
fn sanitize_remote_url(url: &str) -> String {
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let scheme = if url.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        if let Some(at_pos) = rest.find('@') {
            // Only strip if the '@' is before the first '/' (i.e. in the authority).
            let slash_pos = rest.find('/').unwrap_or(rest.len());
            if at_pos < slash_pos {
                return format!("{scheme}://{}", &rest[at_pos + 1..]);
            }
        }
        url.to_string()
    } else {
        url.to_string()
    }
}

/// A key `murk init` found in the environment or in `~/.config/murk/keys`.
#[derive(Debug)]
pub struct DiscoveredKey {
    pub secret_key: SecretString,
    pub pubkey: String,
    /// Where the key came from: `MURK_KEY`, `MURK_KEY_FILE`, or a stored key.
    pub source: crate::env::KeySource,
}

impl DiscoveredKey {
    fn new(secret_key: SecretString, source: crate::env::KeySource) -> Result<Self, String> {
        let identity = crypto::parse_identity(secret_key.expose_secret())
            .map_err(|e| format!("{}: {e}", source.describe()))?;
        let pubkey = identity.pubkey_string().map_err(|e| e.to_string())?;
        Ok(Self {
            secret_key,
            pubkey,
            source,
        })
    }
}

/// Try to find an existing age key from the environment.
///
/// Checks `MURK_KEY` first, then reads the file at `MURK_KEY_FILE` if set.
/// Does NOT read `.env` — for direnv users, the shim already exports both
/// variables into the environment, so the environment is the authoritative
/// source and `.env` is only a write-only convenience populated by `murk init`.
pub fn discover_existing_key() -> Result<Option<DiscoveredKey>, String> {
    // The env vars are read in one place (the env module) so the auth read path
    // stays auditable — see tests/invariants.rs.
    crate::env::key_from_env_only()?
        .map(|(key, source)| DiscoveredKey::new(key, source))
        .transpose()
}

/// Find the key already stored for this vault in `~/.config/murk/keys`, for
/// `murk init` to reuse instead of generating a new one.
///
/// Generating a key writes `keys/<vault-hash>`, so without this check `init`
/// would silently replace an identity the operator still needs whenever the
/// environment did not name it (a fresh clone, a new worktree, a deleted
/// `.env`). For an existing vault it looks where the runtime would (this
/// checkout, then sibling worktrees — see [`crate::env::discover_key_file`]);
/// for a new vault (`include_siblings == false`) only at this checkout's own
/// key file, the one generation would overwrite.
///
/// Strict and agent mode never auto-use a stored key, so there a stored key
/// is an error rather than a reuse: init neither adopts nor replaces it.
pub fn discover_stored_key(
    vault_path: &str,
    include_siblings: bool,
) -> Result<Option<DiscoveredKey>, String> {
    let path = if include_siblings {
        crate::env::discover_key_file(vault_path)
    } else {
        Some(crate::env::key_file_path(vault_path)?).filter(|p| p.exists())
    };
    let Some(path) = path else {
        return Ok(None);
    };
    if crate::hardening::strict_mode() {
        return Err([
            format!(
                "a key for this vault is already stored at {}",
                path.display()
            ),
            "strict mode (MURK_STRICT or MURK_AGENT) neither uses nor replaces stored keys".into(),
            format!("to use it, set MURK_KEY_FILE={}", path.display()),
        ]
        .join("\n"));
    }
    let secret_key = crate::env::read_stored_key(&path)?;
    DiscoveredKey::new(secret_key, crate::env::KeySource::Auto(path)).map(Some)
}

/// Status of an existing vault relative to a given key.
#[derive(Debug)]
pub struct InitStatus {
    /// Whether the key's pubkey is in the vault's recipient list.
    pub authorized: bool,
    /// The public key derived from the secret key.
    pub pubkey: String,
    /// Display name from encrypted meta, if decryptable and present.
    pub display_name: Option<String>,
}

/// Check whether a secret key is authorized in an existing vault.
///
/// Parses the identity from `secret_key`, checks the recipient list, and
/// attempts to decrypt meta for the display name.
pub fn check_init_status(vault: &types::Vault, secret_key: &str) -> Result<InitStatus, String> {
    let identity = crypto::parse_identity(secret_key).map_err(|e| e.to_string())?;
    let pubkey = identity.pubkey_string().map_err(|e| e.to_string())?;
    let authorized = vault.recipients.contains(&pubkey);

    let display_name = if authorized {
        crate::decrypt_meta(vault, &identity)?
            .and_then(|meta| meta.recipients.get(&pubkey).cloned())
            .filter(|name| !name.is_empty())
    } else {
        None
    };

    Ok(InitStatus {
        authorized,
        pubkey,
        display_name,
    })
}

/// Create a new vault with a single recipient.
///
/// Detects the git remote URL and builds the initial vault struct.
/// The caller is responsible for writing the vault to disk via `vault::write`.
pub fn create_vault(
    vault_name: &str,
    pubkey: &str,
    name: &str,
) -> Result<types::Vault, crate::error::MurkError> {
    use crate::error::MurkError;

    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.to_string(), name.to_string());

    let recipient = crypto::parse_recipient(pubkey)?;

    // Detect git repo URL, stripping any embedded credentials.
    let repo = crate::git::git_command()
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| sanitize_remote_url(s.trim()))
        .unwrap_or_default();

    let mut vault = types::Vault {
        version: types::VAULT_VERSION.into(),
        created: now_utc(),
        vault_name: vault_name.into(),
        repo,
        recipients: vec![pubkey.to_string()],
        schema: BTreeMap::new(),
        policy: None,
        secrets: BTreeMap::new(),
        meta: String::new(),
    };

    let mac_key_hex = crate::generate_mac_key();
    let mac_key = crate::decode_mac_key(&mac_key_hex).unwrap();
    let mac = crate::compute_mac(&vault, &BTreeMap::new(), &BTreeMap::new(), Some(&mac_key));
    // The initial vault is unsigned: `create_vault` holds only the public key,
    // and an empty vault has nothing to protect. The first secret write signs it.
    let meta = types::Meta {
        recipients: recipient_names,
        mac,
        mac_key: Some(mac_key_hex),
        github_pins: HashMap::new(),
        groups: BTreeMap::new(),
        grants: BTreeMap::new(),
        signers: BTreeMap::new(),
        sig: None,
    };
    crate::validate::meta(&meta)
        .map_err(|e| MurkError::Secret(format!("refusing to write invalid vault meta: {e}")))?;
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &[recipient])?;

    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::testutil::{CWD_LOCK, ENV_LOCK};

    // ── discover_existing_key tests ──

    #[test]
    fn discover_existing_key_from_env() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        unsafe { env::set_var("MURK_KEY", &secret) };
        let result = discover_existing_key();
        unsafe { env::remove_var("MURK_KEY") };

        let dk = result.unwrap().unwrap();
        assert_eq!(dk.secret_key.expose_secret(), secret.as_str());
        assert_eq!(dk.pubkey, pubkey);
    }

    #[test]
    fn discover_existing_key_ignores_dotenv() {
        // discover_existing_key must not read .env from CWD, even
        // in the init flow. A .env sitting in the current directory with an
        // inline MURK_KEY is explicitly *not* a trusted input source.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::remove_var("MURK_KEY");
            env::remove_var("MURK_KEY_FILE");
        }

        let dir = std::env::temp_dir().join("murk_test_discover_ignores_dotenv");
        std::fs::create_dir_all(&dir).unwrap();
        let (secret, _pubkey) = generate_keypair();
        std::fs::write(dir.join(".env"), format!("MURK_KEY={secret}\n")).unwrap();

        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = discover_existing_key();
        std::env::set_current_dir(&orig_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(
            result.unwrap().is_none(),
            "discover_existing_key must not fall back to .env"
        );
    }

    #[test]
    fn discover_existing_key_from_env_file_var() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::remove_var("MURK_KEY");
        }

        let (secret, pubkey) = generate_keypair();
        let dir = std::env::temp_dir().join("murk_test_discover_env_file");
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key");
        std::fs::write(&key_path, format!("{secret}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        unsafe { env::set_var("MURK_KEY_FILE", &key_path) };
        let result = discover_existing_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_dir_all(&dir).unwrap();

        let dk = result.unwrap().unwrap();
        assert_eq!(dk.secret_key.expose_secret(), secret.as_str());
        assert_eq!(dk.pubkey, pubkey);
    }

    #[test]
    fn discover_existing_key_neither_set() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cwd = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { env::remove_var("MURK_KEY") };

        // Use a dir with no .env.
        let dir = std::env::temp_dir().join("murk_test_discover_none");
        std::fs::create_dir_all(&dir).unwrap();
        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = discover_existing_key();
        std::env::set_current_dir(&orig_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn discover_existing_key_invalid_key() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe { env::set_var("MURK_KEY", "not-a-valid-age-key") };
        let result = discover_existing_key();
        unsafe { env::remove_var("MURK_KEY") };

        assert!(result.is_err());
    }

    // ── check_init_status tests ──

    #[test]
    fn check_init_status_authorized() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        // Build a vault with this recipient in the list and encrypted meta.
        let mut names = HashMap::new();
        names.insert(pubkey.clone(), "Alice".to_string());
        let meta = types::Meta {
            recipients: names,
            mac: String::new(),
            mac_key: None,
            github_pins: HashMap::new(),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let meta_enc = encrypt_value(&meta_json, &[recipient]).unwrap();

        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: std::collections::BTreeMap::new(),
            policy: None,
            secrets: std::collections::BTreeMap::new(),
            meta: meta_enc,
        };

        let status = check_init_status(&vault, &secret).unwrap();
        assert!(status.authorized);
        assert_eq!(status.pubkey, pubkey);
        assert_eq!(status.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn check_init_status_not_authorized() {
        let (secret, pubkey) = generate_keypair();
        let (_, other_pubkey) = generate_keypair();

        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![other_pubkey],
            schema: std::collections::BTreeMap::new(),
            policy: None,
            secrets: std::collections::BTreeMap::new(),
            meta: String::new(),
        };

        let status = check_init_status(&vault, &secret).unwrap();
        assert!(!status.authorized);
        assert_eq!(status.pubkey, pubkey);
        assert!(status.display_name.is_none());
    }

    #[test]
    fn create_vault_basic() {
        let (_, pubkey) = generate_keypair();

        let vault = create_vault(".murk", &pubkey, "Bob").unwrap();
        assert_eq!(vault.version, types::VAULT_VERSION);
        assert_eq!(vault.vault_name, ".murk");
        assert_eq!(vault.recipients, vec![pubkey]);
        assert!(vault.schema.is_empty());
        assert!(vault.secrets.is_empty());
        assert!(!vault.meta.is_empty(), "meta is empty");
    }

    // ── sanitize_remote_url tests ──

    #[test]
    fn sanitize_strips_https_credentials() {
        assert_eq!(
            sanitize_remote_url("https://user:pass@github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }

    #[test]
    fn sanitize_strips_https_token() {
        assert_eq!(
            sanitize_remote_url("https://ghp_abc123@github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }

    #[test]
    fn sanitize_preserves_clean_https() {
        assert_eq!(
            sanitize_remote_url("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }

    #[test]
    fn sanitize_preserves_ssh() {
        assert_eq!(
            sanitize_remote_url("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git"
        );
    }

    #[test]
    fn sanitize_strips_http_credentials() {
        assert_eq!(
            sanitize_remote_url("http://user:pass@example.com/repo"),
            "http://example.com/repo"
        );
    }
}
