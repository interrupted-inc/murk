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

/// Strip credentials and other secrets from a git remote URL before it goes
/// into the plaintext vault header.
///
/// - URL form (`scheme://authority/path`, any scheme, any case): drops
///   everything up to the last `@` of the authority (user, password or token),
///   and any `?query` or `#fragment`, where tokens also travel.
///   `https://user:p@ss@host/o/r?token=x` becomes `https://host/o/r`.
/// - scp-like form (`user@host:path`): keeps a plain user such as `git@`, but
///   drops a `user:password@` prefix entirely.
/// - Anything else (a local path) is returned unchanged.
fn sanitize_remote_url(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        // Strip userinfo before cutting ?query/#fragment, so a `?` or `#`
        // inside a password cannot hide the `@` that ends it.
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let rest = match rest[..authority_end].rfind('@') {
            Some(at) => &rest[at + 1..],
            None => rest,
        };
        let rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
        return format!("{}://{rest}", scheme.to_ascii_lowercase());
    }
    // scp-like `user@host:path`. A plain user (`git@`) stays; a user with a
    // password loses everything up to the last `@` before the path, since the
    // password may itself contain `@`.
    match url.split_once('@') {
        Some((user, _)) if user.contains(':') && !user.contains(['/', '\\']) => {
            let prefix_end = url.find('/').unwrap_or(url.len());
            let at = url[..prefix_end].rfind('@').unwrap_or(user.len());
            url[at + 1..].to_string()
        }
        _ => url.to_string(),
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
/// `.env`). It looks where the runtime would: this checkout, then sibling
/// worktrees (see [`crate::env::discover_key_file`]). That holds for a new
/// vault too: a fresh key stored for a worktree's path would shadow the
/// sibling's key there.
///
/// Strict and agent mode never auto-use a stored key, so there a stored key
/// is an error rather than a reuse: init neither adopts nor replaces it.
pub fn discover_stored_key(vault_path: &str) -> Result<Option<DiscoveredKey>, String> {
    let path = crate::env::discover_key_file(vault_path);
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
    DiscoveredKey::new(secret_key, crate::env::KeySource::Auto(path.clone()))
        .map(Some)
        .map_err(|e| {
            format!(
                "{e}\nif you do not need {}, move it aside and run murk init again",
                path.display()
            )
        })
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
    let listed = crate::recipients::find_recipient(vault, &pubkey);
    let authorized = listed.is_some();

    let display_name = if let Some(listed) = listed {
        crate::decrypt_meta(vault, &identity)?
            .and_then(|meta| meta.recipients.get(listed).cloned())
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

/// Create a new vault with a single recipient, signed by that recipient.
///
/// Detects the git remote URL and builds the initial vault struct, with a fresh
/// vault id and generation 1. The caller writes it to disk via `vault::write`,
/// then records it as trusted with [`pin_created_vault`].
pub fn create_vault(
    vault_name: &str,
    identity: &crypto::MurkIdentity,
    name: &str,
) -> Result<types::Vault, crate::error::MurkError> {
    use crate::error::MurkError;

    let pubkey = identity.pubkey_string()?;
    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.clone(), name.to_string());

    let recipient = crypto::parse_recipient(&pubkey)?;

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
        vault_id: crate::save::new_vault_id(),
        generation: 1,
        recipients: vec![pubkey.clone()],
        agents: BTreeMap::new(),
        sig: None,
        schema: BTreeMap::new(),
        policy: None,
        secrets: BTreeMap::new(),
        meta: String::new(),
    };

    let mac_key_hex = crate::generate_mac_key();
    let mac_key = crate::decode_mac_key(&mac_key_hex).unwrap();
    let mac = crate::compute_mac(&vault, &BTreeMap::new(), &BTreeMap::new(), Some(&mac_key));
    let mut signers = BTreeMap::new();
    crate::register_signer(&vault, &mut signers, identity);
    let meta = types::Meta {
        recipients: recipient_names,
        mac,
        mac_key: Some(mac_key_hex),
        github_pins: HashMap::new(),
        groups: BTreeMap::new(),
        grants: BTreeMap::new(),
        signers,
        sig: None,
    };
    // Every piece of header text here is new.
    crate::validate::new_header_text(None, &vault, &meta.recipients)
        .map_err(|e| MurkError::Secret(format!("refusing to write {e}")))?;
    crate::validate::meta(&meta)
        .map_err(|e| MurkError::Secret(format!("refusing to write invalid vault meta: {e}")))?;
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &[recipient])?;
    // Signed from the start: an unsigned vault is refused by every signing-
    // capable loader, and a forged "empty" vault would otherwise collect the
    // first secret written to it. The signature covers the finished file.
    vault.sig = crate::sign_vault(&vault, identity);

    Ok(vault)
}

/// Record a vault this machine just created as trusted, with its creator (and
/// the creator's verifying key) as the only trusted signer. The pin is updated
/// under its lock from a fresh read, like every other pin write, so what it
/// already holds — the rollback marks of other branches, confirmed signing
/// keys, grants seen — is kept. The new vault replaces the vault id and the
/// trusted set, and resets the mark of the branch it is created on (it starts
/// at generation 1).
pub fn pin_created_vault(
    vault_path: &str,
    vault: &types::Vault,
    identity: &crate::crypto::MurkIdentity,
) -> Result<(), String> {
    if !crate::pins::signer_pin_available() {
        return Ok(());
    }
    let creator = vault.recipients.first().cloned().unwrap_or_default();
    let mut registry = BTreeMap::new();
    crate::register_signer(vault, &mut registry, identity);
    let signature = types::SignatureState::Signed {
        signer: creator.clone(),
        v: crate::signature::SIGNED_VIEW_VERSION,
    };
    let loaded = crate::trust::Loaded {
        vault,
        signature: &signature,
        signer_vk: crate::signature::registry_entry(&registry, &creator).map(String::as_str),
        registry: &registry,
        names: &HashMap::new(),
        groups: &BTreeMap::new(),
        grants: &BTreeMap::new(),
        loader_can_sign: true,
        operator_key: None,
    };
    let head = crate::trust::head_of(vault_path);
    crate::pins::update(vault_path, |fresh| {
        Ok(Some(crate::trust::accepted_pin(
            &loaded, fresh, true, &head,
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::testutil::{CWD_LOCK, ENV_LOCK};

    // ── pin_created_vault ──

    /// Run `f` with a sandboxed HOME. Caller holds ENV_LOCK.
    fn in_home<T>(f: impl FnOnce() -> T) -> T {
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("MURK_NO_SIGNER_PIN");
        }
        let out = f();
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        out
    }

    #[test]
    fn pin_created_vault_keeps_the_history_an_existing_pin_recorded() {
        // The pin already holds another vault's history (a deleted vault, or
        // a sibling worktree sharing the pin). Creating a vault here must not
        // discard it: marks of other branches and confirmed keys stay.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        in_home(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(".murk");
            let path = path.to_str().unwrap();
            let existing = crate::pins::TrustPin {
                v: crate::pins::PIN_VERSION,
                vault_id: "00112233445566778899aabbccddeeff".into(),
                generation: 9,
                branches: BTreeMap::from([("main".into(), 9)]),
                trusted: ["age1someone".into()].into(),
                ever_trusted: ["age1someone".into()].into(),
                signers: BTreeMap::from([("age1someone".into(), "vk".into())]),
                was_signed: true,
                ..Default::default()
            };
            crate::pins::write(path, &existing).unwrap();
            let (secret, pubkey) = generate_keypair();
            let id = make_identity(&secret);
            let v = create_vault(".murk", &id, "alice").unwrap();
            pin_created_vault(path, &v, &id).unwrap();
            let pin = crate::pins::read(path).unwrap().unwrap();
            assert_eq!(pin.vault_id, v.vault_id);
            assert_eq!(pin.trusted, [pubkey].into());
            assert_eq!(pin.branches.get("main"), Some(&9), "other marks kept");
            assert_eq!(
                pin.signers.get("age1someone").map(String::as_str),
                Some("vk")
            );
            assert!(pin.ever_trusted.contains("age1someone"));
            // Outside a checkout the single mark restarts with the new vault,
            // so it is not refused as a rollback.
            assert_eq!(pin.generation, 1);
        });
    }

    #[test]
    fn pin_created_vault_keeps_what_an_empty_pin_recorded() {
        // A pin with no trust decision yet (only the downgrade bit, as left by
        // a murk 0.13 pin) is merged into, not overwritten.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        in_home(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(".murk");
            let path = path.to_str().unwrap();
            let empty = crate::pins::TrustPin {
                v: crate::pins::PIN_VERSION,
                was_signed: true,
                ..Default::default()
            };
            crate::pins::write(path, &empty).unwrap();
            let (secret, pubkey) = generate_keypair();
            let id = make_identity(&secret);
            let v = create_vault(".murk", &id, "alice").unwrap();
            pin_created_vault(path, &v, &id).unwrap();
            let pin = crate::pins::read(path).unwrap().unwrap();
            assert_eq!(pin.vault_id, v.vault_id);
            assert!(pin.trusted.contains(&pubkey));
            assert!(pin.was_signed);
        });
    }

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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
    fn create_vault_is_signed_by_its_creator_with_an_identity() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);

        let vault = create_vault(".murk", &identity, "Bob").unwrap();
        assert_eq!(vault.recipients, vec![pubkey.clone()]);
        assert_eq!(vault.generation, 1);
        assert_eq!(vault.vault_id.len(), 32);
        // A fresh vault loads signed: an unsigned one would be refused.
        let murk = crate::decrypt_vault(&vault, &identity).unwrap();
        assert_eq!(
            murk.signature,
            types::SignatureState::Signed {
                signer: pubkey,
                v: crate::signature::SIGNED_VIEW_VERSION
            }
        );
    }

    #[test]
    fn create_vault_refuses_text_that_can_forge_output() {
        let (secret, _) = generate_keypair();
        let identity = crate::testutil::make_identity(&secret);
        let err = create_vault(".murk", &identity, "Bob\u{202e}").unwrap_err();
        assert!(err.to_string().contains("meta.recipients"), "{err}");
        let err = create_vault(".murk\r", &identity, "Bob").unwrap_err();
        assert!(err.to_string().contains("vault_name"), "{err}");
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

    #[test]
    fn sanitize_strips_credentials_from_every_url_form() {
        for (url, want) in [
            // `@` inside the password: cut at the last `@` of the authority.
            (
                "https://user:p@ss@example.com/o/r.git",
                "https://example.com/o/r.git",
            ),
            (
                "HTTPS://user:secrettoken@example.com/o/r.git",
                "https://example.com/o/r.git",
            ),
            (
                "ssh://git:hunter2@example.com/o/r.git",
                "ssh://example.com/o/r.git",
            ),
            (
                "https://example.com/o/r.git?token=abc123",
                "https://example.com/o/r.git",
            ),
            (
                "https://example.com/o/r.git#tok",
                "https://example.com/o/r.git",
            ),
            // `?` / `#` inside the password must not hide the `@`.
            ("https://u:a?b#c@example.com/o/r", "https://example.com/o/r"),
            ("git+ssh://tok@example.com/o/r", "git+ssh://example.com/o/r"),
            ("user:pass@example.com:o/r.git", "example.com:o/r.git"),
            // `@` inside an scp-form password: strip up to the last `@`.
            ("user:p@ss@example.com:o/r.git", "example.com:o/r.git"),
            ("user:p@ss@example.com:repo.git", "example.com:repo.git"),
            ("git@example.com:o/r@v1.git", "git@example.com:o/r@v1.git"),
            // `@` in the path is not userinfo.
            ("https://example.com/o/r@v1", "https://example.com/o/r@v1"),
            ("/srv/git/repo.git", "/srv/git/repo.git"),
        ] {
            assert_eq!(sanitize_remote_url(url), want, "{url}");
        }
    }
}
