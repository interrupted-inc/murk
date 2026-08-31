//! Encrypted secrets manager for developers — one file, age encryption, git-friendly.
//!
//! This library provides the core functionality for murk: vault I/O, age encryption,
//! BIP39 key recovery, and secret management. The CLI binary wraps this library.

#![warn(clippy::pedantic)]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::too_many_arguments,
    clippy::implicit_hasher
)]

// Domain modules — pub(crate) unless main.rs needs direct path access.
pub(crate) mod agent;
pub mod cli;
pub(crate) mod codename;
pub mod connect;
pub mod crypto;
pub mod edit;
pub(crate) mod env;
pub mod error;
pub(crate) mod export;
pub(crate) mod git;
pub mod github;
pub(crate) mod grants;
pub(crate) mod groups;
pub mod hardening;
pub(crate) mod info;
pub(crate) mod init;
pub(crate) mod merge;
pub mod pins;
pub(crate) mod policy;
pub(crate) mod recipients;
pub mod recovery;
pub mod scan;
pub(crate) mod secrets;
pub mod signing;
pub mod types;
pub mod vault;

#[cfg(feature = "python")]
mod python;

// Shared test utilities
#[cfg(test)]
pub mod testutil;

// Property-based invariant tests (crypto roundtrip, tamper-evidence, scope
// isolation). Kept in their own file so lib.rs doesn't grow.
#[cfg(test)]
mod property_tests;

// Re-exports: keep the flat murk_cli::foo() API for main.rs
pub use agent::{AgentPlan, AgentPlanKey, agent_plan, format_agent_plan_text};
pub use env::{
    EnvrcStatus, KeySource, agent_key_file_path, agent_keys_dir, dotenv_has_murk_key,
    env_permission_warning, home_short, key_file_path, parse_env, resolve_key,
    resolve_key_for_vault, resolve_key_with_source, write_envrc, write_key_ref_to_dotenv,
    write_key_to_dotenv, write_key_to_file,
};
pub use error::MurkError;
pub use export::{
    DiffEntry, DiffKind, decrypt_vault_values, diff_secrets, export_secrets, format_diff_lines,
    parse_and_decrypt_values, resolve_secrets,
};
pub use git::{CommitSignature, MergeDriverSetupStep, last_commit_signature, setup_merge_driver};
pub use github::{GitHubError, fetch_keys};
pub use grants::{create_grant, parse_ttl, remove_grant, validate_grant_name};
pub use groups::{
    add_member, create_group, delete_group, remove_member, resolve_member, validate_group_name,
};
pub use info::{InfoEntry, VaultInfo, format_info_lines, lifecycle_segment, vault_info};
pub use init::{DiscoveredKey, InitStatus, check_init_status, create_vault, discover_existing_key};
pub use merge::{MergeDriverOutput, run_merge_driver};
pub use policy::{check_agent_keys, enforce_agent_policy, is_agent_identity, is_agent_key_allowed};
pub use recipients::{
    RecipientEntry, RevokeResult, authorize_recipient, format_recipient_lines, key_type_label,
    list_recipients, revoke_recipient, truncate_pubkey,
};
pub use secrets::{
    EXPIRY_WARN_DAYS, RotationIssue, add_grouped_secret, add_secret, describe_key, get_secret,
    import_secrets, list_keys, mark_revoked, remove_secret, rotation_health,
};

use std::path::Path;

mod load;
mod mac;
mod save;
mod signature;

pub use load::{decrypt_vault, load_vault};
pub(crate) use mac::{compute_mac, decode_mac_key, generate_mac_key, verify_mac};
pub use save::save_vault;
pub(crate) use signature::{sign_vault, signing_identity, verify_vault_signature};
// Internal helpers surfaced at the crate root only for the split-out unit and
// property tests to reach across module boundaries.
#[cfg(test)]
pub(crate) use mac::compute_mac_v5;
#[cfg(test)]
pub(crate) use signature::{SIGNED_VIEW_VERSION, signing_message};

/// Check whether a key name is a valid shell identifier (safe for `export KEY=...`).
/// Must start with a letter or underscore, and contain only `[A-Za-z0-9_]`.
pub fn is_valid_key_name(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

// Re-export polymorphic types for consumers.
pub use crypto::{MurkIdentity, MurkRecipient};

/// Decrypt the meta blob from a vault, returning the deserialized Meta if possible.
pub fn decrypt_meta(vault: &types::Vault, identity: &crypto::MurkIdentity) -> Option<types::Meta> {
    if vault.meta.is_empty() {
        return None;
    }
    let plaintext = decrypt_value(&vault.meta, identity).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Parse a list of pubkey strings into recipients (age or SSH).
pub(crate) fn parse_recipients(
    pubkeys: &[String],
) -> Result<Vec<crypto::MurkRecipient>, MurkError> {
    pubkeys
        .iter()
        .map(|pk| crypto::parse_recipient(pk).map_err(MurkError::from))
        .collect()
}

/// Encrypt a value and return base64-encoded ciphertext.
pub fn encrypt_value(
    plaintext: &[u8],
    recipients: &[crypto::MurkRecipient],
) -> Result<String, MurkError> {
    let ciphertext = crypto::encrypt(plaintext, recipients)?;
    Ok(BASE64.encode(&ciphertext))
}

/// Decrypt a base64-encoded ciphertext and return plaintext bytes.
///
/// The returned buffer is zeroized on drop.
pub fn decrypt_value(
    encoded: &str,
    identity: &crypto::MurkIdentity,
) -> Result<Zeroizing<Vec<u8>>, MurkError> {
    let ciphertext = BASE64.decode(encoded).map_err(|e| {
        MurkError::Crypto(crypto::CryptoError::Decrypt(format!("invalid base64: {e}")))
    })?;
    Ok(crypto::decrypt(&ciphertext, identity)?)
}

/// Validate decrypted bytes as UTF-8 and return a zeroizing `String`.
///
/// The returned `String` and the input `&[u8]` are both zeroized when dropped
/// (assuming the caller holds the bytes inside a `Zeroizing`), so plaintext
/// never escapes to a non-zeroed buffer.
pub(crate) fn plaintext_bytes_to_zeroizing_string(
    bytes: &[u8],
) -> Result<Zeroizing<String>, std::str::Utf8Error> {
    let s = std::str::from_utf8(bytes)?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Read a vault file from disk.
///
/// This is a thin wrapper around `vault::read` for a convenient string-path API.
pub fn read_vault(vault_path: &str) -> Result<types::Vault, MurkError> {
    Ok(vault::read(Path::new(vault_path))?)
}

/// Resolve a vault path argument, walking up parent directories to discover the vault.
///
/// Mirrors how git finds `.git` and cargo finds `Cargo.toml`: if the user passed a bare
/// filename (no path separator, not absolute) and it does not exist in the current
/// directory, walk up from CWD looking for a file of that name. Stops at:
///
/// - a directory containing `.git` (the git root — don't escape the repo)
/// - `$HOME` (don't traverse into parents of the user's home)
/// - the filesystem root
///
/// If a match is found, returns the absolute path. Otherwise returns the input unchanged,
/// so downstream error messages still reference what the user asked for.
///
/// Explicit paths (absolute, or containing `/` or `\`) are returned unchanged — the user
/// told us exactly where to look, so don't second-guess them.
pub fn resolve_vault_path(arg: &str) -> String {
    use std::path::PathBuf;

    // Explicit path: no traversal.
    if arg.is_empty() || arg.contains('/') || arg.contains('\\') || Path::new(arg).is_absolute() {
        return arg.to_string();
    }

    let Ok(cwd) = std::env::current_dir() else {
        return arg.to_string();
    };

    // Found in CWD — nothing to discover.
    if cwd.join(arg).exists() {
        return arg.to_string();
    }

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join(arg);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        // Stop at git root after checking this directory.
        if dir.join(".git").exists() {
            break;
        }
        // Stop at $HOME boundary (don't traverse above the user's home).
        if let Some(ref h) = home
            && dir == h.as_path()
        {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    arg.to_string()
}

/// Generate an ISO-8601 UTC timestamp.
pub(crate) fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    use std::fs;

    use crate::testutil::ENV_LOCK;

    #[test]
    fn resolve_vault_path_finds_in_parent_dir() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        // Create a fake git repo with a vault at the root and a nested subdir.
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();

        assert_eq!(
            std::fs::canonicalize(&got).unwrap(),
            std::fs::canonicalize(dir.path().join(".murk")).unwrap()
        );
    }

    #[test]
    fn resolve_vault_path_returns_as_is_when_found_in_cwd() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(got, ".murk");
    }

    #[test]
    fn resolve_vault_path_passes_through_explicit_paths() {
        assert_eq!(resolve_vault_path("/abs/path.murk"), "/abs/path.murk");
        assert_eq!(resolve_vault_path("./foo.murk"), "./foo.murk");
        assert_eq!(resolve_vault_path("sub/dir.murk"), "sub/dir.murk");
    }

    #[test]
    fn resolve_vault_path_stops_at_git_root() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        // Vault lives OUTSIDE the git repo; traversal should not find it.
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let nested = repo.join("sub");
        fs::create_dir(&nested).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();

        // Unchanged — we stopped at the git root and never saw the outer vault.
        assert_eq!(got, ".murk");
    }

    #[test]
    fn encrypt_decrypt_value_roundtrip() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let encoded = encrypt_value(b"hello world", &[recipient]).unwrap();
        let decrypted = decrypt_value(&encoded, &identity).unwrap();
        assert_eq!(&decrypted[..], b"hello world");
    }

    #[test]
    fn decrypt_value_invalid_base64() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);

        let result = decrypt_value("not!valid!base64!!!", &identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid base64"));
    }

    #[test]
    fn encrypt_value_multiple_recipients() {
        let (secret_a, pubkey_a) = generate_keypair();
        let (secret_b, pubkey_b) = generate_keypair();

        let recipients = vec![make_recipient(&pubkey_a), make_recipient(&pubkey_b)];
        let encoded = encrypt_value(b"shared secret", &recipients).unwrap();

        // Both can decrypt.
        let id_a = make_identity(&secret_a);
        let id_b = make_identity(&secret_b);
        assert_eq!(
            &decrypt_value(&encoded, &id_a).unwrap()[..],
            b"shared secret"
        );
        assert_eq!(
            &decrypt_value(&encoded, &id_b).unwrap()[..],
            b"shared secret"
        );
    }

    #[test]
    fn decrypt_value_wrong_key_fails() {
        let (_, pubkey) = generate_keypair();
        let (wrong_secret, _) = generate_keypair();

        let recipient = make_recipient(&pubkey);
        let wrong_identity = make_identity(&wrong_secret);

        let encoded = encrypt_value(b"secret", &[recipient]).unwrap();
        assert!(decrypt_value(&encoded, &wrong_identity).is_err());
    }

    #[test]
    fn valid_key_names() {
        assert!(is_valid_key_name("DATABASE_URL"));
        assert!(is_valid_key_name("_PRIVATE"));
        assert!(is_valid_key_name("A"));
        assert!(is_valid_key_name("key123"));
    }

    #[test]
    fn invalid_key_names() {
        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("123_START"));
        assert!(!is_valid_key_name("KEY-NAME"));
        assert!(!is_valid_key_name("KEY NAME"));
        assert!(!is_valid_key_name("FOO$(bar)"));
        assert!(!is_valid_key_name("KEY=VAL"));
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
