// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared test helpers for vault construction and key generation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use zeroize::Zeroizing;

/// Process-global lock for tests that mutate env vars (MURK_KEY, MURK_KEY_FILE).
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Process-global lock for tests that change the working directory.
pub static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Holds [`ENV_LOCK`] with `MURK_KEY` set to a key (and `MURK_KEY_FILE` unset),
/// clearing it on drop. For tests that save, since `save_vault` resolves the
/// saving identity from the environment.
pub struct MurkKeyEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
}

pub fn murk_key_env(secret: &str) -> MurkKeyEnv {
    let lock = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    unsafe { std::env::set_var("MURK_KEY", secret) };
    unsafe { std::env::remove_var("MURK_KEY_FILE") };
    MurkKeyEnv { _lock: lock }
}

impl Drop for MurkKeyEnv {
    fn drop(&mut self) {
        unsafe { std::env::remove_var("MURK_KEY") };
    }
}

/// A named in-place edit of a vault, for tests that tamper with one field at a time.
pub type VaultRewrite = fn(&mut types::Vault);

/// `fs::canonicalize` with Windows' `\\?\` verbatim prefix removed.
///
/// Fixtures that build a git worktree hand these paths straight to `git`, and
/// git for Windows does not accept verbatim paths. Canonicalizing is still
/// necessary because `git worktree` records the real path of a checkout, and on
/// macOS a temp dir reached via `/var` really lives in `/private/var` — without
/// it a fixture's own paths would not match what git wrote down.
// Twin of `real_path` in `tests/common/mod.rs` (unit vs. integration test
// binaries can't share `cfg(test)` code) — mirror any edit there.
pub fn real_path(path: &std::path::Path) -> std::path::PathBuf {
    let canonical = std::fs::canonicalize(path).expect("canonicalize fixture path");
    let text = canonical.to_string_lossy();
    // Only a drive-letter path is safe to unwrap: stripping the prefix from a
    // verbatim UNC path (`\\?\UNC\server\share`) would corrupt it.
    let stripped = text.strip_prefix(r"\\?\").filter(|rest| {
        let bytes = rest.as_bytes();
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\"
    });
    std::path::PathBuf::from(stripped.unwrap_or(&text).to_string())
}

use age::secrecy::ExposeSecret;

use crate::{crypto, types};

pub fn generate_keypair() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let secret = identity.to_string();
    let pubkey = identity.to_public().to_string();
    (secret.expose_secret().to_string(), pubkey)
}

pub fn make_recipient(pubkey: &str) -> crypto::MurkRecipient {
    crypto::parse_recipient(pubkey).unwrap()
}

pub fn make_identity(secret: &str) -> crypto::MurkIdentity {
    crypto::parse_identity(secret).unwrap()
}

pub fn empty_vault() -> types::Vault {
    types::Vault {
        version: types::VAULT_VERSION.into(),
        created: "2026-02-28T00:00:00Z".into(),
        vault_name: ".murk".into(),
        repo: String::new(),
        vault_id: String::new(),
        generation: 0,
        agents: BTreeMap::new(),
        sig: None,
        recipients: vec![],
        schema: BTreeMap::new(),
        policy: None,
        secrets: BTreeMap::new(),
        meta: String::new(),
    }
}

pub fn empty_murk() -> types::Murk {
    types::Murk {
        values: HashMap::new(),
        recipients: HashMap::new(),
        private: HashMap::new(),
        legacy_mac: false,
        github_pins: HashMap::new(),
        ..Default::default()
    }
}

/// Wrap a string in `Zeroizing` for test inserts into `Murk.values` / `Murk.private`.
pub fn secret(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

/// Build a single-secret vault (value "REAL") with `recipients=[pubkey]`.
pub fn signed_test_vault(pubkey: &str, recipient: &crypto::MurkRecipient) -> types::Vault {
    let mut vault = types::Vault {
        version: types::VAULT_VERSION.into(),
        created: "2026-02-28T00:00:00Z".into(),
        vault_name: ".murk".into(),
        repo: String::new(),
        vault_id: String::new(),
        generation: 0,
        agents: BTreeMap::new(),
        sig: None,
        recipients: vec![pubkey.to_string()],
        schema: BTreeMap::new(),
        policy: None,
        secrets: BTreeMap::new(),
        meta: String::new(),
    };
    vault.secrets.insert(
        "API_KEY".into(),
        types::SecretEntry {
            shared: crate::encrypt_value(b"REAL", std::slice::from_ref(recipient)).unwrap(),
            private: BTreeMap::new(),
            grouped: BTreeMap::new(),
        },
    );
    vault
}

/// A real unencrypted ssh-ed25519 keypair, shared across the vault
/// load/save/signature tests (crypto.rs and signing.rs keep local copies).
pub const SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
pub const SSH_ED25519_PK: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

/// A syntactically valid age X25519 recipient (the age README example key) for
/// vault fixtures that must pass load-time validation but never decrypt.
pub const AGE_PK: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
