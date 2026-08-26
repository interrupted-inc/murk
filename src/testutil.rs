//! Shared test helpers for vault construction and key generation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use zeroize::Zeroizing;

/// Process-global lock for tests that mutate env vars (MURK_KEY, MURK_KEY_FILE).
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Process-global lock for tests that change the working directory.
pub static CWD_LOCK: Mutex<()> = Mutex::new(());

/// `fs::canonicalize` with Windows' `\\?\` verbatim prefix removed.
///
/// Fixtures that build a git worktree hand these paths straight to `git`, and
/// git for Windows does not accept verbatim paths. Canonicalizing is still
/// necessary because `git worktree` records the real path of a checkout, and on
/// macOS a temp dir reached via `/var` really lives in `/private/var` — without
/// it a fixture's own paths would not match what git wrote down.
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
