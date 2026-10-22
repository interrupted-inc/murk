// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small cast of vault users and a ground-truth view of who can read what.
//!
//! [`Cast::new`] builds a vault with three members (alice, who ran `init`, plus
//! bob and carol) and an outsider who is never authorized. [`cells`] decrypts
//! every ciphertext in a vault file with each given identity straight through
//! age, without going through murk, so a test can compare who *can* read each
//! value with who *should*.

// Each integration binary compiles this module; most use only part of it.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use assert_cmd::Command;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// Vault filename every cast command targets (via `MURK_VAULT`).
pub const VAULT: &str = "test.murk";

/// One identity: a display label, its age secret key, and its public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Who {
    pub label: String,
    pub secret: String,
    pub pubkey: String,
}

impl Who {
    /// A fresh x25519 identity.
    pub fn generate(label: &str) -> Self {
        let identity = age::x25519::Identity::generate();
        Self {
            label: label.to_string(),
            secret: identity.to_string().expose_secret().to_string(),
            pubkey: identity.to_public().to_string(),
        }
    }

    /// An identity from an `AGE-SECRET-KEY-...` string (surrounding whitespace
    /// and `#` comment lines, as in a key file, are ignored).
    pub fn from_secret(label: &str, secret: &str) -> Self {
        let secret = secret
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .unwrap_or_else(|| panic!("no age secret key for {label}"))
            .to_string();
        let identity: age::x25519::Identity = secret.parse().expect("parse age secret key");
        Self {
            label: label.to_string(),
            pubkey: identity.to_public().to_string(),
            secret,
        }
    }
}

/// A vault in `dir` (also `HOME`) with alice, bob and carol as members, and an
/// outsider who is not a recipient.
pub struct Cast {
    pub dir: PathBuf,
    pub alice: Who,
    pub bob: Who,
    pub carol: Who,
    pub outsider: Who,
}

impl Cast {
    /// Run `murk init` as alice in `dir`, then authorize bob and carol by name.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let (secret, _) = super::init_vault(&dir);
        let cast = Self {
            alice: Who::from_secret("alice", &secret),
            bob: Who::generate("bob"),
            carol: Who::generate("carol"),
            outsider: Who::generate("outsider"),
            dir,
        };
        for who in [&cast.bob, &cast.carol] {
            cast.murk_as(&cast.alice)
                .args(["circle", "authorize", &who.pubkey, "--name", &who.label])
                .assert()
                .success();
        }
        cast
    }

    /// Rebuild a cast around an existing vault file (e.g. a copy of a fixture
    /// built once with [`Cast::new`]) in a fresh `dir`.
    pub fn from_vault(dir: impl AsRef<Path>, vault_bytes: &[u8], template: &Cast) -> Self {
        let dir = dir.as_ref().to_path_buf();
        fs::write(dir.join(VAULT), vault_bytes).expect("write vault copy");
        Self {
            dir,
            alice: template.alice.clone(),
            bob: template.bob.clone(),
            carol: template.carol.clone(),
            outsider: template.outsider.clone(),
        }
    }

    /// The three members, in a fixed order.
    pub fn members(&self) -> [&Who; 3] {
        [&self.alice, &self.bob, &self.carol]
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir.join(VAULT)
    }

    /// A hermetic `murk` command run as `who` against the cast's vault.
    pub fn murk_as(&self, who: &Who) -> Command {
        let mut cmd = super::murk(&self.dir, &who.secret);
        cmd.env("MURK_VAULT", VAULT);
        cmd
    }

    /// Mint an agent grant as `issuer` that can read `keys`, and return the
    /// grant's identity (labelled `grant:<name>`).
    pub fn grant(&self, issuer: &Who, name: &str, keys: &[&str]) -> Who {
        let out = self.grant_key_path(name);
        let mut cmd = self.murk_as(issuer);
        cmd.args(["agent", "grant", "--name", name, "--out"])
            .arg(&out);
        for key in keys {
            cmd.args(["--only", key]);
        }
        cmd.assert().success();
        self.read_grant(name)
    }

    /// Where [`Cast::grant`] writes a grant's key file.
    pub fn grant_key_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("grant-{name}.key"))
    }

    /// The identity in a grant key file written to [`Cast::grant_key_path`].
    pub fn read_grant(&self, name: &str) -> Who {
        let text = fs::read_to_string(self.grant_key_path(name)).expect("read grant key file");
        Who::from_secret(&format!("grant:{name}"), &text)
    }
}

/// Where a value lives in a vault entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// The shared value, encrypted to every member.
    Shared,
    /// A named group's value.
    Group(String),
    /// A personal value (an override, or an agent grant's copy), by pubkey.
    Private(String),
}

/// One value: a key name and the tier it sits in.
pub type Cell = (String, Tier);

/// Every value in a vault: for each cell, the label of each given identity that
/// can decrypt it, with the plaintext it reads. A cell nobody given can read
/// still appears, with an empty map.
pub type Cells = BTreeMap<Cell, BTreeMap<String, String>>;

/// Decrypt every value in the vault at `vault_path` with each of `who`.
pub fn cells(vault_path: impl AsRef<Path>, who: &[Who]) -> Cells {
    let text = fs::read_to_string(vault_path).expect("read vault");
    let vault: serde_json::Value = serde_json::from_str(&text).expect("parse vault json");
    let identities: Vec<(&str, age::x25519::Identity)> = who
        .iter()
        .map(|w| {
            (
                w.label.as_str(),
                w.secret.parse().expect("parse age secret"),
            )
        })
        .collect();

    let mut out = Cells::new();
    let secrets = vault["secrets"].as_object().expect("vault secrets object");
    for (key, entry) in secrets {
        let mut put = |tier: Tier, ciphertext: &str| {
            let readers = identities
                .iter()
                .filter_map(|(label, id)| {
                    decrypt(ciphertext, id).map(|pt| ((*label).to_string(), pt))
                })
                .collect();
            out.insert((key.clone(), tier), readers);
        };
        if let Some(shared) = entry["shared"].as_str().filter(|s| !s.is_empty()) {
            put(Tier::Shared, shared);
        }
        for (field, tier) in [
            ("scoped", Tier::Private as fn(String) -> Tier),
            ("grouped", Tier::Group),
        ] {
            if let Some(map) = entry[field].as_object() {
                for (name, ciphertext) in map {
                    put(
                        tier(name.clone()),
                        ciphertext.as_str().expect("ciphertext string"),
                    );
                }
            }
        }
    }
    out
}

/// Who can read each cell, without the plaintexts.
pub fn readers(cells: &Cells) -> BTreeMap<Cell, BTreeSet<String>> {
    cells
        .iter()
        .map(|(cell, by)| (cell.clone(), by.keys().cloned().collect()))
        .collect()
}

/// The vault's decrypted meta blob, read as `who`; `None` if `who` can't.
pub fn meta(vault_path: impl AsRef<Path>, who: &Who) -> Option<serde_json::Value> {
    let text = fs::read_to_string(vault_path).expect("read vault");
    let vault: serde_json::Value = serde_json::from_str(&text).expect("parse vault json");
    let identity = who.secret.parse().expect("parse age secret");
    let plaintext = decrypt(vault["meta"].as_str()?, &identity)?;
    Some(serde_json::from_str(&plaintext).expect("parse meta json"))
}

/// Decrypt one base64 age ciphertext from a vault; `None` if `identity` is
/// not among its recipients.
pub fn decrypt(encoded: &str, identity: &age::x25519::Identity) -> Option<String> {
    let ciphertext = BASE64.decode(encoded).ok()?;
    let decryptor = age::Decryptor::new_buffered(&ciphertext[..]).ok()?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .ok()?;
    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).ok()?;
    Some(plaintext)
}
