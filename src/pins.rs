// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The local trust pin: what this machine last accepted for a vault.
//!
//! A vault carries its own recipient list, so "signed by a recipient" proves
//! nothing against someone who can write the file: they list their own key and
//! sign with it. Trust has to be anchored outside the repo. The pin is that
//! anchor — a per-vault record under `~/.config/murk/signer-pins/` holding:
//!
//! - `trusted`: the keys allowed to sign the next version (the non-grant
//!   recipients of the last vault this machine accepted);
//! - `grants`: every agent-grant key ever seen, which never count as signers;
//! - `groups`: group membership as last accepted, so a membership change by a
//!   non-member is refused;
//! - `vault_id` and `generation`: the vault's identity and the highest save
//!   counter accepted, so another vault's file or an older revision is refused;
//! - `was_signed`: whether a signed version was ever accepted, so a stripped
//!   signature is refused;
//! - `signers`: confirmed verifying keys of age signers;
//! - `removed`: keys removed from the vault, with the generation they were
//!   removed at, so an older revision cannot bring them back.
//!
//! The pin is written only by an accepted load, an explicit `murk trust`, or
//! this machine's own save — never from an unverified vault. See
//! [`crate::trust`] for the rules applied against it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Format version of a trust pin. Pins without it (murk ≤ 0.13 trust-on-first-
/// use registry pins) carry no trust decision; only their `was_signed` bit is
/// kept.
pub const PIN_VERSION: u32 = 2;

/// What this machine last accepted for one vault. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPin {
    #[serde(default)]
    pub v: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_id: String,
    #[serde(default)]
    pub generation: u64,
    /// Highest counter accepted per git branch. The rollback check compares
    /// with the branch the vault is checked out on, so moving to an older
    /// branch is not a rollback but a branch going backwards is. `generation`
    /// is the highest overall, used for vaults outside a repository and to
    /// number the next save.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub branches: BTreeMap<String, u64>,
    /// Every key that was ever a trusted signer here. A historical revision
    /// (`murk diff` against a git ref) verifies if its signer is in this set,
    /// so a teammate revoked since still verifies for their old revisions.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub ever_trusted: BTreeSet<String>,
    /// Canonical recipient keys (see [`crate::recipients::canonical_recipient`])
    /// trusted to sign this vault.
    #[serde(default)]
    pub trusted: BTreeSet<String>,
    /// Canonical keys of every agent grant seen on an accepted version.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub grants: BTreeSet<String>,
    /// Group name → canonical member keys, as last accepted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, BTreeSet<String>>,
    /// Canonical pubkey → base64 verifying key of an age signer.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signers: BTreeMap<String, String>,
    /// Keys an accepted vault removed: canonical key → the generation of the
    /// vault that removed it. A vault listing the key at that generation or
    /// below, or signed by it, is refused; a newer vault from a trusted signer
    /// that lists it again, or `murk trust --re-add`, takes it out.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed: BTreeMap<String, u64>,
    /// Whether a signed version of this vault was ever accepted here.
    #[serde(default)]
    pub was_signed: bool,
}

impl TrustPin {
    /// Whether this pin records a trust decision (a `murk trust`, an accepted
    /// load, or an own save), as opposed to a legacy or empty record.
    pub fn has_trust(&self) -> bool {
        self.v >= PIN_VERSION && !self.trusted.is_empty()
    }
}

/// Path to the pin file for a vault: `~/.config/murk/signer-pins/<hash>.json`.
///
/// Inside a git checkout the hash is over the repository's common git
/// directory plus the vault's path in the checkout, so every worktree of the
/// repository shares one pin. Elsewhere it is over the vault's absolute path
/// with its directory resolved (`fs::canonicalize`), so `.murk`, `./.murk` and
/// a path through a symlinked directory share one pin.
pub fn pin_path(vault_path: &str) -> Option<PathBuf> {
    pin_paths(vault_path).into_iter().next()
}

/// Where a pin for `vault_path` may live, preferred first: the repository
/// identity (see [`pin_path`]), then the resolved absolute path, then the
/// lexical absolute path murk ≤ 0.13 used. Reads take the first that exists,
/// so a vault that was created before `git init`, or pinned by an older
/// release, keeps its pin; writes always go to the first.
fn pin_paths(vault_path: &str) -> Vec<PathBuf> {
    if std::env::var_os("MURK_NO_SIGNER_PIN").is_some() {
        return Vec::new();
    }
    let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) else {
        return Vec::new();
    };
    let p = std::path::Path::new(vault_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => return Vec::new(),
        }
    };
    let resolved = match (abs.parent(), abs.file_name()) {
        (Some(dir), Some(name)) => {
            std::fs::canonicalize(dir).map_or_else(|_| abs.clone(), |d| d.join(name))
        }
        _ => abs.clone(),
    };
    let mut identities = Vec::new();
    if let Some(repo) = crate::git::repository_vault_identity(&resolved) {
        identities.push(repo);
    }
    // The same vault in a sibling worktree, pinned by path before the
    // repository existed (or by murk ≤ 0.13): accept that pin too.
    let siblings: Vec<PathBuf> = crate::git::worktree_root(resolved.parent().unwrap_or(&resolved))
        .and_then(|root| {
            let relative = resolved.strip_prefix(&root).ok()?.to_path_buf();
            Some(
                crate::git::sibling_worktrees(&root)
                    .into_iter()
                    .map(|w| w.join(&relative))
                    .collect(),
            )
        })
        .unwrap_or_default();
    identities.push(resolved);
    identities.push(abs);
    identities.extend(siblings);
    identities.dedup();

    let dir = std::path::Path::new(&home)
        .join(".config")
        .join("murk")
        .join("signer-pins");
    identities
        .iter()
        .map(|identity| dir.join(format!("{}.json", short_hash(identity))))
        .collect()
}

fn short_hash(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(path.to_string_lossy().as_bytes());
    hash.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether a trust pin can be stored on this machine — false when opted out
/// (`MURK_NO_SIGNER_PIN`) or when there is no home directory. Trust then comes
/// only from `MURK_TRUSTED_SIGNERS`.
pub fn signer_pin_available() -> bool {
    std::env::var_os("MURK_NO_SIGNER_PIN").is_none()
        && (std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some())
}

/// Read the pin for `vault_path`. `Ok(None)` when pinning is unavailable or no
/// pin exists yet. A pin that exists but cannot be read or parsed is an error:
/// silently treating it as empty would forget a rollback high-water mark.
pub fn read(vault_path: &str) -> Result<Option<TrustPin>, String> {
    let mut found = None;
    for path in pin_paths(vault_path) {
        match std::fs::read_to_string(&path) {
            Ok(c) => {
                found = Some((path, c));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read trust pin {}: {e}", path.display())),
        }
    }
    let Some((path, contents)) = found else {
        return Ok(None);
    };
    let mut pin: TrustPin = serde_json::from_str(&contents).map_err(|e| {
        format!(
            "trust pin {} is corrupt ({e}) — delete it and run `murk trust`",
            path.display()
        )
    })?;
    if pin.v < PIN_VERSION {
        // A murk ≤ 0.13 pin: its registry entries were recorded trust-on-first-
        // use from unverified vaults, so they carry no trust. Keep only the
        // downgrade bit.
        pin = TrustPin {
            was_signed: pin.was_signed,
            ..TrustPin::default()
        };
    }
    Ok(Some(pin))
}

/// Write the pin for `vault_path`. Errors when pinning is unavailable or the
/// write fails, so a caller recording an explicit trust decision can say so.
pub fn write(vault_path: &str, pin: &TrustPin) -> Result<(), String> {
    let path = pin_path(vault_path).ok_or_else(|| {
        "no trust pin can be stored (MURK_NO_SIGNER_PIN is set or there is no HOME) — set MURK_TRUSTED_SIGNERS instead".to_string()
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid trust pin path {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // ~/.config/murk should stay 0700 like the key dirs.
        if let Some(murk_dir) = parent.parent() {
            let _ = std::fs::set_permissions(murk_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let mut pin = pin.clone();
    pin.v = PIN_VERSION;
    let json = serde_json::to_string_pretty(&pin).map_err(|e| format!("trust pin: {e}"))?;
    write_pin_file(&path, json.as_bytes())
        .map_err(|e| format!("cannot write trust pin {}: {e}", path.display()))
}

/// Read, change and write the pin for `vault_path` under an exclusive lock
/// (`<pin>.lock`), so concurrent murk processes — worktrees of one repository
/// share a pin — never write from a stale read: a lowered rollback mark, or
/// keys and grants another process just learned, lost. `f` gets the pin as
/// it is now and returns the pin to write, or `None` to leave it, or an error
/// to report.
pub fn update<F>(vault_path: &str, f: F) -> Result<(), String>
where
    F: FnOnce(Option<&TrustPin>) -> Result<Option<TrustPin>, String>,
{
    use fs2::FileExt;

    let path = pin_path(vault_path).ok_or_else(|| {
        "no trust pin can be stored (MURK_NO_SIGNER_PIN is set or there is no HOME) — set MURK_TRUSTED_SIGNERS instead".to_string()
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid trust pin path {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let lock_path = path.with_extension("lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = opts
        .open(&lock_path)
        .map_err(|e| format!("cannot open {}: {e}", lock_path.display()))?;
    lock.lock_exclusive()
        .map_err(|e| format!("cannot lock {}: {e}", lock_path.display()))?;
    let current = read(vault_path)?;
    let result = match f(current.as_ref())? {
        Some(pin) => write(vault_path, &pin),
        None => Ok(()),
    };
    let _ = FileExt::unlock(&lock);
    result
}

/// Write the pin file atomically: a `0600` temp file in the same directory,
/// fsynced, then renamed over `path`. A symlink at `path` is refused outright —
/// pins are integrity data, and writing through a planted link would clobber
/// its target and let whoever controls that target steer the pin. The rename
/// replaces a directory entry and never follows a link, so a symlink planted
/// after the check cannot redirect the write either.
fn write_pin_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the pin is a symlink — refusing to follow it",
        ));
    }
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sandbox HOME so the pin lands in a temp dir, and serialize with other
    /// tests that mutate HOME.
    fn with_home<T>(f: impl FnOnce(&str) -> T) -> T {
        use crate::testutil::ENV_LOCK;
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", dir.path()) };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };
        let out = f(dir.path().to_str().unwrap());
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        out
    }

    #[test]
    fn legacy_pin_keeps_only_the_downgrade_bit() {
        with_home(|_| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                r#"{"signers":{"age1mallory":"vkMALLORY"},"was_signed":true}"#,
            )
            .unwrap();
            let pin = read("/proj/.murk").unwrap().unwrap();
            assert!(pin.was_signed);
            assert!(
                pin.signers.is_empty(),
                "TOFU registry entries carry no trust"
            );
            assert!(!pin.has_trust());
        });
    }

    #[test]
    fn corrupt_pin_is_an_error_not_an_empty_pin() {
        with_home(|_| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{not json").unwrap();
            assert!(read("/proj/.murk").unwrap_err().contains("corrupt"));
        });
    }

    #[test]
    fn dot_prefixed_paths_share_one_pin() {
        with_home(|home| {
            let dir = std::path::Path::new(home).join("repo");
            std::fs::create_dir_all(&dir).unwrap();
            let a = dir.join(".murk");
            let b = dir.join(".").join(".murk");
            assert_eq!(pin_path(a.to_str().unwrap()), pin_path(b.to_str().unwrap()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pin_is_refused_and_its_target_untouched() {
        with_home(|home| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let target = std::path::Path::new(home).join("victim");
            std::fs::write(&target, "original").unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();

            assert!(write("/proj/.murk", &TrustPin::default()).is_err());

            assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn new_pin_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_home(|_| {
            write("/proj/.murk", &TrustPin::default()).unwrap();
            let mode = std::fs::metadata(pin_path("/proj/.murk").unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        });
    }
}
