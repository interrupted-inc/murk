// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trust-on-first-use pinning of a vault's signer registry.
//!
//! The signer registry (`Meta::signers`, pubkey → Ed25519 verifying key) lives
//! in the encrypted meta blob, which anyone can re-encrypt using the public
//! recipient keys. So on its own it's attacker-mutable: a repo-writer could
//! register their *own* verifying key under an existing recipient's pubkey and
//! sign with their own key, forging that recipient's signature.
//!
//! This pin closes that. For a native age key the mapping pubkey → verifying key
//! is a fixed derivation (see [`crate::signing`]), so a given pubkey must always
//! carry the *same* verifying key. We record the mapping locally on first sight
//! and flag any later change for an existing pubkey — which is never legitimate
//! and indicates the registry was tampered with. New pubkeys are trust-on-first-
//! use (like GitHub key pinning): recorded, not rejected.
//!
//! The pin is local state under `~/.config/murk/signer-pins/`; it does not travel
//! with the repo. It is best-effort — a missing home dir or unreadable pin never
//! blocks a load, it just skips the check.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct SignerPin {
    /// pubkey → base64 Ed25519 verifying key, as first seen.
    signers: BTreeMap<String, String>,
    /// Whether this vault has ever loaded with a valid signature on this machine.
    /// Monotonic: once true, a later unsigned load is a downgrade.
    #[serde(default)]
    was_signed: bool,
}

/// Result of reconciling a vault's current signer registry against the local pin.
#[derive(Debug, PartialEq, Eq)]
pub enum PinVerdict {
    /// No conflict. `first_use` lists signer pubkeys seen for the first time on
    /// this machine (newly pinned) — their key is trust-on-first-use, not yet
    /// anchored. A pubkey absent from `first_use` matched an existing pin, so its
    /// key is anchored by a prior trusted load.
    Ok {
        first_use: BTreeSet<String>,
        /// True when the vault was signed before on this machine but loaded
        /// unsigned now — a stripped signature, or a merge result not yet
        /// re-signed. Not a hard conflict; the loader warns, strict refuses.
        downgraded: bool,
    },
    /// An existing pubkey's verifying key changed since it was pinned. Never
    /// legitimate: the registry was altered to forge this recipient's signature.
    Conflict { signer: String },
}

/// Path to the pin file for a vault: `~/.config/murk/signer-pins/<vault-hash>.json`.
/// The hash matches the scheme used for key auto-discovery (lexical abs path).
fn pin_path(vault_path: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;

    let p = std::path::Path::new(vault_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(p)
    };
    let hash = Sha256::digest(abs.to_string_lossy().as_bytes());
    let short: String = hash.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });

    Some(
        std::path::Path::new(&home)
            .join(".config")
            .join("murk")
            .join("signer-pins")
            .join(format!("{short}.json")),
    )
}

/// Whether signer pinning can actually anchor a signature on this machine —
/// false when opted out (`MURK_NO_SIGNER_PIN`) or when there is no home dir to
/// store the pin. When false, a present signature is trust-only, never anchored,
/// so callers can surface the blind spot rather than letting it pass silently.
pub fn signer_pin_available() -> bool {
    std::env::var_os("MURK_NO_SIGNER_PIN").is_none()
        && (std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some())
}

/// Reconcile the vault's current signer registry against the local pin.
///
/// Returns `Conflict` when an already-pinned pubkey now maps to a different
/// verifying key. Otherwise records any new pubkeys and returns `Ok` with the
/// set of first-seen (trust-on-first-use) signers, plus `downgraded` — the vault
/// was signed before on this machine but is unsigned now. `currently_signed` is
/// whether this load carried a valid signature. When pinning is unavailable
/// (opted out, or no home dir) every signer is first-use and no downgrade is
/// reported, since nothing is anchored.
pub fn reconcile(
    vault_path: &str,
    signers: &BTreeMap<String, String>,
    currently_signed: bool,
) -> PinVerdict {
    evaluate(vault_path, signers, currently_signed, true)
}

/// Check a signer registry against the local pin without recording anything.
///
/// Same verdict as [`reconcile`], for vault contents that are not the working
/// file (e.g. a git revision read by `murk diff`). A historical revision must
/// not extend the pin: its signers were never trusted on this machine, and
/// recording them would let old or attacker-supplied history poison it.
pub fn check(
    vault_path: &str,
    signers: &BTreeMap<String, String>,
    currently_signed: bool,
) -> PinVerdict {
    evaluate(vault_path, signers, currently_signed, false)
}

fn evaluate(
    vault_path: &str,
    signers: &BTreeMap<String, String>,
    currently_signed: bool,
    record: bool,
) -> PinVerdict {
    // No anchor available → nothing is anchored and we can't detect a downgrade.
    let all_unanchored = || PinVerdict::Ok {
        first_use: signers.keys().cloned().collect(),
        downgraded: false,
    };
    if std::env::var_os("MURK_NO_SIGNER_PIN").is_some() {
        return all_unanchored();
    }
    let Some(path) = pin_path(vault_path) else {
        return all_unanchored();
    };

    let mut pin: SignerPin = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Any existing pubkey whose verifying key changed is tampering.
    for (pubkey, vk) in signers {
        if let Some(pinned) = pin.signers.get(pubkey)
            && pinned != vk
        {
            return PinVerdict::Conflict {
                signer: pubkey.clone(),
            };
        }
    }

    // A vault signed before but unsigned now has been downgraded — the signature
    // was stripped, or it's a merge result awaiting re-signing.
    let downgraded = pin.was_signed && !currently_signed;

    // No conflict — extend the pin with any newly seen signers (TOFU), and report
    // them as first-use so callers don't over-trust an unanchored key.
    let mut first_use = BTreeSet::new();
    for (pubkey, vk) in signers {
        if !pin.signers.contains_key(pubkey) {
            pin.signers.insert(pubkey.clone(), vk.clone());
            first_use.insert(pubkey.clone());
        }
    }

    // Record having-been-signed once, monotonically.
    let newly_signed = currently_signed && !pin.was_signed;
    if newly_signed {
        pin.was_signed = true;
    }
    if record && (!first_use.is_empty() || newly_signed) {
        write_pin(&path, &pin);
    }

    PinVerdict::Ok {
        first_use,
        downgraded,
    }
}

fn write_pin(path: &std::path::Path, pin: &SignerPin) {
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // ~/.config/murk should stay 0700 like the key dirs.
        if let Some(murk_dir) = parent.parent() {
            let _ = std::fs::set_permissions(murk_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let Ok(json) = serde_json::to_string_pretty(pin) else {
        return;
    };
    // Best-effort like the rest of the pin; a failed write just skips anchoring.
    let _ = write_pin_file(path, json.as_bytes());
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
            format!(
                "signer pin is a symlink — refusing to follow: {}",
                path.display()
            ),
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

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The set of first-use signers from an `Ok` verdict (panics on `Conflict`).
    fn first_use_of(v: PinVerdict) -> BTreeSet<String> {
        match v {
            PinVerdict::Ok { first_use, .. } => first_use,
            PinVerdict::Conflict { signer } => panic!("unexpected conflict: {signer}"),
        }
    }

    /// The `downgraded` flag from an `Ok` verdict (panics on `Conflict`).
    fn downgraded_of(v: PinVerdict) -> bool {
        match v {
            PinVerdict::Ok { downgraded, .. } => downgraded,
            PinVerdict::Conflict { signer } => panic!("unexpected conflict: {signer}"),
        }
    }

    #[test]
    fn first_use_then_anchored() {
        with_home(|_| {
            let s = map(&[("age1alice", "vkALICE")]);
            // First sight: reported as first-use (not yet anchored).
            assert_eq!(
                first_use_of(reconcile("/proj/.murk", &s, true)),
                BTreeSet::from(["age1alice".to_string()])
            );
            // Second sight: matched the pin → anchored, so no longer first-use.
            assert!(first_use_of(reconcile("/proj/.murk", &s, true)).is_empty());
        });
    }

    #[test]
    fn only_the_new_signer_is_first_use() {
        with_home(|_| {
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            // Bob joins: alice is now anchored, only bob is first-use.
            assert_eq!(
                first_use_of(reconcile(
                    "/proj/.murk",
                    &map(&[("age1alice", "vkALICE"), ("age1bob", "vkBOB")]),
                    true
                )),
                BTreeSet::from(["age1bob".to_string()])
            );
        });
    }

    #[test]
    fn changed_verifying_key_for_existing_pubkey_conflicts() {
        with_home(|_| {
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            // Attacker registers a different verifying key under alice's pubkey.
            assert_eq!(
                reconcile("/proj/.murk", &map(&[("age1alice", "vkATTACKER")]), true),
                PinVerdict::Conflict {
                    signer: "age1alice".into()
                }
            );
        });
    }

    #[test]
    fn check_detects_conflicts_but_never_records() {
        with_home(|_| {
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            assert_eq!(
                check("/proj/.murk", &map(&[("age1alice", "vkATTACKER")]), true),
                PinVerdict::Conflict {
                    signer: "age1alice".into()
                }
            );
            // A revision's unseen signer is checked, not pinned: the attacker's
            // key is still first-use on the next real load, and alice's pin stands.
            check("/proj/.murk", &map(&[("age1mallory", "vkMALLORY")]), true);
            assert_eq!(
                first_use_of(reconcile(
                    "/proj/.murk",
                    &map(&[("age1alice", "vkALICE"), ("age1mallory", "vkOTHER")]),
                    true
                )),
                BTreeSet::from(["age1mallory".to_string()])
            );
        });
    }

    #[test]
    fn pins_are_per_vault_path() {
        with_home(|_| {
            reconcile("/a/.murk", &map(&[("age1alice", "vkALICE")]), true);
            // A different vault with the same pubkey but a different key: no
            // cross-contamination — separate pin file, so no conflict.
            assert_eq!(
                first_use_of(reconcile(
                    "/b/.murk",
                    &map(&[("age1alice", "vkOTHER")]),
                    true
                )),
                BTreeSet::from(["age1alice".to_string()])
            );
        });
    }

    #[test]
    fn opt_out_disables_the_check_and_anchoring() {
        with_home(|_| {
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            unsafe { std::env::set_var("MURK_NO_SIGNER_PIN", "1") };
            // Opted out: even a changed key passes, and nothing is anchored
            // (every signer reported first-use).
            assert_eq!(
                first_use_of(reconcile(
                    "/proj/.murk",
                    &map(&[("age1alice", "vkATTACKER")]),
                    true
                )),
                BTreeSet::from(["age1alice".to_string()])
            );
            unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };
        });
    }

    #[test]
    fn signed_then_unsigned_is_a_downgrade() {
        with_home(|_| {
            let s = map(&[("age1alice", "vkALICE")]);
            // First load carried a signature — records was_signed.
            assert!(!downgraded_of(reconcile("/proj/.murk", &s, true)));
            // Later load is unsigned → flagged as a downgrade.
            assert!(downgraded_of(reconcile("/proj/.murk", &map(&[]), false)));
        });
    }

    #[test]
    fn never_signed_unsigned_is_not_a_downgrade() {
        with_home(|_| {
            // A vault only ever loaded unsigned (hardware/ssh-rsa team): no signal.
            assert!(!downgraded_of(reconcile("/proj/.murk", &map(&[]), false)));
            assert!(!downgraded_of(reconcile("/proj/.murk", &map(&[]), false)));
        });
    }

    #[test]
    fn re_signing_clears_the_downgrade() {
        with_home(|_| {
            let s = map(&[("age1alice", "vkALICE")]);
            reconcile("/proj/.murk", &s, true);
            // Unsigned right after a merge → downgrade flagged.
            assert!(downgraded_of(reconcile("/proj/.murk", &map(&[]), false)));
            // Re-signed → cleared.
            assert!(!downgraded_of(reconcile("/proj/.murk", &s, true)));
        });
    }

    #[test]
    fn opt_out_suppresses_downgrade_detection() {
        with_home(|_| {
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            unsafe { std::env::set_var("MURK_NO_SIGNER_PIN", "1") };
            assert!(!downgraded_of(reconcile("/proj/.murk", &map(&[]), false)));
            unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };
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

            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);

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
            reconcile("/proj/.murk", &map(&[("age1alice", "vkALICE")]), true);
            let mode = std::fs::metadata(pin_path("/proj/.murk").unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        });
    }
}
