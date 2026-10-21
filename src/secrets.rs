// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret CRUD operations on the in-memory `Murk` state.

use zeroize::Zeroizing;

use crate::{now_utc, types};

/// Add or update a secret in the working state.
/// If `scoped` is true, stores in scoped (encrypted to self only), and
/// `pubkey` must be `Some` — the operator's pubkey to key the private entry
/// under. `pubkey` is unused (and may be `None`) when `scoped` is false.
///
/// `pubkey` is a caller-resolved value rather than a `MurkIdentity` because
/// deriving it (`MurkIdentity::pubkey_string`) is fallible for SSH identities
/// — the caller resolves it up front (dying gracefully on failure) instead of
/// this function panicking on a bad key.
/// Returns true if the key was new (no existing schema entry).
pub fn add_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    desc: Option<&str>,
    example: Option<&str>,
    scoped: bool,
    tags: &[String],
    pubkey: Option<&str>,
) -> bool {
    if scoped {
        // `me` is a per-identity override layered on top of the base tier — it
        // does not change which group owns the key, so shared/grouped are left
        // untouched.
        let pubkey = pubkey.expect("scoped add_secret requires a resolved pubkey");
        murk.private
            .entry(key.into())
            .or_default()
            .insert(pubkey.to_string(), Zeroizing::new(value.to_owned()));
    } else {
        // Setting the shared (everyone) value makes `everyone` the base tier, so
        // any named-group assignment is dropped — otherwise the stale grouped
        // ciphertext would still win over the new shared value for members.
        murk.grouped.remove(key);
        murk.values
            .insert(key.into(), Zeroizing::new(value.to_owned()));
    }

    upsert_schema(vault, key, desc, example, tags, !scoped)
}

/// Add or update a secret encrypted to a named group. The operator must be a
/// member of the group (so they can read it and re-encrypt it later). Assigning
/// a secret to a group makes the group its sole base tier: any existing shared
/// value and other group assignments are dropped so non-members can't read it.
/// Returns true if the key was new (no existing schema entry).
pub fn add_grouped_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    desc: Option<&str>,
    example: Option<&str>,
    group: &str,
    tags: &[String],
    operator_pubkey: &str,
) -> Result<bool, crate::error::MurkError> {
    use crate::error::MurkError;

    let members = murk
        .groups
        .get(group)
        .ok_or_else(|| MurkError::Group(format!("group not found: {group}")))?;
    if !members.iter().any(|pk| pk == operator_pubkey) {
        return Err(MurkError::Group(format!(
            "you must be a member of group \"{group}\" to add secrets to it"
        )));
    }

    // The group becomes the sole base tier for this key.
    murk.values.remove(key);
    let entry = murk.grouped.entry(key.into()).or_default();
    entry.clear();
    entry.insert(group.into(), Zeroizing::new(value.to_owned()));

    Ok(upsert_schema(vault, key, desc, example, tags, true))
}

/// Where a key's values live, as seen by the operator `pubkey`. Rotation reads
/// this to replace each value in its own tier instead of moving it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyTiers {
    /// The key has a shared (everyone) value.
    pub shared: bool,
    /// Named groups holding a value the operator can read (is a member of), sorted.
    pub groups: Vec<String>,
    /// Named groups holding a value the operator can't read (is not a member of),
    /// sorted. Only a member can re-encrypt these.
    pub foreign_groups: Vec<String>,
    /// The operator has a personal (`me`) override of the key.
    pub own_override: bool,
}

/// Report which tiers hold a value of `key`. Readable tiers come from the
/// decrypted working state; group values the operator can't decrypt are found
/// in the on-disk entry. Other recipients' overrides are not reported: the
/// operator can neither read nor rotate them.
pub fn key_tiers(vault: &types::Vault, murk: &types::Murk, key: &str, pubkey: &str) -> KeyTiers {
    let readable = murk.grouped.get(key);
    let mut groups: Vec<String> = readable
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    groups.sort();
    let foreign_groups = vault
        .secrets
        .get(key)
        .map(|e| {
            e.grouped
                .keys()
                .filter(|g| !readable.is_some_and(|m| m.contains_key(*g)))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    KeyTiers {
        shared: murk.values.contains_key(key),
        groups,
        foreign_groups,
        own_override: murk
            .private
            .get(key)
            .is_some_and(|m| m.contains_key(pubkey)),
    }
}

/// Replace `key`'s value in `tier` without moving it: a shared value stays
/// shared, a group value stays in that group (re-encrypted to the group's
/// current members on save), and an override stays `pubkey`'s own. Errors when
/// the operator holds no value of `key` in `tier`, so rotation never creates a
/// tier and never widens who can read a value.
pub fn rotate_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    tier: &crate::SecretTier,
    pubkey: &str,
) -> Result<(), crate::error::MurkError> {
    use crate::SecretTier;

    let slot = match tier {
        SecretTier::Everyone => murk.values.get_mut(key),
        SecretTier::Group(name) => murk.grouped.get_mut(key).and_then(|m| m.get_mut(name)),
        SecretTier::Me => murk.private.get_mut(key).and_then(|m| m.get_mut(pubkey)),
    };
    let Some(slot) = slot else {
        return Err(crate::error::MurkError::Secret(format!(
            "{key} has no value you can rotate in that tier"
        )));
    };
    *slot = Zeroizing::new(value.to_owned());
    // The leaver never read your override, so writing it settles nothing.
    let clears_revoke = !matches!(tier, SecretTier::Me);
    upsert_schema(vault, key, None, None, &[], clears_revoke);
    Ok(())
}

/// Insert or update the schema entry for a key, bumping `updated`. Returns true
/// if the key was new and no description was supplied (the caller uses this to
/// decide whether to print a "describe this key" hint). `clears_revoke` is true
/// only for a write that replaces the value a revoked recipient could read (the
/// shared or a group value); a personal-override write leaves that value, and so
/// the pending-rotation marker, in place.
fn upsert_schema(
    vault: &mut types::Vault,
    key: &str,
    desc: Option<&str>,
    example: Option<&str>,
    tags: &[String],
    clears_revoke: bool,
) -> bool {
    let is_new = !vault.schema.contains_key(key);

    let now = now_utc();
    if let Some(entry) = vault.schema.get_mut(key) {
        if let Some(d) = desc {
            entry.description = d.into();
        }
        if let Some(e) = example {
            entry.example = Some(e.into());
        }
        if !tags.is_empty() {
            for t in tags {
                if !entry.tags.contains(t) {
                    entry.tags.push(t.clone());
                }
            }
        }
        entry.updated = Some(now);
        // Replacing the exposed value satisfies any outstanding post-revoke
        // rotation, so the marker is cleared — its presence always means
        // "still owed a rotation".
        if clears_revoke {
            entry.revoked_at = None;
        }
    } else {
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: desc.unwrap_or("").into(),
                example: example.map(Into::into),
                tags: tags.to_vec(),
                created: Some(now.clone()),
                updated: Some(now),
                ..Default::default()
            },
        );
    }

    is_new && desc.is_none()
}

/// Mark `keys` as owing a post-revoke rotation, stamping each with `revoked_at`.
///
/// Called when a recipient is revoked and rotation is deferred: the revoked
/// recipient can still decrypt the live value from git history until it changes,
/// so the obligation is recorded durably (and survives the user declining the
/// rotation prompt). `doctor` surfaces it until a value write clears it. Keys
/// without a schema entry are skipped — `rotation_health` only reads the schema,
/// so an unschematized key could not be flagged anyway. `now` is injected to keep
/// this testable and consistent with [`rotation_health`].
pub fn mark_revoked(vault: &mut types::Vault, keys: &[String], now: chrono::DateTime<chrono::Utc>) {
    let ts = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    for key in keys {
        if let Some(entry) = vault.schema.get_mut(key) {
            entry.revoked_at = Some(ts.clone());
        }
    }
}

/// Remove a secret from the working state and schema.
pub fn remove_secret(vault: &mut types::Vault, murk: &mut types::Murk, key: &str) {
    murk.values.remove(key);
    murk.private.remove(key);
    murk.grouped.remove(key);
    vault.schema.remove(key);
}

/// Look up a decrypted value. Resolution order, highest priority first:
/// a personal scoped override, then a named-group value we can read, then the
/// shared (everyone) value.
pub fn get_secret<'a>(murk: &'a types::Murk, key: &str, pubkey: &str) -> Option<&'a str> {
    if let Some(value) = murk.private.get(key).and_then(|m| m.get(pubkey)) {
        return Some(value.as_str());
    }
    if let Some(value) = murk.grouped.get(key).and_then(|m| m.values().next()) {
        return Some(value.as_str());
    }
    murk.values.get(key).map(|v| v.as_str())
}

/// Return key names from the vault schema, optionally filtered by tags.
pub fn list_keys<'a>(vault: &'a types::Vault, tags: &[String]) -> Vec<&'a str> {
    vault
        .schema
        .iter()
        .filter(|(_, entry)| tags.is_empty() || entry.tags.iter().any(|t| tags.contains(t)))
        .map(|(key, _)| key.as_str())
        .collect()
}

/// What [`set_secret`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretWrite {
    /// The key was new and got no description, so the caller may suggest one.
    pub needs_desc_hint: bool,
    /// The tiers that now hold the written value.
    pub tiers: Vec<crate::SecretTier>,
    /// The base tiers (shared or named groups) the key held before an explicit
    /// tier moved it elsewhere. Empty when the key did not change tier.
    pub moved_from: Vec<crate::SecretTier>,
}

/// Write `value` to `key` as the operator `pubkey`.
///
/// With `tier: None` the key keeps the tier(s) it is in: a shared value stays
/// shared, a group value stays in its group (re-encrypted to the group's
/// current members on save), and a key whose only value is the operator's
/// personal override updates that override. Only a new key (one with no value
/// at all) gets a shared value.
///
/// With an explicit `tier` the value goes there, as [`add_secret`] and
/// [`add_grouped_secret`] do; [`SecretWrite::moved_from`] reports the base
/// tiers the key left.
///
/// Errors before changing anything when a group the operator is not a member
/// of holds a value of `key` and the write targets its base tier (see
/// [`check_foreign_groups`]). A personal override (`me`) is still allowed.
/// Also errors, with `tier: None`, when the key's only values are other
/// recipients' overrides: there is no tier to keep, and the key isn't new, so
/// the caller must choose one.
#[allow(clippy::too_many_arguments)]
pub fn set_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    desc: Option<&str>,
    example: Option<&str>,
    tier: Option<&crate::SecretTier>,
    tags: &[String],
    pubkey: &str,
) -> Result<SecretWrite, crate::error::MurkError> {
    use crate::SecretTier;

    let before = key_tiers(vault, murk, key, pubkey);
    if tier != Some(&SecretTier::Me) {
        check_foreign_groups(key, &before)?;
    }
    let mut base: Vec<SecretTier> = before
        .shared
        .then_some(SecretTier::Everyone)
        .into_iter()
        .chain(before.groups.iter().cloned().map(SecretTier::Group))
        .collect();

    let Some(tier) = tier else {
        if base.is_empty() {
            let others_only = !before.own_override
                && vault
                    .secrets
                    .get(key)
                    .is_some_and(|e| !e.private.is_empty());
            if others_only {
                return Err(crate::error::MurkError::Secret(format!(
                    "{key} holds only other recipients' personal overrides — choose who can read the new value with --group (everyone, me, or a group name)"
                )));
            }
            base.push(if before.own_override {
                SecretTier::Me
            } else {
                SecretTier::Everyone
            });
        }
        for t in &base {
            let v = Zeroizing::new(value.to_owned());
            match t {
                SecretTier::Everyone => {
                    murk.values.insert(key.into(), v);
                }
                SecretTier::Group(name) => {
                    murk.grouped
                        .entry(key.into())
                        .or_default()
                        .insert(name.clone(), v);
                }
                SecretTier::Me => {
                    murk.private
                        .entry(key.into())
                        .or_default()
                        .insert(pubkey.into(), v);
                }
            }
        }
        // Only a shared or group write replaces a value a revoked recipient
        // could read; an override write leaves the rotation owed.
        let clears_revoke = base.iter().any(|t| *t != SecretTier::Me);
        return Ok(SecretWrite {
            needs_desc_hint: upsert_schema(vault, key, desc, example, tags, clears_revoke),
            tiers: base,
            moved_from: Vec::new(),
        });
    };

    let needs_desc_hint = match tier {
        SecretTier::Group(name) => {
            add_grouped_secret(vault, murk, key, value, desc, example, name, tags, pubkey)?
        }
        SecretTier::Everyone | SecretTier::Me => add_secret(
            vault,
            murk,
            key,
            value,
            desc,
            example,
            *tier == SecretTier::Me,
            tags,
            Some(pubkey),
        ),
    };
    // An override sits on top of the base tier, so it never moves the key.
    let moved = *tier != SecretTier::Me && !base.is_empty() && base != [tier.clone()];
    Ok(SecretWrite {
        needs_desc_hint,
        tiers: vec![tier.clone()],
        moved_from: if moved { base } else { Vec::new() },
    })
}

/// Refuse a write to `key`'s shared or group value when a group the operator is
/// not a member of holds a value of it: only a member can replace that value,
/// and a base value beside it would be readable by recipients outside the group.
pub fn check_foreign_groups(key: &str, tiers: &KeyTiers) -> Result<(), crate::error::MurkError> {
    match tiers.foreign_groups.first() {
        Some(group) => Err(crate::error::MurkError::Group(format!(
            "{key} is held by group {group}, which you are not a member of — only its members can update it"
        ))),
        None => Ok(()),
    }
}

/// Update a key's plaintext schema metadata.
///
/// `rotation_interval_days` and `expires_at` are tri-state patches so a
/// `describe` that omits them never clobbers sticky rotation policy:
/// - `None`        — leave the existing value untouched
/// - `Some(None)`  — clear it
/// - `Some(Some)`  — set it
pub fn describe_key(
    vault: &mut types::Vault,
    key: &str,
    description: &str,
    example: Option<&str>,
    tags: &[String],
    rotation_interval_days: Option<Option<u32>>,
    expires_at: Option<Option<&str>>,
) {
    if let Some(entry) = vault.schema.get_mut(key) {
        entry.description = description.into();
        entry.example = example.map(Into::into);
        if !tags.is_empty() {
            entry.tags = tags.to_vec();
        }
        if let Some(patch) = rotation_interval_days {
            entry.rotation_interval_days = patch;
        }
        if let Some(patch) = expires_at {
            entry.expires_at = patch.map(Into::into);
        }
    } else {
        let now = now_utc();
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: description.into(),
                example: example.map(Into::into),
                tags: tags.to_vec(),
                created: Some(now.clone()),
                updated: Some(now),
                // flatten() turns the tri-state patch into the stored value:
                // a clear (Some(None)) and an absent patch (None) both mean None.
                rotation_interval_days: rotation_interval_days.flatten(),
                expires_at: expires_at.flatten().map(Into::into),
                revoked_at: None,
            },
        );
    }
}

/// Days of lead time before a hard `expires_at` is flagged as "expiring soon".
pub const EXPIRY_WARN_DAYS: i64 = 14;

/// A rotation-hygiene problem found by [`rotation_health`].
///
/// Serializes with a `reason` tag (e.g. `{"reason": "overdue", "key": ...}`)
/// so `rotate --list --json` output is stable for scripts and agents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RotationIssue {
    /// `rotation_interval_days` has elapsed since the value was last changed.
    Overdue {
        key: String,
        last_rotated: String,
        interval_days: u32,
        overdue_days: i64,
    },
    /// A rotation interval is set but there is no `updated` timestamp to anchor it.
    NoBaseline { key: String, interval_days: u32 },
    /// `expires_at` is in the past.
    Expired {
        key: String,
        expired_at: String,
        days_ago: i64,
    },
    /// `expires_at` falls within [`EXPIRY_WARN_DAYS`] of now.
    ExpiringSoon {
        key: String,
        expires_at: String,
        days_left: i64,
    },
    /// A recipient who could read this key was revoked and it has not been
    /// rotated since — the revoked recipient can still decrypt the live value
    /// from git history. Driven by the `revoked_at` marker's presence.
    RevokePending { key: String, since: String },
}

/// Evaluate per-key rotation hygiene against `now`.
///
/// Reads only the plaintext schema, so it runs without decrypting the vault.
/// `now` is injected (rather than read from the clock) to keep this pure and
/// deterministically testable. Expects a vault that passed validation (every
/// vault read goes through [`crate::vault::parse`]), so its timestamps are
/// RFC-3339; one that somehow is not is skipped rather than guessed at.
pub fn rotation_health(
    vault: &types::Vault,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<RotationIssue> {
    use chrono::Duration;

    let mut issues = Vec::new();
    for (key, entry) in &vault.schema {
        // Soft rotation interval, anchored on the last value change (`updated`).
        if let Some(days) = entry.rotation_interval_days {
            match &entry.updated {
                Some(ts) => {
                    if let Some(updated) = parse_ts(ts) {
                        let due = updated + Duration::days(i64::from(days));
                        if now > due {
                            issues.push(RotationIssue::Overdue {
                                key: key.clone(),
                                last_rotated: ts.clone(),
                                interval_days: days,
                                overdue_days: (now - due).num_days(),
                            });
                        }
                    }
                }
                None => issues.push(RotationIssue::NoBaseline {
                    key: key.clone(),
                    interval_days: days,
                }),
            }
        }

        // Hard expiry.
        if let Some(ts) = &entry.expires_at {
            match parse_ts(ts) {
                Some(expiry) if now >= expiry => issues.push(RotationIssue::Expired {
                    key: key.clone(),
                    expired_at: ts.clone(),
                    days_ago: (now - expiry).num_days(),
                }),
                Some(expiry) if expiry - now <= Duration::days(EXPIRY_WARN_DAYS) => {
                    issues.push(RotationIssue::ExpiringSoon {
                        key: key.clone(),
                        expires_at: ts.clone(),
                        days_left: (expiry - now).num_days(),
                    });
                }
                _ => {}
            }
        }

        // Outstanding post-revoke rotation. The marker's presence is the signal
        // (a value write clears it), so this is independent of `now`.
        if let Some(since) = &entry.revoked_at {
            issues.push(RotationIssue::RevokePending {
                key: key.clone(),
                since: since.clone(),
            });
        }
    }
    issues
}

/// Parse an ISO-8601 / RFC-3339 timestamp (the format `now_utc` emits) into UTC.
fn parse_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::collections::HashMap;

    #[test]
    fn add_secret_shared() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let needs_hint = add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "value",
            None,
            None,
            false,
            &[],
            None,
        );

        assert!(needs_hint);
        assert_eq!(murk.values["KEY"].as_str(), "value");
        assert!(vault.schema.contains_key("KEY"));
        let description = &vault.schema["KEY"].description;
        assert!(description.is_empty(), "{description:?}");
    }

    #[test]
    fn add_secret_with_description() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let needs_hint = add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "value",
            Some("a desc"),
            None,
            false,
            &[],
            None,
        );

        assert!(!needs_hint);
        assert_eq!(vault.schema["KEY"].description, "a desc");
    }

    #[test]
    fn add_secret_scoped() {
        let (_secret, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "scoped_val",
            None,
            None,
            true,
            &[],
            Some(&pubkey),
        );

        assert!(!murk.values.contains_key("KEY"));
        assert_eq!(murk.private["KEY"][&pubkey].as_str(), "scoped_val");
    }

    #[test]
    fn add_secret_scoped_accepts_a_bare_pubkey_no_identity_required() {
        // The scoped branch used to derive the pubkey via
        // `MurkIdentity::pubkey_string()`, which is fallible for SSH identities
        // (`age::ssh::Recipient::try_from` can fail) and was force-unwrapped
        // with `.expect(...)`. It now takes a caller-resolved pubkey string
        // directly, so it needs no `MurkIdentity` in scope at all — proving the
        // scoped branch is no longer coupled to that fallible derivation.
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        let pubkey = "ssh-rsa AAAAB3NotAnActualKeyJustAPlainString";

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "scoped_val",
            None,
            None,
            true,
            &[],
            Some(pubkey),
        );

        assert!(!murk.values.contains_key("KEY"));
        assert_eq!(murk.private["KEY"][pubkey].as_str(), "scoped_val");
    }

    #[test]
    fn add_secret_merges_tags() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let tags1 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v1", None, None, false, &tags1, None,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db"]);

        let tags2 = vec!["backend".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v2", None, None, false, &tags2, None,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);

        // Adding duplicate tag should not create duplicates.
        let tags3 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v3", None, None, false, &tags3, None,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);
    }

    #[test]
    fn add_secret_updates_existing_desc() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v1",
            Some("old"),
            None,
            false,
            &[],
            None,
        );
        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v2",
            Some("new"),
            None,
            false,
            &[],
            None,
        );
        assert_eq!(vault.schema["KEY"].description, "new");
    }

    #[test]
    fn add_secret_sets_example() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "value",
            None,
            Some("ex-value"),
            false,
            &[],
            None,
        );
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("ex-value"));
    }

    #[test]
    fn add_secret_none_example_preserves_existing() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v1",
            None,
            Some("keep-me"),
            false,
            &[],
            None,
        );
        // A later value write that omits --example must not clear the example.
        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v2",
            None,
            None,
            false,
            &[],
            None,
        );
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("keep-me"));
    }

    #[test]
    fn remove_secret_clears_all() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "desc".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("val"));
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), secret("scoped_val"));
        murk.private.insert("KEY".into(), scoped);

        remove_secret(&mut vault, &mut murk, "KEY");

        assert!(!murk.values.contains_key("KEY"));
        assert!(!murk.private.contains_key("KEY"));
        assert!(!vault.schema.contains_key("KEY"));
    }

    #[test]
    fn get_secret_shared_value() {
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("shared_val"));

        assert_eq!(get_secret(&murk, "KEY", "age1pk"), Some("shared_val"));
    }

    #[test]
    fn get_secret_scoped_overrides_shared() {
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("shared_val"));
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), secret("scoped_val"));
        murk.private.insert("KEY".into(), scoped);

        assert_eq!(get_secret(&murk, "KEY", "age1pk"), Some("scoped_val"));
    }

    #[test]
    fn get_secret_missing_returns_none() {
        let murk = empty_murk();
        assert_eq!(get_secret(&murk, "NONEXISTENT", "age1pk"), None);
    }

    #[test]
    fn list_keys_no_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let keys = list_keys(&vault, &[]);
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn list_keys_with_tag_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["db".into()],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["api".into()],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "C".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let keys = list_keys(&vault, &["db".into()]);
        assert_eq!(keys, vec!["A"]);
    }

    #[test]
    fn list_keys_no_matches() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["db".into()],
                ..Default::default()
            },
        );

        let keys = list_keys(&vault, &["nonexistent".into()]);
        assert!(keys.is_empty(), "{keys:?}");
    }

    #[test]
    fn describe_key_creates_new() {
        let mut vault = empty_vault();
        describe_key(
            &mut vault,
            "KEY",
            "a description",
            Some("example"),
            &["tag".into()],
            None,
            None,
        );

        assert_eq!(vault.schema["KEY"].description, "a description");
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("example"));
        assert_eq!(vault.schema["KEY"].tags, vec!["tag"]);
    }

    #[test]
    fn describe_key_updates_existing() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "old".into(),
                example: Some("old_ex".into()),
                tags: vec!["old_tag".into()],
                ..Default::default()
            },
        );

        describe_key(
            &mut vault,
            "KEY",
            "new",
            None,
            &["new_tag".into()],
            None,
            None,
        );

        assert_eq!(vault.schema["KEY"].description, "new");
        assert_eq!(vault.schema["KEY"].example, None);
        assert_eq!(vault.schema["KEY"].tags, vec!["new_tag"]);
    }

    #[test]
    fn describe_key_preserves_tags_if_empty() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "old".into(),
                example: None,
                tags: vec!["keep".into()],
                ..Default::default()
            },
        );

        describe_key(&mut vault, "KEY", "new desc", None, &[], None, None);

        assert_eq!(vault.schema["KEY"].tags, vec!["keep"]);
    }

    // ── New edge-case tests ──

    #[test]
    fn add_secret_overwrite_shared_with_scoped() {
        let (_secret, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "shared_val",
            None,
            None,
            false,
            &[],
            None,
        );
        assert_eq!(murk.values["KEY"].as_str(), "shared_val");

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "scoped_val",
            None,
            None,
            true,
            &[],
            Some(&pubkey),
        );
        // Shared value still exists, scoped override added.
        assert_eq!(murk.values["KEY"].as_str(), "shared_val");
        assert_eq!(murk.private["KEY"][&pubkey].as_str(), "scoped_val");
    }

    #[test]
    fn add_secret_empty_value() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "",
            None,
            None,
            false,
            &[],
            None,
        );
        assert_eq!(murk.values["KEY"].as_str(), "");
    }

    #[test]
    fn remove_secret_nonexistent() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        // Should not panic.
        remove_secret(&mut vault, &mut murk, "NONEXISTENT");
    }

    // ── Rotation metadata ──

    #[test]
    fn describe_key_sets_rotation_and_expiry_on_new_key() {
        let mut vault = empty_vault();
        describe_key(
            &mut vault,
            "TOKEN",
            "api token",
            None,
            &[],
            Some(Some(90)),
            Some(Some("2026-09-01T23:59:59Z")),
        );
        let e = &vault.schema["TOKEN"];
        assert_eq!(e.rotation_interval_days, Some(90));
        assert_eq!(e.expires_at.as_deref(), Some("2026-09-01T23:59:59Z"));
    }

    #[test]
    fn describe_key_rotation_patch_is_sticky_and_clearable() {
        let mut vault = empty_vault();
        describe_key(&mut vault, "K", "d", None, &[], Some(Some(30)), None);
        assert_eq!(vault.schema["K"].rotation_interval_days, Some(30));

        // A later describe that omits the flag (None) preserves the interval.
        describe_key(&mut vault, "K", "d2", None, &[], None, None);
        assert_eq!(vault.schema["K"].rotation_interval_days, Some(30));

        // Some(None) clears it.
        describe_key(&mut vault, "K", "d3", None, &[], Some(None), None);
        assert_eq!(vault.schema["K"].rotation_interval_days, None);
    }

    fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn vault_with(entry: types::SchemaEntry) -> types::Vault {
        let mut v = empty_vault();
        v.schema.insert("K".into(), entry);
        v
    }

    #[test]
    fn rotation_health_flags_overdue() {
        let vault = vault_with(types::SchemaEntry {
            updated: Some("2026-01-01T00:00:00Z".into()),
            rotation_interval_days: Some(30),
            ..Default::default()
        });
        // 60 days later: 30 past due.
        let issues = rotation_health(&vault, ts("2026-03-02T00:00:00Z"));
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            &issues[0],
            RotationIssue::Overdue { key, overdue_days, .. } if key == "K" && *overdue_days == 30
        ));
    }

    #[test]
    fn rotation_health_silent_when_within_interval() {
        let vault = vault_with(types::SchemaEntry {
            updated: Some("2026-01-01T00:00:00Z".into()),
            rotation_interval_days: Some(90),
            ..Default::default()
        });
        let issues = rotation_health(&vault, ts("2026-02-01T00:00:00Z"));
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn rotation_health_flags_no_baseline() {
        let vault = vault_with(types::SchemaEntry {
            rotation_interval_days: Some(30),
            ..Default::default()
        });
        assert!(matches!(
            &rotation_health(&vault, ts("2026-03-02T00:00:00Z"))[0],
            RotationIssue::NoBaseline {
                interval_days: 30,
                ..
            }
        ));
    }

    #[test]
    fn rotation_health_flags_expired_and_expiring_soon() {
        let expired = vault_with(types::SchemaEntry {
            expires_at: Some("2026-01-01T00:00:00Z".into()),
            ..Default::default()
        });
        assert!(matches!(
            &rotation_health(&expired, ts("2026-01-11T00:00:00Z"))[0],
            RotationIssue::Expired { days_ago: 10, .. }
        ));

        let soon = vault_with(types::SchemaEntry {
            expires_at: Some("2026-01-10T00:00:00Z".into()),
            ..Default::default()
        });
        assert!(matches!(
            &rotation_health(&soon, ts("2026-01-01T00:00:00Z"))[0],
            RotationIssue::ExpiringSoon { days_left: 9, .. }
        ));

        // Far out: silent.
        let issues = rotation_health(&soon, ts("2025-06-01T00:00:00Z"));
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn rotation_health_flags_revoke_pending() {
        // The marker's presence is the signal — independent of `now` and of any
        // interval/expiry policy.
        let vault = vault_with(types::SchemaEntry {
            revoked_at: Some("2026-06-18T00:00:00Z".into()),
            ..Default::default()
        });
        assert!(matches!(
            &rotation_health(&vault, ts("2030-01-01T00:00:00Z"))[0],
            RotationIssue::RevokePending { key, since }
                if key == "K" && since == "2026-06-18T00:00:00Z"
        ));
    }

    #[test]
    fn mark_revoked_stamps_only_existing_schema_entries() {
        let mut vault = vault_with(types::SchemaEntry::default());
        mark_revoked(
            &mut vault,
            &["K".into(), "ABSENT".into()],
            ts("2026-06-18T12:00:00Z"),
        );
        assert_eq!(
            vault.schema["K"].revoked_at.as_deref(),
            Some("2026-06-18T12:00:00Z")
        );
        // A key with no schema entry is silently skipped — nothing to flag.
        assert!(!vault.schema.contains_key("ABSENT"));
    }

    #[test]
    fn value_write_clears_revoke_marker() {
        // A rotation (any value write) must clear the obligation: presence of
        // `revoked_at` always means "still owed a rotation since the revoke".
        let mut vault = vault_with(types::SchemaEntry {
            description: "d".into(),
            revoked_at: Some("2026-06-18T00:00:00Z".into()),
            ..Default::default()
        });
        let mut murk = empty_murk();
        set_secret(
            &mut vault,
            &mut murk,
            "K",
            "new",
            None,
            None,
            None,
            &[],
            "pk",
        )
        .unwrap();
        assert_eq!(vault.schema["K"].revoked_at, None);
        let issues = rotation_health(&vault, ts("2030-01-01T00:00:00Z"));
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn set_secret_override_write_keeps_revoke_marker() {
        // The key's only value is the operator's override: rewriting it leaves
        // the exposed base value (if any) unchanged, so the rotation stays owed.
        let mut vault = vault_with(types::SchemaEntry {
            revoked_at: Some("2026-06-18T00:00:00Z".into()),
            ..Default::default()
        });
        let mut murk = empty_murk();
        murk.private
            .entry("K".into())
            .or_default()
            .insert("pk".into(), secret("old"));
        let write = set_secret(
            &mut vault,
            &mut murk,
            "K",
            "new",
            None,
            None,
            None,
            &[],
            "pk",
        )
        .unwrap();
        assert_eq!(write.tiers, vec![crate::SecretTier::Me]);
        assert_eq!(murk.private["K"]["pk"].as_str(), "new");
        assert!(!murk.values.contains_key("K"));
        assert_eq!(
            vault.schema["K"].revoked_at.as_deref(),
            Some("2026-06-18T00:00:00Z")
        );
    }

    #[test]
    fn set_secret_new_keys_are_shared_and_get_a_schema_entry() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        for (key, value) in [("KEY1", "val1"), ("KEY2", "val2")] {
            let write = set_secret(
                &mut vault,
                &mut murk,
                key,
                value,
                None,
                Some("shared-example"),
                None,
                &[],
                "pk",
            )
            .unwrap();
            assert_eq!(write.tiers, vec![crate::SecretTier::Everyone]);
            assert!(write.needs_desc_hint);
        }
        assert_eq!(murk.values["KEY1"].as_str(), "val1");
        assert_eq!(murk.values["KEY2"].as_str(), "val2");
        assert_eq!(
            vault.schema["KEY1"].example.as_deref(),
            Some("shared-example")
        );
        assert_eq!(
            vault.schema["KEY2"].example.as_deref(),
            Some("shared-example")
        );
    }

    #[test]
    fn set_secret_update_keeps_existing_schema_metadata() {
        let mut vault = vault_with(types::SchemaEntry {
            description: "existing desc".into(),
            example: Some("ex".into()),
            tags: vec!["tag".into()],
            ..Default::default()
        });
        let mut murk = empty_murk();
        murk.values.insert("K".into(), secret("old"));
        let write = set_secret(
            &mut vault,
            &mut murk,
            "K",
            "new",
            None,
            None,
            None,
            &[],
            "pk",
        )
        .unwrap();
        assert!(!write.needs_desc_hint);
        assert_eq!(murk.values["K"].as_str(), "new");
        assert_eq!(vault.schema["K"].description, "existing desc");
        assert_eq!(vault.schema["K"].example.as_deref(), Some("ex"));
        assert_eq!(vault.schema["K"].tags, vec!["tag"]);
    }

    #[test]
    fn add_grouped_secret_scopes_to_group_and_drops_shared() {
        let (_, operator) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        // Operator is the sole member — exercises the membership guard's true arm.
        murk.groups.insert("team".into(), vec![operator.clone()]);
        murk.values.insert("K".into(), secret("old-shared"));

        let is_new = add_grouped_secret(
            &mut vault,
            &mut murk,
            "K",
            "v",
            None,
            None,
            "team",
            &[],
            &operator,
        )
        .unwrap();

        assert!(is_new, "a brand-new key with no description returns true");
        assert!(
            !murk.values.contains_key("K"),
            "the shared value must be dropped when a key is scoped to a group"
        );
        assert_eq!(
            murk.grouped
                .get("K")
                .and_then(|g| g.get("team"))
                .map(|v| v.as_str()),
            Some("v"),
            "the value must be scoped under the named group"
        );
    }

    #[test]
    fn add_grouped_secret_rejects_non_member_operator() {
        let (_, operator) = generate_keypair();
        let (_, other) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        // Operator is NOT a member of the group — must be refused.
        murk.groups.insert("team".into(), vec![other.clone()]);

        let result = add_grouped_secret(
            &mut vault,
            &mut murk,
            "K",
            "v",
            None,
            None,
            "team",
            &[],
            &operator,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rotation_health_not_overdue_at_exact_due_moment() {
        let vault = vault_with(types::SchemaEntry {
            rotation_interval_days: Some(10),
            updated: Some("2026-01-01T00:00:00Z".into()),
            ..Default::default()
        });
        // Exactly at the due instant (updated + 10 days): `>` means not overdue.
        let issues = rotation_health(&vault, ts("2026-01-11T00:00:00Z"));
        assert!(issues.is_empty(), "{issues:?}");
        // One second past due → overdue.
        assert!(
            rotation_health(&vault, ts("2026-01-11T00:00:01Z"))
                .iter()
                .any(|i| matches!(i, RotationIssue::Overdue { .. }))
        );
    }
}
