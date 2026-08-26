//! Secret CRUD operations on the in-memory `Murk` state.

use zeroize::Zeroizing;

use crate::{crypto, now_utc, types};

/// Add or update a secret in the working state.
/// If `scoped` is true, stores in scoped (encrypted to self only).
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
    identity: &crypto::MurkIdentity,
) -> bool {
    if scoped {
        // `me` is a per-identity override layered on top of the base tier — it
        // does not change which group owns the key, so shared/grouped are left
        // untouched.
        let pubkey = identity.pubkey_string().expect("valid identity has pubkey");
        murk.private
            .entry(key.into())
            .or_default()
            .insert(pubkey, Zeroizing::new(value.to_owned()));
    } else {
        // Setting the shared (everyone) value makes `everyone` the base tier, so
        // any named-group assignment is dropped — otherwise the stale grouped
        // ciphertext would still win over the new shared value for members.
        murk.grouped.remove(key);
        murk.values
            .insert(key.into(), Zeroizing::new(value.to_owned()));
    }

    upsert_schema(vault, key, desc, example, tags)
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

    Ok(upsert_schema(vault, key, desc, example, tags))
}

/// Insert or update the schema entry for a key, bumping `updated`. Returns true
/// if the key was new and no description was supplied (the caller uses this to
/// decide whether to print a "describe this key" hint).
fn upsert_schema(
    vault: &mut types::Vault,
    key: &str,
    desc: Option<&str>,
    example: Option<&str>,
    tags: &[String],
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
        // A value write satisfies any outstanding post-revoke rotation, so the
        // marker is cleared — its presence always means "still owed a rotation".
        entry.revoked_at = None;
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

/// Import multiple secrets at once.
///
/// For each `(key, value)` pair, inserts the value into murk and ensures a
/// schema entry exists. Returns the list of imported key names.
///
/// Values arrive already wrapped in [`Zeroizing`] so callers do not have to
/// hold plaintext in a bare `String` across the import boundary.
pub fn import_secrets(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    pairs: &[(String, Zeroizing<String>)],
    example: Option<&str>,
) -> Vec<String> {
    let now = now_utc();
    let mut imported = Vec::new();
    for (key, value) in pairs {
        // Shared (everyone) base tier — drop any prior group assignment.
        murk.grouped.remove(key);
        murk.values.insert(key.clone(), value.clone());

        if let Some(entry) = vault.schema.get_mut(key.as_str()) {
            entry.updated = Some(now.clone());
            if let Some(e) = example {
                entry.example = Some(e.into());
            }
            // A value write clears any outstanding post-revoke rotation marker.
            entry.revoked_at = None;
        } else {
            vault.schema.insert(
                key.clone(),
                types::SchemaEntry {
                    description: String::new(),
                    example: example.map(Into::into),
                    tags: vec![],
                    created: Some(now.clone()),
                    updated: Some(now.clone()),
                    ..Default::default()
                },
            );
        }

        imported.push(key.clone());
    }
    imported
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
    /// A stored timestamp could not be parsed as RFC-3339.
    BadTimestamp {
        key: String,
        field: &'static str,
        value: String,
    },
}

/// Evaluate per-key rotation hygiene against `now`.
///
/// Reads only the plaintext schema, so it runs without decrypting the vault.
/// `now` is injected (rather than read from the clock) to keep this pure and
/// deterministically testable.
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
                Some(ts) => match parse_ts(ts) {
                    Some(updated) => {
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
                    None => issues.push(RotationIssue::BadTimestamp {
                        key: key.clone(),
                        field: "updated",
                        value: ts.clone(),
                    }),
                },
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
                Some(_) => {}
                None => issues.push(RotationIssue::BadTimestamp {
                    key: key.clone(),
                    field: "expires_at",
                    value: ts.clone(),
                }),
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
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
        );

        assert!(needs_hint);
        assert_eq!(murk.values["KEY"].as_str(), "value");
        assert!(vault.schema.contains_key("KEY"));
        assert!(vault.schema["KEY"].description.is_empty());
    }

    #[test]
    fn add_secret_with_description() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
        );

        assert!(!needs_hint);
        assert_eq!(vault.schema["KEY"].description, "a desc");
    }

    #[test]
    fn add_secret_scoped() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
        );

        assert!(!murk.values.contains_key("KEY"));
        assert_eq!(murk.private["KEY"][&pubkey].as_str(), "scoped_val");
    }

    #[test]
    fn add_secret_merges_tags() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let tags1 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v1", None, None, false, &tags1, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db"]);

        let tags2 = vec!["backend".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v2", None, None, false, &tags2, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);

        // Adding duplicate tag should not create duplicates.
        let tags3 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v3", None, None, false, &tags3, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);
    }

    #[test]
    fn add_secret_updates_existing_desc() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
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
            &identity,
        );
        assert_eq!(vault.schema["KEY"].description, "new");
    }

    #[test]
    fn add_secret_sets_example() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
        );
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("ex-value"));
    }

    #[test]
    fn add_secret_none_example_preserves_existing() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
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
            &identity,
        );
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("keep-me"));
    }

    #[test]
    fn import_secrets_applies_example_to_all() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        let pairs = vec![
            ("A".into(), Zeroizing::new("a".into())),
            ("B".into(), Zeroizing::new("b".into())),
        ];
        import_secrets(&mut vault, &mut murk, &pairs, Some("shared-example"));
        assert_eq!(vault.schema["A"].example.as_deref(), Some("shared-example"));
        assert_eq!(vault.schema["B"].example.as_deref(), Some("shared-example"));
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
        assert!(keys.is_empty());
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
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
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
            &identity,
        );
        // Shared value still exists, scoped override added.
        assert_eq!(murk.values["KEY"].as_str(), "shared_val");
        assert_eq!(murk.private["KEY"][&pubkey].as_str(), "scoped_val");
    }

    #[test]
    fn add_secret_empty_value() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
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
            &identity,
        );
        assert_eq!(murk.values["KEY"].as_str(), "");
    }

    #[test]
    fn import_secrets_basic() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let pairs = vec![
            ("KEY1".into(), Zeroizing::new("val1".into())),
            ("KEY2".into(), Zeroizing::new("val2".into())),
        ];
        let imported = import_secrets(&mut vault, &mut murk, &pairs, None);

        assert_eq!(imported, vec!["KEY1", "KEY2"]);
        assert_eq!(murk.values["KEY1"].as_str(), "val1");
        assert_eq!(murk.values["KEY2"].as_str(), "val2");
        assert!(vault.schema.contains_key("KEY1"));
        assert!(vault.schema.contains_key("KEY2"));
    }

    #[test]
    fn import_secrets_existing_schema_preserved() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY1".into(),
            types::SchemaEntry {
                description: "existing desc".into(),
                example: Some("ex".into()),
                tags: vec!["tag".into()],
                ..Default::default()
            },
        );
        let mut murk = empty_murk();

        let pairs = vec![("KEY1".into(), Zeroizing::new("new_val".into()))];
        import_secrets(&mut vault, &mut murk, &pairs, None);

        assert_eq!(murk.values["KEY1"].as_str(), "new_val");
        assert_eq!(vault.schema["KEY1"].description, "existing desc");
    }

    #[test]
    fn import_secrets_empty() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        let imported = import_secrets(&mut vault, &mut murk, &[], None);
        assert!(imported.is_empty());
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
        assert!(rotation_health(&vault, ts("2026-02-01T00:00:00Z")).is_empty());
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
        assert!(rotation_health(&soon, ts("2025-06-01T00:00:00Z")).is_empty());
    }

    #[test]
    fn rotation_health_flags_bad_timestamp() {
        let vault = vault_with(types::SchemaEntry {
            expires_at: Some("not-a-date".into()),
            ..Default::default()
        });
        assert!(matches!(
            &rotation_health(&vault, ts("2026-01-01T00:00:00Z"))[0],
            RotationIssue::BadTimestamp {
                field: "expires_at",
                ..
            }
        ));
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
        import_secrets(&mut vault, &mut murk, &[("K".into(), secret("new"))], None);
        assert_eq!(vault.schema["K"].revoked_at, None);
        assert!(rotation_health(&vault, ts("2030-01-01T00:00:00Z")).is_empty());
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
        assert!(rotation_health(&vault, ts("2026-01-11T00:00:00Z")).is_empty());
        // One second past due → overdue.
        assert!(
            rotation_health(&vault, ts("2026-01-11T00:00:01Z"))
                .iter()
                .any(|i| matches!(i, RotationIssue::Overdue { .. }))
        );
    }
}
