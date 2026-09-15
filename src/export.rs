//! Export and diff logic for vault secrets.

use std::collections::{BTreeMap, HashMap};

use zeroize::Zeroizing;

use crate::types;

/// Merge private overrides over shared values and filter by tag.
/// Returns raw (unescaped) values suitable for env var injection.
///
/// Values are wrapped in `Zeroizing` so plaintext is cleared from memory
/// when the returned map is dropped.
pub fn resolve_secrets(
    vault: &types::Vault,
    murk: &types::Murk,
    pubkey: &str,
    tags: &[String],
) -> BTreeMap<String, Zeroizing<String>> {
    // Collect straight into the result map — no intermediate map holding
    // extra copies of plaintext.
    let mut values = murk
        .values
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<BTreeMap<String, Zeroizing<String>>>();

    // Apply named-group values we can read. A group secret has no shared value,
    // so this is usually an addition; the private override (below) still wins over it.
    for (key, group_map) in &murk.grouped {
        if let Some(value) = group_map.values().next() {
            values.insert(key.clone(), value.clone());
        }
    }

    // Apply private overrides.
    for (key, scoped_map) in &murk.private {
        if let Some(value) = scoped_map.get(pubkey) {
            values.insert(key.clone(), value.clone());
        }
    }

    // Filter by tag.
    if !tags.is_empty() {
        let allowed: std::collections::HashSet<&str> = vault
            .schema
            .iter()
            .filter(|(_, e)| e.tags.iter().any(|t| tags.contains(t)))
            .map(|(k, _)| k.as_str())
            .collect();
        values.retain(|k, _| allowed.contains(k.as_str()));
    }
    values
}

/// Build shell-escaped export key-value pairs for `eval $(murk export)`.
/// Wraps values in single quotes with embedded quote escaping.
pub fn export_secrets(
    vault: &types::Vault,
    murk: &types::Murk,
    pubkey: &str,
    tags: &[String],
) -> BTreeMap<String, Zeroizing<String>> {
    resolve_secrets(vault, murk, pubkey, tags)
        .into_iter()
        .map(|(k, v)| (k, Zeroizing::new(v.replace('\'', "'\\''"))))
        .collect()
}

/// Decrypt all shared secret values from a vault.
///
/// Silently skips entries that fail to decrypt (the caller may not have been
/// a recipient at the time the vault was written). Returns a map of key → plaintext value.
pub fn decrypt_vault_values(
    vault: &types::Vault,
    identity: &crate::crypto::MurkIdentity,
) -> HashMap<String, Zeroizing<String>> {
    let pubkey = identity.pubkey_string().unwrap_or_default();
    let mut values = HashMap::new();
    for (key, entry) in &vault.secrets {
        // Decrypt shared value.
        if !entry.shared.is_empty()
            && let Ok(value) = crate::decrypt_value(&entry.shared, identity).and_then(|pt| {
                crate::plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| crate::error::MurkError::Secret(e.to_string()))
            })
        {
            values.insert(key.clone(), value);
        }
        // Private override takes priority.
        if let Some(encoded) = entry.private.get(&pubkey)
            && let Ok(value) = crate::decrypt_value(encoded, identity).and_then(|pt| {
                crate::plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| crate::error::MurkError::Secret(e.to_string()))
            })
        {
            values.insert(key.clone(), value);
        }
    }
    values
}

/// Parse a vault from its JSON string and decrypt all shared values.
///
/// Combines `vault::parse` with `decrypt_vault_values` for use cases
/// where the vault contents come from a string (e.g., `git show`).
pub fn parse_and_decrypt_values(
    vault_contents: &str,
    identity: &crate::crypto::MurkIdentity,
) -> Result<HashMap<String, Zeroizing<String>>, String> {
    let vault = crate::vault::parse(vault_contents).map_err(|e| e.to_string())?;
    Ok(decrypt_vault_values(&vault, identity))
}

/// The kind of change in a diff entry.
#[derive(Debug, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
}

/// A single entry in a secret diff.
///
/// `old_value` and `new_value` are held in `Zeroizing` so plaintext is cleared
/// when the entry is dropped. Formatting/printing callers should take care not
/// to retain their own unzeroed copies.
pub struct DiffEntry {
    pub key: String,
    pub kind: DiffKind,
    pub old_value: Option<Zeroizing<String>>,
    pub new_value: Option<Zeroizing<String>>,
}

/// Manual `Debug`: prints the key and kind (schema-level metadata) but never
/// the decrypted plaintext in `old_value`/`new_value` — those are
/// `Option<Zeroizing<String>>`, and `Zeroizing` forwards `Debug` transparently
/// (it is a `#[derive(Debug)]` tuple struct), so a derived `Debug` here would
/// leak secret material into any accidental `{:?}` log.
impl std::fmt::Debug for DiffEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiffEntry")
            .field("key", &self.key)
            .field("kind", &self.kind)
            .field("old_value", &self.old_value.as_ref().map(|_| "<redacted>"))
            .field("new_value", &self.new_value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Compare two sets of secret values and return the differences.
pub fn diff_secrets(
    old: &HashMap<String, Zeroizing<String>>,
    new: &HashMap<String, Zeroizing<String>>,
) -> Vec<DiffEntry> {
    let mut all_keys: Vec<&str> = old
        .keys()
        .chain(new.keys())
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    all_keys.sort_unstable();

    let mut entries = Vec::new();
    for key in all_keys {
        match (old.get(key), new.get(key)) {
            (None, Some(v)) => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Added,
                old_value: None,
                new_value: Some(v.clone()),
            }),
            (Some(v), None) => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Removed,
                old_value: Some(v.clone()),
                new_value: None,
            }),
            (Some(old_v), Some(new_v)) if **old_v != **new_v => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Changed,
                old_value: Some(old_v.clone()),
                new_value: Some(new_v.clone()),
            }),
            _ => {}
        }
    }
    entries
}

/// Format diff entries as display lines.
/// Returns plain-text lines (no ANSI colors) suitable for testing.
pub fn format_diff_lines(entries: &[DiffEntry], show_values: bool) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            let symbol = match entry.kind {
                DiffKind::Added => "+",
                DiffKind::Removed => "-",
                DiffKind::Changed => "~",
            };
            if show_values {
                let old = entry.old_value.as_ref().map_or("", |v| v.as_str());
                let new = entry.new_value.as_ref().map_or("", |v| v.as_str());
                match entry.kind {
                    DiffKind::Added => format!("{symbol} {} = {}", entry.key, new),
                    DiffKind::Removed => format!("{symbol} {} = {}", entry.key, old),
                    DiffKind::Changed => {
                        format!("{symbol} {} {} → {}", entry.key, old, new)
                    }
                }
            } else {
                format!("{symbol} {}", entry.key)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::types;

    #[test]
    fn export_secrets_basic() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "FOO".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("FOO".into(), secret("bar"));

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports["FOO"].as_str(), "bar");
    }

    #[test]
    fn export_secrets_scoped_override() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("shared"));
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), secret("override"));
        murk.private.insert("KEY".into(), scoped);

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports["KEY"].as_str(), "override");
    }

    #[test]
    fn export_secrets_tag_filter() {
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

        let mut murk = empty_murk();
        murk.values.insert("A".into(), secret("val_a"));
        murk.values.insert("B".into(), secret("val_b"));

        let exports = export_secrets(&vault, &murk, "age1pk", &["db".into()]);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports["A"].as_str(), "val_a");
    }

    #[test]
    fn export_secrets_shell_escaping() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("it's a test"));

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports["KEY"].as_str(), "it'\\''s a test");
    }

    #[test]
    fn diff_secrets_no_changes() {
        let old = HashMap::from([("K".into(), secret("V"))]);
        let new = old.clone();
        assert!(diff_secrets(&old, &new).is_empty());
    }

    #[test]
    fn diff_secrets_added() {
        let old = HashMap::new();
        let new = HashMap::from([("KEY".into(), secret("val"))]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Added);
        assert_eq!(entries[0].key, "KEY");
        assert_eq!(entries[0].new_value.as_deref(), Some(&String::from("val")));
    }

    #[test]
    fn diff_secrets_removed() {
        let old = HashMap::from([("KEY".into(), secret("val"))]);
        let new = HashMap::new();
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Removed);
        assert_eq!(entries[0].old_value.as_deref(), Some(&String::from("val")));
    }

    #[test]
    fn diff_secrets_changed() {
        let old = HashMap::from([("KEY".into(), secret("old_val"))]);
        let new = HashMap::from([("KEY".into(), secret("new_val"))]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Changed);
        assert_eq!(
            entries[0].old_value.as_deref(),
            Some(&String::from("old_val"))
        );
        assert_eq!(
            entries[0].new_value.as_deref(),
            Some(&String::from("new_val"))
        );
    }

    #[test]
    fn diff_secrets_mixed() {
        let old = HashMap::from([
            ("KEEP".into(), secret("same")),
            ("REMOVE".into(), secret("gone")),
            ("CHANGE".into(), secret("old")),
        ]);
        let new = HashMap::from([
            ("KEEP".into(), secret("same")),
            ("ADD".into(), secret("new")),
            ("CHANGE".into(), secret("new")),
        ]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 3);

        let kinds: Vec<&DiffKind> = entries.iter().map(|e| &e.kind).collect();
        assert!(kinds.contains(&&DiffKind::Added));
        assert!(kinds.contains(&&DiffKind::Removed));
        assert!(kinds.contains(&&DiffKind::Changed));
    }

    #[test]
    fn diff_secrets_sorted_by_key() {
        let old = HashMap::new();
        let new = HashMap::from([
            ("Z".into(), secret("z")),
            ("A".into(), secret("a")),
            ("M".into(), secret("m")),
        ]);
        let entries = diff_secrets(&old, &new);
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["A", "M", "Z"]);
    }

    // ── format_diff_lines tests ──

    #[test]
    fn format_diff_lines_without_values() {
        let entries = vec![
            DiffEntry {
                key: "NEW_KEY".into(),
                kind: DiffKind::Added,
                old_value: None,
                new_value: Some(secret("secret")),
            },
            DiffEntry {
                key: "OLD_KEY".into(),
                kind: DiffKind::Removed,
                old_value: Some(secret("old")),
                new_value: None,
            },
            DiffEntry {
                key: "MOD_KEY".into(),
                kind: DiffKind::Changed,
                old_value: Some(secret("v1")),
                new_value: Some(secret("v2")),
            },
        ];
        let lines = format_diff_lines(&entries, false);
        assert_eq!(lines, vec!["+ NEW_KEY", "- OLD_KEY", "~ MOD_KEY"]);
    }

    #[test]
    fn format_diff_lines_with_values() {
        let entries = vec![
            DiffEntry {
                key: "KEY".into(),
                kind: DiffKind::Added,
                old_value: None,
                new_value: Some(secret("new_val")),
            },
            DiffEntry {
                key: "KEY2".into(),
                kind: DiffKind::Changed,
                old_value: Some(secret("old")),
                new_value: Some(secret("new")),
            },
        ];
        let lines = format_diff_lines(&entries, true);
        assert_eq!(lines[0], "+ KEY = new_val");
        assert_eq!(lines[1], "~ KEY2 old → new");
    }

    #[test]
    fn format_diff_lines_empty() {
        let lines = format_diff_lines(&[], false);
        assert!(lines.is_empty());
    }

    // ── resolve_secrets tests ──

    #[test]
    fn resolve_secrets_basic() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "FOO".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("FOO".into(), secret("bar"));

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["FOO"].as_str(), "bar");
    }

    #[test]
    fn resolve_secrets_no_escaping() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("it's a test"));

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved["KEY"].as_str(), "it's a test");
    }

    #[test]
    fn resolve_secrets_scoped_override() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("shared"));
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), secret("override"));
        murk.private.insert("KEY".into(), scoped);

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved["KEY"].as_str(), "override");
    }

    #[test]
    fn resolve_secrets_tag_filter() {
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

        let mut murk = empty_murk();
        murk.values.insert("A".into(), secret("val_a"));
        murk.values.insert("B".into(), secret("val_b"));

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &["db".into()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["A"].as_str(), "val_a");
    }

    #[test]
    fn resolve_secrets_tag_in_schema_but_no_secret() {
        let mut vault = empty_vault();
        // Schema says key "ORPHAN" exists with tag "db", but no secret value.
        vault.schema.insert(
            "ORPHAN".into(),
            types::SchemaEntry {
                description: "orphan key".into(),
                example: None,
                tags: vec!["db".into()],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "REAL".into(),
            types::SchemaEntry {
                description: "has a value".into(),
                example: None,
                tags: vec!["db".into()],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        // Only REAL has a value, ORPHAN does not.
        murk.values.insert("REAL".into(), secret("real_val"));

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &["db".into()]);
        // ORPHAN should not appear since it has no value.
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["REAL"].as_str(), "real_val");
        assert!(!resolved.contains_key("ORPHAN"));
    }

    #[test]
    fn resolve_secrets_scoped_pubkey_not_in_recipients() {
        let mut vault = empty_vault();
        vault.recipients = vec!["age1alice".into()];
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), secret("shared"));
        // Private override for a pubkey NOT in vault.recipients.
        let mut scoped = HashMap::new();
        scoped.insert("age1outsider".into(), secret("outsider_val"));
        murk.private.insert("KEY".into(), scoped);

        // The outsider's override should still be applied (resolve doesn't gate on recipient list).
        let resolved = resolve_secrets(&vault, &murk, "age1outsider", &[]);
        assert_eq!(resolved["KEY"].as_str(), "outsider_val");

        // Alice gets the shared value since she has no private override.
        let resolved_alice = resolve_secrets(&vault, &murk, "age1alice", &[]);
        assert_eq!(resolved_alice["KEY"].as_str(), "shared");
    }

    // ── New edge-case tests ──

    #[test]
    fn export_secrets_empty_vault() {
        let vault = empty_vault();
        let murk = empty_murk();
        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert!(exports.is_empty());
    }

    #[test]
    fn decrypt_vault_values_basic() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val2", &[recipient]).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let values = crate::export::decrypt_vault_values(&vault, &identity);
        assert_eq!(values.len(), 2);
        assert_eq!(values["KEY1"].as_str(), "val1");
        assert_eq!(values["KEY2"].as_str(), "val2");
    }

    #[test]
    fn decrypt_vault_values_wrong_key_skips() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();
        let wrong_identity = make_identity(&wrong_secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient]).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let values = crate::export::decrypt_vault_values(&vault, &wrong_identity);
        assert!(values.is_empty());
    }

    #[test]
    fn decrypt_vault_values_empty_vault() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let vault = empty_vault();

        let values = crate::export::decrypt_vault_values(&vault, &identity);
        assert!(values.is_empty());
    }

    #[test]
    fn diff_secrets_both_empty() {
        let old = HashMap::new();
        let new = HashMap::new();
        assert!(diff_secrets(&old, &new).is_empty());
    }

    // ── parse_and_decrypt_values tests ──

    #[test]
    fn parse_and_decrypt_values_roundtrip() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val2", &[recipient]).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let json = serde_json::to_string(&vault).unwrap();
        let values = parse_and_decrypt_values(&json, &identity).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values["KEY1"].as_str(), "val1");
        assert_eq!(values["KEY2"].as_str(), "val2");
    }

    #[test]
    fn parse_and_decrypt_values_invalid_json() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);

        let result = parse_and_decrypt_values("not valid json", &identity);
        assert!(result.is_err());
    }

    #[test]
    fn parse_and_decrypt_values_wrong_key() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();
        let wrong_identity = make_identity(&wrong_secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient]).unwrap(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let json = serde_json::to_string(&vault).unwrap();
        let values = parse_and_decrypt_values(&json, &wrong_identity).unwrap();
        assert!(values.is_empty());
    }
}
