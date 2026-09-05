//! Vault info/introspection logic.

use crate::{codename, types};

/// Number of pubkey characters to show when a display name is unavailable.
const PUBKEY_DISPLAY_LEN: usize = 12;

/// Fall back to a truncated pubkey when no display name is known for it.
fn truncated_pubkey_fallback(pk: &str) -> String {
    pk.chars().take(PUBKEY_DISPLAY_LEN).collect::<String>() + "\u{2026}"
}

/// A single key entry in the vault info output.
#[derive(Debug, Default)]
pub struct InfoEntry {
    pub key: String,
    pub description: String,
    pub example: Option<String>,
    pub tags: Vec<String>,
    /// Soft rotation interval in days, if set (public schema metadata).
    pub rotation_interval_days: Option<u32>,
    /// Hard expiry (ISO-8601 UTC), if set (public schema metadata).
    pub expires_at: Option<String>,
    /// Display names (or truncated pubkeys) of recipients with scoped overrides.
    pub scoped_recipients: Vec<String>,
}

/// Build the at-a-glance lifecycle segment shown after each info row, e.g.
/// `rotate 90d  expires 2026-09-01`. Returns an empty string when neither is
/// set. The expiry is shown as a bare date (the stored time is end-of-day).
/// Public schema, so this renders without a key — same as tags.
pub fn lifecycle_segment(rotation_interval_days: Option<u32>, expires_at: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(days) = rotation_interval_days {
        parts.push(format!("rotate {days}d"));
    }
    if let Some(ts) = expires_at {
        let date = ts.split('T').next().unwrap_or(ts);
        parts.push(format!("expires {date}"));
    }
    parts.join("  ")
}

/// Aggregated vault information for display.
#[derive(Debug)]
pub struct VaultInfo {
    pub vault_name: String,
    pub codename: String,
    pub repo: String,
    pub created: String,
    pub recipient_count: usize,
    /// Recipient display names (populated when key is available).
    pub recipient_names: Vec<String>,
    /// Your own identity in this vault (display name, if known).
    pub self_name: Option<String>,
    /// Your own pubkey in this vault (for reference even without meta).
    pub self_pubkey: Option<String>,
    pub entries: Vec<InfoEntry>,
}

/// Compute vault info from raw vault bytes.
///
/// `raw_bytes` is the full file contents (for codename computation).
/// `tags` filters entries by tag (empty = all).
/// `secret_key` enables meta decryption for scoped-recipient display names.
pub fn vault_info(
    raw_bytes: &[u8],
    tags: &[String],
    secret_key: Option<&str>,
) -> Result<VaultInfo, String> {
    let vault: types::Vault = serde_json::from_slice(raw_bytes).map_err(|e| e.to_string())?;

    let codename = codename::from_bytes(raw_bytes);

    // Filter by tag if specified.
    let filtered: Vec<(&String, &types::SchemaEntry)> = if tags.is_empty() {
        vault.schema.iter().collect()
    } else {
        vault
            .schema
            .iter()
            .filter(|(_, e)| e.tags.iter().any(|t| tags.contains(t)))
            .collect()
    };

    // Derive self pubkey from the secret key (if available).
    let self_pubkey = secret_key.and_then(|sk| {
        let identity = crate::crypto::parse_identity(sk).ok()?;
        identity.pubkey_string().ok()
    });

    // Try to decrypt meta for recipient names.
    let meta_data = secret_key.and_then(|sk| {
        let identity = crate::crypto::parse_identity(sk).ok()?;
        crate::decrypt_meta(&vault, &identity)
    });

    let entries = filtered
        .iter()
        .map(|(key, entry)| {
            let scoped_recipients = if let Some(ref meta) = meta_data {
                vault
                    .secrets
                    .get(key.as_str())
                    .map(|s| {
                        s.private
                            .keys()
                            .map(|pk| {
                                meta.recipients
                                    .get(pk)
                                    .cloned()
                                    .unwrap_or_else(|| truncated_pubkey_fallback(pk))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            };

            InfoEntry {
                key: (*key).clone(),
                description: entry.description.clone(),
                example: entry.example.clone(),
                tags: entry.tags.clone(),
                rotation_interval_days: entry.rotation_interval_days,
                expires_at: entry.expires_at.clone(),
                scoped_recipients,
            }
        })
        .collect();

    // Build recipient name list when meta is available.
    let recipient_names = if let Some(ref meta) = meta_data {
        vault
            .recipients
            .iter()
            .map(|pk| {
                meta.recipients
                    .get(pk)
                    .cloned()
                    .unwrap_or_else(|| truncated_pubkey_fallback(pk))
            })
            .collect()
    } else {
        vec![]
    };

    // Resolve self name from meta if pubkey is known.
    let self_name = self_pubkey.as_ref().and_then(|pk| {
        meta_data
            .as_ref()
            .and_then(|m| m.recipients.get(pk).cloned())
    });

    Ok(VaultInfo {
        vault_name: vault.vault_name.clone(),
        codename,
        repo: vault.repo.clone(),
        created: vault.created.clone(),
        recipient_count: vault.recipients.len(),
        recipient_names,
        self_name,
        self_pubkey,
        entries,
    })
}

/// Format vault info as plain-text lines (no ANSI colors).
/// `has_meta` indicates whether scoped/tag columns should be shown.
pub fn format_info_lines(info: &VaultInfo, has_meta: bool) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!("▓░ {}", info.vault_name));
    lines.push(format!("   codename    {}", info.codename));
    if !info.repo.is_empty() {
        lines.push(format!("   repo        {}", info.repo));
    }
    lines.push(format!("   created     {}", info.created));
    lines.push(format!("   recipients  {}", info.recipient_count));

    if info.entries.is_empty() {
        lines.push(String::new());
        lines.push("   no keys in vault".into());
        return lines;
    }

    lines.push(String::new());

    let key_width = info.entries.iter().map(|e| e.key.len()).max().unwrap_or(0);
    let desc_width = info
        .entries
        .iter()
        .map(|e| e.description.len())
        .max()
        .unwrap_or(0);
    let example_width = info
        .entries
        .iter()
        .map(|e| {
            e.example
                .as_ref()
                .map_or(0, |ex| format!("(e.g. {ex})").len())
        })
        .max()
        .unwrap_or(0);

    // Tags are always public — show them regardless of key availability.
    let any_tags = info.entries.iter().any(|e| !e.tags.is_empty());
    let tag_width = if any_tags {
        info.entries
            .iter()
            .map(|e| {
                if e.tags.is_empty() {
                    0
                } else {
                    format!("[{}]", e.tags.join(", ")).len()
                }
            })
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    for entry in &info.entries {
        let example_str = entry
            .example
            .as_ref()
            .map(|ex| format!("(e.g. {ex})"))
            .unwrap_or_default();

        let key_padded = format!("{:<key_width$}", entry.key);
        let desc_padded = format!("{:<desc_width$}", entry.description);
        let ex_padded = format!("{example_str:<example_width$}");

        let tag_str = if entry.tags.is_empty() {
            String::new()
        } else {
            format!("[{}]", entry.tags.join(", "))
        };
        let tag_padded = if any_tags {
            format!("  {tag_str:<tag_width$}")
        } else {
            String::new()
        };

        // Lifecycle policy is public — show it regardless of key, like tags.
        let lifecycle =
            lifecycle_segment(entry.rotation_interval_days, entry.expires_at.as_deref());
        let lifecycle_str = if lifecycle.is_empty() {
            String::new()
        } else {
            format!("  {lifecycle}")
        };

        // Scoped recipients only shown when meta is available.
        let scoped_str = if has_meta && !entry.scoped_recipients.is_empty() {
            format!("  ✦ {}", entry.scoped_recipients.join(", "))
        } else {
            String::new()
        };

        lines.push(format!(
            "   {key_padded}  {desc_padded}  {ex_padded}{tag_padded}{lifecycle_str}{scoped_str}"
        ));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_vault_bytes(schema: BTreeMap<String, types::SchemaEntry>) -> Vec<u8> {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: "https://github.com/test/repo".into(),
            recipients: vec!["age1test".into()],
            schema,
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        serde_json::to_vec(&vault).unwrap()
    }

    #[test]
    fn vault_info_basic() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            types::SchemaEntry {
                description: "database url".into(),
                example: Some("postgres://...".into()),
                tags: vec!["db".into()],
                ..Default::default()
            },
        );
        let bytes = test_vault_bytes(schema);

        let info = vault_info(&bytes, &[], None).unwrap();
        assert_eq!(info.vault_name, ".murk");
        assert!(!info.codename.is_empty());
        assert_eq!(info.repo, "https://github.com/test/repo");
        assert_eq!(info.recipient_count, 1);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].key, "DB_URL");
        assert_eq!(info.entries[0].description, "database url");
        assert_eq!(info.entries[0].example.as_deref(), Some("postgres://..."));
    }

    #[test]
    fn vault_info_tag_filter() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            types::SchemaEntry {
                description: "db".into(),
                example: None,
                tags: vec!["db".into()],
                ..Default::default()
            },
        );
        schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "api".into(),
                example: None,
                tags: vec!["api".into()],
                ..Default::default()
            },
        );
        let bytes = test_vault_bytes(schema);

        let info = vault_info(&bytes, &["db".into()], None).unwrap();
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].key, "DB_URL");
    }

    #[test]
    fn vault_info_empty_schema() {
        let bytes = test_vault_bytes(BTreeMap::new());
        let info = vault_info(&bytes, &[], None).unwrap();
        assert!(info.entries.is_empty());
    }

    #[test]
    fn vault_info_invalid_json() {
        let result = vault_info(b"not json", &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn vault_info_valid_json_missing_fields() {
        // Valid JSON but not a vault — should fail deserialization.
        let result = vault_info(b"{\"foo\": \"bar\"}", &[], None);
        assert!(result.is_err());
    }

    // ── format_info_lines tests ──

    #[test]
    fn format_info_empty_vault() {
        let info = VaultInfo {
            vault_name: "test.murk".into(),
            codename: "bright-fox-dawn".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![],
        };
        let lines = format_info_lines(&info, false);
        assert!(lines[0].contains("test.murk"));
        assert!(lines[1].contains("bright-fox-dawn"));
        assert!(lines.iter().any(|l| l.contains("no keys in vault")));
    }

    #[test]
    fn format_info_with_entries() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: "https://github.com/test/repo".into(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 2,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![
                InfoEntry {
                    key: "DATABASE_URL".into(),
                    description: "Production DB".into(),
                    example: Some("postgres://...".into()),
                    tags: vec![],
                    scoped_recipients: vec![],
                    ..Default::default()
                },
                InfoEntry {
                    key: "API_KEY".into(),
                    description: "OpenAI key".into(),
                    example: None,
                    tags: vec![],
                    scoped_recipients: vec![],
                    ..Default::default()
                },
            ],
        };
        let lines = format_info_lines(&info, false);
        assert!(lines.iter().any(|l| l.contains("repo")));
        assert!(lines.iter().any(|l| l.contains("DATABASE_URL")));
        assert!(lines.iter().any(|l| l.contains("API_KEY")));
        assert!(lines.iter().any(|l| l.contains("(e.g. postgres://...)")));
    }

    #[test]
    fn format_info_with_tags_and_scoped() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 2,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![InfoEntry {
                key: "DB_URL".into(),
                description: "Database".into(),
                example: None,
                tags: vec!["prod".into()],
                scoped_recipients: vec!["alice".into()],
                ..Default::default()
            }],
        };
        let lines = format_info_lines(&info, true);
        let entry_line = lines.iter().find(|l| l.contains("DB_URL")).unwrap();
        assert!(entry_line.contains("[prod]"));
        assert!(entry_line.contains("✦ alice"));
    }

    #[test]
    fn format_info_tags_visible_without_meta() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![InfoEntry {
                key: "DB_URL".into(),
                description: "Database".into(),
                example: None,
                tags: vec!["prod".into()],
                scoped_recipients: vec![],
                ..Default::default()
            }],
        };
        // has_meta=false — tags should still show.
        let lines = format_info_lines(&info, false);
        let entry_line = lines.iter().find(|l| l.contains("DB_URL")).unwrap();
        assert!(entry_line.contains("[prod]"));
    }

    #[test]
    fn format_info_recipient_count() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 3,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![],
        };
        let lines = format_info_lines(&info, false);
        assert!(lines.iter().any(|l| l.contains('3')));
    }

    #[test]
    fn format_info_no_repo_omitted() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![],
        };
        let lines = format_info_lines(&info, false);
        assert!(!lines.iter().any(|l| l.contains("repo")));
    }

    #[test]
    fn format_info_with_repo() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: "https://github.com/test/repo".into(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![],
        };
        let lines = format_info_lines(&info, false);
        assert!(lines.iter().any(|l| l.contains("repo")));
    }

    #[test]
    fn format_info_multiple_tags() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![InfoEntry {
                key: "KEY".into(),
                description: "desc".into(),
                example: None,
                tags: vec!["prod".into(), "db".into()],
                scoped_recipients: vec![],
                ..Default::default()
            }],
        };
        let lines = format_info_lines(&info, false);
        let entry_line = lines.iter().find(|l| l.contains("KEY")).unwrap();
        assert!(entry_line.contains("[prod, db]"));
    }

    #[test]
    fn vault_info_preserves_timestamps() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "test".into(),
                created: Some("2026-03-01T00:00:00Z".into()),
                updated: Some("2026-03-15T00:00:00Z".into()),
                ..Default::default()
            },
        );
        let bytes = test_vault_bytes(schema);
        let info = vault_info(&bytes, &[], None).unwrap();
        // Timestamps are in schema, not in InfoEntry — but the vault parses correctly.
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].key, "KEY");
    }

    // ── lifecycle metadata ──

    #[test]
    fn lifecycle_segment_renders_both_or_neither() {
        assert_eq!(lifecycle_segment(None, None), "");
        assert_eq!(lifecycle_segment(Some(90), None), "rotate 90d");
        assert_eq!(
            lifecycle_segment(None, Some("2026-09-01T23:59:59Z")),
            "expires 2026-09-01"
        );
        assert_eq!(
            lifecycle_segment(Some(30), Some("2026-09-01T23:59:59Z")),
            "rotate 30d  expires 2026-09-01"
        );
    }

    #[test]
    fn vault_info_carries_lifecycle_fields() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "TOKEN".into(),
            types::SchemaEntry {
                description: "api token".into(),
                rotation_interval_days: Some(90),
                expires_at: Some("2026-09-01T23:59:59Z".into()),
                ..Default::default()
            },
        );
        let bytes = test_vault_bytes(schema);
        let info = vault_info(&bytes, &[], None).unwrap();
        assert_eq!(info.entries[0].rotation_interval_days, Some(90));
        assert_eq!(
            info.entries[0].expires_at.as_deref(),
            Some("2026-09-01T23:59:59Z")
        );
    }

    #[test]
    fn format_info_shows_lifecycle_without_meta() {
        let info = VaultInfo {
            vault_name: ".murk".into(),
            codename: "cool-name".into(),
            repo: String::new(),
            created: "2026-01-01T00:00:00Z".into(),
            recipient_count: 1,
            recipient_names: vec![],
            self_name: None,
            self_pubkey: None,
            entries: vec![InfoEntry {
                key: "TOKEN".into(),
                description: "api token".into(),
                rotation_interval_days: Some(90),
                expires_at: Some("2026-09-01T23:59:59Z".into()),
                ..Default::default()
            }],
        };
        // has_meta=false — lifecycle is public, must still render.
        let line = format_info_lines(&info, false)
            .into_iter()
            .find(|l| l.contains("TOKEN"))
            .unwrap();
        assert!(line.contains("rotate 90d"), "got: {line}");
        assert!(line.contains("expires 2026-09-01"), "got: {line}");
    }
}
