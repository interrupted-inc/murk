// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agent-oriented schema output for AI agent prompts.
//!
//! `murk agent plan` emits the vault schema (key names, descriptions, examples,
//! tags) without any secret values, recipient pubkeys, or other identifying
//! metadata. The output is safe to paste into an agent prompt: an agent can be
//! given enough context to write code against the required env vars without
//! ever decrypting the vault.

use std::fmt::Write;

use serde::Serialize;

use crate::types::Vault;

/// Schema-only view of a vault, suitable for agent prompt context.
#[derive(Debug, Clone, Serialize)]
pub struct AgentPlan {
    pub entries: Vec<AgentPlanKey>,
}

/// One key in the schema. Mirrors `info::InfoEntry` minus any field that names
/// a recipient or carries recipient-derived metadata.
#[derive(Debug, Clone, Serialize)]
pub struct AgentPlanKey {
    pub key: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Build an `AgentPlan` from a vault's schema. If `tags` is non-empty an entry
/// is included only when it carries one of the requested tags.
pub fn agent_plan(vault: &Vault, tags: &[String]) -> AgentPlan {
    let entries = vault
        .schema
        .iter()
        .filter(|(_, e)| tags.is_empty() || e.tags.iter().any(|t| tags.contains(t)))
        .map(|(name, entry)| AgentPlanKey {
            key: name.clone(),
            description: entry.description.clone(),
            example: entry.example.clone(),
            tags: entry.tags.clone(),
        })
        .collect();

    AgentPlan { entries }
}

/// Format an `AgentPlan` as plain text (no ANSI). Columns are aligned.
pub fn format_agent_plan_text(plan: &AgentPlan) -> String {
    let mut out = format!(
        "plan: {} key{}\n",
        plan.entries.len(),
        if plan.entries.len() == 1 { "" } else { "s" }
    );

    if plan.entries.is_empty() {
        return out;
    }

    let key_width = plan.entries.iter().map(|e| e.key.len()).max().unwrap_or(0);
    let desc_width = plan
        .entries
        .iter()
        .map(|e| e.description.len())
        .max()
        .unwrap_or(0);
    let example_width = plan
        .entries
        .iter()
        .map(|e| {
            e.example
                .as_ref()
                .map_or(0, |ex| format!("(e.g. {ex})").len())
        })
        .max()
        .unwrap_or(0);
    let any_tags = plan.entries.iter().any(|e| !e.tags.is_empty());

    out.push('\n');
    for entry in &plan.entries {
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
            format!("  [{}]", entry.tags.join(", "))
        };

        if any_tags {
            let _ = writeln!(out, "  {key_padded}  {desc_padded}  {ex_padded}{tag_str}");
        } else {
            let _ = writeln!(out, "  {key_padded}  {desc_padded}  {ex_padded}");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SchemaEntry, VAULT_VERSION};
    use std::collections::BTreeMap;

    fn make_vault() -> Vault {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DATABASE_URL".into(),
            SchemaEntry {
                description: "Postgres connection string".into(),
                example: Some("postgres://localhost/db".into()),
                tags: vec!["db".into()],
                created: None,
                updated: None,
                ..Default::default()
            },
        );
        schema.insert(
            "STRIPE_SECRET_KEY".into(),
            SchemaEntry {
                description: "Stripe API key".into(),
                example: None,
                tags: vec!["payments".into()],
                created: None,
                updated: None,
                ..Default::default()
            },
        );
        Vault {
            version: VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: "myapp".into(),
            repo: String::new(),
            recipients: vec!["age1exampleabc".into()],
            schema,
            policy: None,
            secrets: BTreeMap::new(),
            meta: "encrypted-meta-blob".into(),
        }
    }

    #[test]
    fn plan_includes_all_keys_when_no_tag_filter() {
        let vault = make_vault();
        let plan = agent_plan(&vault, &[]);
        assert_eq!(plan.entries.len(), 2);
    }

    #[test]
    fn plan_filters_by_tag() {
        let vault = make_vault();
        let plan = agent_plan(&vault, &["db".to_string()]);
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].key, "DATABASE_URL");
    }

    #[test]
    fn plan_empty_when_filter_matches_nothing() {
        let vault = make_vault();
        let plan = agent_plan(&vault, &["nonexistent".to_string()]);
        assert!(plan.entries.is_empty());
    }

    #[test]
    fn json_does_not_leak_recipients_meta_or_vault_name() {
        let vault = make_vault();
        let plan = agent_plan(&vault, &[]);
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("age1exampleabc"));
        assert!(!json.contains("encrypted-meta-blob"));
        assert!(!json.contains("recipient"));
        assert!(!json.contains("\"meta\""));
        assert!(!json.contains("myapp"));
        assert!(!json.contains("vault_name"));
    }

    #[test]
    fn text_format_includes_key_description_example_and_tag() {
        let vault = make_vault();
        let plan = agent_plan(&vault, &[]);
        let text = format_agent_plan_text(&plan);
        assert!(text.contains("plan: 2 keys"));
        assert!(!text.contains("myapp"));
        assert!(text.contains("DATABASE_URL"));
        assert!(text.contains("Postgres connection string"));
        assert!(text.contains("(e.g. postgres://localhost/db)"));
        assert!(text.contains("[db]"));
    }

    #[test]
    fn text_format_handles_empty_schema() {
        let mut vault = make_vault();
        vault.schema = BTreeMap::new();
        let plan = agent_plan(&vault, &[]);
        let text = format_agent_plan_text(&plan);
        assert!(text.contains("plan: 0 keys"));
    }

    #[test]
    fn text_format_singularizes_one_key() {
        let mut vault = make_vault();
        vault.schema.remove("STRIPE_SECRET_KEY");
        let plan = agent_plan(&vault, &[]);
        let text = format_agent_plan_text(&plan);
        assert!(text.contains("plan: 1 key"));
        assert!(!text.contains("1 keys"));
    }
}
