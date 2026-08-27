use super::*;
use age::secrecy::ExposeSecret;
use colored::Colorize;
use std::path::Path;

pub(crate) fn cmd_info(tags: &[String], json: bool, vault_path: &str) {
    // Route through the hardened loader so info rejects symlinked vaults and
    // enforces the version check — same as every other read path.
    let (_vault, raw_bytes) = try_or_die(murk_cli::vault::read_with_raw(Path::new(vault_path)));
    let key_with_source = murk_cli::resolve_key_with_source(vault_path).ok();
    let secret_key = key_with_source
        .as_ref()
        .map(|(k, _)| k.expose_secret().to_string());
    let key_source = key_with_source.as_ref().map(|(_, s)| s.clone());
    let info = try_or_die(murk_cli::vault_info(
        &raw_bytes,
        tags,
        secret_key.as_deref(),
    ));

    if json {
        let entries: Vec<serde_json::Value> = info
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "description": e.description,
                    "example": e.example,
                    "tags": e.tags,
                    "rotation_interval_days": e.rotation_interval_days,
                    "expires_at": e.expires_at,
                    "scoped_recipients": e.scoped_recipients,
                })
            })
            .collect();
        let mut out = serde_json::json!({
            "vault_name": info.vault_name,
            "codename": info.codename,
            "repo": info.repo,
            "created": info.created,
            "recipient_count": info.recipient_count,
            "entries": entries,
        });
        if !info.recipient_names.is_empty() {
            out["recipient_names"] = serde_json::json!(info.recipient_names);
        }
        if let Some(name) = &info.self_name {
            out["self_name"] = serde_json::json!(name);
        }
        if let Some(pk) = &info.self_pubkey {
            out["self_pubkey"] = serde_json::json!(pk);
        }
        if let Some(src) = &key_source {
            out["key_source"] = serde_json::json!(src.describe());
        }
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    // Nameplate: ░▓ vault_name
    println!(
        "{} {}",
        "▓░".dimmed(),
        info.vault_name.truecolor(135, 95, 255).bold()
    );
    println!("   {}    {}", "codename".dimmed(), info.codename);
    if !info.repo.is_empty() {
        println!("   {}        {}", "repo".dimmed(), info.repo);
    }
    println!("   {}     {}", "created".dimmed(), info.created);
    println!("   {}  {}", "recipients".dimmed(), info.recipient_count);

    if !info.recipient_names.is_empty() {
        for name in &info.recipient_names {
            let marker = if info.self_name.as_ref() == Some(name) {
                "*"
            } else {
                " "
            };
            println!("   {} {} {}", " ".repeat(9), marker, name.green().bold());
        }
    }

    if let Some(src) = &key_source {
        println!("   {}  {}", "key".dimmed(), src.describe().dimmed());
    }

    if info.entries.is_empty() {
        println!();
        println!("   {}", "no keys in vault".dimmed());
        return;
    }

    println!();

    // Compute column widths for aligned output.
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

    let has_meta = secret_key.is_some();

    // Tags are always public — show them regardless of key.
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

        // Pad plain strings for alignment, then apply colors.
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
            murk_cli::lifecycle_segment(entry.rotation_interval_days, entry.expires_at.as_deref());
        let lifecycle_str = if lifecycle.is_empty() {
            String::new()
        } else {
            format!("  {}", lifecycle.dimmed())
        };

        // Scoped recipients only shown when meta is available.
        let scoped_str = if has_meta && !entry.scoped_recipients.is_empty() {
            format!(
                "  {}",
                format!("✦ {}", entry.scoped_recipients.join(", ")).dimmed()
            )
        } else {
            String::new()
        };

        println!(
            "   {}  {}  {}{}{}{}",
            key_padded.magenta().dimmed().bold(),
            desc_padded,
            ex_padded.dimmed(),
            tag_padded.yellow(),
            lifecycle_str,
            scoped_str
        );
    }
}
