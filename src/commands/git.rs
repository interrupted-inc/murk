// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use murk_cli::{DiffKind, MergeDriverSetupStep, vault};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process;

pub(crate) fn cmd_merge_driver(base_path: &str, ours_path: &str, theirs_path: &str) {
    let base_contents = fs::read_to_string(base_path)
        .unwrap_or_else(|e| die(&format_args!("reading base {base_path}: {e}"), 1));
    let ours_contents = fs::read_to_string(ours_path)
        .unwrap_or_else(|e| die(&format_args!("reading ours {ours_path}: {e}"), 1));
    let theirs_contents = fs::read_to_string(theirs_path)
        .unwrap_or_else(|e| die(&format_args!("reading theirs {theirs_path}: {e}"), 1));

    let output = murk_cli::run_merge_driver(&base_contents, &ours_contents, &theirs_contents)
        .unwrap_or_else(|e| die(&e, 1));

    if !output.meta_regenerated && output.result.conflicts.is_empty() {
        // Check if the merge actually changed secrets or recipients vs ours.
        // If so, the MAC in ours.meta is stale and the vault would fail integrity checks.
        // Skip this check when there are conflicts — the user must resolve and re-merge anyway.
        let ours_vault = vault::parse(
            &fs::read_to_string(ours_path)
                .unwrap_or_else(|e| die(&format_args!("re-reading ours: {e}"), 1)),
        )
        .unwrap_or_else(|e| die(&e, 1));

        let content_changed = output.result.vault.secrets != ours_vault.secrets
            || output.result.vault.recipients != ours_vault.recipients;

        if content_changed {
            eprintln!(
                "{} MURK_KEY not available and merge changed secrets/recipients",
                "error".red().bold()
            );
            eprintln!(
                "  {}",
                "set MURK_KEY and retry the merge to regenerate integrity metadata".dimmed()
            );
            process::exit(1);
        }

        eprintln!(
            "{} MURK_KEY not available — meta not regenerated (content unchanged, safe to proceed)",
            "warn".yellow().bold()
        );
    }

    // Write merged result to ours path (%A).
    vault::write(Path::new(ours_path), &output.result.vault)
        .unwrap_or_else(|e| die(&format_args!("writing merged vault: {e}"), 1));

    if output.result.conflicts.is_empty() {
        eprintln!("{} vault merged cleanly", "◆".magenta());
        process::exit(0);
    } else {
        eprintln!(
            "{} {} conflict{}:",
            "✕".red(),
            output.result.conflicts.len(),
            if output.result.conflicts.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for c in &output.result.conflicts {
            eprintln!("  {} {} — {}", "✕".red(), c.field.bold(), c.reason);
        }
        process::exit(1);
    }
}

pub(crate) fn cmd_setup_merge_driver() {
    let steps = try_or_die(murk_cli::setup_merge_driver());

    for step in &steps {
        match step {
            MergeDriverSetupStep::GitattributesAlreadyExists => {
                eprintln!(
                    "{} .gitattributes already contains merge driver entry",
                    "◆".magenta()
                );
            }
            MergeDriverSetupStep::GitattributesAppended => {
                eprintln!("{} appended to .gitattributes", "◆".magenta());
            }
            MergeDriverSetupStep::GitattributesCreated => {
                eprintln!("{} created .gitattributes", "◆".magenta());
            }
            MergeDriverSetupStep::GitConfigured => {
                eprintln!("{} git merge driver configured", "◆".magenta());
            }
        }
    }

    eprintln!(
        "  {}",
        "commit .gitattributes so all collaborators use the merge driver".dimmed()
    );
}

pub(crate) fn cmd_diff(git_ref: &str, show_values: bool, json: bool, vault_path: &str) {
    if show_values {
        super::secrets::strict_guard_plaintext_stdout(
            "pipe the output to a program instead of redirecting it to a file",
        );
    }
    let (vault, current_murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    let old_contents =
        murk_cli::vault_at_revision(git_ref, vault_path).unwrap_or_else(|e| die(&e, 1));
    let old_values: HashMap<String, zeroize::Zeroizing<String>> = match old_contents {
        None => {
            eprintln!(
                "{} {vault_path} does not exist at {git_ref} — every secret shows as added",
                "◆".magenta()
            );
            HashMap::new()
        }
        Some(contents) => {
            // The revision gets the same verification as the working vault, so
            // diff never decrypts content that `murk get` would refuse.
            let (old_vault, old_murk) = murk_cli::decrypt_vault_revision(
                vault_path, &contents, &identity,
            )
            .unwrap_or_else(|e| match e {
                murk_cli::MurkError::Vault(_) => {
                    die(&format_args!("parsing vault at {git_ref}: {e}"), 1)
                }
                murk_cli::MurkError::Integrity(_) => die(
                    &format_args!(
                        "vault at {git_ref} failed verification, so it is not shown: {e}"
                    ),
                    1,
                ),
                _ => die(&format_args!("cannot decrypt vault at {git_ref}: {e}"), 1),
            });
            if old_murk.signature_downgraded {
                eprintln!(
                    "{} vault at {git_ref} is unsigned, but this vault was signed before on this machine — its integrity rests on git",
                    "warn".yellow().bold()
                );
            } else if matches!(old_murk.signature, types::SignatureState::Unsigned)
                && !old_vault.secrets.is_empty()
            {
                eprintln!(
                    "{} vault at {git_ref} is unsigned — its integrity rests on git",
                    "warn".yellow().bold()
                );
            }
            murk_cli::resolve_secrets(&old_vault, &old_murk, &pubkey, &[])
                .into_iter()
                .collect()
        }
    };

    let current_values: HashMap<String, zeroize::Zeroizing<String>> =
        murk_cli::resolve_secrets(&vault, &current_murk, &pubkey, &[])
            .into_iter()
            .collect();
    let entries = murk_cli::diff_secrets(&old_values, &current_values);

    if json {
        // Values only with --show-values, as in the human output.
        // serde_json copies into its own owned String; zeroization ends at this boundary.
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                let mut obj = serde_json::json!({
                    "key": e.key,
                    "kind": format!("{:?}", e.kind).to_lowercase(),
                });
                if show_values {
                    obj["old_value"] = e.old_value.as_ref().map(|v| v.as_str()).into();
                    obj["new_value"] = e.new_value.as_ref().map(|v| v.as_str()).into();
                }
                obj
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    if entries.is_empty() {
        eprintln!("{}", "no changes".dimmed());
        return;
    }

    for entry in &entries {
        let old = entry.old_value.as_ref().map_or("", |v| v.as_str());
        let new = entry.new_value.as_ref().map_or("", |v| v.as_str());
        match entry.kind {
            DiffKind::Added => {
                if show_values {
                    println!("{} {} = {}", "+".magenta().bold(), entry.key.bold(), new);
                } else {
                    println!("{} {}", "+".magenta().bold(), entry.key.bold());
                }
            }
            DiffKind::Removed => {
                if show_values {
                    println!("{} {} = {}", "-".red().bold(), entry.key.bold(), old);
                } else {
                    println!("{} {}", "-".red().bold(), entry.key.bold());
                }
            }
            DiffKind::Changed => {
                if show_values {
                    println!(
                        "{} {} {} {} {}",
                        "~".yellow().bold(),
                        entry.key.bold(),
                        old,
                        "→".dimmed(),
                        new
                    );
                } else {
                    println!("{} {}", "~".yellow().bold(), entry.key.bold());
                }
            }
        }
    }
}
