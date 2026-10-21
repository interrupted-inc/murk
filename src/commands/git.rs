// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use murk_cli::{DiffKind, MergeDriverSetupStep, vault};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process;

pub(crate) fn cmd_merge_driver(
    base_path: &str,
    ours_path: &str,
    theirs_path: &str,
    vault_path: Option<&str>,
) {
    let base_contents = fs::read_to_string(base_path)
        .unwrap_or_else(|e| die(&format_args!("reading base {base_path}: {e}"), 1));
    let ours_contents = fs::read_to_string(ours_path)
        .unwrap_or_else(|e| die(&format_args!("reading ours {ours_path}: {e}"), 1));
    let theirs_contents = fs::read_to_string(theirs_path)
        .unwrap_or_else(|e| die(&format_args!("reading theirs {theirs_path}: {e}"), 1));

    // git runs the driver from the work-tree root and passes the vault's path
    // as %P; a driver configured before 0.14 has no %P, so fall back to the
    // configured default vault.
    let vault_path =
        vault_path.map_or_else(|| murk_cli::resolve_vault_path(".murk"), str::to_string);
    let output = murk_cli::run_merge_driver(
        &base_contents,
        &ours_contents,
        &theirs_contents,
        &vault_path,
    )
    .unwrap_or_else(|e| die(&e, 1));

    if let Some(reason) = output.needs_key
        && output.result.conflicts.is_empty()
    {
        // Without a key the merged vault keeps ours' meta, MAC and signature.
        // That is only sound when the merge changed nothing they cover and
        // theirs changed no encrypted meta (which would otherwise be dropped).
        // Write nothing and exit non-zero, so git records a conflict instead of
        // committing a vault that may fail verification or lose theirs' meta.
        // With conflicts the user must resolve and re-merge anyway, so that
        // path stays below.
        eprintln!(
            "{} MURK_KEY not available and {reason}",
            "error".red().bold()
        );
        eprintln!(
            "  {}",
            "set MURK_KEY or MURK_KEY_FILE, then abort and redo the merge to regenerate integrity metadata"
                .dimmed()
        );
        process::exit(1);
    }

    if !output.meta_regenerated && output.result.conflicts.is_empty() {
        eprintln!(
            "{} MURK_KEY not available — meta not regenerated (secrets, recipients, schema, policy and theirs' meta unchanged, safe to proceed)",
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
        // A conflicted merge never gets new integrity metadata: the written file
        // keeps ours' meta, so it verifies only where it still equals ours.
        eprintln!(
            "  {}",
            "resolve by taking one side (git checkout --ours or --theirs) and redoing the other side's changes with murk"
                .dimmed()
        );
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
    // `diff` is the review step before `murk trust`, so it must run on a vault
    // this machine does not trust yet. It still fails on a broken MAC or
    // signature; trust is reported, not enforced.
    let inspected = try_or_die(murk_cli::inspect_vault(vault_path));
    if let Some(msg) = inspected.refusal_message(vault_path) {
        eprintln!(
            "{} not trusted on this machine: {}",
            "warn".yellow().bold(),
            msg.lines().next().unwrap_or_default()
        );
    }
    let murk_cli::InspectedVault {
        vault: _vault,
        murk: current_murk,
        identity,
        ..
    } = inspected;

    // Get the old vault contents from git.
    let output = murk_cli::git_command()
        .args(["show", &format!("{git_ref}:{vault_path}")])
        .output()
        .unwrap_or_else(|e| die(&format_args!("running git: {e}"), 1));

    let mut old_values: HashMap<String, zeroize::Zeroizing<String>> = if output.status.success() {
        let old_contents = String::from_utf8_lossy(&output.stdout);
        match murk_cli::parse_and_decrypt_values(&old_contents, &identity) {
            Ok(values) => {
                if values.is_empty() {
                    // Check if the old vault had secrets — if so, we couldn't decrypt.
                    if let Ok(old_vault) = vault::parse(&old_contents)
                        && !old_vault.secrets.is_empty()
                    {
                        eprintln!(
                            "{} cannot decrypt vault at {git_ref} — you may not have been a recipient",
                            "⚠".yellow()
                        );
                    }
                }
                values
            }
            Err(e) => die(&format_args!("parsing vault at {git_ref}: {e}"), 1),
        }
    } else {
        HashMap::<String, zeroize::Zeroizing<String>>::new()
    };

    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let mut current_values: HashMap<String, zeroize::Zeroizing<String>> =
        murk_cli::resolve_secrets(&_vault, &current_murk, &pubkey, &[])
            .into_iter()
            .collect();
    // `--show-values` prints values, so an agent grant (or self-scope) only
    // diffs keys the current policy allows.
    if murk_cli::agent_policy_applies(&current_murk, &pubkey) && _vault.policy.is_some() {
        old_values.retain(|k, _| murk_cli::is_agent_key_allowed(&_vault, k));
        current_values.retain(|k, _| murk_cli::is_agent_key_allowed(&_vault, k));
    }
    let entries = murk_cli::diff_secrets(&old_values, &current_values);

    if json {
        // serde_json copies into its own owned String; zeroization ends at this boundary.
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "kind": format!("{:?}", e.kind).to_lowercase(),
                    "old_value": e.old_value.as_ref().map(|v| v.as_str()),
                    "new_value": e.new_value.as_ref().map(|v| v.as_str()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    // Who can read and who signed matter as much as the values: a forged vault
    // that lists its author as a recipient shows up here, not in the values.
    let old_vault = output
        .status
        .success()
        .then(|| vault::parse(&String::from_utf8_lossy(&output.stdout)).ok())
        .flatten();
    let mut header_changes = 0;
    if let Some(old) = &old_vault {
        let canon = |v: &murk_cli::types::Vault| -> std::collections::BTreeMap<String, String> {
            v.recipients
                .iter()
                .map(|r| (murk_cli::canonical_recipient(r).into_owned(), r.clone()))
                .collect()
        };
        let (before, after) = (canon(old), canon(&_vault));
        for (k, r) in &after {
            if !before.contains_key(k) {
                header_changes += 1;
                println!(
                    "{} recipient {}",
                    "+".magenta().bold(),
                    murk_cli::trust::label(&current_murk.recipients, r)
                );
            }
        }
        for (k, r) in &before {
            if !after.contains_key(k) {
                header_changes += 1;
                println!(
                    "{} recipient {}",
                    "-".red().bold(),
                    murk_cli::truncate_pubkey(r)
                );
            }
        }
        let old_meta = murk_cli::decrypt_meta(old, &identity).ok().flatten();
        let old_signer = old.sig.as_ref().map(|s| s.signer.clone()).or_else(|| {
            old_meta
                .as_ref()
                .and_then(|m| m.sig.as_ref().map(|s| s.signer.clone()))
        });
        // A changed signing key for an existing recipient: the signer
        // registry claims a different key for them than before.
        if let Some(old_meta) = &old_meta {
            let keys = |m: &std::collections::BTreeMap<String, String>| {
                m.iter()
                    .map(|(pk, vk)| (murk_cli::canonical_recipient(pk).into_owned(), vk.clone()))
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            let (was, now) = (keys(&old_meta.signers), keys(&current_murk.signers));
            for (pk, vk) in &now {
                if was.get(pk).is_some_and(|old_vk| old_vk != vk) {
                    header_changes += 1;
                    println!(
                        "{} signing key of {} {} {}",
                        "~".yellow().bold(),
                        murk_cli::trust::label(&current_murk.recipients, pk),
                        "→".dimmed(),
                        murk_cli::signing::fingerprint(vk).unwrap_or_default()
                    );
                }
            }
        }
        let new_signer = match &current_murk.signature {
            murk_cli::types::SignatureState::Signed { signer, .. } => Some(signer.clone()),
            murk_cli::types::SignatureState::Unsigned => None,
        };
        let canon_opt = |s: &Option<String>| {
            s.as_deref()
                .map(|k| murk_cli::canonical_recipient(k).into_owned())
        };
        if canon_opt(&old_signer) != canon_opt(&new_signer) {
            header_changes += 1;
            let show = |s: &Option<String>| {
                s.as_deref().map_or_else(
                    || "unsigned".to_string(),
                    |k| murk_cli::trust::label(&current_murk.recipients, k),
                )
            };
            println!(
                "{} signer {} {} {}",
                "~".yellow().bold(),
                show(&old_signer),
                "→".dimmed(),
                show(&new_signer)
            );
        }
        if old.policy != _vault.policy {
            header_changes += 1;
            println!("{} policy", "~".yellow().bold());
        }
        if let Some(old_meta) = &old_meta {
            let label = |k: &str| murk_cli::trust::label(&current_murk.recipients, k);
            for (name, grant) in &current_murk.grants {
                if old_meta.grants.get(name) != Some(grant) {
                    header_changes += 1;
                    println!(
                        "{} grant {} ({})",
                        "~".yellow().bold(),
                        murk_cli::show_untrusted(name),
                        label(&grant.pubkey)
                    );
                }
            }
            for name in old_meta.grants.keys() {
                if !current_murk.grants.contains_key(name) {
                    header_changes += 1;
                    println!(
                        "{} grant {}",
                        "-".red().bold(),
                        murk_cli::show_untrusted(name)
                    );
                }
            }
            let groups: std::collections::BTreeSet<&String> = current_murk
                .groups
                .keys()
                .chain(old_meta.groups.keys())
                .collect();
            for group in groups {
                let before = old_meta.groups.get(group).cloned().unwrap_or_default();
                let after = current_murk.groups.get(group).cloned().unwrap_or_default();
                for m in after.iter().filter(|m| !before.contains(m)) {
                    header_changes += 1;
                    println!(
                        "{} group {} member {}",
                        "+".magenta().bold(),
                        murk_cli::show_untrusted(group),
                        label(m)
                    );
                }
                for m in before.iter().filter(|m| !after.contains(m)) {
                    header_changes += 1;
                    println!(
                        "{} group {} member {}",
                        "-".red().bold(),
                        murk_cli::show_untrusted(group),
                        label(m)
                    );
                }
            }
        }
    }

    if entries.is_empty() {
        if header_changes == 0 {
            eprintln!("{}", "no changes".dimmed());
        }
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
