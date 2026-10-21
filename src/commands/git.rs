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
    if show_values {
        super::secrets::strict_guard_plaintext_stdout(
            "pipe the output to a program instead of redirecting it to a file",
        );
    }
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
        vault,
        murk,
        identity,
        ..
    } = inspected;
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    let old = match murk_cli::vault_at_revision(git_ref, vault_path).unwrap_or_else(|e| die(&e, 1))
    {
        None => {
            eprintln!(
                "{} {vault_path} does not exist at {git_ref} — every secret shows as added",
                "◆".magenta()
            );
            None
        }
        Some(contents) => Some(revision(git_ref, vault_path, &contents, &identity)),
    };

    let old_values: HashMap<String, zeroize::Zeroizing<String>> =
        old.as_ref()
            .map_or_else(HashMap::new, |(old_vault, old_murk)| {
                murk_cli::resolve_secrets(old_vault, old_murk, &pubkey, &[])
                    .into_iter()
                    .collect()
            });
    let current_values: HashMap<String, zeroize::Zeroizing<String>> =
        murk_cli::resolve_secrets(&vault, &murk, &pubkey, &[])
            .into_iter()
            .collect();
    let mut entries = murk_cli::diff_secrets(&old_values, &current_values);
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let changes = old.as_ref().map_or_else(Vec::new, |(old_vault, old_murk)| {
        structural_changes((old_vault, old_murk), (&vault, &murk))
    });
    // Display names: the current ones, and for keys gone since the ref (a
    // revoked recipient, a former signer) the names they had there.
    let mut names = old
        .as_ref()
        .map(|(_, old_murk)| old_murk.recipients.clone())
        .unwrap_or_default();
    names.extend(murk.recipients.iter().map(|(k, v)| (k.clone(), v.clone())));

    if json {
        // Values only with --show-values, as in the human output; a change
        // entry never carries one. serde_json copies into its own owned
        // String; zeroization ends at this boundary.
        let secrets: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                let mut obj = serde_json::json!({
                    "key": e.key,
                    "kind": diff_kind(&e.kind),
                });
                if show_values {
                    obj["old_value"] = e.old_value.as_ref().map(|v| v.as_str()).into();
                    obj["new_value"] = e.new_value.as_ref().map(|v| v.as_str()).into();
                }
                obj
            })
            .collect();
        let changes: Vec<serde_json::Value> = changes.iter().map(|c| c.to_json(&names)).collect();
        let out = serde_json::json!({ "secrets": secrets, "changes": changes });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    for change in &changes {
        println!("{}", change.line(&names));
    }
    if entries.is_empty() {
        if changes.is_empty() {
            eprintln!("{}", "no changes".dimmed());
        }
        return;
    }

    // Values are shown in `.env` quoting: one line each, with control and
    // invisible characters escaped, so a value cannot drive the terminal or
    // pass for other output. `--json` carries the exact bytes.
    let shown = |v: Option<&zeroize::Zeroizing<String>>| {
        let mut out = zeroize::Zeroizing::new(String::new());
        murk_cli::dotenv::push_value(&mut out, v.map_or("", |v| v.as_str()));
        out
    };
    for entry in &entries {
        let key = murk_cli::terminal_text(&entry.key, false);
        let old = shown(entry.old_value.as_ref());
        let new = shown(entry.new_value.as_ref());
        let (old, new) = (old.as_str(), new.as_str());
        match entry.kind {
            DiffKind::Added if show_values => {
                println!("{} {} = {}", "+".magenta().bold(), key.bold(), new);
            }
            DiffKind::Added => println!("{} {}", "+".magenta().bold(), key.bold()),
            DiffKind::Removed if show_values => {
                println!("{} {} = {}", "-".red().bold(), key.bold(), old);
            }
            DiffKind::Removed => println!("{} {}", "-".red().bold(), key.bold()),
            DiffKind::Changed if show_values => println!(
                "{} {} {} {} {}",
                "~".yellow().bold(),
                key.bold(),
                old,
                "→".dimmed(),
                new
            ),
            DiffKind::Changed => println!("{} {}", "~".yellow().bold(), key.bold()),
        }
    }
}

/// Verify and decrypt the vault at `git_ref`, or exit. A revision that fails
/// verification, or that this machine's trust pin refuses, is never shown.
fn revision(
    git_ref: &str,
    vault_path: &str,
    contents: &str,
    identity: &murk_cli::crypto::MurkIdentity,
) -> (murk_cli::types::Vault, murk_cli::types::Murk) {
    let (old_vault, old_murk, standing) = murk_cli::decrypt_vault_revision(
        vault_path, contents, identity,
    )
    .unwrap_or_else(|e| match e {
        murk_cli::MurkError::Vault(_) => die(&format_args!("parsing vault at {git_ref}: {e}"), 1),
        murk_cli::MurkError::Integrity(_) | murk_cli::MurkError::Trust(_) => die(
            &format_args!("vault at {git_ref} failed verification, so it is not shown: {e}"),
            1,
        ),
        _ => die(&format_args!("cannot decrypt vault at {git_ref}: {e}"), 1),
    });
    match standing {
        murk_cli::RevisionTrust::Trusted => {}
        murk_cli::RevisionTrust::Unsigned => eprintln!(
            "{} vault at {git_ref} is unsigned — its integrity rests on git",
            "warn".yellow().bold()
        ),
        murk_cli::RevisionTrust::NotTrustedHere(why) => eprintln!(
            "{} vault at {git_ref} not trusted on this machine: {why}",
            "warn".yellow().bold()
        ),
    }
    (old_vault, old_murk)
}

fn diff_kind(kind: &DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "added",
        DiffKind::Removed => "removed",
        DiffKind::Changed => "changed",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Added,
    Removed,
    Changed,
}

/// One change to who can read or sign the vault, or to its policy, grants or
/// groups. Every field is vault-supplied; none is a secret value.
enum Change {
    Recipient {
        op: Op,
        key: String,
        name: Option<String>,
    },
    Signer {
        from: Option<String>,
        to: Option<String>,
    },
    SigningKey {
        key: String,
        fingerprint: String,
    },
    Policy,
    Grant {
        op: Op,
        name: String,
        key: Option<String>,
    },
    GroupMember {
        op: Op,
        group: String,
        key: String,
    },
}

impl Change {
    fn to_json(&self, names: &HashMap<String, String>) -> serde_json::Value {
        let name = |k: &str| name_of(names, k);
        let op = |op: &Op| match op {
            Op::Added => "added",
            Op::Removed => "removed",
            Op::Changed => "changed",
        };
        match self {
            Change::Recipient { op: o, key, name } => serde_json::json!({
                "kind": "recipient", "op": op(o), "key": key, "name": name,
            }),
            Change::Signer { from, to } => serde_json::json!({
                "kind": "signer", "op": "changed", "from": from, "to": to,
            }),
            Change::SigningKey { key, fingerprint } => serde_json::json!({
                "kind": "signing_key", "op": "changed", "key": key, "name": name(key),
                "to": fingerprint,
            }),
            Change::Policy => serde_json::json!({ "kind": "policy", "op": "changed" }),
            Change::Grant { op: o, name, key } => serde_json::json!({
                "kind": "grant", "op": op(o), "name": name, "key": key,
            }),
            Change::GroupMember { op: o, group, key } => serde_json::json!({
                "kind": "group_member", "op": op(o), "group": group, "key": key,
                "name": name(key),
            }),
        }
    }

    /// The terminal line, with every vault-supplied string escaped. Keys are
    /// labelled with their display name (see `trust::label`).
    fn line(&self, names: &HashMap<String, String>) -> String {
        let label = |k: &str| murk_cli::trust::label(names, k);
        let sign = |op: &Op| match op {
            Op::Added => "+".magenta().bold(),
            Op::Removed => "-".red().bold(),
            Op::Changed => "~".yellow().bold(),
        };
        match self {
            Change::Recipient { op, key, .. } => format!("{} recipient {}", sign(op), label(key)),
            Change::Signer { from, to } => {
                let show =
                    |s: &Option<String>| s.as_deref().map_or_else(|| "unsigned".into(), label);
                format!(
                    "{} signer {} {} {}",
                    sign(&Op::Changed),
                    show(from),
                    "→".dimmed(),
                    show(to)
                )
            }
            Change::SigningKey { key, fingerprint } => format!(
                "{} signing key of {} {} {}",
                sign(&Op::Changed),
                label(key),
                "→".dimmed(),
                fingerprint
            ),
            Change::Policy => format!("{} policy", sign(&Op::Changed)),
            Change::Grant {
                op: Op::Removed,
                name,
                ..
            } => format!(
                "{} grant {}",
                sign(&Op::Removed),
                murk_cli::terminal_text(name, false)
            ),
            Change::Grant { op, name, key } => format!(
                "{} grant {} ({})",
                sign(op),
                murk_cli::terminal_text(name, false),
                key.as_deref().map(label).unwrap_or_default()
            ),
            Change::GroupMember { op, group, key } => format!(
                "{} group {} member {}",
                sign(op),
                murk_cli::terminal_text(group, false),
                label(key)
            ),
        }
    }
}

/// `k`'s display name in `names`, matched by canonical key.
fn name_of(names: &HashMap<String, String>, k: &str) -> Option<String> {
    names
        .iter()
        .find(|(pk, _)| murk_cli::same_recipient(pk, k))
        .map(|(_, n)| n.clone())
        .filter(|n| !n.is_empty())
}

/// Who can read and who signed matter as much as the values: a forged vault
/// that lists its author as a recipient shows up here, not in the values.
fn structural_changes(
    (old_vault, old): (&murk_cli::types::Vault, &murk_cli::types::Murk),
    (new_vault, new): (&murk_cli::types::Vault, &murk_cli::types::Murk),
) -> Vec<Change> {
    use std::collections::{BTreeMap, BTreeSet};
    let canon = |k: &str| murk_cli::canonical_recipient(k).into_owned();
    let mut changes = Vec::new();

    let keys = |v: &murk_cli::types::Vault| -> BTreeMap<String, String> {
        v.recipients.iter().map(|r| (canon(r), r.clone())).collect()
    };
    let (before, after) = (keys(old_vault), keys(new_vault));
    for (k, r) in &after {
        if !before.contains_key(k) {
            changes.push(Change::Recipient {
                op: Op::Added,
                key: r.clone(),
                name: name_of(&new.recipients, r),
            });
        }
    }
    for (k, r) in &before {
        if !after.contains_key(k) {
            changes.push(Change::Recipient {
                op: Op::Removed,
                key: r.clone(),
                name: name_of(&old.recipients, r),
            });
        }
    }

    // A changed signing key for an existing recipient: the signer registry
    // claims a different key for them than before.
    let registry = |m: &BTreeMap<String, String>| -> BTreeMap<String, String> {
        m.iter().map(|(pk, vk)| (canon(pk), vk.clone())).collect()
    };
    let (was, now) = (registry(&old.signers), registry(&new.signers));
    for (pk, vk) in &now {
        if was.get(pk).is_some_and(|old_vk| old_vk != vk) {
            changes.push(Change::SigningKey {
                key: pk.clone(),
                fingerprint: murk_cli::signing::fingerprint(vk).unwrap_or_default(),
            });
        }
    }

    let signer = |m: &murk_cli::types::Murk| match &m.signature {
        murk_cli::types::SignatureState::Signed { signer, .. } => Some(signer.clone()),
        murk_cli::types::SignatureState::Unsigned => None,
    };
    let (from, to) = (signer(old), signer(new));
    if from.as_deref().map(canon) != to.as_deref().map(canon) {
        changes.push(Change::Signer { from, to });
    }

    if old_vault.policy != new_vault.policy {
        changes.push(Change::Policy);
    }

    for (name, grant) in &new.grants {
        match old.grants.get(name) {
            Some(g) if g == grant => {}
            was => changes.push(Change::Grant {
                op: if was.is_some() {
                    Op::Changed
                } else {
                    Op::Added
                },
                name: name.clone(),
                key: Some(grant.pubkey.clone()),
            }),
        }
    }
    for name in old.grants.keys() {
        if !new.grants.contains_key(name) {
            changes.push(Change::Grant {
                op: Op::Removed,
                name: name.clone(),
                key: None,
            });
        }
    }

    let groups: BTreeSet<&String> = new.groups.keys().chain(old.groups.keys()).collect();
    for group in groups {
        let before = old.groups.get(group).cloned().unwrap_or_default();
        let after = new.groups.get(group).cloned().unwrap_or_default();
        for m in after.iter().filter(|m| !before.contains(m)) {
            changes.push(Change::GroupMember {
                op: Op::Added,
                group: group.clone(),
                key: m.clone(),
            });
        }
        for m in before.iter().filter(|m| !after.contains(m)) {
            changes.push(Change::GroupMember {
                op: Op::Removed,
                group: group.clone(),
                key: m.clone(),
            });
        }
    }
    changes
}
