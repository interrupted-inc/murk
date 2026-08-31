use super::*;
use age::secrecy::ExposeSecret;
use colored::Colorize;
use murk_cli::cli::{GroupCommand, PolicyCommand};
use murk_cli::vault;
use std::io::{self, IsTerminal};
use std::path::Path;

pub(crate) fn is_ssh_rsa(key: &str) -> bool {
    key.starts_with("ssh-rsa ")
}

/// Abort if any of the given keys are ssh-rsa, unless the user passed
/// `--allow-ssh-rsa`. Default-closed because ssh-rsa has known weaknesses
/// (see RUSTSEC-2023-0071) and ed25519 is strictly better for this use case.
pub(crate) fn reject_rsa_keys(keys: &[String], allow: bool) {
    let rsa_count = keys.iter().filter(|k| is_ssh_rsa(k)).count();
    if rsa_count == 0 {
        return;
    }
    if allow {
        eprintln!(
            "{} {} ssh-rsa key{} authorized via --allow-ssh-rsa — ed25519 is strongly recommended (see RUSTSEC-2023-0071)",
            "warn".yellow().bold(),
            rsa_count,
            if rsa_count == 1 { "" } else { "s" }
        );
        return;
    }
    die(
        &format_args!(
            "refusing to authorize {rsa_count} ssh-rsa key{s} — ed25519 is strongly recommended (see RUSTSEC-2023-0071). Pass --allow-ssh-rsa to override.",
            s = if rsa_count == 1 { "" } else { "s" }
        ),
        1,
    );
}

/// Add freshly-authorized pubkeys to `group` (if set). The caller must be a
/// member of the group. Dies on error.
pub(crate) fn add_recipients_to_group(
    current: &mut murk_cli::types::Murk,
    group: Option<&str>,
    pubkeys: &[String],
    operator_pubkey: &str,
) {
    let Some(g) = group else { return };
    for pk in pubkeys {
        try_or_die(murk_cli::add_member(current, g, pk, operator_pubkey));
    }
}

pub(crate) fn cmd_authorize(
    pubkey: &str,
    name: Option<&str>,
    group: Option<&str>,
    force: bool,
    allow_ssh_rsa: bool,
    vault_path: &str,
) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;
    let operator_pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    if let Some(username) = pubkey.strip_prefix("github:") {
        // Fetch all SSH keys from GitHub.
        let all_keys = try_or_die(murk_cli::fetch_keys(username).map_err(|e| e.to_string()));

        // TOFU: check fetched keys against pinned fingerprints. Pin checking
        // runs over the full key set (including ssh-rsa) so rotation of an
        // rsa key is still detected even though we refuse to authorize it.
        let pinned = murk_cli::decrypt_meta(&vault, &identity)
            .and_then(|m| {
                let pins = m.github_pins.get(username)?.clone();
                Some(pins)
            })
            .unwrap_or_default();

        if !force && let Err(msg) = murk_cli::github::check_pins(username, &all_keys, &pinned) {
            die(&msg, 1);
        }

        // Filter ssh-rsa out of the authorize set unless explicitly allowed.
        // We don't abort the whole operation the way we do for a single raw
        // pubkey — GitHub users often have a mix of key types and the common
        // case is "use the ed25519 ones, skip the rsa ones with a warning."
        let rsa_skipped = all_keys.iter().filter(|(_, k)| is_ssh_rsa(k)).count();
        let keys: Vec<_> = if allow_ssh_rsa {
            all_keys.iter().collect()
        } else {
            all_keys.iter().filter(|(_, k)| !is_ssh_rsa(k)).collect()
        };
        if rsa_skipped > 0 && !allow_ssh_rsa {
            eprintln!(
                "{} skipped {} ssh-rsa key{} from {}@github — ed25519 is strongly recommended (see RUSTSEC-2023-0071). Pass --allow-ssh-rsa to include them.",
                "warn".yellow().bold(),
                rsa_skipped,
                if rsa_skipped == 1 { "" } else { "s" },
                username
            );
        }
        if keys.is_empty() {
            die(
                &format_args!(
                    "no authorizable keys for {username}@github — all {total} key{s} were ssh-rsa and --allow-ssh-rsa was not set",
                    total = all_keys.len(),
                    s = if all_keys.len() == 1 { "" } else { "s" }
                ),
                1,
            );
        }

        let display_name = format!("{username}@github");
        let mut added = 0;
        let mut authorized: Vec<String> = Vec::new();
        let mut type_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for (_, key_string) in &keys {
            // Skip keys already in the vault.
            if vault.recipients.contains(key_string) {
                continue;
            }

            try_or_die(murk_cli::authorize_recipient(
                &mut vault,
                &mut current,
                key_string,
                Some(&display_name),
            ));

            let key_type = murk_cli::github::key_type_label(key_string);
            *type_counts.entry(key_type.to_string()).or_default() += 1;
            authorized.push((*key_string).clone());
            added += 1;
        }

        add_recipients_to_group(&mut current, group, &authorized, &operator_pubkey);

        if added == 0 {
            eprintln!(
                "{} all {} SSH keys for {}@github are already authorized",
                "◆".magenta(),
                keys.len(),
                username
            );
            return;
        }

        // Update pinned fingerprints for this GitHub user. Pin the full
        // upstream set, not just the filtered one, so future TOFU comparisons
        // still detect when an ssh-rsa key rotates even though we don't
        // authorize it.
        let new_pins: Vec<String> = all_keys
            .iter()
            .map(|(_, k)| murk_cli::github::fingerprint(k))
            .collect();
        current.github_pins.insert(username.to_string(), new_pins);

        save_vault(vault_path, &mut vault, &original, &current);

        // Build summary like "2 ssh-ed25519, 1 ssh-rsa".
        let mut parts: Vec<String> = type_counts
            .iter()
            .map(|(t, n)| format!("{n} {t}"))
            .collect();
        parts.sort();
        let summary = parts.join(", ");

        eprintln!(
            "{} authorized {} ({} key{})",
            "◆".magenta(),
            display_name.bold(),
            summary,
            if added == 1 { "" } else { "s" }
        );
    } else if let Some(path_hint) = pubkey.strip_prefix("ssh:") {
        // Read SSH public key from a file.
        let path = if path_hint.is_empty() {
            // Default: ~/.ssh/id_ed25519.pub
            let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));
            std::path::PathBuf::from(home).join(".ssh/id_ed25519.pub")
        } else {
            if path_hint.starts_with('~') {
                let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));
                std::path::PathBuf::from(path_hint.replacen('~', &home, 1))
            } else {
                std::path::PathBuf::from(path_hint)
            }
        };

        let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            die(&format_args!("cannot read {}: {e}", path.display()), 1);
        });
        // Take first non-empty line (pub files may have trailing newlines).
        let key_line = contents
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_else(|| die(&format_args!("empty key file: {}", path.display()), 1));
        // Strip the comment field if present (ssh-type base64 comment).
        let key_string = {
            let parts: Vec<&str> = key_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                format!("{} {}", parts[0], parts[1])
            } else {
                key_line.to_string()
            }
        };

        reject_rsa_keys(std::slice::from_ref(&key_string), allow_ssh_rsa);
        try_or_die(murk_cli::authorize_recipient(
            &mut vault,
            &mut current,
            &key_string,
            name,
        ));

        add_recipients_to_group(
            &mut current,
            group,
            std::slice::from_ref(&key_string),
            &operator_pubkey,
        );

        save_vault(vault_path, &mut vault, &original, &current);

        let display = name
            .map(|n| n.to_string())
            .unwrap_or_else(|| path.display().to_string());
        eprintln!("{} authorized {}", "◆".magenta(), display.bold());
    } else {
        // Raw pubkey (age or SSH).
        reject_rsa_keys(&[pubkey.to_string()], allow_ssh_rsa);
        try_or_die(murk_cli::authorize_recipient(
            &mut vault,
            &mut current,
            pubkey,
            name,
        ));

        add_recipients_to_group(
            &mut current,
            group,
            std::slice::from_ref(&pubkey.to_string()),
            &operator_pubkey,
        );

        save_vault(vault_path, &mut vault, &original, &current);

        let display = name.unwrap_or(pubkey);
        eprintln!("{} authorized {}", "◆".magenta(), display.bold());
    }
}

pub(crate) fn cmd_revoke(recipient: &str, rotate: bool, vault_path: &str) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let result = try_or_die(murk_cli::revoke_recipient(
        &mut vault,
        &mut current,
        recipient,
    ));

    // Record that the exposed keys now owe a rotation before persisting, so the
    // obligation survives the user declining the prompt below (or the process
    // dying). An in-session rotation clears the marker again via `add_secret`.
    murk_cli::mark_revoked(&mut vault, &result.exposed_keys, chrono::Utc::now());

    // Persist the removal first so the recipient is durably revoked even if the
    // user aborts the rotation prompts below.
    save_vault(vault_path, &mut vault, &original, &current);

    let display = result.display_name.as_deref().unwrap_or(recipient);
    eprintln!(
        "{} removed {} from recipients",
        "◆".magenta(),
        display.bold(),
    );

    if !result.exposed_keys.is_empty() {
        let n = result.exposed_keys.len();
        let plural = if n == 1 { "" } else { "s" };
        eprintln!();
        eprintln!(
            "{} {display} had access to {n} secret{plural} — rotate them:",
            "⚠".yellow(),
        );
        for key in &result.exposed_keys {
            eprintln!("  {} {}", "▸".dimmed(), key.bold());
        }
        eprintln!();

        // Rotate now if --rotate was passed, or if the user opts in at the prompt.
        let do_rotate = rotate
            || (io::stdin().is_terminal()
                && confirm(&format!("rotate {n} exposed secret{plural} now?")));

        if do_rotate {
            rotate_exposed(
                vault_path,
                &mut vault,
                &current,
                &result.exposed_keys,
                &identity,
            );
        } else {
            eprintln!(
                "  {}",
                "run `murk rotate --all` to rotate each secret".dimmed()
            );
        }
    }
    eprintln!();
    eprintln!(
        "  {}",
        "this recipient can still decrypt previous versions from git history".dimmed()
    );
}

pub(crate) fn cmd_group(sub: GroupCommand) {
    match sub {
        GroupCommand::Create { name, vault } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (mut vault, murk, identity, _lock) = load_vault_locked(&vault_path);
            let original = murk.clone();
            let mut current = murk;
            let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

            try_or_die(murk_cli::create_group(&mut current, &name, &pubkey));
            save_vault(&vault_path, &mut vault, &original, &current);
            eprintln!("{} created group {}", "◆".magenta(), name.bold());
        }

        GroupCommand::Ls { json, vault } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (_vault, murk, identity) = load_vault(&vault_path);
            let self_pubkey = identity.pubkey_string().ok();

            if json {
                let map: serde_json::Map<String, serde_json::Value> = murk
                    .groups
                    .iter()
                    .map(|(name, members)| {
                        let arr: Vec<serde_json::Value> = members
                            .iter()
                            .map(|pk| serde_json::Value::String(pk.clone()))
                            .collect();
                        (name.clone(), serde_json::Value::Array(arr))
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&map).unwrap());
                return;
            }

            if murk.groups.is_empty() {
                eprintln!(
                    "{}",
                    "no groups — create one with `murk group create`".dimmed()
                );
                return;
            }

            for (name, members) in &murk.groups {
                eprintln!("{} {}", "◆".magenta(), name.bold());
                for pk in members {
                    let label = murk
                        .recipients
                        .get(pk)
                        .filter(|n| !n.is_empty())
                        .cloned()
                        .unwrap_or_else(|| murk_cli::truncate_pubkey(pk));
                    let marker = if Some(pk) == self_pubkey.as_ref() {
                        "*"
                    } else {
                        " "
                    };
                    eprintln!("  {marker} {}", label.green().bold());
                }
            }
        }

        GroupCommand::Add {
            name,
            member,
            vault,
        } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (mut vault, murk, identity, _lock) = load_vault_locked(&vault_path);
            let original = murk.clone();
            let mut current = murk;
            let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

            let member_pk = try_or_die(murk_cli::resolve_member(&vault, &current, &member));
            let added = try_or_die(murk_cli::add_member(
                &mut current,
                &name,
                &member_pk,
                &pubkey,
            ));
            if !added {
                eprintln!(
                    "{} {} is already in group {}",
                    "◆".magenta(),
                    member.bold(),
                    name.bold()
                );
                return;
            }
            save_vault(&vault_path, &mut vault, &original, &current);
            eprintln!(
                "{} added {} to group {}",
                "◆".magenta(),
                member.bold(),
                name.bold()
            );
        }

        GroupCommand::Rm {
            name,
            member,
            vault,
        } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (mut vault, murk, identity, _lock) = load_vault_locked(&vault_path);
            let original = murk.clone();
            let mut current = murk;
            let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

            match member {
                Some(member) => {
                    let member_pk = try_or_die(murk_cli::resolve_member(&vault, &current, &member));
                    let removed = try_or_die(murk_cli::remove_member(
                        &mut current,
                        &name,
                        &member_pk,
                        &pubkey,
                    ));
                    if !removed {
                        eprintln!(
                            "{} {} is not in group {}",
                            "◆".magenta(),
                            member.bold(),
                            name.bold()
                        );
                        return;
                    }
                    save_vault(&vault_path, &mut vault, &original, &current);
                    eprintln!(
                        "{} removed {} from group {}",
                        "◆".magenta(),
                        member.bold(),
                        name.bold()
                    );
                }
                None => {
                    try_or_die(murk_cli::delete_group(&vault, &mut current, &name));
                    save_vault(&vault_path, &mut vault, &original, &current);
                    eprintln!("{} deleted group {}", "◆".magenta(), name.bold());
                }
            }
        }
    }
}

pub(crate) fn cmd_policy(sub: PolicyCommand) {
    match sub {
        PolicyCommand::Show { json, vault } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            // Policy lives in the plaintext header — no key needed to read it.
            let v = murk_cli::vault::read(Path::new(&vault_path)).unwrap_or_else(|e| die(&e, 1));
            let tags = v.policy.as_ref().map(|p| p.agent_allow_tags.clone());
            if json {
                let out = serde_json::json!({ "agent_allow_tags": tags });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                return;
            }
            match tags {
                None => eprintln!(
                    "{} no agent policy — agent mode is unrestricted",
                    "◆".magenta()
                ),
                Some(tags) if tags.is_empty() => eprintln!(
                    "{} agents are locked out (allow-list is empty)",
                    "⚠".yellow()
                ),
                Some(tags) => {
                    eprintln!("{} agents may only receive secrets tagged:", "◆".magenta());
                    eprintln!("  {}", tags.join(", ").bold());
                }
            }
        }
        PolicyCommand::Set { allow_tag, vault } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (mut vault, murk, _identity, _lock) = load_vault_locked(&vault_path);
            let original = murk.clone();
            let current = murk;
            vault.policy = Some(murk_cli::types::Policy {
                agent_allow_tags: allow_tag.clone(),
            });
            save_vault(&vault_path, &mut vault, &original, &current);
            eprintln!(
                "{} agent allow-list set to {}",
                "◆".magenta(),
                allow_tag.join(", ").bold()
            );
        }
        PolicyCommand::Clear { vault } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            let (mut vault, murk, _identity, _lock) = load_vault_locked(&vault_path);
            if vault.policy.is_none() {
                eprintln!("{} no policy to clear", "◆".magenta());
                return;
            }
            let original = murk.clone();
            let current = murk;
            vault.policy = None;
            save_vault(&vault_path, &mut vault, &original, &current);
            eprintln!(
                "{} policy cleared — agent mode is unrestricted",
                "◆".magenta()
            );
        }
    }
}

/// Truncate a pubkey for display: first 8 chars + "…" + last 4 chars.
pub(crate) fn cmd_recipients(json: bool, vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let secret_key = murk_cli::resolve_key_for_vault(vault_path)
        .ok()
        .map(|s| s.expose_secret().to_string());
    let entries = murk_cli::list_recipients(&vault, secret_key.as_deref());

    if json {
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "pubkey": e.pubkey,
                    "name": e.display_name,
                    "is_self": e.is_self,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    let has_names = entries.iter().any(|e| e.display_name.is_some());

    if !has_names {
        // Locked: plain pubkeys to stdout for piping.
        for entry in &entries {
            println!("{}", entry.pubkey);
        }
        return;
    }

    // Group entries by display name so multi-key recipients (e.g. github
    // users with several SSH keys) are shown as a single consolidated line.
    let mut groups: Vec<(Option<&str>, Vec<&murk_cli::RecipientEntry>)> = Vec::new();
    for entry in &entries {
        let name = entry.display_name.as_deref();
        if let Some(group) = groups
            .iter_mut()
            .find(|(n, _)| *n == name && name.is_some())
        {
            group.1.push(entry);
        } else {
            groups.push((name, vec![entry]));
        }
    }

    // Compute name column width for alignment.
    let name_width = groups
        .iter()
        .map(|(name, _)| name.map_or(0, |n| n.len()))
        .max()
        .unwrap_or(0);

    for (name, group) in &groups {
        let is_self = group.iter().any(|e| e.is_self);
        let marker = if is_self { "◆" } else { " " };
        let label = name.unwrap_or("");
        let label_padded = format!("{label:<name_width$}");

        let key_type = murk_cli::key_type_label(&group[0].pubkey);
        let key_info = if group.len() == 1 {
            murk_cli::truncate_pubkey(&group[0].pubkey)
        } else {
            format!("({} keys)", group.len())
        };

        if is_self {
            println!(
                "{} {}  {}",
                marker.magenta(),
                label_padded.magenta().bold(),
                format!("{key_info}  {key_type}").dimmed()
            );
        } else {
            println!(
                "{}",
                format!("  {label_padded}  {key_info}  {key_type}").dimmed()
            );
        }
    }
}
