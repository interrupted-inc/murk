// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use murk_cli::{SecretTier, is_valid_key_name, types, vault};
use std::fs;
use std::path::Path;
use std::process;

/// Generate `length` random bytes and encode them as a fresh secret value,
/// either lowercase hex or URL-safe base64.
///
/// Both the raw entropy (`Zeroizing<Vec<u8>>`) and the encoded string are held
/// in [`zeroize::Zeroizing`] so the newly minted secret is wiped from memory on
/// drop instead of lingering on the heap.
pub(crate) fn random_secret(length: usize, hex: bool) -> zeroize::Zeroizing<String> {
    use base64::Engine;

    let bytes: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new((0..length).map(|_| rand::random::<u8>()).collect());

    let value = if hex {
        let mut s = String::with_capacity(length * 2);
        for b in bytes.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice())
    };

    zeroize::Zeroizing::new(value)
}

/// Map `--group`/`--scoped` onto a tier (see [`SecretTier::parse`] for the
/// reserved names); `--scoped` is a deprecated alias for `--group me`. Both
/// flags at once is a usage error.
pub(crate) fn resolve_secret_tier(group: Option<&str>, scoped: bool) -> SecretTier {
    if let Some(g) = group {
        if scoped {
            die(
                &format_args!("pass either --group or --scoped, not both"),
                1,
            );
        }
        SecretTier::parse(g)
    } else if scoped {
        eprintln!(
            "{} --scoped is deprecated; use --group me",
            "warn".yellow().bold()
        );
        SecretTier::Me
    } else {
        SecretTier::Everyone
    }
}

/// Read a key's value for the given tier from the working state.
pub(crate) fn tier_get(
    current: &murk_cli::types::Murk,
    tier: &SecretTier,
    pubkey: &str,
    key: &str,
) -> Option<zeroize::Zeroizing<String>> {
    match tier {
        SecretTier::Everyone => current.values.get(key).cloned(),
        SecretTier::Me => current
            .private
            .get(key)
            .and_then(|m| m.get(pubkey))
            .cloned(),
        SecretTier::Group(name) => current.grouped.get(key).and_then(|m| m.get(name)).cloned(),
    }
}

/// Set a key's value for the given tier in the working state.
pub(crate) fn tier_set(
    current: &mut murk_cli::types::Murk,
    tier: &SecretTier,
    pubkey: &str,
    key: &str,
    value: zeroize::Zeroizing<String>,
) {
    match tier {
        SecretTier::Everyone => {
            // everyone is the base tier — drop any group assignment so the
            // shared value isn't shadowed by stale grouped ciphertext.
            current.grouped.remove(key);
            current.values.insert(key.to_string(), value);
        }
        SecretTier::Me => {
            // me is an override; leave the base tier untouched.
            current
                .private
                .entry(key.to_string())
                .or_default()
                .insert(pubkey.to_string(), value);
        }
        SecretTier::Group(name) => {
            // the named group becomes the sole base tier.
            current.values.remove(key);
            let entry = current.grouped.entry(key.to_string()).or_default();
            entry.clear();
            entry.insert(name.to_string(), value);
        }
    }
}

/// List all (key, value) pairs visible at the given tier, sorted by key.
pub(crate) fn tier_list(
    current: &murk_cli::types::Murk,
    tier: &SecretTier,
    pubkey: &str,
) -> Vec<(String, zeroize::Zeroizing<String>)> {
    let mut entries: Vec<(String, zeroize::Zeroizing<String>)> = match tier {
        SecretTier::Everyone => current
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        SecretTier::Me => current
            .private
            .iter()
            .filter_map(|(k, m)| m.get(pubkey).map(|v| (k.clone(), v.clone())))
            .collect(),
        SecretTier::Group(name) => current
            .grouped
            .iter()
            .filter_map(|(k, m)| m.get(name).map(|v| (k.clone(), v.clone())))
            .collect(),
    };
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// Warn when a key is named like a loader/shell/tool variable: `export` and
/// `exec` will refuse to set it without `--allow-reserved`.
pub(crate) fn warn_if_reserved(key: &str) {
    if murk_cli::is_reserved_env_name(key) {
        eprintln!(
            "{} {} is a reserved environment name (it changes how programs, shells or murk run) — `murk export` and `murk exec` will refuse it unless you pass --allow-reserved",
            "warn".yellow().bold(),
            key.bold()
        );
    }
}

pub(crate) fn cmd_add(
    key: &str,
    value: &str,
    desc: Option<&str>,
    example: Option<&str>,
    group: Option<&str>,
    scoped: bool,
    tags: &[String],
    vault_path: &str,
) {
    if !is_valid_key_name(key) {
        die(
            &format_args!(
                "invalid key name: {}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]",
                key.bold()
            ),
            1,
        );
    }
    warn_if_reserved(key);

    let tier = resolve_secret_tier(group, scoped);

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let (needs_desc_hint, label) = match &tier {
        SecretTier::Group(name) => {
            let pubkey = try_or_die(identity.pubkey_string());
            let needs = try_or_die(murk_cli::add_grouped_secret(
                &mut vault,
                &mut current,
                key,
                value,
                desc,
                example,
                name,
                tags,
                &pubkey,
            ));
            (needs, format!(" (group {name})"))
        }
        tier => {
            let scoped = matches!(tier, SecretTier::Me);
            let pubkey = scoped.then(|| try_or_die(identity.pubkey_string()));
            let needs = murk_cli::add_secret(
                &mut vault,
                &mut current,
                key,
                value,
                desc,
                example,
                scoped,
                tags,
                pubkey.as_deref(),
            );
            (
                needs,
                if scoped {
                    " (me)".to_string()
                } else {
                    String::new()
                },
            )
        }
    };

    eprintln!("{} added {}{label}", "◆".magenta(), key.bold());

    if needs_desc_hint {
        eprintln!(
            "  {}",
            format!("run: murk describe {key} \"your description\"").dimmed()
        );
    }

    save_vault(vault_path, &mut vault, &original, &current);
}

pub(crate) fn cmd_import(
    file: &str,
    force: bool,
    group: Option<&str>,
    example: Option<&str>,
    vault_path: &str,
) {
    let tier = resolve_secret_tier(group, false);
    // Wrap the raw file contents in Zeroizing so the plaintext is wiped
    // from memory as soon as parsing completes, not when the function returns.
    let contents = zeroize::Zeroizing::new(
        fs::read_to_string(file)
            .unwrap_or_else(|e| die(&format_args!("cannot read {file}: {e}"), 1)),
    );

    // Warn about MURK_* keys that will be skipped during import.
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim();
            if key.starts_with("MURK_") {
                eprintln!(
                    "{} skipping {}: murk variables cannot be imported",
                    "⚠".yellow(),
                    key.bold()
                );
            }
        }
    }

    let all_pairs = murk_cli::parse_env(&contents);

    // Filter out keys that aren't valid shell identifiers. Values stay
    // wrapped in Zeroizing end-to-end.
    let mut pairs: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
    for (key, value) in &all_pairs {
        if is_valid_key_name(key) {
            warn_if_reserved(key);
            pairs.push((key.clone(), value.clone()));
        } else {
            eprintln!("{} skipping invalid key name: {}", "⚠".yellow(), key.bold());
        }
    }

    if pairs.is_empty() {
        eprintln!("{}", format!("no secrets found in {file}").dimmed());
        return;
    }

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    // Check for collisions with existing secrets (any tier).
    if !force {
        let collisions: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| {
                current.values.contains_key(k)
                    || current.grouped.contains_key(k)
                    || current.private.contains_key(k)
            })
            .map(|(k, _)| k.as_str())
            .collect();
        if !collisions.is_empty() {
            for key in &collisions {
                eprintln!("{} {} already exists", "warn".yellow().bold(), key.bold());
            }
            die(
                &format_args!(
                    "{} existing secret{} would be overwritten. Use --force to overwrite",
                    collisions.len(),
                    if collisions.len() == 1 { "" } else { "s" }
                ),
                1,
            );
        }
    }

    let imported: Vec<String> = match &tier {
        SecretTier::Everyone => murk_cli::import_secrets(&mut vault, &mut current, &pairs, example),
        SecretTier::Me => {
            let pubkey = try_or_die(identity.pubkey_string());
            for (key, value) in &pairs {
                murk_cli::add_secret(
                    &mut vault,
                    &mut current,
                    key,
                    value,
                    None,
                    example,
                    true,
                    &[],
                    Some(&pubkey),
                );
            }
            pairs.iter().map(|(k, _)| k.clone()).collect()
        }
        SecretTier::Group(name) => {
            let pubkey = try_or_die(identity.pubkey_string());
            for (key, value) in &pairs {
                try_or_die(murk_cli::add_grouped_secret(
                    &mut vault,
                    &mut current,
                    key,
                    value,
                    None,
                    example,
                    name,
                    &[],
                    &pubkey,
                ));
            }
            pairs.iter().map(|(k, _)| k.clone()).collect()
        }
    };

    for key in &imported {
        eprintln!("  {} {}", "◆".magenta(), key.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);
    let count = imported.len();
    let label = match &tier {
        SecretTier::Group(name) => format!(" into group {name}"),
        SecretTier::Me => " (me)".to_string(),
        SecretTier::Everyone => String::new(),
    };
    eprintln!(
        "{} imported {count} secret{}{label}",
        "◆".magenta(),
        if count == 1 { "" } else { "s" }
    );
}

pub(crate) fn cmd_generate(
    key: &str,
    length: usize,
    hex: bool,
    desc: Option<&str>,
    example: Option<&str>,
    group: Option<&str>,
    tags: &[String],
    vault_path: &str,
) {
    if !is_valid_key_name(key) {
        die(
            &format_args!(
                "invalid key name: {}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]",
                key.bold()
            ),
            1,
        );
    }
    warn_if_reserved(key);

    let tier = resolve_secret_tier(group, false);
    let value = random_secret(length, hex);

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let label = match &tier {
        SecretTier::Group(name) => {
            let pubkey = try_or_die(identity.pubkey_string());
            try_or_die(murk_cli::add_grouped_secret(
                &mut vault,
                &mut current,
                key,
                &value,
                desc,
                example,
                name,
                tags,
                &pubkey,
            ));
            format!(" (group {name})")
        }
        tier => {
            let scoped = matches!(tier, SecretTier::Me);
            let pubkey = scoped.then(|| try_or_die(identity.pubkey_string()));
            murk_cli::add_secret(
                &mut vault,
                &mut current,
                key,
                &value,
                desc,
                example,
                scoped,
                tags,
                pubkey.as_deref(),
            );
            if scoped {
                " (me)".to_string()
            } else {
                String::new()
            }
        }
    };

    eprintln!("{} generated {}{label}", "◆".magenta(), key.bold());

    save_vault(vault_path, &mut vault, &original, &current);
}

pub(crate) fn cmd_rotate(
    key: Option<&str>,
    all: bool,
    generate: bool,
    length: usize,
    hex: bool,
    values_from: Option<&str>,
    vault_path: &str,
) {
    if key.is_none() && !all {
        die(&"specify a key name or use --all", 1);
    }
    if key.is_some() && all {
        die(&"cannot specify both a key name and --all", 1);
    }
    if all && generate {
        die(
            &"--generate cannot be used with --all — external secrets need manual rotation",
            1,
        );
    }
    let source = if generate {
        ValueSource::Generate { length, hex }
    } else if let Some(path) = values_from {
        ValueSource::Named(read_values_from(path))
    } else {
        ValueSource::Prompt
    };

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let pubkey = try_or_die(identity.pubkey_string());
    let original = murk.clone();
    let mut current = murk;

    let keys_to_rotate: Vec<String> = if all {
        vault.secrets.keys().cloned().collect()
    } else {
        let k = key.unwrap();
        if !vault.secrets.contains_key(k) {
            die(&format_args!("key {} not found in vault", k.bold()), 1);
        }
        vec![k.to_string()]
    };

    // Plan every key before reading any value, so a refusal never leaves input
    // half-consumed or the vault half-rotated.
    let plans: Vec<KeyPlan> = keys_to_rotate
        .into_iter()
        .map(|k| {
            let tiers = murk_cli::key_tiers(&vault, &current, &k, &pubkey);
            match rotation_targets(&tiers) {
                Ok(targets) => {
                    let note = (tiers.own_override && !targets.contains(&SecretTier::Me)).then(
                        || format!("your personal override of {k} is unchanged — `murk add {k} --group me` replaces it"),
                    );
                    KeyPlan {
                        key: k,
                        targets,
                        skipped: Vec::new(),
                        note,
                    }
                }
                Err(msg) => KeyPlan {
                    key: k,
                    targets: Vec::new(),
                    skipped: vec![msg],
                    note: None,
                },
            }
        })
        .collect();

    if !all && let Some(reason) = plans[0].skipped.first() {
        die(
            &format_args!("cannot rotate {}: {reason}", plans[0].key.bold()),
            1,
        );
    }
    check_batch(&vault, &plans, &source, None);

    if plans.is_empty() {
        eprintln!("{}", "no secrets to rotate".dimmed());
        return;
    }

    let outcome = run_rotation(&mut vault, &mut current, &pubkey, &plans, &source);
    if outcome.rotated == 0 {
        return;
    }
    save_vault(vault_path, &mut vault, &original, &current);
    outcome.report();

    if outcome.rotated > 1 {
        eprintln!();
        eprintln!(
            "{} rotated {} secrets",
            "✓".green(),
            outcome.rotated.to_string().bold()
        );
    }
}

/// The tiers `rotate` replaces for a key: its base value, wherever it lives (the
/// shared value or the groups the operator belongs to). A personal override is
/// a deliberate per-recipient deviation, so it is rotated only when it is the
/// key's sole value the operator holds. Errors (with the reason) when the key
/// can't be rotated without leaving a stale value or moving it to a wider tier.
fn rotation_targets(tiers: &murk_cli::KeyTiers) -> Result<Vec<SecretTier>, String> {
    if let Some(group) = tiers.foreign_groups.first() {
        return Err(format!(
            "it is held by group {group}, which you are not a member of — a member must rotate it"
        ));
    }
    let mut targets = Vec::new();
    if tiers.shared {
        targets.push(SecretTier::Everyone);
    }
    targets.extend(tiers.groups.iter().cloned().map(SecretTier::Group));
    if targets.is_empty() {
        if !tiers.own_override {
            return Err(
                "it holds only other recipients' personal overrides, which only they can rotate"
                    .to_string(),
            );
        }
        targets.push(SecretTier::Me);
    }
    Ok(targets)
}

/// List keys needing rotation — the same signals doctor reports, but scoped to
/// rotation and machine-readable. Reads only the plaintext schema, so it works
/// without a key. JSON mode always exits 0 (empty array when clean); human mode
/// exits 1 when anything needs rotating, so it can gate scripts.
pub(crate) fn cmd_rotate_list(json: bool, vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let issues = murk_cli::rotation_health(&vault, chrono::Utc::now());

    if json {
        println!("{}", serde_json::to_string_pretty(&issues).unwrap());
        return;
    }

    if issues.is_empty() {
        eprintln!("{} no keys need rotation", "ok".green().bold());
        return;
    }

    let findings: Vec<Finding> = issues.iter().map(rotation_finding).collect();
    report_findings(&findings, "rotation");
}

pub(crate) fn cmd_rm(key: &str, vault_path: &str) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let pubkey = try_or_die(identity.pubkey_string());
    let original = murk.clone();
    let mut current = murk;

    // Removing a key drops only what the operator can read; anything else
    // would stay on disk while `ls` stops listing it. Refuse instead.
    try_or_die(murk_cli::require_group_access(
        &vault, &current, key, &pubkey,
    ));
    let tiers = murk_cli::key_tiers(&vault, &current, key, &pubkey);
    let holds_unreadable = vault
        .secrets
        .get(key)
        .is_some_and(|e| !e.private.is_empty());
    if holds_unreadable && !tiers.shared && tiers.groups.is_empty() && !tiers.own_override {
        die(
            &format_args!(
                "{key} holds only other recipients' personal overrides, which only they can remove"
            ),
            1,
        );
    }

    murk_cli::remove_secret(&mut vault, &mut current, key);

    save_vault(vault_path, &mut vault, &original, &current);
    eprintln!("{} removed {}", "◆".magenta(), key.bold());
}

/// In strict mode, refuse to write plaintext secret values to a regular file on
/// stdout (e.g. `murk export > .env`, `murk get KEY > token.txt`). Pipes and
/// terminals are allowed — the rule targets accidental disk persistence, the
/// same threat the `edit` RAM-tmpdir guard addresses. `hint` is a one-line
/// suggestion of a safe alternative. Returns having exited the process on a
/// refusal.
pub(crate) fn strict_guard_plaintext_stdout(hint: &str) {
    if murk_cli::hardening::strict_mode() && murk_cli::hardening::stdout_is_regular_file() {
        eprintln!(
            "{} MURK_STRICT refuses writing plaintext secrets to a file",
            "error".red().bold()
        );
        eprintln!("  {}", hint.dimmed());
        process::exit(1);
    }
}

pub(crate) fn cmd_get(key: &str, vault_path: &str) {
    strict_guard_plaintext_stdout("capture in a variable instead, e.g. TOKEN=$(murk get KEY)");
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    // An agent grant is always held to the policy; an operator only under
    // self-scope. Fails closed before any value is printed.
    try_or_die(murk_cli::enforce_agent_policy(
        &vault,
        &murk,
        &pubkey,
        &[key.to_string()],
    ));

    if let Some(value) = murk_cli::get_secret(&murk, key, &pubkey) {
        println!("{value}");
        return;
    }

    // A granted agent sees every key *name* (the schema is plaintext header) but
    // can only decrypt its scope. Saying "key not found" for a key whose name it
    // can read is misleading — name the real reason the read failed closed.
    let out_of_scope = murk
        .grants
        .values()
        .any(|g| g.pubkey == pubkey && !g.scope.iter().any(|k| k == key));
    if out_of_scope && vault.schema.contains_key(key) {
        die(
            &format_args!("{} is outside this grant's scope", key.bold()),
            1,
        );
    }

    die(
        &format_args!(
            "key not found: {}. Run {} to see available keys",
            key.bold(),
            "murk ls".bold()
        ),
        1,
    );
}

pub(crate) fn cmd_ls(tags: &[String], json: bool, vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let keys = murk_cli::list_keys(&vault, tags);
    if json {
        println!("{}", serde_json::to_string_pretty(&keys).unwrap());
    } else {
        for key in keys {
            println!("{key}");
        }
    }
}

pub(crate) fn cmd_describe(
    key: &str,
    description: &str,
    example: Option<&str>,
    tags: &[String],
    rotate_every: Option<&str>,
    expires: Option<&str>,
    vault_path: &str,
) {
    let rotation_patch = parse_rotate_every(rotate_every).unwrap_or_else(|e| die(&e, 2));
    let expires_patch = parse_expires(expires).unwrap_or_else(|e| die(&e, 2));

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let pubkey = try_or_die(identity.pubkey_string());
    try_or_die(murk_cli::require_group_access(&vault, &murk, key, &pubkey));

    murk_cli::describe_key(
        &mut vault,
        key,
        description,
        example,
        tags,
        rotation_patch,
        expires_patch.as_ref().map(|inner| inner.as_deref()),
    );

    // Describe only changes schema (plaintext) — but we still need to write the vault.
    // Re-save with no value changes so ciphertext is preserved.
    save_vault(vault_path, &mut vault, &original, &murk);
}

/// Parse `--rotate-every` into a tri-state schema patch: `None` leaves the
/// interval untouched, `Some(None)` clears it, `Some(Some(n))` sets N days.
pub(crate) fn parse_rotate_every(input: Option<&str>) -> Result<Option<Option<u32>>, String> {
    let Some(raw) = input else { return Ok(None) };
    let s = raw.trim();
    if s.eq_ignore_ascii_case("never") || s.eq_ignore_ascii_case("none") {
        return Ok(Some(None));
    }
    let digits = s.strip_suffix(['d', 'D']).unwrap_or(s);
    match digits.parse::<u32>() {
        Ok(0) => Ok(Some(None)),
        Ok(n) => Ok(Some(Some(n))),
        Err(_) => Err(format!(
            "invalid --rotate-every {raw:?} (use days like 90 or 90d, or never)"
        )),
    }
}

/// Parse `--expires` into a tri-state patch. Accepts a full RFC-3339 timestamp
/// or a bare `YYYY-MM-DD` date (stored as end-of-day UTC); `never` clears it.
pub(crate) fn parse_expires(input: Option<&str>) -> Result<Option<Option<String>>, String> {
    let Some(raw) = input else { return Ok(None) };
    let s = raw.trim();
    if s.eq_ignore_ascii_case("never") || s.eq_ignore_ascii_case("none") {
        return Ok(Some(None));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        let norm = dt
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        return Ok(Some(Some(norm)));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(Some(Some(format!("{}T23:59:59Z", d.format("%Y-%m-%d")))));
    }
    Err(format!(
        "invalid --expires {raw:?} (use a date like 2026-09-01, or never)"
    ))
}

pub(crate) fn cmd_export(tags: &[String], json: bool, allow_reserved: bool, vault_path: &str) {
    strict_guard_plaintext_stdout("pipe to a process instead, e.g. eval \"$(murk export)\"");
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    if json {
        let mut raw = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);
        apply_agent_policy(
            &mut raw,
            &vault,
            murk_cli::agent_policy_applies(&murk, &pubkey),
        );
        raw.retain(|k, _| {
            let ok = is_valid_key_name(k);
            if !ok {
                eprintln!("{} skipping unsafe key name: {}", "⚠".yellow(), k.bold());
            }
            ok
        });
        // JSON output is routinely turned into an environment too.
        refuse_reserved(raw.keys(), allow_reserved);
        // serde_json copies into its own owned String, so zeroization ends here.
        // Controlled boundary: JSON export intentionally writes plaintext to
        // stdout (murk-lints secret_uncontrolled_escape).
        #[cfg_attr(dylint_lib = "murk_lints", allow(secret_uncontrolled_escape))]
        let map: serde_json::Map<String, serde_json::Value> = raw
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.to_string())))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
    } else {
        let mut exports = murk_cli::export_secrets(&vault, &murk, &pubkey, tags);
        apply_agent_policy(
            &mut exports,
            &vault,
            murk_cli::agent_policy_applies(&murk, &pubkey),
        );
        exports.retain(|k, _| {
            let ok = is_valid_key_name(k);
            if !ok {
                eprintln!("{} skipping unsafe key name: {}", "⚠".yellow(), k.bold());
            }
            ok
        });
        // Checked before anything is printed: `eval "$(murk export)"` must not
        // half-apply.
        refuse_reserved(exports.keys(), allow_reserved);
        for (k, escaped) in &exports {
            println!("export {k}='{}'", escaped.as_str());
        }
    }
}

/// For an agent grant or under self-scope (`applies`), drop keys the vault's
/// agent policy forbids from an export map, warning (not silently) about what
/// was withheld. A no-op without a policy or when the policy doesn't apply.
pub(crate) fn apply_agent_policy(
    map: &mut std::collections::BTreeMap<String, zeroize::Zeroizing<String>>,
    vault: &types::Vault,
    applies: bool,
) {
    if !(applies && vault.policy.is_some()) {
        return;
    }
    let withheld: Vec<String> = map
        .keys()
        .filter(|k| !murk_cli::is_agent_key_allowed(vault, k))
        .cloned()
        .collect();
    if withheld.is_empty() {
        return;
    }
    map.retain(|k, _| murk_cli::is_agent_key_allowed(vault, k));
    eprintln!(
        "{} agent policy: withholding {} key(s) not allowed by policy: {}",
        "⚠".yellow(),
        withheld.len(),
        withheld.join(", ")
    );
}

pub(crate) fn cmd_edit(key: Option<&str>, scoped: bool, group: Option<&str>, vault_path: &str) {
    let tier = resolve_secret_tier(group, scoped);

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    if murk_cli::hardening::self_scope() && vault.policy.is_some() {
        match key {
            Some(k) => try_or_die(murk_cli::check_agent_keys(&vault, &[k.to_string()])),
            None => die(
                &format_args!(
                    "bulk edit is unavailable under self-scope — edit a specific allowed key"
                ),
                1,
            ),
        }
    }

    if let SecretTier::Group(name) = &tier {
        match current.groups.get(name) {
            None => die(&format_args!("group not found: {name}"), 1),
            Some(members) if !members.contains(&pubkey) => die(
                &format_args!("you must be a member of group \"{name}\" to edit it"),
                1,
            ),
            Some(_) => {}
        }
    }

    let tier_label = match &tier {
        SecretTier::Everyone => String::new(),
        SecretTier::Me => " (me)".to_string(),
        SecretTier::Group(name) => format!(" (group {name})"),
    };

    // Build the edit buffer.
    let (header, entries) = if let Some(k) = key {
        // Single key: just the raw value.
        let value = tier_get(&current, &tier, &pubkey, k).unwrap_or_else(|| {
            die(&format_args!("key {} not found{tier_label}", k.bold()), 1);
        });
        (
            format!(
                "# Editing {k}{tier_label}\n# Save and quit to apply. Empty value or exit non-zero to abort.\n",
            ),
            vec![(k.to_string(), value)] as Vec<(String, zeroize::Zeroizing<String>)>,
        )
    } else {
        // All keys: KEY=VALUE format.
        let entries = tier_list(&current, &tier, &pubkey);
        let scope_note = match &tier {
            SecretTier::Everyone => String::new(),
            SecretTier::Me => "# Editing your personal (me) values.\n".to_string(),
            SecretTier::Group(name) => format!("# Editing group {name} values.\n"),
        };
        let header = format!(
            "# Edit secrets below. Lines starting with # are ignored.\n\
             # Format: KEY=VALUE (one per line).\n\
             # Delete a line to remove that secret. Add KEY=VALUE to create.\n\
             # Save and quit to apply. Exit non-zero to abort.\n{scope_note}\n",
        );
        (header, entries)
    };

    let single_key = key.is_some();
    let buffer: zeroize::Zeroizing<String> = if single_key {
        zeroize::Zeroizing::new(format!("{}{}", header, entries[0].1.as_str()))
    } else {
        let mut buf = header;
        for (k, v) in &entries {
            buf.push_str(&format!("{k}={}\n", v.as_str()));
        }
        zeroize::Zeroizing::new(buf)
    };

    // Prefer XDG_RUNTIME_DIR (typically tmpfs, not written to disk) over /tmp.
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);

    // Strict mode: refuse to write the decrypted secret anywhere but RAM. The
    // best-effort wipe below can't undo a write to a journaled/CoW disk, so when
    // MURK_STRICT is set we fail closed rather than fall back to a disk temp dir.
    if murk_cli::hardening::strict_mode() && !murk_cli::hardening::is_ram_backed(&dir) {
        eprintln!(
            "{} MURK_STRICT is set but {} is not RAM-backed",
            "error".red().bold(),
            dir.display()
        );
        eprintln!(
            "  {}",
            "edit would write the secret to disk — aborting".dimmed()
        );
        eprintln!(
            "  {}",
            "use add/rotate/import (stdin) instead, or point XDG_RUNTIME_DIR at a tmpfs".dimmed()
        );
        std::process::exit(1);
    }

    use super::editor::{EditAbort, edit_in_scratch_file};
    let edited = match edit_in_scratch_file(&dir, &buffer) {
        Ok(text) => text,
        Err(EditAbort::Failed(msg)) => die(&msg, 1),
        #[cfg(unix)]
        Err(EditAbort::Signaled(sig)) => {
            // The editor was killed: die from the same signal, as git does.
            super::signals::raise_default(sig);
            process::exit(128 + sig);
        }
    };

    // Parse and apply changes.
    if single_key {
        let k = key.unwrap();
        // Strip comment header, trim trailing newline.
        let mut new_value: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            edited
                .lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let trimmed_len = new_value.trim_end_matches('\n').len();
        new_value.truncate(trimmed_len);

        if new_value.is_empty() {
            eprintln!("{} empty value — no changes", "◆".magenta());
            return;
        }

        let old_value = tier_get(&current, &tier, &pubkey, k);

        if old_value.as_ref().map(|v| v.as_str()) == Some(new_value.as_str()) {
            eprintln!("{} no changes", "◆".magenta());
            return;
        }

        tier_set(&mut current, &tier, &pubkey, k, new_value);

        save_vault(vault_path, &mut vault, &original, &current);
        eprintln!("{} updated {}{tier_label}", "◆".magenta(), k.bold());
    } else {
        // Multi-key: parse KEY=VALUE lines, diff against original.
        let mut new_entries: std::collections::BTreeMap<String, zeroize::Zeroizing<String>> =
            std::collections::BTreeMap::new();
        for line in edited.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (k, v) = match trimmed.split_once('=') {
                Some((k, v)) => (k.trim(), v),
                None => {
                    eprintln!(
                        "{} skipping malformed line: {}",
                        "⚠".yellow(),
                        trimmed.dimmed()
                    );
                    continue;
                }
            };
            if !is_valid_key_name(k) {
                eprintln!("{} skipping invalid key name: {}", "⚠".yellow(), k.bold());
                continue;
            }
            new_entries.insert(k.to_string(), zeroize::Zeroizing::new(v.to_string()));
        }

        // Compute diff.
        let old_entries: std::collections::BTreeMap<String, zeroize::Zeroizing<String>> =
            entries.into_iter().collect();
        let mut added = 0usize;
        let mut updated = 0usize;
        let mut removed = 0usize;

        // Add or update.
        for (k, v) in &new_entries {
            match old_entries.get(k) {
                Some(old_v) if old_v.as_str() == v.as_str() => {} // Unchanged.
                Some(_) => {
                    tier_set(&mut current, &tier, &pubkey, k, v.clone());
                    updated += 1;
                }
                None => {
                    tier_set(&mut current, &tier, &pubkey, k, v.clone());
                    // Ensure schema entry exists for new keys.
                    vault
                        .schema
                        .entry(k.clone())
                        .or_insert_with(murk_cli::types::SchemaEntry::default);
                    added += 1;
                }
            }
        }

        // Remove deleted keys.
        for k in old_entries.keys() {
            if !new_entries.contains_key(k) {
                match &tier {
                    SecretTier::Everyone => {
                        current.values.remove(k);
                        current.private.remove(k);
                        current.grouped.remove(k);
                        vault.schema.remove(k);
                    }
                    SecretTier::Me => {
                        if let Some(m) = current.private.get_mut(k) {
                            m.remove(&pubkey);
                        }
                    }
                    SecretTier::Group(name) => {
                        if let Some(m) = current.grouped.get_mut(k) {
                            m.remove(name);
                        }
                    }
                }
                removed += 1;
            }
        }

        if added == 0 && updated == 0 && removed == 0 {
            eprintln!("{} no changes", "◆".magenta());
            return;
        }

        save_vault(vault_path, &mut vault, &original, &current);

        let mut parts = vec![];
        if added > 0 {
            parts.push(format!("{added} added"));
        }
        if updated > 0 {
            parts.push(format!("{updated} updated"));
        }
        if removed > 0 {
            parts.push(format!("{removed} removed"));
        }
        eprintln!("{} {}", "◆".magenta(), parts.join(", "));
    }
}

/// Overwrite a file with zeros and remove it.
pub(crate) fn overwrite_and_remove(path: &std::path::Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len() as usize;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let _ = f.write_all(&vec![0u8; len]);
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod describe_flags {
    use super::{parse_expires, parse_rotate_every};

    #[test]
    fn rotate_every_tri_state() {
        // Absent flag leaves the field untouched.
        assert_eq!(parse_rotate_every(None), Ok(None));
        // Days, with or without the `d` suffix.
        assert_eq!(parse_rotate_every(Some("90")), Ok(Some(Some(90))));
        assert_eq!(parse_rotate_every(Some("90d")), Ok(Some(Some(90))));
        // `never` and zero both clear it.
        assert_eq!(parse_rotate_every(Some("never")), Ok(Some(None)));
        assert_eq!(parse_rotate_every(Some("0")), Ok(Some(None)));
        // Garbage is rejected.
        assert!(parse_rotate_every(Some("soon")).is_err());
    }

    #[test]
    fn expires_accepts_date_and_normalizes() {
        // Bare date becomes end-of-day UTC.
        assert_eq!(
            parse_expires(Some("2026-09-01")),
            Ok(Some(Some("2026-09-01T23:59:59Z".into())))
        );
        // Full RFC-3339 is normalized to the stored format.
        assert_eq!(
            parse_expires(Some("2026-09-01T12:00:00Z")),
            Ok(Some(Some("2026-09-01T12:00:00Z".into())))
        );
        // `never` clears; absent leaves untouched.
        assert_eq!(parse_expires(Some("never")), Ok(Some(None)));
        assert_eq!(parse_expires(None), Ok(None));
        // Garbage is rejected.
        assert!(parse_expires(Some("2026-13-99")).is_err());
    }
}
