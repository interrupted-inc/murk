// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared plumbing for the command handlers: process-exit helpers, TTY prompts,
//! vault load/save wrappers, and the `Finding` reporting used by check commands.

use colored::Colorize;
use murk_cli::{MurkIdentity, types};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process;

pub(crate) mod completion;
pub(crate) mod editor;
pub(crate) mod exec;
pub(crate) mod git;
pub(crate) mod grants;
pub(crate) mod info;
pub(crate) mod init;
pub(crate) mod recipients;
pub(crate) mod recover;
pub(crate) mod scan;
pub(crate) mod secrets;
#[cfg(unix)]
pub(crate) mod signals;
pub(crate) mod supervise;
pub(crate) mod trust;
pub(crate) mod verify;

// `murk agent exec` reuses the plain `exec` handler.
pub(crate) use exec::cmd_exec;

/// Print an error message and exit with the given code.
///
/// A message may carry follow-up guidance on additional lines: the first line
/// is the error itself, and every line after it renders as an indented `hint`
/// (see `docs/cli-style.md`). Splitting here keeps presentation out of the
/// library — an error stays plain text with no prefixes or color baked in —
/// and leaves a narrow terminal one short line to wrap instead of a paragraph.
pub(crate) fn die(msg: &dyn std::fmt::Display, code: i32) -> ! {
    let text = msg.to_string();
    let mut lines = text.lines();
    eprintln!("{} {}", "✕".red(), lines.next().unwrap_or_default());
    for hint in lines {
        eprintln!("  {} {hint}", "hint".cyan().bold());
    }
    process::exit(code);
}

/// Unwrap a result or print the error and exit with code 1.
pub(crate) fn try_or_die<T>(result: Result<T, impl std::fmt::Display>) -> T {
    result.unwrap_or_else(|e| die(&e, 1))
}

/// Refuse to inject vault keys named like loader/shell/tool variables (see
/// [`murk_cli::is_reserved_env_name`]) unless the operator passed
/// `--allow-reserved`. A vault writer must not get to pick `PATH`,
/// `LD_PRELOAD`, `GIT_SSH_COMMAND` or `MURK_STRICT` for whoever runs it.
pub(crate) fn refuse_reserved<'a>(keys: impl IntoIterator<Item = &'a String>, allow: bool) {
    if allow {
        return;
    }
    let reserved: Vec<&str> = keys
        .into_iter()
        .map(String::as_str)
        .filter(|k| murk_cli::is_reserved_env_name(k))
        .collect();
    if !reserved.is_empty() {
        die(
            &format_args!(
                "refusing to set {} from the vault: {} control how programs, shells or murk itself run\nreview who added {} (`murk diff`, `git log -p`), then pass --allow-reserved if you mean it",
                reserved.join(", "),
                if reserved.len() == 1 {
                    "it would"
                } else {
                    "they would"
                },
                if reserved.len() == 1 { "it" } else { "them" },
            ),
            1,
        );
    }
}

/// Prompt the user for a line of input, with an optional default value.
pub(crate) fn prompt(label: &str, default: Option<&str>) -> String {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    if let Some(def) = default {
        eprint!("{label} [{def}]: ");
    } else {
        eprint!("{label}: ");
    }
    stdout.flush().ok();

    let mut line = String::new();
    stdin.lock().read_line(&mut line).unwrap_or(0);
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        trimmed
    }
}

/// Ask a yes/no question on the TTY. Defaults to no (anything but `y`/`yes`).
pub(crate) fn confirm(question: &str) -> bool {
    eprint!("{question} [y/N]: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap_or(0);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub(crate) fn resolve_key() -> age::secrecy::SecretString {
    try_or_die(murk_cli::resolve_key())
}

pub(crate) fn load_vault(vault: &str) -> (types::Vault, types::Murk, MurkIdentity) {
    if let Some(warning) = murk_cli::env_permission_warning() {
        eprintln!("{warning}");
    }
    // `murk_cli::load_vault` refuses a vault this machine does not trust
    // (unsigned, untrusted signer, rolled back, ...), so every caller and
    // binding gets the same rules. What reaches here is trusted, or unsigned
    // and loaded by a key that cannot sign.
    let result = try_or_die(murk_cli::load_vault(vault));
    if result.1.legacy_mac {
        eprintln!(
            "{} vault uses legacy unkeyed MAC — run any write command to upgrade to BLAKE3",
            "warn".yellow().bold()
        );
    }
    if matches!(result.1.signature, types::SignatureState::Unsigned) {
        eprintln!(
            "{} vault is unsigned and your key cannot sign — nothing in the vault shows who wrote it; rely on signed git commits",
            "warn".yellow().bold()
        );
    }
    maybe_nudge_agent_path(vault);
    result
}

/// Fires the CI personal-key hint at most once per process. Module-level so
/// [`suppress_agent_nudge`] can consume it.
static AGENT_NUDGE: std::sync::Once = std::sync::Once::new();

/// One-time hint when CI is decrypting with the operator's personal stored key —
/// the agent anti-pattern. CI context alone never changes behavior (see
/// `hardening::ci_context`); this only points at the scoped path. Stays quiet
/// with an explicit key/grant, in agent context, or under strict.
///
/// The remedy it names is a grant key, never `murk agent exec`: agent exec
/// refuses the stored key unless `--allow-operator-key` is passed, and that path
/// prints its own warning (in or out of CI) and suppresses this hint.
pub(crate) fn maybe_nudge_agent_path(vault: &str) {
    if !murk_cli::hardening::ci_context()
        || murk_cli::hardening::agent_context()
        || murk_cli::hardening::strict_mode()
    {
        return;
    }
    if let Ok((_, murk_cli::KeySource::Auto(_))) = murk_cli::resolve_key_with_source(vault) {
        AGENT_NUDGE.call_once(|| {
            eprintln!(
                "{} CI is decrypting with your personal key",
                "hint".cyan().bold()
            );
            eprintln!(
                "  {}",
                "prefer a scoped grant key: `murk agent init`, then MURK_KEY_FILE + MURK_AGENT=1"
                    .dimmed()
            );
            eprintln!("  {}", "see docs/ai-agents.md".dimmed());
        });
    }
}

/// Silence [`maybe_nudge_agent_path`] for the rest of the process. For a command
/// that has already printed its own personal-key warning.
pub(crate) fn suppress_agent_nudge() {
    AGENT_NUDGE.call_once(|| {});
}

/// Load the vault while holding an exclusive lock for the entire read-modify-write cycle.
/// Returns the lock guard — hold it until after `save_vault` completes.
///
/// Every CLI write loads through here, so an agent grant is refused up front,
/// before any prompt or editor session. `save_vault` repeats the check.
pub(crate) fn load_vault_locked(
    vault: &str,
) -> (
    types::Vault,
    types::Murk,
    MurkIdentity,
    murk_cli::vault::VaultLock,
) {
    let lock = try_or_die(
        murk_cli::vault::lock(std::path::Path::new(vault)).map_err(murk_cli::MurkError::Vault),
    );
    let (v, m, i) = load_vault(vault);
    try_or_die(murk_cli::ensure_writable(&m));
    (v, m, i, lock)
}

pub(crate) fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) {
    try_or_die(murk_cli::save_vault(vault_path, vault, original, current));
}

/// Read one secret value: a hidden prompt on a terminal, or all of piped
/// stdin with one trailing newline removed, so a multi-line value such as a
/// PEM key arrives whole (`cat key.pem | murk add TLS_KEY`).
///
/// The value is returned in [`zeroize::Zeroizing`] so the plaintext is wiped
/// from memory when the caller drops it. `rpassword` already returns the typed
/// password in a `String`; we wrap it (and the piped input) so the secret does
/// not linger on the heap after use.
pub(crate) fn resolve_value(key: &str) -> zeroize::Zeroizing<String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return prompt_value(key);
    }
    let mut value = zeroize::Zeroizing::new(String::new());
    stdin
        .lock()
        .read_to_string(&mut value)
        .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        die(&"empty value from stdin", 1);
    }
    value
}

/// Read one value of a batch: a hidden prompt on a terminal, or the next line
/// of piped stdin (e.g. `printf "v1\nv2\n" | murk rotate --all`). Piped batch
/// values can't span lines; call [`ensure_stdin_drained`] after the last one.
pub(crate) fn resolve_line(key: &str) -> zeroize::Zeroizing<String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return prompt_value(key);
    }
    let mut line = zeroize::Zeroizing::new(String::new());
    stdin
        .lock()
        .read_line(&mut line)
        .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
    let trimmed = zeroize::Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
    if trimmed.is_empty() {
        die(&"empty value from stdin", 1);
    }
    trimmed
}

/// Refuse a piped batch that left input unread. Any leftover byte, even a
/// blank or whitespace-only line, means the lines didn't match the values one
/// for one, so the values read so far may belong to other keys.
pub(crate) fn ensure_stdin_drained(expected: usize) {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return;
    }
    let mut rest = zeroize::Zeroizing::new(String::new());
    stdin
        .lock()
        .read_to_string(&mut rest)
        .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
    if !rest.is_empty() {
        die(
            &format_args!(
                "piped input has more lines than the {expected} values this batch takes, so nothing was changed\npiped batch values are one per line and can't span lines\nrotate a multi-line value on its own with `murk rotate KEY`, which reads all of stdin"
            ),
            1,
        );
    }
}

/// Prompt for a value without echo.
fn prompt_value(key: &str) -> zeroize::Zeroizing<String> {
    eprint!("value for {key}: ");
    io::stderr().flush().ok();
    let password = zeroize::Zeroizing::new(rpassword::read_password().unwrap_or_else(|e| {
        eprintln!();
        die(&format_args!("reading input: {e}"), 1);
    }));
    if password.is_empty() {
        die(&"empty value", 1);
    }
    password
}

/// Display suffix for a rotated value's tier: empty for the shared value,
/// otherwise ` (group NAME)` or ` (me)`, matching `add`/`generate`.
pub(crate) fn tier_label(tier: &murk_cli::SecretTier) -> String {
    match tier {
        murk_cli::SecretTier::Everyone => String::new(),
        murk_cli::SecretTier::Group(name) => format!(" (group {name})"),
        murk_cli::SecretTier::Me => " (me)".to_string(),
    }
}

/// One key's part in a rotation batch, worked out before any value is read.
pub(crate) struct KeyPlan {
    pub(crate) key: String,
    /// Tiers whose value is replaced, in prompt order. Each stays in its tier.
    pub(crate) targets: Vec<murk_cli::SecretTier>,
    /// Values of this key the operator can't rotate, each with the reason.
    /// They are reported and left as they are.
    pub(crate) skipped: Vec<String>,
    /// Printed after the key is rotated (e.g. an override left unchanged).
    pub(crate) note: Option<String>,
}

/// Where a rotation batch gets its new values.
pub(crate) enum ValueSource {
    /// A prompt per value on a terminal; one line per value, by position, when
    /// stdin is piped.
    Prompt,
    /// `--generate`: a fresh random value per tier.
    Generate { length: usize, hex: bool },
    /// `--values-from`: `KEY=value` lines, matched by key name.
    Named(Vec<(String, zeroize::Zeroizing<String>)>),
}

/// What a rotation batch did.
pub(crate) struct RotationOutcome {
    /// Keys whose planned values were all replaced.
    pub(crate) rotated: usize,
    /// Keys with a value left unrotated: one the operator can't rotate, or one
    /// `--values-from` didn't name.
    pub(crate) left: Vec<String>,
    /// The "rotated" report, printed by [`RotationOutcome::report`] only once
    /// the caller has saved the vault.
    done: Vec<String>,
}

impl RotationOutcome {
    /// Print what was rotated. Call only after the vault is saved, so a
    /// "rotated" line always means the new value is on disk.
    pub(crate) fn report(&self) {
        for line in &self.done {
            eprintln!("{line}");
        }
    }

    /// Print the "rotated N secrets" total. Also only after the save.
    pub(crate) fn report_total(&self) {
        let plural = if self.rotated == 1 { "" } else { "s" };
        eprintln!();
        eprintln!(
            "{} rotated {} secret{plural}",
            "✓".green(),
            self.rotated.to_string().bold(),
        );
    }
}

/// Read `--values-from` input (`-` for stdin) with the `murk import` parser.
/// The raw contents are wiped as soon as they are parsed. A file is refused if
/// it is a symlink, and a warning names it if others can read it: it holds new
/// plaintext credentials, and `-` avoids writing them to disk at all.
pub(crate) fn read_values_from(path: &str) -> Vec<(String, zeroize::Zeroizing<String>)> {
    let mut contents = zeroize::Zeroizing::new(String::new());
    if path == "-" {
        io::stdin()
            .read_to_string(&mut contents)
            .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
    } else {
        let file = std::path::Path::new(path);
        if file.is_symlink() {
            die(
                &format_args!(
                    "{path} is a symlink — refusing to follow it\npass the file itself, or pipe the values with `--values-from -`"
                ),
                1,
            );
        }
        if let Some(mode) = murk_cli::secret_file_loose_mode(file) {
            eprintln!(
                "{} {path} holds plaintext secrets and is readable by others (mode {mode:o}) — run `chmod 600 {path}`, or pipe the values with `--values-from -`",
                "warn".yellow().bold(),
            );
        }
        *contents = std::fs::read_to_string(file)
            .unwrap_or_else(|e| die(&format_args!("cannot read {path}: {e}"), 1));
    }
    murk_cli::parse_env(&contents)
}

/// Refuse a rotation batch whose values could land on the wrong key, before
/// any value is read or anything is written.
///
/// Piped prompt input is matched by position, so it is refused when a key
/// would be skipped or would take more than one value. `--values-from` input is
/// matched by name, so it is refused when it names a key this batch can't
/// rotate; keys it leaves out are simply not rotated. `retry` is an extra hint
/// line for the refusal (e.g. how to revoke now and rotate afterwards).
pub(crate) fn check_batch(
    vault: &types::Vault,
    plans: &[KeyPlan],
    source: &ValueSource,
    retry: Option<&str>,
) {
    let retry = retry.map(|r| format!("\n{r}")).unwrap_or_default();
    match source {
        ValueSource::Generate { .. } => {}
        ValueSource::Prompt => {
            if io::stdin().is_terminal() {
                return;
            }
            let shifting: Vec<String> = plans
                .iter()
                .filter_map(|p| {
                    if !p.skipped.is_empty() {
                        Some(format!("{}: {}", p.key, p.skipped.join("; ")))
                    } else if p.targets.len() > 1 {
                        Some(format!("{}: it holds values in more than one tier", p.key))
                    } else {
                        None
                    }
                })
                .collect();
            if !shifting.is_empty() {
                die(
                    &format_args!(
                        "refusing piped values, so nothing was changed: they are matched by position, and these keys would shift later values onto the wrong keys\n{}\nname each value instead with --values-from FILE (KEY=value lines){retry}",
                        shifting.join("\n")
                    ),
                    1,
                );
            }
        }
        ValueSource::Named(pairs) => {
            let mut seen = std::collections::HashSet::new();
            let mut problems = Vec::new();
            for (k, v) in pairs {
                let plan = plans.iter().find(|p| p.key == *k);
                let reason = if !seen.insert(k.as_str()) {
                    Some("named more than once".to_string())
                } else {
                    match plan {
                        None if !vault.secrets.contains_key(k) => {
                            Some("not in this vault".to_string())
                        }
                        None => Some("not part of this rotation".to_string()),
                        Some(p) if !p.skipped.is_empty() => Some(p.skipped.join("; ")),
                        Some(p) if p.targets.is_empty() => {
                            Some("nothing of it is left to rotate".to_string())
                        }
                        Some(p) if p.targets.len() > 1 => Some(
                            "it holds values in more than one tier; rotate it interactively"
                                .to_string(),
                        ),
                        Some(_) if v.is_empty() => Some("empty value".to_string()),
                        Some(_) => None,
                    }
                };
                if let Some(reason) = reason {
                    problems.push(format!("{k}: {reason}"));
                }
            }
            if !problems.is_empty() {
                die(
                    &format_args!(
                        "refusing --values-from: it names keys this rotation can't take, so nothing was changed\n{}{retry}",
                        problems.join("\n")
                    ),
                    1,
                );
            }
        }
    }
}

/// Replace every planned value from `source`, each in its own tier. Run
/// [`check_batch`] first. Every value is collected before any is written, so
/// input that runs short aborts with nothing changed. The caller saves, then
/// calls [`RotationOutcome::report`].
pub(crate) fn run_rotation(
    vault: &mut types::Vault,
    current: &mut types::Murk,
    pubkey: &str,
    plans: &[KeyPlan],
    source: &ValueSource,
) -> RotationOutcome {
    let named: std::collections::HashMap<&str, &zeroize::Zeroizing<String>> = match source {
        ValueSource::Named(pairs) => pairs.iter().map(|(k, v)| (k.as_str(), v)).collect(),
        _ => Default::default(),
    };
    let mut left = Vec::new();
    let mut missing = Vec::new();
    let mut writes = Vec::new();
    // A batch of one value reads all of piped stdin, so a multi-line value
    // arrives whole; a longer batch reads one line per value.
    let prompted: usize = plans.iter().map(|p| p.targets.len()).sum();

    for plan in plans {
        let k = &plan.key;
        for reason in &plan.skipped {
            eprintln!("{} skipped {} — {reason}", "warn".yellow().bold(), k.bold());
        }
        if !plan.skipped.is_empty() {
            left.push(k.clone());
        }
        if plan.targets.is_empty() {
            continue;
        }
        if matches!(source, ValueSource::Named(_)) && !named.contains_key(k.as_str()) {
            missing.push(k.clone());
            continue;
        }
        let values: Vec<zeroize::Zeroizing<String>> = plan
            .targets
            .iter()
            .map(|tier| match source {
                ValueSource::Prompt if prompted == 1 => {
                    resolve_value(&format!("{k}{}", tier_label(tier)))
                }
                ValueSource::Prompt => resolve_line(&format!("{k}{}", tier_label(tier))),
                ValueSource::Generate { length, hex } => secrets::random_secret(*length, *hex),
                ValueSource::Named(_) => named[k.as_str()].clone(),
            })
            .collect();
        writes.push((plan, values));
    }
    if matches!(source, ValueSource::Prompt) && prompted > 1 {
        ensure_stdin_drained(prompted);
    }

    if !missing.is_empty() {
        eprintln!(
            "{} left unrotated, not named in --values-from: {}",
            "warn".yellow().bold(),
            missing.join(", ")
        );
        left.extend(missing);
    }

    let mut done = Vec::new();
    for (plan, values) in &writes {
        let k = &plan.key;
        for (tier, value) in plan.targets.iter().zip(values) {
            try_or_die(murk_cli::rotate_secret(
                vault, current, k, value, tier, pubkey,
            ));
            done.push(format!(
                "{} rotated {}{}",
                "◆".magenta(),
                k.bold(),
                tier_label(tier)
            ));
        }
        if let Some(note) = &plan.note {
            done.push(format!("  {}", note.dimmed()));
        }
    }
    RotationOutcome {
        rotated: writes.len(),
        left,
        done,
    }
}

/// Plan the rotation of the values a revoked recipient could read: the shared
/// value, and values in `exposed_groups` (the groups they belonged to). Other
/// tiers were never readable by them and are left alone. A group value the
/// operator can't read is skipped, since only a group member can rotate it.
pub(crate) fn plan_exposed(
    vault: &types::Vault,
    current: &types::Murk,
    pubkey: &str,
    keys: &[String],
    exposed_groups: &[String],
) -> Vec<KeyPlan> {
    use murk_cli::SecretTier;

    keys.iter()
        .map(|k| {
            let tiers = murk_cli::key_tiers(vault, current, k, pubkey);
            let mut targets = Vec::new();
            if tiers.shared {
                targets.push(SecretTier::Everyone);
            }
            targets.extend(
                tiers
                    .groups
                    .iter()
                    .filter(|g| exposed_groups.contains(g))
                    .map(|g| SecretTier::Group(g.clone())),
            );
            let skipped = tiers
                .foreign_groups
                .iter()
                .filter(|g| exposed_groups.contains(g))
                .map(|g| {
                    format!(
                        "it is held by group {g}, which you are not a member of — a member must rotate it"
                    )
                })
                .collect::<Vec<_>>();
            let note = (targets.is_empty() && skipped.is_empty())
                .then(|| format!("{k}: no value they could read is left to rotate"));
            KeyPlan {
                key: k.clone(),
                targets,
                skipped,
                note,
            }
        })
        .collect()
}

/// Rotate the planned values after a revoke, on the same in-memory state as
/// the revoke itself, so the caller saves both in one write. Keys left
/// unrotated (skipped, or not named in `--values-from`) keep a pending-rotation
/// marker, so `murk rotate --list` and `doctor` still flag them. The caller
/// saves, then calls [`RotationOutcome::report`] and
/// [`RotationOutcome::report_total`].
pub(crate) fn rotate_exposed(
    vault: &mut types::Vault,
    current: &mut types::Murk,
    pubkey: &str,
    plans: &[KeyPlan],
    source: &ValueSource,
) -> RotationOutcome {
    for plan in plans.iter().filter(|p| p.targets.is_empty()) {
        if let Some(note) = &plan.note {
            eprintln!("  {}", note.dimmed());
        }
    }
    let outcome = run_rotation(vault, current, pubkey, plans, source);
    murk_cli::mark_revoked(vault, &outcome.left, chrono::Utc::now());
    outcome
}

/// A single finding produced by a check command (`verify`, `doctor`, ...).
/// Each check either passes silently or pushes a `Finding` describing what's
/// wrong and how to fix it. See `docs/cli-style.md` for the output contract.
pub(crate) struct Finding {
    /// Short category tag for the failing-item line (e.g. "mac", "recipients").
    pub(crate) category: &'static str,
    /// One-line human-readable message.
    pub(crate) message: String,
    /// Optional fix hint, printed dimmed under the parent line.
    pub(crate) fix: Option<String>,
}

/// Emit a list of findings to stderr per the CLI style guide and exit(1) if
/// any exist. `header` is a single verb-phrase like "vault" or "repo" — the
/// reporter prints "warn N issue{s} in {header}" above the list.
///
/// Returns `()` on no findings. Exits the process on any finding — callers
/// should finish any "ok" lines before calling this.
pub(crate) fn report_findings(findings: &[Finding], header: &str) {
    if findings.is_empty() {
        return;
    }

    eprintln!();
    eprintln!(
        "{} {} issue{} in {}",
        "warn".yellow().bold(),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        header
    );
    for f in findings {
        eprintln!("  {} {} — {}", "✕".red(), f.category.bold(), f.message);
        if let Some(fix) = &f.fix {
            eprintln!("      {}", fix.dimmed());
        }
    }
    std::process::exit(1);
}

/// Render a [`murk_cli::RotationIssue`] as a doctor [`Finding`].
pub(crate) fn rotation_finding(issue: &murk_cli::RotationIssue) -> Finding {
    use murk_cli::RotationIssue::*;
    // Show the date portion of stored end-of-day timestamps; they read cleaner.
    let day = |ts: &str| ts.split('T').next().unwrap_or(ts).to_string();
    match issue {
        Overdue {
            key,
            last_rotated,
            interval_days,
            overdue_days,
        } => Finding {
            category: "rotation",
            message: format!(
                "{key} is {overdue_days}d overdue for rotation ({interval_days}d interval, last changed {})",
                day(last_rotated)
            ),
            fix: Some(format!("rotate it: `murk rotate {key}`")),
        },
        NoBaseline { key, interval_days } => Finding {
            category: "rotation",
            message: format!(
                "{key} has a {interval_days}d rotation interval but no last-updated timestamp"
            ),
            fix: Some(format!(
                "set a value so the clock can start: `murk add {key}`"
            )),
        },
        Expired {
            key,
            expired_at,
            days_ago,
        } => Finding {
            category: "expiry",
            message: format!("{key} expired {days_ago}d ago ({})", day(expired_at)),
            fix: Some(format!(
                "rotate it and set a new expiry: `murk rotate {key}` then `murk describe {key} ... --expires DATE`"
            )),
        },
        ExpiringSoon {
            key,
            expires_at,
            days_left,
        } => Finding {
            category: "expiry",
            message: format!("{key} expires in {days_left}d ({})", day(expires_at)),
            fix: Some(format!("rotate it before it lapses: `murk rotate {key}`")),
        },
        RevokePending { key, since } => Finding {
            category: "rotation",
            message: format!(
                "{key} not rotated since a recipient was revoked on {}",
                day(since)
            ),
            fix: Some(format!("rotate it: `murk rotate {key}`")),
        },
    }
}
