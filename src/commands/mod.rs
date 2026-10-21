// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared plumbing for the command handlers: process-exit helpers, TTY prompts,
//! vault load/save wrappers, and the `Finding` reporting used by check commands.

use colored::Colorize;
use murk_cli::{MurkIdentity, types};
use std::io::{self, BufRead, IsTerminal, Write};
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

/// Resolve the secret value from stdin pipe or interactive prompt.
/// Returns the value or exits with an error.
/// Prompt for (or read from stdin) a secret value.
///
/// The value is returned in [`zeroize::Zeroizing`] so the plaintext is wiped
/// from memory when the caller drops it. `rpassword` already returns the typed
/// password in a `String`; we wrap it (and the piped-input line) so the secret
/// does not linger on the heap after use.
pub(crate) fn resolve_value(key: &str) -> zeroize::Zeroizing<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        // Piped input: read one line so multiple calls can each consume a value
        // e.g. `printf "v1\nv2\n" | murk rotate --all`
        let mut line = zeroize::Zeroizing::new(String::new());
        stdin
            .lock()
            .read_line(&mut line)
            .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
        let trimmed = zeroize::Zeroizing::new(line.trim_end_matches('\n').to_string());
        if trimmed.is_empty() {
            die(&"empty value from stdin", 1);
        }
        return trimmed;
    }

    // Interactive TTY: prompt without echo.
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

/// Rotate the given keys in the still-locked session after a revoke, prompting
/// for each new value. `baseline` is the post-revoke state already on disk; we
/// diff against it so only the rotated ciphertexts are re-encrypted.
pub(crate) fn rotate_exposed(
    vault_path: &str,
    vault: &mut types::Vault,
    baseline: &types::Murk,
    keys: &[String],
) {
    let original = baseline.clone();
    let mut current = baseline.clone();

    for k in keys {
        let new_value = resolve_value(k);
        murk_cli::add_secret(
            vault,
            &mut current,
            k,
            &new_value,
            None,
            None,
            false,
            &[],
            None,
        );
        eprintln!("{} rotated {}", "◆".magenta(), k.bold());
    }

    save_vault(vault_path, vault, &original, &current);

    let plural = if keys.len() == 1 { "" } else { "s" };
    eprintln!();
    eprintln!(
        "{} rotated {} secret{plural}",
        "✓".green(),
        keys.len().to_string().bold(),
    );
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
