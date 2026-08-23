use murk_cli::cli::{
    AgentCommand, CircleCommand, Cli, Command, CompletionAction, GroupCommand, PolicyCommand,
};
use murk_cli::{
    DiffKind, EnvrcStatus, MergeDriverSetupStep, MurkIdentity, is_valid_key_name, recovery, types,
    vault,
};

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process;

use age::secrecy::ExposeSecret;
use clap::{CommandFactory, Parser};
use colored::Colorize;

mod mcp;

/// Print an error message and exit with the given code.
fn die(msg: &dyn std::fmt::Display, code: i32) -> ! {
    eprintln!("{} {msg}", "✕".red());
    process::exit(code);
}

/// Unwrap a result or print the error and exit with code 1.
fn try_or_die<T>(result: Result<T, impl std::fmt::Display>) -> T {
    result.unwrap_or_else(|e| die(&e, 1))
}

/// Prompt the user for a line of input, with an optional default value.
fn prompt(label: &str, default: Option<&str>) -> String {
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
fn confirm(question: &str) -> bool {
    eprint!("{question} [y/N]: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap_or(0);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Generate a BIP39 keypair, write key to ~/.config/murk/keys/, reference in .env.
/// Returns (secret_key, pubkey). Secret key is wrapped in `Zeroizing` so the
/// plaintext clears when the caller drops it.
fn generate_and_write_key(vault_name: &str) -> (zeroize::Zeroizing<String>, String) {
    eprintln!("{} generating keypair...", "◆".magenta());
    let (phrase, secret_key, pubkey) = try_or_die(recovery::generate());

    // Check .env for existing MURK_KEY.
    if murk_cli::dotenv_has_murk_key() {
        let answer = prompt(
            "MURK_KEY already exists in .env. Overwrite? [y/N]",
            Some("N"),
        );
        if !answer.eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            process::exit(1);
        }
    }

    // Write key to ~/.config/murk/keys/<hash> and reference in .env.
    let key_path = try_or_die(murk_cli::key_file_path(vault_name));
    try_or_die(murk_cli::write_key_to_file(&key_path, &secret_key));
    try_or_die(murk_cli::write_key_ref_to_dotenv(&key_path));
    eprintln!(
        "{} key saved to {}",
        "◆".magenta(),
        key_path.display().to_string().dimmed()
    );

    // Print recovery phrase.
    eprintln!();
    eprintln!(
        "{} {}",
        "⚠".yellow(),
        "RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:"
            .yellow()
            .bold()
    );
    eprintln!("  {}", phrase.as_str().bold());
    eprintln!();
    eprintln!(
        "  {}",
        ".env contains a reference to your key — it is safe to commit, but the key file is not"
            .dimmed()
    );

    (secret_key, pubkey)
}

fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // If vault already exists, handle onboarding flow.
    if vault_path.exists() {
        let vault = try_or_die(vault::read(vault_path));

        eprintln!("{}", format!("{vault_name} already exists").dimmed());

        // Try to find an existing key: env var first, then .env file.
        let dk = try_or_die(murk_cli::discover_existing_key());
        let (secret_key, pubkey) = match dk {
            Some(dk) => (Some(dk.secret_key), dk.pubkey),
            None => {
                let (_secret_key, pubkey) = generate_and_write_key(vault_name);
                eprintln!();
                (None, pubkey)
            }
        };

        let status = match &secret_key {
            Some(sk) => try_or_die(murk_cli::check_init_status(&vault, sk.expose_secret())),
            None => {
                // No secret key — fall back to simple recipient check.
                if vault.recipients.contains(&pubkey) {
                    eprintln!("{} authorized  {}", "◆".magenta(), pubkey.dimmed());
                } else {
                    eprintln!(
                        "{} {}",
                        "⚠".yellow(),
                        "not authorized \u{2014} share your public key to get added:".yellow()
                    );
                    eprintln!("  {}", pubkey.bold());
                }
                return;
            }
        };

        if status.authorized {
            let name_display = match status.display_name {
                Some(ref name) if !name.is_empty() => format!("  {}", name.bold()),
                _ => String::new(),
            };
            eprintln!(
                "{} authorized  {}{}",
                "◆".magenta(),
                status.pubkey.dimmed(),
                name_display
            );
        } else {
            eprintln!(
                "{} {}",
                "⚠".yellow(),
                "not authorized \u{2014} share your public key to get added:".yellow()
            );
            eprintln!("  {}", status.pubkey.bold());
        }
        return;
    }

    // --- New vault flow ---

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        die(&"name is required", 1);
    }

    let (_secret_key, pubkey) = generate_and_write_key(vault_name);

    let v = try_or_die(murk_cli::create_vault(vault_name, &pubkey, &name));
    try_or_die(vault::write(vault_path, &v));

    eprintln!();
    eprintln!(
        "{} vault initialized — added {} as recipient",
        "◆".magenta(),
        name.bold()
    );
    eprintln!("  {}", "run: murk add KEY".dimmed());
}

fn resolve_key() -> age::secrecy::SecretString {
    try_or_die(murk_cli::resolve_key())
}

fn load_vault(vault: &str) -> (types::Vault, types::Murk, MurkIdentity) {
    if let Some(warning) = murk_cli::env_permission_warning() {
        eprintln!("{warning}");
    }
    let result = try_or_die(murk_cli::load_vault(vault));
    if result.1.legacy_mac {
        eprintln!(
            "{} vault uses legacy unkeyed MAC — run any write command to upgrade to BLAKE3",
            "warn".yellow().bold()
        );
    }
    // A vault signed before and now unsigned is the sharper signal — surface it
    // distinctly (a merge is the common benign cause; a strip is not).
    if result.1.signature_downgraded {
        eprintln!(
            "{} vault was signed before and is now unsigned — expected right after `git merge` (re-sign with any write command after reviewing `murk diff`); otherwise investigate before trusting it",
            "warn".yellow().bold()
        );
    } else if matches!(result.1.signature, types::SignatureState::Unsigned)
        && !result.0.secrets.is_empty()
        && result.2.is_signing_capable()
    {
        // Nudge only when the operator can actually fix it: a vault with secrets
        // that isn't signed, loaded by a signing-capable key. SSH/hardware users
        // can't sign, so staying unsigned is expected (integrity anchor is git).
        eprintln!(
            "{} vault is unsigned — run any write command to sign it (integrity relies on git until then)",
            "warn".yellow().bold()
        );
    }
    // Signature present but pinning is off (MURK_NO_SIGNER_PIN or no HOME, e.g.
    // some CI): the signature can't be anchored, so a swapped signer key would go
    // uncaught. Surface the blind spot rather than letting it pass silently.
    if matches!(
        result.1.signature,
        types::SignatureState::Signed {
            anchored: false,
            ..
        }
    ) && !result.0.secrets.is_empty()
        && !murk_cli::pins::signer_pin_available()
    {
        eprintln!(
            "{} signer pinning is off (MURK_NO_SIGNER_PIN or no HOME) — the signature is trust-only and not anchored; anchor authorship with signed git commits",
            "warn".yellow().bold()
        );
    }
    maybe_nudge_agent_path(vault);
    // The signer-registry pin (a changed verifying key for an already-seen signer)
    // is enforced as a hard failure inside `murk_cli::load_vault`, so it applies
    // to every caller. Nothing to do here.
    result
}

/// One-time hint when CI is decrypting with the operator's personal stored key —
/// the agent anti-pattern. CI context alone never changes behavior (see
/// `hardening::ci_context`); this only points at the scoped path. Stays quiet
/// with an explicit key/grant, in agent context, or under strict.
fn maybe_nudge_agent_path(vault: &str) {
    use std::sync::Once;
    static NUDGE: Once = Once::new();
    if !murk_cli::hardening::ci_context()
        || murk_cli::hardening::agent_context()
        || murk_cli::hardening::strict_mode()
    {
        return;
    }
    if let Ok((_, murk_cli::KeySource::Auto(_))) = murk_cli::resolve_key_with_source(vault) {
        NUDGE.call_once(|| {
            eprintln!(
                "{} CI is using your personal stored key — prefer a scoped `murk agent grant` + `MURK_AGENT=1`, or `murk agent exec` (see docs/ai-agents.md)",
                "hint".dimmed()
            );
        });
    }
}

/// Load the vault while holding an exclusive lock for the entire read-modify-write cycle.
/// Returns the lock guard — hold it until after `save_vault` completes.
fn load_vault_locked(
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

fn save_vault(
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
fn resolve_value(key: &str) -> zeroize::Zeroizing<String> {
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

/// Generate `length` random bytes and encode them as a fresh secret value,
/// either lowercase hex or URL-safe base64.
///
/// Both the raw entropy (`Zeroizing<Vec<u8>>`) and the encoded string are held
/// in [`zeroize::Zeroizing`] so the newly minted secret is wiped from memory on
/// drop instead of lingering on the heap.
fn random_secret(length: usize, hex: bool) -> zeroize::Zeroizing<String> {
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

/// Resolved destination tier for a secret command, from `--group`/`--scoped`.
enum SecretTier {
    /// The shared value, encrypted to all recipients (the default).
    Everyone,
    /// A personal scoped value, encrypted to the caller only.
    Me,
    /// A named group, encrypted to that group's members.
    Group(String),
}

/// Map `--group`/`--scoped` onto a tier. The reserved names `everyone`/`me`
/// route to the shared/scoped tiers; `--scoped` is a deprecated alias for
/// `--group me`. Both flags at once is a usage error.
fn resolve_secret_tier(group: Option<&str>, scoped: bool) -> SecretTier {
    if let Some(g) = group {
        if scoped {
            die(
                &format_args!("pass either --group or --scoped, not both"),
                1,
            );
        }
        match g {
            "everyone" | "all" | "shared" => SecretTier::Everyone,
            "me" | "self" | "mine" => SecretTier::Me,
            _ => SecretTier::Group(g.to_string()),
        }
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

impl SecretTier {
    /// Short suffix for status lines, e.g. ` (group prod)`.
    fn label(&self) -> String {
        match self {
            SecretTier::Everyone => String::new(),
            SecretTier::Me => " (me)".to_string(),
            SecretTier::Group(name) => format!(" (group {name})"),
        }
    }
}

/// Read a key's value for the given tier from the working state.
fn tier_get(
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
fn tier_set(
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
fn tier_list(
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

fn cmd_add(
    key: &str,
    value: &str,
    desc: Option<&str>,
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
                name,
                tags,
                &pubkey,
            ));
            (needs, format!(" (group {name})"))
        }
        tier => {
            let scoped = matches!(tier, SecretTier::Me);
            let needs = murk_cli::add_secret(
                &mut vault,
                &mut current,
                key,
                value,
                desc,
                scoped,
                tags,
                &identity,
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

fn cmd_import(file: &str, force: bool, group: Option<&str>, vault_path: &str) {
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
        SecretTier::Everyone => murk_cli::import_secrets(&mut vault, &mut current, &pairs),
        SecretTier::Me => {
            for (key, value) in &pairs {
                murk_cli::add_secret(
                    &mut vault,
                    &mut current,
                    key,
                    value,
                    None,
                    true,
                    &[],
                    &identity,
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

fn cmd_generate(
    key: &str,
    length: usize,
    hex: bool,
    desc: Option<&str>,
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
                name,
                tags,
                &pubkey,
            ));
            format!(" (group {name})")
        }
        tier => {
            let scoped = matches!(tier, SecretTier::Me);
            murk_cli::add_secret(
                &mut vault,
                &mut current,
                key,
                &value,
                desc,
                scoped,
                tags,
                &identity,
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

fn cmd_rotate(
    key: Option<&str>,
    all: bool,
    generate: bool,
    length: usize,
    hex: bool,
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

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
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

    if keys_to_rotate.is_empty() {
        eprintln!("{}", "no secrets to rotate".dimmed());
        return;
    }

    let mut rotated = 0;
    for k in &keys_to_rotate {
        let new_value = if generate {
            random_secret(length, hex)
        } else {
            resolve_value(k)
        };

        murk_cli::add_secret(
            &mut vault,
            &mut current,
            k,
            &new_value,
            None,
            false,
            &[],
            &identity,
        );
        rotated += 1;
        eprintln!("{} rotated {}", "◆".magenta(), k.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);

    if rotated > 1 {
        eprintln!();
        eprintln!(
            "{} rotated {} secrets",
            "✓".green(),
            rotated.to_string().bold()
        );
    }
}

/// List keys needing rotation — the same signals doctor reports, but scoped to
/// rotation and machine-readable. Reads only the plaintext schema, so it works
/// without a key. JSON mode always exits 0 (empty array when clean); human mode
/// exits 1 when anything needs rotating, so it can gate scripts.
fn cmd_rotate_list(json: bool, vault_path: &str) {
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

fn cmd_rm(key: &str, vault_path: &str) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

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
fn strict_guard_plaintext_stdout(hint: &str) {
    if murk_cli::hardening::strict_mode() && murk_cli::hardening::stdout_is_regular_file() {
        eprintln!(
            "{} MURK_STRICT refuses writing plaintext secrets to a file",
            "error".red().bold()
        );
        eprintln!("  {}", hint.dimmed());
        process::exit(1);
    }
}

fn cmd_get(key: &str, vault_path: &str) {
    strict_guard_plaintext_stdout("capture in a variable instead, e.g. TOKEN=$(murk get KEY)");
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    if murk_cli::hardening::self_scope() {
        try_or_die(murk_cli::check_agent_keys(&vault, &[key.to_string()]));
    }

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

fn cmd_ls(tags: &[String], json: bool, vault_path: &str) {
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

fn cmd_describe(
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

    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();

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
fn parse_rotate_every(input: Option<&str>) -> Result<Option<Option<u32>>, String> {
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
fn parse_expires(input: Option<&str>) -> Result<Option<Option<String>>, String> {
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

fn cmd_export(tags: &[String], json: bool, vault_path: &str) {
    strict_guard_plaintext_stdout("pipe to a process instead, e.g. eval \"$(murk export)\"");
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    if json {
        let mut raw = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);
        apply_self_scope(&mut raw, &vault);
        // serde_json copies into its own owned String, so zeroization ends here.
        let map: serde_json::Map<String, serde_json::Value> = raw
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.to_string())))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
    } else {
        let mut exports = murk_cli::export_secrets(&vault, &murk, &pubkey, tags);
        apply_self_scope(&mut exports, &vault);
        for (k, escaped) in &exports {
            if !is_valid_key_name(k) {
                eprintln!("{} skipping unsafe key name: {}", "⚠".yellow(), k.bold());
                continue;
            }
            println!("export {k}='{}'", escaped.as_str());
        }
    }
}

/// Under self-scope, drop keys the vault's agent policy forbids from an export
/// map, warning (not silently) about what was withheld. A no-op without a policy
/// or outside self-scope.
fn apply_self_scope(
    map: &mut std::collections::BTreeMap<String, zeroize::Zeroizing<String>>,
    vault: &types::Vault,
) {
    if !(murk_cli::hardening::self_scope() && vault.policy.is_some()) {
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
        "{} self-scope: withholding {} key(s) not allowed by policy: {}",
        "⚠".yellow(),
        withheld.len(),
        withheld.join(", ")
    );
}

fn cmd_edit(key: Option<&str>, scoped: bool, group: Option<&str>, vault_path: &str) {
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

    let tier_label = tier.label();

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

    let mut tmp = tempfile::Builder::new()
        .prefix("murk-edit-")
        .suffix(".env")
        .tempfile_in(&dir)
        .unwrap_or_else(|e| die(&format_args!("creating tempfile: {e}"), 1));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    use std::io::Write;
    tmp.write_all(buffer.as_bytes())
        .unwrap_or_else(|e| die(&format_args!("writing tempfile: {e}"), 1));
    tmp.flush()
        .unwrap_or_else(|e| die(&format_args!("flushing tempfile: {e}"), 1));

    // Open $EDITOR.
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());

    let path = tmp.path().to_path_buf();
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .unwrap_or_else(|e| die(&format_args!("launching {editor}: {e}"), 1));

    if !status.success() {
        // Securely wipe tempfile before exiting.
        overwrite_and_remove(&path);
        die(&"editor exited with error — aborting", 1);
    }

    // Read back the edited content. Wrap in Zeroizing so the plaintext
    // buffer is wiped as soon as parsing finishes.
    let edited = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| die(&format_args!("reading tempfile: {e}"), 1)),
    );

    // Securely wipe the tempfile (overwrite with zeros before unlinking).
    overwrite_and_remove(&path);

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
fn overwrite_and_remove(path: &std::path::Path) {
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

fn cmd_exec(
    command: &[String],
    only: &[String],
    tags: &[String],
    clean_env: bool,
    agent_mode: bool,
    vault_path: &str,
) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let mut secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);

    // Filter to specific keys if --only is provided.
    if !only.is_empty() {
        secrets.retain(|k, _| only.contains(k));
        for key in only {
            if !secrets.contains_key(key) {
                die(&format_args!("key not found: {key}"), 1);
            }
        }
    }

    // In agent mode or under self-scope, the vault's policy decides which keys may be injected.
    // Fails closed before any secret reaches the child environment.
    if agent_mode || murk_cli::hardening::self_scope() {
        let keys: Vec<String> = secrets.keys().cloned().collect();
        try_or_die(murk_cli::check_agent_keys(&vault, &keys));
    }

    // `Command::env` panics on a NUL in a value (or an `=`/NUL/empty key), so
    // validate before injecting — a NUL-bearing secret should fail with a clear
    // error, not crash. Vault key names are already `[A-Za-z0-9_]`; the key check
    // is defense in depth. (Mirrors the `murk mcp` `murk_exec` guard.)
    for (key, value) in &secrets {
        if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
            die(
                &format_args!(
                    "{key}: cannot be injected as an environment variable (invalid key or NUL byte in value)"
                ),
                1,
            );
        }
    }

    let program = &command[0];
    let args = &command[1..];

    let build_cmd = |cmd: &mut process::Command| {
        if clean_env {
            cmd.env_clear();
            // Preserve the minimum vars subprocesses need to function.
            // On Windows, cmd.exe and the stdlib break without SystemRoot
            // and friends.
            #[cfg(windows)]
            let preserve: &[&str] = &[
                "PATH",
                "PATHEXT",
                "SystemRoot",
                "SystemDrive",
                "ComSpec",
                "WINDIR",
                "TEMP",
                "TMP",
                "APPDATA",
                "LOCALAPPDATA",
                "USERPROFILE",
                "HOMEDRIVE",
                "HOMEPATH",
            ];
            #[cfg(not(windows))]
            let preserve: &[&str] = &["PATH", "HOME", "TERM"];
            for var in preserve {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }
            // Mark the child as an agent context, and set MURK_STRICT too so an
            // older `murk` on PATH (which only knows MURK_STRICT) still refuses to
            // fall back to the operator's stored key via the preserved HOME. A
            // safe default, not a sandbox: a child can unset these or read the key
            // file directly — real isolation is the OS's job.
            if agent_mode {
                cmd.env("MURK_AGENT", "1");
                cmd.env("MURK_STRICT", "1");
            }
        } else {
            cmd.env_remove("MURK_KEY");
            cmd.env_remove("MURK_KEY_FILE");
        }
        // `secrets` holds the decrypted values in `Zeroizing` and is wiped when
        // it drops. Handing them to the child's environment necessarily copies
        // the plaintext into the block passed to `execve(2)`; that copy lives in
        // the kernel/child and is outside our control, so it is intentionally
        // not zeroized here. This is the documented boundary of best-effort
        // zeroization.
        cmd.envs(&secrets);
    };

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = process::Command::new(program);
        cmd.args(args);
        build_cmd(&mut cmd);
        let err = cmd.exec();
        die(&err, 1);
    }

    #[cfg(not(unix))]
    {
        let mut cmd = process::Command::new(program);
        cmd.args(args);
        build_cmd(&mut cmd);
        let status = cmd.status().unwrap_or_else(|e| die(&e, 1));
        process::exit(status.code().unwrap_or(1));
    }
}

fn cmd_env(vault: &str) {
    match murk_cli::write_envrc(vault) {
        Ok(EnvrcStatus::AlreadyPresent) => {
            eprintln!("{} .envrc already contains murk export", "◆".magenta());
        }
        Ok(EnvrcStatus::Appended) => {
            eprintln!("{} appended to .envrc", "◆".magenta());
            eprintln!("  {}", "run: direnv allow".dimmed());
        }
        Ok(EnvrcStatus::Created) => {
            eprintln!("{} created .envrc", "◆".magenta());
            eprintln!("  {}", "run: direnv allow".dimmed());
        }
        Err(e) => die(&e, 1),
    }
}

fn cmd_merge_driver(base_path: &str, ours_path: &str, theirs_path: &str) {
    let base_contents = fs::read_to_string(base_path)
        .unwrap_or_else(|e| die(&format_args!("reading base {base_path}: {e}"), 2));
    let ours_contents = fs::read_to_string(ours_path)
        .unwrap_or_else(|e| die(&format_args!("reading ours {ours_path}: {e}"), 2));
    let theirs_contents = fs::read_to_string(theirs_path)
        .unwrap_or_else(|e| die(&format_args!("reading theirs {theirs_path}: {e}"), 2));

    let output = murk_cli::run_merge_driver(&base_contents, &ours_contents, &theirs_contents)
        .unwrap_or_else(|e| die(&e, 2));

    if !output.meta_regenerated && output.result.conflicts.is_empty() {
        // Check if the merge actually changed secrets or recipients vs ours.
        // If so, the MAC in ours.meta is stale and the vault would fail integrity checks.
        // Skip this check when there are conflicts — the user must resolve and re-merge anyway.
        let ours_vault = vault::parse(
            &fs::read_to_string(ours_path)
                .unwrap_or_else(|e| die(&format_args!("re-reading ours: {e}"), 2)),
        )
        .unwrap_or_else(|e| die(&e, 2));

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
        .unwrap_or_else(|e| die(&format_args!("writing merged vault: {e}"), 2));

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

fn cmd_setup_merge_driver() {
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

fn cmd_diff(git_ref: &str, show_values: bool, json: bool, vault_path: &str) {
    let (_vault, current_murk, identity) = load_vault(vault_path);

    // Get the old vault contents from git.
    let output = process::Command::new("git")
        .args(["show", &format!("{git_ref}:{vault_path}")])
        .output()
        .unwrap_or_else(|e| die(&format_args!("running git: {e}"), 1));

    let old_values: HashMap<String, zeroize::Zeroizing<String>> = if output.status.success() {
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
    let current_values: HashMap<String, zeroize::Zeroizing<String>> =
        murk_cli::resolve_secrets(&_vault, &current_murk, &pubkey, &[])
            .into_iter()
            .collect();
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

fn is_ssh_rsa(key: &str) -> bool {
    key.starts_with("ssh-rsa ")
}

/// Abort if any of the given keys are ssh-rsa, unless the user passed
/// `--allow-ssh-rsa`. Default-closed because ssh-rsa has known weaknesses
/// (see RUSTSEC-2023-0071) and ed25519 is strictly better for this use case.
fn reject_rsa_keys(keys: &[String], allow: bool) {
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
fn add_recipients_to_group(
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

fn cmd_authorize(
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

fn cmd_revoke(recipient: &str, rotate: bool, vault_path: &str) {
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

fn cmd_group(sub: GroupCommand) {
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

fn cmd_policy(sub: PolicyCommand) {
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

/// Rotate the given keys in the still-locked session after a revoke, prompting
/// for each new value. `baseline` is the post-revoke state already on disk; we
/// diff against it so only the rotated ciphertexts are re-encrypted.
fn rotate_exposed(
    vault_path: &str,
    vault: &mut types::Vault,
    baseline: &types::Murk,
    keys: &[String],
    identity: &MurkIdentity,
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
            false,
            &[],
            identity,
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

/// Truncate a pubkey for display: first 8 chars + "…" + last 4 chars.
fn cmd_recipients(json: bool, vault_path: &str) {
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

/// Whether the just-restored identity is a recipient of the given vault JSON.
/// `Some(true)` = recipient, `Some(false)` = not a recipient, `None` = can't
/// tell (unparseable vault, or a key with no comparable pubkey). Drives only a
/// best-effort sanity warning — never gates the restore.
fn restored_key_is_recipient(secret_key: &str, vault_contents: &str) -> Option<bool> {
    let vault = vault::parse(vault_contents).ok()?;
    let identity = murk_cli::crypto::parse_identity(secret_key).ok()?;
    let pubkey = identity.pubkey_string().ok()?;
    Some(vault.recipients.contains(&pubkey))
}

fn cmd_restore(vault: &str) {
    let phrase = if io::stdin().is_terminal() {
        eprint!("Enter 24-word recovery phrase: ");
        io::stderr().flush().ok();
        let password = rpassword::read_password().unwrap_or_else(|e| {
            eprintln!();
            die(&format_args!("reading input: {e}"), 1);
        });
        eprintln!();
        password
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap_or(0);
        line.trim().to_string()
    };

    if phrase.is_empty() {
        die(&"recovery phrase is required", 1);
    }

    let key = try_or_die(recovery::recover(&phrase));

    // A *different* valid 24-word phrase also decodes to a valid key — just not
    // yours. If a vault is reachable here and the restored identity isn't one
    // of its recipients, that's a strong hint the phrase was wrong. Best-effort:
    // it never fails the restore, and the key still prints.
    let vault_path = murk_cli::resolve_vault_path(vault);
    if let Ok(contents) = fs::read_to_string(&vault_path)
        && restored_key_is_recipient(key.as_str(), &contents) == Some(false)
    {
        eprintln!(
            "{} restored identity is not a recipient of {vault_path}. If you're recovering an existing key, double-check the phrase (a different valid phrase yields a different but working key)",
            "warn".yellow().bold(),
        );
    }

    println!("{}", key.as_str());
}

fn cmd_recover() {
    let secret_key = resolve_key();

    // SSH keys and plugin identities don't have BIP39 recovery phrases.
    let identity =
        murk_cli::crypto::parse_identity(secret_key.expose_secret()).unwrap_or_else(|e| die(&e, 1));
    match identity {
        MurkIdentity::Ssh { .. } => die(
            &"recovery phrases are for age keys only. SSH keys are managed by your SSH agent — back up ~/.ssh instead",
            1,
        ),
        MurkIdentity::Plugin { .. } => die(
            &"plugin identities (YubiKey, Secure Enclave, FIDO2) do not have recovery phrases. BIP39 words encode the raw 32 key bytes, but hardware-backed keys never leave the device — there are no bytes to encode. Recovery means enrolling a backup hardware device at setup and adding its pubkey as a recipient with `murk authorize`",
            1,
        ),
        MurkIdentity::Age(_) => {}
    }

    println!(
        "{}",
        try_or_die(recovery::phrase_from_key(secret_key.expose_secret())).as_str()
    );
}

fn cmd_info(tags: &[String], json: bool, vault_path: &str) {
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

fn cmd_scan(paths: &[String], vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, &[]);

    if secrets.is_empty() {
        eprintln!("{} no secrets to scan for", "ok".green().bold());
        return;
    }

    let scan_paths: Vec<&str> = if paths.is_empty() {
        vec!["."]
    } else {
        paths.iter().map(String::as_str).collect()
    };

    let findings = murk_cli::scan::scan_for_leaks(&scan_paths, &secrets, 8);

    for f in &findings {
        eprintln!(
            "{} {} leaked in {}",
            "warn".yellow().bold(),
            f.key.bold(),
            f.path
        );
    }

    if findings.is_empty() {
        eprintln!("{} no leaked secrets found", "ok".green().bold());
    } else {
        eprintln!(
            "{} {} leaked secret{} found",
            "error".red().bold(),
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        );
        process::exit(1);
    }
}

/// Run the MCP (Model Context Protocol) stdio server.
///
/// Fails closed unless this is a scoped *agent* identity — a grant key plus
/// `MURK_AGENT=1`. Running the server with the operator's stored key (or any
/// non-grant recipient) would hand a connected agent the operator's full read
/// scope over MCP, defeating the point, so both the agent-context opt-in and a
/// grant identity are required. stdout is the JSON-RPC channel; every diagnostic
/// here goes to stderr.
fn cmd_mcp(vault_path: &str, allow_exec: bool) {
    // Cheap gate first: the caller must have opted into agent context. No key or
    // vault load is needed to reject the obvious misuse.
    if !murk_cli::hardening::agent_context() {
        die(
            &"murk mcp must run in agent context: set MURK_AGENT=1 and use a scoped grant key (run `murk agent init` to mint one)",
            1,
        );
    }

    // Resolve the key and load the vault. Agent context forces strict mode, so
    // this will not silently fall back to the operator's stored key. The
    // decrypted state is handed to the server so the tools read in-process.
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    // The resolved identity must be one of the vault's grants. Anything else —
    // the operator's own key, a plain recipient — is refused: the whole point is
    // to bound the agent to a grant's scope.
    if !murk_cli::is_agent_identity(&murk, &pubkey) {
        die(
            &"murk mcp refuses to run without a scoped grant: this identity is not a `murk agent grant` key (fail-closed). Mint one with `murk agent init`.",
            1,
        );
    }

    try_or_die(mcp::serve(
        mcp::McpState {
            vault,
            murk,
            pubkey,
        },
        allow_exec,
    ));
}

fn cmd_skeleton(output: Option<&str>, vault_path: &str) {
    let vault = murk_cli::vault::read(Path::new(vault_path)).unwrap_or_else(|e| die(&e, 1));

    let skeleton = murk_cli::types::Vault {
        version: vault.version,
        created: vault.created,
        vault_name: vault.vault_name,
        repo: vault.repo,
        recipients: Vec::new(),
        schema: vault.schema,
        // Policy is public header metadata (like schema) — keep it in the
        // skeleton so the agent posture travels with the shared shape.
        policy: vault.policy,
        secrets: BTreeMap::new(),
        meta: String::new(),
    };

    let json = serde_json::to_string_pretty(&skeleton).unwrap();
    match output {
        Some(path) => {
            fs::write(path, format!("{json}\n")).unwrap_or_else(|e| die(&e, 1));
            eprintln!("{} wrote skeleton to {}", "ok".green().bold(), path.bold());
        }
        None => println!("{json}"),
    }
}

fn cmd_agent_exec(command: &[String], only: &[String], vault_path: &str) {
    // Announce the exposure boundary on stderr before exec replaces the
    // process. After execve the subprocess owns stderr and we cannot print.
    eprintln!(
        "{} agent exec — clean env, injecting {} key{}",
        "◆".magenta(),
        only.len(),
        if only.len() == 1 { "" } else { "s" }
    );
    for key in only {
        eprintln!("  {}", key.dimmed());
    }

    cmd_exec(
        command,
        only,
        &[],
        /* clean_env */ true,
        /* agent_mode */ true,
        vault_path,
    );
}

/// Mint a scoped agent grant in one locked transaction and hand off the
/// ephemeral key. When `allow_tags` is `Some`, the vault's agent allow-list is
/// set first (so scope validation reflects it) — used by `agent init`; `None`
/// leaves the policy unchanged. A single `save_vault` covers both the optional
/// policy change and the grant. Returns the written key path, or `None` when the
/// key was streamed to stdout.
fn mint_grant(
    name: &str,
    only: &[String],
    ttl: &str,
    renew: bool,
    out: Option<&str>,
    allow_tags: Option<&[String]>,
    vault_path: &str,
) -> Option<String> {
    use age::secrecy::ExposeSecret;

    try_or_die(murk_cli::validate_grant_name(name));
    let ttl_dur = try_or_die(murk_cli::parse_ttl(ttl));

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let issuer = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let original = murk.clone();
    let mut current = murk;

    // Renewal: drop the existing grant and revoke its key before minting the
    // replacement — one vault write covers both, so there is no window with two
    // live keys and no partial revoke-without-regrant state on failure.
    if renew && current.grants.contains_key(name) {
        let old = try_or_die(murk_cli::remove_grant(&mut current, name));
        try_or_die(murk_cli::revoke_recipient(
            &mut vault,
            &mut current,
            &old.pubkey,
        ));
        eprintln!(
            "{} renewing {} — its previous key is revoked",
            "◆".magenta(),
            name.bold()
        );
    }

    // Set the allow-list before validating scope so a single save covers both the
    // policy and the grant — no policy-without-grant partial state. (The key-file
    // handoff below is a separate step, as in `agent grant`.)
    if let Some(tags) = allow_tags {
        vault.policy = Some(murk_cli::types::Policy {
            agent_allow_tags: tags.to_vec(),
        });
        eprintln!(
            "{} agent allow-list set to {}",
            "◆".magenta(),
            tags.join(", ").bold()
        );
    }

    // The vault's policy decides which keys may be granted to an agent.
    try_or_die(murk_cli::check_agent_keys(&vault, only));

    // Mint a fresh ephemeral identity for the agent — never the operator's key.
    let agent_id = age::x25519::Identity::generate();
    let agent_secret = agent_id.to_string();
    let agent_pubkey = agent_id.to_public().to_string();

    // The agent becomes a recipient (so it can decrypt meta and its scoped
    // values) named for the grant, then we stage the scoped copies + metadata.
    vault.recipients.push(agent_pubkey.clone());
    current
        .recipients
        .insert(agent_pubkey.clone(), format!("agent:{name}"));
    let entry = try_or_die(murk_cli::create_grant(
        &mut current,
        name,
        &agent_pubkey,
        only,
        &issuer,
        chrono::Utc::now(),
        ttl_dur,
    ));

    save_vault(vault_path, &mut vault, &original, &current);

    eprintln!(
        "{} granted {} read access to {} key{} until {}",
        "◆".magenta(),
        name.bold(),
        entry.scope.len(),
        if entry.scope.len() == 1 { "" } else { "s" },
        entry.expires_at.dimmed(),
    );
    for key in &entry.scope {
        eprintln!("  {} {}", "▸".dimmed(), key.bold());
    }

    // Hand off the ephemeral key.
    let secret = agent_secret.expose_secret();
    match out {
        Some("-") => {
            println!("{secret}");
            eprintln!(
                "{} key streamed to stdout — capture it now; it is not stored",
                "⚠".yellow()
            );
            None
        }
        Some(path) => {
            try_or_die(murk_cli::write_key_to_file(Path::new(path), secret));
            Some(path.to_string())
        }
        None => {
            let path = try_or_die(murk_cli::agent_key_file_path(vault_path, name));
            try_or_die(murk_cli::write_key_to_file(&path, secret));
            Some(path.display().to_string())
        }
    }
}

/// The reminder printed after any grant handoff.
fn print_ttl_advisory() {
    eprintln!();
    eprintln!(
        "  {}",
        "reads fail closed after the TTL — `murk agent revoke` + rotate is still the real close"
            .dimmed()
    );
}

fn cmd_agent_grant(
    name: &str,
    only: &[String],
    ttl: &str,
    renew: bool,
    out: Option<&str>,
    vault_path: &str,
) {
    if let Some(path) = mint_grant(name, only, ttl, renew, out, None, vault_path) {
        print_grant_handoff(only, &path);
    }
    print_ttl_advisory();
}

/// Print how to run an agent with a grant key file, and the containment caveat.
///
/// The run command is split across two indented lines with a shell continuation
/// so the block fits an 80-column terminal: a grant key path is ~48 columns even
/// with `$HOME` collapsed, and one-lining it wrapped on every real invocation.
/// `--only` is repeated per key — clap takes one value per occurrence, so a
/// space-joined list silently fed the extra keys to the child command.
fn print_grant_handoff(only: &[String], key_path: &str) {
    let key_path = murk_cli::home_short(key_path);
    let only_args = only
        .iter()
        .map(|k| format!("--only {k}"))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!();
    eprintln!(
        "{} agent key written to {}",
        "ok".green().bold(),
        key_path.bold()
    );
    eprintln!("  {}", "run the agent with:".dimmed());
    eprintln!("    {}", format!("MURK_KEY_FILE={key_path} \\").dimmed());
    eprintln!(
        "    {}",
        format!("MURK_AGENT=1 murk agent exec {only_args} -- <cmd>").dimmed()
    );
    eprintln!(
        "  {}",
        "for real isolation, run it where it can't read ~/.config/murk/keys".dimmed()
    );
}

/// The project root for MCP configs: the directory holding the vault.
fn project_dir_of(vault_path: &str) -> std::path::PathBuf {
    Path::new(vault_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// A project-local MCP config is often committed. It only ever holds a
/// machine-specific key-file *path* (never key material), but committing it is
/// per-machine noise and leaks the grant name — so warn, and offer to ignore it.
fn offer_gitignore(project_dir: &Path, config_path: &Path) {
    let Ok(rel) = config_path.strip_prefix(project_dir) else {
        return;
    };
    let rel = rel.to_string_lossy().replace('\\', "/");
    let gitignore = project_dir.join(".gitignore");
    let existing = fs::read_to_string(&gitignore).unwrap_or_default();
    let already = existing.lines().any(|l| {
        let l = l.trim();
        l == rel || l == format!("/{rel}")
    });
    if already {
        return;
    }
    eprintln!(
        "  {} {} is project-local; committing it shares a machine path and the grant name",
        "⚠".yellow(),
        rel.bold()
    );
    if io::stdin().is_terminal() && confirm(&format!("add {rel} to .gitignore?")) {
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&rel);
        content.push('\n');
        match fs::write(&gitignore, content) {
            Ok(()) => eprintln!("  {} added {} to .gitignore", "ok".green(), rel.bold()),
            Err(e) => eprintln!("  {} could not update .gitignore: {e}", "✗".red()),
        }
    }
}

fn cmd_agent_connect(
    client: Option<&str>,
    only: &[String],
    allow_tag: &[String],
    allow_exec: bool,
    ttl: &str,
    name: &str,
    vault_path: &str,
) {
    use murk_cli::connect;
    let project_dir = project_dir_of(vault_path);
    let known = || {
        connect::ADAPTERS
            .iter()
            .map(|a| a.id)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let targets: Vec<&connect::ClientAdapter> = match client {
        Some(id) => vec![connect::adapter(id).unwrap_or_else(|| {
            die(
                &format_args!("unknown editor '{id}' — known: {}", known()),
                2,
            )
        })],
        None => {
            let found = connect::detect(&project_dir);
            if found.is_empty() {
                die(
                    &format_args!("no AI editor config detected here — name one: {}", known()),
                    1,
                );
            }
            found
        }
    };

    // One scoped grant for the vault; every target editor points at its key file.
    // A second connect reuses the existing grant rather than re-minting, but only
    // when the requested scope matches — an editor never silently gets a grant
    // wider or narrower than the command line asked for.
    let allow = (!allow_tag.is_empty()).then_some(allow_tag);
    let (_v, existing, _id) = load_vault(vault_path);
    let key_path = if let Some(entry) = existing.grants.get(name) {
        let norm = |xs: &[String]| {
            let mut v: Vec<String> = xs.to_vec();
            v.sort_unstable();
            v.dedup();
            v
        };
        if norm(only) != norm(&entry.scope) {
            die(
                &format_args!(
                    "grant '{name}' already exists scoped to [{}] — run `murk agent disconnect --name {name} --rotate` to re-scope",
                    entry.scope.join(", ")
                ),
                1,
            );
        }
        if !allow_tag.is_empty() {
            eprintln!(
                "  {} grant {} already exists — --allow-tag not re-applied",
                "⚠".yellow(),
                name.bold()
            );
        }
        let p = try_or_die(murk_cli::agent_key_file_path(vault_path, name));
        if !p.exists() {
            die(
                &format_args!(
                    "grant '{name}' exists but its key file is gone — `murk agent disconnect --name {name} --rotate`, then reconnect"
                ),
                1,
            );
        }
        eprintln!(
            "{} reusing grant {} ({} key{})",
            "◆".magenta(),
            name.bold(),
            entry.scope.len(),
            if entry.scope.len() == 1 { "" } else { "s" }
        );
        p.display().to_string()
    } else {
        let Some(p) = mint_grant(name, only, ttl, false, None, allow, vault_path) else {
            return;
        };
        p
    };
    let extra_args: Vec<String> = allow_exec
        .then(|| "--allow-exec".to_string())
        .into_iter()
        .collect();

    eprintln!();
    let mut failed = false;
    for adapter in &targets {
        match connect::connect_client(adapter, &project_dir, &key_path, &extra_args) {
            Ok(outcome) => {
                eprintln!(
                    "{} {} — {} {}",
                    "ok".green().bold(),
                    adapter.display.bold(),
                    if outcome.created {
                        "created"
                    } else {
                        "updated"
                    },
                    outcome.path.display().to_string().dimmed()
                );
                offer_gitignore(&project_dir, &outcome.path);
            }
            Err(e) => {
                eprintln!("{} {}: {e}", "✗".red(), adapter.display);
                failed = true;
            }
        }
    }

    eprintln!();
    eprintln!(
        "  {}",
        format!(
            "restart the editor to load the server; remove it with `murk agent disconnect --name {name}`"
        )
        .dimmed()
    );
    print_ttl_advisory();
    if failed {
        process::exit(1);
    }
}

fn cmd_agent_disconnect(client: Option<&str>, rotate: bool, name: &str, vault_path: &str) {
    use murk_cli::connect;
    let project_dir = project_dir_of(vault_path);
    let targets: Vec<&connect::ClientAdapter> = match client {
        Some(id) => vec![connect::adapter(id).unwrap_or_else(|| {
            let known = connect::ADAPTERS
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>()
                .join(", ");
            die(&format_args!("unknown editor '{id}' — known: {known}"), 2)
        })],
        None => connect::ADAPTERS.iter().collect(),
    };

    let mut removed_any = false;
    let mut failed = false;
    for adapter in &targets {
        match connect::disconnect_client(adapter, &project_dir) {
            Ok(Some(path)) => {
                removed_any = true;
                eprintln!(
                    "{} {} — removed murk from {}",
                    "ok".green().bold(),
                    adapter.display.bold(),
                    path.display().to_string().dimmed()
                );
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("{} {}: {e}", "✗".red(), adapter.display);
                failed = true;
            }
        }
    }
    if !removed_any {
        eprintln!("{} no murk MCP entries found to remove", "◆".magenta());
    }

    if rotate {
        eprintln!();
        cmd_agent_revoke(name, true, vault_path);
    } else {
        eprintln!(
            "  {}",
            format!("the grant is still live — add --rotate (or `murk agent revoke {name} --rotate`) to close it")
                .dimmed()
        );
    }
    if failed {
        process::exit(1);
    }
}

fn cmd_agent_init(
    name: &str,
    only: &[String],
    allow_tags: &[String],
    ttl: &str,
    out: Option<&str>,
    vault_path: &str,
) {
    let allow = if allow_tags.is_empty() {
        None
    } else {
        Some(allow_tags)
    };
    if let Some(path) = mint_grant(name, only, ttl, false, out, allow, vault_path) {
        print_grant_handoff(only, &path);
        print_isolation_snippet();
    }
    print_ttl_advisory();
}

/// A concrete isolation recipe. murk's env guardrails are a safe default, but the
/// real boundary is the OS — show how to run the agent where it can't read the
/// operator's key directory.
fn print_isolation_snippet() {
    eprintln!();
    eprintln!(
        "  {}",
        "isolation (murk is a guardrail, not a sandbox): run the command".dimmed()
    );
    eprintln!(
        "  {}",
        "  above as an identity that CANNOT read ~/.config/murk — a separate".dimmed()
    );
    eprintln!(
        "  {}",
        "  user or container — with only the grant key file readable to it.".dimmed()
    );
}

fn cmd_agent_ls(json: bool, vault_path: &str) {
    let (_vault, murk, _identity) = load_vault(vault_path);
    let now = chrono::Utc::now();

    if json {
        let grants: Vec<serde_json::Value> = murk
            .grants
            .iter()
            .map(|(name, g)| {
                serde_json::json!({
                    "name": name,
                    "pubkey": g.pubkey,
                    "scope": g.scope,
                    "issued_at": g.issued_at,
                    "expires_at": g.expires_at,
                    "expired": grant_is_expired(&g.expires_at, now),
                })
            })
            .collect();
        let mut s = serde_json::to_string_pretty(&grants).unwrap();
        s.push('\n');
        print!("{s}");
        return;
    }

    if murk.grants.is_empty() {
        eprintln!("{} no active grants", "◆".magenta());
        return;
    }

    for (name, g) in &murk.grants {
        let status = grant_status(&g.expires_at, now);
        eprintln!(
            "{} {}  {}  {}",
            "◆".magenta(),
            name.bold(),
            murk_cli::truncate_pubkey(&g.pubkey).dimmed(),
            status,
        );
        eprintln!("  {}", g.scope.join(", ").dimmed());
    }
}

fn cmd_agent_revoke(name: &str, rotate: bool, vault_path: &str) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    // Remove the grant record, then revoke its ephemeral recipient (which clears
    // the agent's scoped ciphertexts). Persist before rotating so the agent is
    // durably gone even if the rotation prompts are aborted.
    let grant = try_or_die(murk_cli::remove_grant(&mut current, name));
    try_or_die(murk_cli::revoke_recipient(
        &mut vault,
        &mut current,
        &grant.pubkey,
    ));
    save_vault(vault_path, &mut vault, &original, &current);

    eprintln!("{} revoked grant {}", "◆".magenta(), name.bold());

    // The agent could read exactly its scope (it was never in the shared layer),
    // so rotate those keys — that's the real close, since the handed-off key can
    // still decrypt old `.murk` versions from git history.
    if !grant.scope.is_empty() {
        let n = grant.scope.len();
        let plural = if n == 1 { "" } else { "s" };
        eprintln!();
        eprintln!(
            "{} the agent could read {n} secret{plural} — rotate them:",
            "⚠".yellow(),
        );
        for key in &grant.scope {
            eprintln!("  {} {}", "▸".dimmed(), key.bold());
        }
        eprintln!();

        let do_rotate = rotate
            || (io::stdin().is_terminal() && confirm(&format!("rotate {n} secret{plural} now?")));
        if do_rotate {
            rotate_exposed(vault_path, &mut vault, &current, &grant.scope, &identity);
        } else {
            eprintln!(
                "  {}",
                "run `murk rotate KEY` to rotate each secret".dimmed()
            );
        }
    }
    eprintln!();
    eprintln!(
        "  {}",
        "the agent's key can still decrypt previous versions from git history".dimmed()
    );
}

/// True if `expires_at` (ISO-8601 UTC) is in the past.
fn grant_is_expired(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|e| e.with_timezone(&chrono::Utc) <= now)
        .unwrap_or(false)
}

/// A colored status string for a grant: time remaining, or how long expired.
fn grant_status(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return format!("expires {expires_at}").dimmed().to_string();
    };
    let exp = exp.with_timezone(&chrono::Utc);
    if exp <= now {
        format!("expired {} ago", human_duration(now - exp))
            .yellow()
            .to_string()
    } else {
        format!("expires in {}", human_duration(exp - now))
            .green()
            .to_string()
    }
}

/// Render a duration roughly, e.g. `2h`, `45m`, `3d`. Coarse on purpose — grant
/// TTLs are advisory, so minute-precision is plenty.
fn human_duration(d: chrono::Duration) -> String {
    let secs = d.num_seconds().abs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn cmd_agent_plan(tags: &[String], json: bool, output: Option<&str>, vault_path: &str) {
    let vault = murk_cli::vault::read(Path::new(vault_path)).unwrap_or_else(|e| die(&e, 1));
    let plan = murk_cli::agent_plan(&vault, tags);

    let rendered = if json {
        let mut s = serde_json::to_string_pretty(&plan).unwrap();
        s.push('\n');
        s
    } else {
        murk_cli::format_agent_plan_text(&plan)
    };

    match output {
        Some(path) => {
            fs::write(path, &rendered).unwrap_or_else(|e| die(&e, 1));
            eprintln!(
                "{} wrote agent plan to {}",
                "ok".green().bold(),
                path.bold()
            );
        }
        None => print!("{rendered}"),
    }
}

/// A single finding produced by a check command (`verify`, `doctor`, ...).
/// Each check either passes silently or pushes a `Finding` describing what's
/// wrong and how to fix it. See `docs/cli-style.md` for the output contract.
struct Finding {
    /// Short category tag for the failing-item line (e.g. "mac", "recipients").
    category: &'static str,
    /// One-line human-readable message.
    message: String,
    /// Optional fix hint, printed dimmed under the parent line.
    fix: Option<String>,
}

/// Emit a list of findings to stderr per the CLI style guide and exit(1) if
/// any exist. `header` is a single verb-phrase like "vault" or "repo" — the
/// reporter prints "warn N issue{s} in {header}" above the list.
///
/// Returns `()` on no findings. Exits the process on any finding — callers
/// should finish any "ok" lines before calling this.
fn report_findings(findings: &[Finding], header: &str) {
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

/// Human label for a signer pubkey: its recipient display name, or a truncated
/// key. Tolerates ssh-ed25519 comment mismatches — the name map may be keyed by
/// `ssh-ed25519 <blob> comment` while the signer is the comment-stripped form.
fn signer_display_name(murk: &types::Murk, signer: &str) -> String {
    if let Some(name) = murk.recipients.get(signer) {
        return name.clone();
    }
    if signer.starts_with("ssh-ed25519 ")
        && let Some((_, name)) = murk
            .recipients
            .iter()
            .find(|(pk, _)| murk_cli::signing::ssh_ed25519_key_eq(pk, signer))
    {
        return name.clone();
    }
    murk_cli::truncate_pubkey(signer)
}

fn cmd_verify(vault_path: &str) {
    // Load the vault first — MAC/integrity failure short-circuits the rest
    // of the checks with the hard error from the loader.
    let (vault, murk, _identity) = load_vault(vault_path);

    let mut findings: Vec<Finding> = Vec::new();

    if murk.legacy_mac {
        findings.push(Finding {
            category: "mac",
            message: "vault uses legacy unkeyed MAC".into(),
            fix: Some("run any write command (e.g. `murk describe`) to upgrade to BLAKE3".into()),
        });
    }

    // Signature status — the real content-integrity anchor. A valid signature
    // proves a recipient authored the current vault; the MAC alone can't (a
    // repo-writer can forge it). An invalid signature would already have failed
    // the load above, so here it is only Signed or Unsigned.
    match &murk.signature {
        types::SignatureState::Signed {
            signer,
            anchored: true,
        } => {
            eprintln!(
                "{} signature  signed by {}",
                "ok".green().bold(),
                signer_display_name(&murk, signer).dimmed()
            );
        }
        // Age signer whose key isn't pinned yet (fresh clone): the signature is
        // trust-on-first-use, not authenticated authorship. Don't present it as a
        // clean "signed by" — warn and point at the real anchor. Not a hard
        // finding: for the vault's own author this is the normal first load, and
        // the key is pinned now, so later tampering is caught.
        types::SignatureState::Signed {
            signer,
            anchored: false,
        } => {
            eprintln!(
                "{} signature  signed by {} — {}",
                "warn".yellow().bold(),
                signer_display_name(&murk, signer).dimmed(),
                "trust-on-first-use (key not yet anchored on this machine); anchor authorship with signed git commits, or use an ssh-ed25519 key".dimmed()
            );
        }
        types::SignatureState::Unsigned
            if !vault.secrets.is_empty() && !murk.signature_downgraded =>
        {
            findings.push(Finding {
                category: "signature",
                message: "vault is unsigned — content integrity relies on git".into(),
                fix: Some(
                    "run any write command with an age or ssh-ed25519 key to sign it; ssh-rsa and hardware/plugin keys cannot sign".into(),
                ),
            });
        }
        types::SignatureState::Unsigned => {}
    }

    // A vault signed before and unsigned now — the sharper signal. Fail the check
    // (report_findings exits non-zero) so `verify` asserts, not just warns.
    if murk.signature_downgraded {
        findings.push(Finding {
            category: "signature",
            message: "vault was signed before and is now unsigned — signature stripped, or a merge left it unsigned".into(),
            fix: Some(
                "re-sign with any write command after reviewing `murk diff`; if the downgrade is unexpected, inspect `git log -p`".into(),
            ),
        });
    }

    // Git anchor — is the vault's latest commit signed? The vault signature
    // covers content; a signed commit covers who landed it. Only surfaced when
    // there is a git history to check.
    match murk_cli::last_commit_signature(vault_path) {
        Some(murk_cli::CommitSignature::Good | murk_cli::CommitSignature::Unverified) => {
            eprintln!(
                "{} commit  last .murk commit is signed",
                "ok".green().bold()
            );
        }
        Some(murk_cli::CommitSignature::Bad) => {
            findings.push(Finding {
                category: "commit",
                message: "last .murk commit has a bad signature".into(),
                fix: Some(
                    "inspect `git log --show-signature -- .murk` — history may be tampered".into(),
                ),
            });
        }
        Some(murk_cli::CommitSignature::Unsigned) => {
            findings.push(Finding {
                category: "commit",
                message: "last .murk commit is unsigned".into(),
                fix: Some(
                    "enable commit signing and protect the branch so vault history is attributable"
                        .into(),
                ),
            });
        }
        None => {}
    }

    // The vault file itself is public-by-design, so we don't care about read
    // perms. We do care about *write* perms: a group-writable vault is an
    // easy way for a local attacker to tamper with ciphertext.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(vault_path) {
            let mode = meta.mode() & 0o777;
            if mode & 0o022 != 0 {
                findings.push(Finding {
                    category: "perms",
                    message: format!("vault file is group/world writable (mode {mode:o})"),
                    fix: Some(format!("chmod 644 {vault_path}")),
                });
            }
        }
    }

    // After the .env kill, every valid key source is safe. Re-resolve
    // explicitly so verify can surface where the key came from — transparency
    // about key provenance is the point.
    match murk_cli::resolve_key_with_source(vault_path) {
        Ok((_, source)) => {
            eprintln!(
                "{} key  {}",
                "ok".green().bold(),
                source.describe().dimmed()
            );
        }
        Err(msg) => {
            findings.push(Finding {
                category: "key",
                message: format!("cannot resolve a key: {msg}"),
                fix: None,
            });
        }
    }

    let rsa_recipients: Vec<&String> = vault
        .recipients
        .iter()
        .filter(|r| r.starts_with("ssh-rsa "))
        .collect();
    if !rsa_recipients.is_empty() {
        findings.push(Finding {
            category: "recipients",
            message: format!(
                "{} ssh-rsa recipient{} present",
                rsa_recipients.len(),
                if rsa_recipients.len() == 1 { "" } else { "s" }
            ),
            fix: Some("rotate to ed25519 keys and `murk revoke` the old ssh-rsa recipients".into()),
        });
    }

    if findings.is_empty() {
        eprintln!("{} vault integrity verified", "ok".green().bold());
        eprintln!("{} no safety issues found", "ok".green().bold());
        return;
    }

    eprintln!("{} vault integrity verified", "ok".green().bold());
    report_findings(&findings, "vault");
}

fn cmd_doctor(vault_path: &str) {
    // doctor is repo-level hygiene — most checks are about the working tree:
    // env files, key files sitting next to the vault, obvious commit-would-be-bad
    // state. It also reads the vault's plaintext schema (no key needed) to flag
    // rotation/expiry drift.
    let mut findings: Vec<Finding> = Vec::new();

    let cwd = std::env::current_dir().unwrap_or_else(|e| die(&e, 1));

    // ── .env contains an inline MURK_KEY ──
    // After the .env kill this is dead config AND a historical footgun.
    // Previously-committed .env files with inline keys are still out there.
    let env_path = cwd.join(".env");
    if env_path.exists()
        && let Ok(contents) = std::fs::read_to_string(&env_path)
    {
        let has_inline = contents.lines().any(|l| {
            let t = l.trim_start();
            (t.starts_with("MURK_KEY=") || t.starts_with("export MURK_KEY="))
                && !t.starts_with("MURK_KEY_FILE=")
                && !t.starts_with("export MURK_KEY_FILE=")
        });
        if has_inline {
            findings.push(Finding {
                category: "dotenv",
                message: "inline MURK_KEY in .env (dead config, risk of commit)".into(),
                fix: Some("remove the MURK_KEY= line and re-run `murk init`".into()),
            });
        }
    }

    // ── .env is not in .gitignore ──
    // Soft guardrail: an untracked .env is fine for local dev, but a .env
    // that isn't excluded from git has probably slipped into a commit
    // somewhere. Ask git directly via `check-ignore` so we respect nested
    // .gitignore files, global excludes, and negated rules.
    if env_path.exists()
        && cwd.join(".git").exists()
        && let Ok(output) = std::process::Command::new("git")
            .args(["check-ignore", "--quiet", ".env"])
            .current_dir(&cwd)
            .status()
        && !output.success()
    {
        findings.push(Finding {
            category: "gitignore",
            message: ".env is not excluded from git".into(),
            fix: Some("add `.env` to .gitignore so it cannot be committed".into()),
        });
    }

    // ── Key file is inside the working tree ──
    // `murk init` puts the key file under ~/.config/murk/keys by default,
    // which is outside any repo. But MURK_KEY_FILE can be set to anywhere,
    // and a user who put it next to the vault has just opted in to
    // committing their private key. Fail loudly.
    if let Ok((_, source)) = murk_cli::resolve_key_with_source(".murk")
        && let murk_cli::KeySource::EnvFile(path) | murk_cli::KeySource::Auto(path) = source
        && let Ok(abs) = std::fs::canonicalize(&path)
        && let Ok(repo) = std::fs::canonicalize(&cwd)
        && abs.starts_with(&repo)
    {
        findings.push(Finding {
            category: "keyfile",
            message: format!("key file {} is inside the working tree", abs.display()),
            fix: Some(
                "move it out of the repo (e.g. ~/.config/murk/keys/) and update MURK_KEY_FILE"
                    .into(),
            ),
        });
    }

    // ── Rotation / expiry drift ──
    // Read-only over the plaintext schema (no decryption). Skipped silently when
    // there's no readable vault — doctor still reports the repo-hygiene findings.
    if let Ok((vault, _raw)) = murk_cli::vault::read_with_raw(Path::new(vault_path)) {
        for issue in murk_cli::rotation_health(&vault, chrono::Utc::now()) {
            findings.push(rotation_finding(&issue));
        }
    }

    if findings.is_empty() {
        eprintln!("{} repo hygiene looks clean", "ok".green().bold());
        return;
    }

    report_findings(&findings, "repo");
}

/// Render a [`murk_cli::RotationIssue`] as a doctor [`Finding`].
fn rotation_finding(issue: &murk_cli::RotationIssue) -> Finding {
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
        BadTimestamp { key, field, value } => Finding {
            category: "schema",
            message: format!("{key} has an unparseable {field} timestamp ({value})"),
            fix: Some("re-set it with a write command, or fix it by hand".into()),
        },
    }
}

fn cmd_completion_generate(shell: clap_complete::Shell) {
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut io::stdout());
}

fn cmd_completion_install(shell: clap_complete::Shell) {
    use clap_complete::Shell;

    let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));

    let (dir, filename) = match shell {
        Shell::Zsh => {
            let dir = format!("{home}/.zfunc");
            (dir, "_murk".to_string())
        }
        Shell::Bash => {
            let dir = format!("{home}/.local/share/bash-completion/completions");
            (dir, "murk".to_string())
        }
        Shell::Fish => {
            let dir = format!("{home}/.config/fish/completions");
            (dir, "murk.fish".to_string())
        }
        Shell::Elvish => {
            let dir = format!("{home}/.config/elvish/lib");
            (dir, "murk.elv".to_string())
        }
        Shell::PowerShell => {
            let dir = format!("{home}/.config/powershell");
            (dir, "_murk.ps1".to_string())
        }
        _ => die(&format!("unsupported shell: {shell}"), 1),
    };

    fs::create_dir_all(&dir).unwrap_or_else(|e| die(&format!("failed to create {dir}: {e}"), 1));

    let path = format!("{dir}/{filename}");
    let mut file =
        fs::File::create(&path).unwrap_or_else(|e| die(&format!("failed to write {path}: {e}"), 1));
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut file);

    eprintln!("{} wrote {}", "ok".green().bold(), path);

    match shell {
        Shell::Zsh => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.zshrc".bold()
            );
            eprintln!("  fpath+=~/.zfunc");
            eprintln!("  autoload -Uz compinit && compinit");
        }
        Shell::Bash => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.bashrc".bold()
            );
            eprintln!(
                "  [[ -r ~/.local/share/bash-completion/completions/murk ]] && \
                 source ~/.local/share/bash-completion/completions/murk"
            );
        }
        Shell::Fish => {
            eprintln!(
                "\n{} completions are loaded automatically by fish",
                "hint".cyan().bold()
            );
        }
        _ => {}
    }
}

fn main() {
    // clap's derive-generated parser uses large stack frames, and the command
    // tree here is big. On Windows the default 1 MiB main-thread stack can
    // overflow during argument parsing, so run everything on a thread with a
    // generous stack. (Other platforms default to ~8 MiB and are unaffected, but
    // running uniformly keeps behavior consistent.)
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawn main thread");
    // Propagate a panic in `run` as a non-zero exit, same as a normal main.
    if handle.join().is_err() {
        process::exit(1);
    }
}

fn run() {
    murk_cli::hardening::disable_core_dumps();
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore { vault } => cmd_restore(&vault),
        Command::Import {
            file,
            force,
            group,
            vault,
        } => {
            cmd_import(
                &file,
                force,
                group.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            );
        }
        Command::Add {
            key,
            desc,
            group,
            scoped,
            tag,
            vault,
        } => {
            let vault = murk_cli::resolve_vault_path(&vault);
            let resolved = resolve_value(&key);
            cmd_add(
                &key,
                &resolved,
                desc.as_deref(),
                group.as_deref(),
                scoped,
                &tag,
                &vault,
            );
        }
        Command::Generate {
            key,
            length,
            hex,
            desc,
            group,
            tag,
            vault,
        } => cmd_generate(
            &key,
            length,
            hex,
            desc.as_deref(),
            group.as_deref(),
            &tag,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Rotate {
            key,
            all,
            generate,
            length,
            hex,
            list,
            json,
            vault,
        } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            if list {
                cmd_rotate_list(json, &vault_path);
            } else {
                cmd_rotate(key.as_deref(), all, generate, length, hex, &vault_path);
            }
        }
        Command::Rm { key, vault } => cmd_rm(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Get { key, vault } => cmd_get(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Ls { tag, json, vault } => {
            cmd_ls(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Describe {
            key,
            description,
            example,
            tag,
            rotate_every,
            expires,
            vault,
        } => cmd_describe(
            &key,
            &description,
            example.as_deref(),
            &tag,
            rotate_every.as_deref(),
            expires.as_deref(),
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Info { tag, json, vault } => {
            cmd_info(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Export { tag, json, vault } => {
            cmd_export(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Edit {
            key,
            scoped,
            group,
            vault,
        } => {
            cmd_edit(
                key.as_deref(),
                scoped,
                group.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            );
        }
        Command::Exec {
            only,
            tag,
            clean_env,
            vault,
            command,
        } => cmd_exec(
            &command,
            &only,
            &tag,
            clean_env,
            /* agent_mode */ false,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Authorize {
            pubkey,
            name,
            force,
            allow_ssh_rsa,
            vault,
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            None,
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Revoke {
            recipient,
            rotate,
            vault,
        } => {
            cmd_revoke(&recipient, rotate, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Circle {
            sub: None,
            json,
            vault,
        } => cmd_recipients(json, &murk_cli::resolve_vault_path(&vault)),
        Command::Circle {
            sub:
                Some(CircleCommand::Authorize {
                    pubkey,
                    name,
                    group,
                    force,
                    allow_ssh_rsa,
                    vault,
                }),
            ..
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            group.as_deref(),
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Circle {
            sub:
                Some(CircleCommand::Revoke {
                    recipient,
                    rotate,
                    vault,
                }),
            ..
        } => cmd_revoke(&recipient, rotate, &murk_cli::resolve_vault_path(&vault)),
        Command::Group { sub } => cmd_group(sub),
        Command::Policy { sub } => cmd_policy(sub),
        Command::Env { vault } => cmd_env(&vault),
        Command::Diff {
            git_ref,
            show_values,
            json,
            vault,
        } => cmd_diff(
            &git_ref,
            show_values,
            json,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::MergeDriver { base, ours, theirs } => cmd_merge_driver(&base, &ours, &theirs),
        Command::SetupMergeDriver => cmd_setup_merge_driver(),
        Command::Verify { vault } => cmd_verify(&murk_cli::resolve_vault_path(&vault)),
        Command::Doctor { vault } => cmd_doctor(&murk_cli::resolve_vault_path(&vault)),
        Command::Skeleton { output, vault } => {
            cmd_skeleton(output.as_deref(), &murk_cli::resolve_vault_path(&vault));
        }
        Command::Agent { sub } => match sub {
            AgentCommand::Plan {
                tag,
                json,
                output,
                vault,
            } => cmd_agent_plan(
                &tag,
                json,
                output.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Exec {
                only,
                vault,
                command,
            } => cmd_agent_exec(&command, &only, &murk_cli::resolve_vault_path(&vault)),
            AgentCommand::Grant {
                name,
                only,
                ttl,
                renew,
                out,
                vault,
            } => cmd_agent_grant(
                &name,
                &only,
                &ttl,
                renew,
                out.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Init {
                name,
                only,
                allow_tag,
                ttl,
                out,
                vault,
            } => cmd_agent_init(
                &name,
                &only,
                &allow_tag,
                &ttl,
                out.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Ls { json, vault } => {
                cmd_agent_ls(json, &murk_cli::resolve_vault_path(&vault));
            }
            AgentCommand::Revoke {
                name,
                rotate,
                vault,
            } => cmd_agent_revoke(&name, rotate, &murk_cli::resolve_vault_path(&vault)),
            AgentCommand::Connect {
                client,
                only,
                allow_tag,
                allow_exec,
                ttl,
                name,
                vault,
            } => cmd_agent_connect(
                client.as_deref(),
                &only,
                &allow_tag,
                allow_exec,
                &ttl,
                &name,
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Disconnect {
                client,
                rotate,
                name,
                vault,
            } => cmd_agent_disconnect(
                client.as_deref(),
                rotate,
                &name,
                &murk_cli::resolve_vault_path(&vault),
            ),
        },
        Command::Scan { paths, vault } => {
            cmd_scan(&paths, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Mcp { vault, allow_exec } => {
            cmd_mcp(&murk_cli::resolve_vault_path(&vault), allow_exec)
        }
        Command::Completion { action } => match action {
            CompletionAction::Generate { shell } => cmd_completion_generate(shell),
            CompletionAction::Install { shell } => cmd_completion_install(shell),
        },
    }
}

#[cfg(test)]
mod cli_structure {
    //! Structural guards over the clap command tree.
    //!
    //! murk keeps each command's handler in a flat `cmd_<name>` function
    //! dispatched from the exhaustive `match` in [`run`], so "every subcommand
    //! has a handler" is already enforced by the compiler — a missing arm won't
    //! build. What the compiler does *not* catch is a subcommand shipped without
    //! help text, or one that no integration test ever exercises. These tests
    //! close both gaps so the CLI surface stays coherent as it grows.

    use clap::CommandFactory;

    use super::Cli;

    /// Collect `(path, has_about)` for every subcommand at any depth, where
    /// `path` is the space-joined invocation (e.g. `"circle authorize"`).
    fn collect(cmd: &clap::Command, prefix: &str, out: &mut Vec<(String, bool)>) {
        for sub in cmd.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            out.push((path.clone(), sub.get_about().is_some()));
            collect(sub, &path, out);
        }
    }

    #[test]
    fn every_subcommand_has_help() {
        let mut subs = Vec::new();
        collect(&Cli::command(), "", &mut subs);

        // Guard against the walk silently finding an empty tree.
        assert!(
            subs.len() >= 25,
            "expected the full command surface, only found {}: {:?}",
            subs.len(),
            subs.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );

        let missing: Vec<&String> = subs
            .iter()
            .filter(|(_, has_about)| !has_about)
            .map(|(path, _)| path)
            .collect();
        assert!(
            missing.is_empty(),
            "these subcommands ship without an about/help string: {missing:?}"
        );
    }

    #[test]
    fn every_top_level_subcommand_has_an_integration_test() {
        // Nested subcommands (e.g. `circle authorize`) are covered transitively
        // through their parent and by `every_subcommand_has_help`; here we only
        // assert each top-level command is actually invoked somewhere in the
        // integration suite, so a new command cannot ship untested.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let sources: String = ["tests/cli.rs", "tests/adversarial.rs"]
            .iter()
            .map(|rel| {
                std::fs::read_to_string(format!("{manifest}/{rel}"))
                    .unwrap_or_else(|e| panic!("reading {rel}: {e}"))
            })
            .collect();

        let untested: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .filter(|name| !sources.contains(&format!("\"{name}\"")))
            .collect();
        assert!(
            untested.is_empty(),
            "these top-level subcommands are never invoked by an integration test: {untested:?}"
        );
    }
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

#[cfg(test)]
mod restore_check {
    use super::restored_key_is_recipient;

    fn vault_json(recipients: &[&str]) -> String {
        let recips = recipients
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"version":"2.0","created":"2026-01-01T00:00:00Z","vault_name":".murk","recipients":[{recips}],"schema":{{}},"secrets":{{}},"meta":""}}"#
        )
    }

    #[test]
    fn recipient_membership_detected() {
        let (_mnemonic, secret, pubkey) = murk_cli::recovery::generate().unwrap();

        // Restored identity IS a recipient — no warning.
        assert_eq!(
            restored_key_is_recipient(&secret, &vault_json(&[pubkey.as_str()])),
            Some(true)
        );
        // Valid-but-wrong phrase case: derived identity is absent from recipients.
        assert_eq!(
            restored_key_is_recipient(&secret, &vault_json(&["age1notyou"])),
            Some(false)
        );
        // Unparseable vault must not raise a false alarm.
        assert_eq!(restored_key_is_recipient(&secret, "{ not json"), None);
    }
}
