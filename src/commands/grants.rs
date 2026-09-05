use super::*;
use colored::Colorize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process;

/// Run the MCP (Model Context Protocol) stdio server.
///
/// Fails closed unless this is a scoped *agent* identity — a grant key plus
/// `MURK_AGENT=1`. Running the server with the operator's stored key (or any
/// non-grant recipient) would hand a connected agent the operator's full read
/// scope over MCP, defeating the point, so both the agent-context opt-in and a
/// grant identity are required. stdout is the JSON-RPC channel; every diagnostic
/// here goes to stderr.
pub(crate) fn cmd_mcp(vault_path: &str, allow_exec: bool) {
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

    try_or_die(crate::mcp::serve(
        crate::mcp::McpState {
            vault,
            murk,
            pubkey,
        },
        allow_exec,
    ));
}

pub(crate) fn cmd_skeleton(output: Option<&str>, vault_path: &str) {
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

pub(crate) fn cmd_agent_exec(command: &[String], only: &[String], vault_path: &str) {
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
pub(crate) fn mint_grant(
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
pub(crate) fn print_ttl_advisory() {
    eprintln!();
    eprintln!(
        "  {}",
        "reads fail closed after the TTL — `murk agent revoke` + rotate is still the real close"
            .dimmed()
    );
}

pub(crate) fn cmd_agent_grant(
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
pub(crate) fn print_grant_handoff(only: &[String], key_path: &str) {
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
pub(crate) fn project_dir_of(vault_path: &str) -> std::path::PathBuf {
    Path::new(vault_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// A project-local MCP config is often committed. It only ever holds a
/// machine-specific key-file *path* (never key material), but committing it is
/// per-machine noise and leaks the grant name — so warn, and offer to ignore it.
pub(crate) fn offer_gitignore(project_dir: &Path, config_path: &Path) {
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

pub(crate) fn cmd_agent_connect(
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

pub(crate) fn cmd_agent_disconnect(
    client: Option<&str>,
    rotate: bool,
    name: &str,
    vault_path: &str,
) {
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

pub(crate) fn cmd_agent_init(
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
pub(crate) fn print_isolation_snippet() {
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

pub(crate) fn cmd_agent_ls(json: bool, vault_path: &str) {
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

pub(crate) fn cmd_agent_revoke(name: &str, rotate: bool, vault_path: &str) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
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
            rotate_exposed(vault_path, &mut vault, &current, &grant.scope);
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
pub(crate) fn grant_is_expired(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|e| e.with_timezone(&chrono::Utc) <= now)
        .unwrap_or(false)
}

/// A colored status string for a grant: time remaining, or how long expired.
pub(crate) fn grant_status(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
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
pub(crate) fn human_duration(d: chrono::Duration) -> String {
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

pub(crate) fn cmd_agent_plan(tags: &[String], json: bool, output: Option<&str>, vault_path: &str) {
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
