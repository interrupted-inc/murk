// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Write the rendered output of `skeleton -o` / `agent plan -o` to a *new* file.
///
/// Both commands are keyless, read-only and safe to auto-approve for an agent,
/// so a path argument must never be able to destroy anything. The file is
/// created with `create_new` (`O_EXCL`), which fails when *anything* is already
/// at `path`: a regular file, the vault itself, or a symlink — even a dangling
/// one, which `O_EXCL` refuses instead of following. Nothing is truncated and
/// nothing is written through a link. There is deliberately no overwrite flag:
/// replacing a file takes an explicit `rm` first.
fn write_new_output(path: &str, contents: &str, vault_path: &str) -> Result<(), String> {
    use std::io::Write;

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let is_vault = matches!(
                (fs::canonicalize(path), fs::canonicalize(vault_path)),
                (Ok(out), Ok(vault)) if out == vault
            );
            return Err(if is_vault {
                format!(
                    "refusing to write {path}: it is the vault\n\
                     choose a path that does not exist yet"
                )
            } else {
                format!(
                    "refusing to overwrite {path}: it already exists (a file or a symlink)\n\
                     choose a path that does not exist yet, or remove it first"
                )
            });
        }
        Err(e) => return Err(format!("cannot write {path}: {e}")),
    };

    if let Err(e) = file.write_all(contents.as_bytes()) {
        // This call created the file, so a partial one is ours to clean up.
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("cannot write {path}: {e}"));
    }
    Ok(())
}

pub(crate) fn cmd_skeleton(output: Option<&str>, vault_path: &str) {
    let vault = murk_cli::vault::read(Path::new(vault_path)).unwrap_or_else(|e| die(&e, 1));

    let skeleton = murk_cli::types::Vault {
        version: vault.version,
        created: vault.created,
        vault_name: vault.vault_name,
        repo: vault.repo,
        // A skeleton is a new vault's starting shape, not this vault: no
        // identity, no counter.
        vault_id: String::new(),
        generation: 0,
        agents: BTreeMap::new(),
        sig: None,
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
            try_or_die(write_new_output(path, &format!("{json}\n"), vault_path));
            eprintln!("{} wrote skeleton to {}", "ok".green().bold(), path.bold());
        }
        None => println!("{json}"),
    }
}

/// `murk agent exec`: run `command` with only the `--only` keys injected.
///
/// Needs an agent grant key. The operator's auto-discovered personal key
/// (`~/.config/murk/keys`) is refused before the vault is loaded, and any other
/// non-grant key (an exported `MURK_KEY_FILE`, say from direnv) is refused by
/// identity once the vault is open, before any secret is resolved. The
/// operator's deliberate `--allow-operator-key` lifts both, with a warning.
pub(crate) fn cmd_agent_exec(
    command: &[String],
    only: &[String],
    allow_operator_key: bool,
    allow_reserved: bool,
    vault_path: &str,
) {
    // A resolution error falls through: `load_vault` reports it with its hints.
    let auto_key = matches!(
        murk_cli::resolve_key_with_source(vault_path),
        Ok((_, murk_cli::KeySource::Auto(_)))
    );
    if auto_key && !allow_operator_key {
        die(
            &"agent exec refuses your personal key (~/.config/murk/keys)\n\
              an agent run must present its own key, not auto-discover yours\n\
              point MURK_KEY_FILE at a grant key (mint one: `murk agent init`)\n\
              or pass --allow-operator-key to use your own key on purpose",
            1,
        );
    }
    if allow_operator_key {
        // The opt-in is the operator's call, so `cmd_exec` never runs it
        // silently. Its warning replaces the CI personal-key hint.
        super::suppress_agent_nudge();
    }

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
        allow_reserved,
        /* operator_key_ok */ allow_operator_key,
        vault_path,
    );
}

/// A grant just minted: where its key went (`None` when streamed to stdout)
/// and the grant's public key, captured while the vault was still locked.
pub(crate) struct Minted {
    pub(crate) path: Option<String>,
    pub(crate) pubkey: String,
}

/// Mint a scoped agent grant in one locked transaction and hand off the
/// ephemeral key. When `allow_tags` is `Some`, the vault's agent allow-list is
/// set first (so scope validation reflects it) — used by `agent init`; `None`
/// leaves the policy unchanged. A single `save_vault` covers both the optional
/// policy change and the grant.
pub(crate) fn mint_grant(
    name: &str,
    only: &[String],
    ttl: &str,
    renew: bool,
    out: Option<&str>,
    allow_tags: Option<&[String]>,
    vault_path: &str,
) -> Minted {
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
    let path = match out {
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
    };
    Minted {
        path,
        pubkey: agent_pubkey,
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
    if let Some(path) = mint_grant(name, only, ttl, renew, out, None, vault_path).path {
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
    // Reusing a grant writes no vault, but connect is still an operator action:
    // a grant key must not wire editors to grant key files.
    try_or_die(murk_cli::ensure_writable(&existing));
    // The key path is a pure function of vault and grant name, so every config
    // can be rendered with it before the grant exists.
    let key_file = try_or_die(murk_cli::agent_key_file_path(vault_path, name));
    let key_path = key_file.display().to_string();
    let reused_scope = if let Some(entry) = existing.grants.get(name) {
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
        if !key_file.exists() {
            die(
                &format_args!(
                    "grant '{name}' exists but its key file is gone — `murk agent disconnect --name {name} --rotate`, then reconnect"
                ),
                1,
            );
        }
        Some(entry.scope.len())
    } else {
        None
    };

    // A non-default vault must reach the configured `murk mcp`, or it looks for
    // `.murk` next to the config and fails with "vault file not found".
    let mut extra_args = connect::vault_args(vault_path);
    if allow_exec {
        extra_args.push("--allow-exec".to_string());
    }

    // Render every target before touching anything: a malformed or symlinked
    // config has to fail while the vault and key directory are still untouched,
    // not after a live grant has been minted for it.
    let mut edits = Vec::new();
    let mut plan_failed = false;
    for adapter in &targets {
        match connect::plan_connect(adapter, &project_dir, &key_path, &extra_args) {
            Ok(edit) => edits.push((*adapter, edit)),
            Err(e) => {
                eprintln!("{} {}: {e}", "✗".red(), adapter.display);
                plan_failed = true;
            }
        }
    }
    if plan_failed {
        die(
            &if reused_scope.is_some() {
                "no editor config was written — fix the error above and re-run"
            } else {
                "no grant was minted and no editor config was written — fix the error above and re-run"
            },
            1,
        );
    }

    let mut minted_pubkey = None;
    if let Some(keys) = reused_scope {
        eprintln!(
            "{} reusing grant {} ({} key{})",
            "◆".magenta(),
            name.bold(),
            keys,
            if keys == 1 { "" } else { "s" }
        );
    } else {
        // `out = None` lands the key at `agent_key_file_path` — the path the
        // rendered configs already carry — and always returns it.
        let minted = mint_grant(name, only, ttl, false, None, allow, vault_path);
        debug_assert_eq!(minted.path.as_deref(), Some(key_path.as_str()));
        // Remembered so a rollback only ever undoes *this* grant. It comes
        // from the mint itself, taken under the vault lock; rereading the key
        // file now could pick up a renewal that ran since.
        minted_pubkey = Some(minted.pubkey);
    }

    // All or nothing: if any write fails, undo the ones that landed and, for a
    // grant minted by this run, revoke it and delete its key file, so a failed
    // connect never leaves a live grant behind.
    eprintln!();
    let mut applied: Vec<(&connect::ClientAdapter, &connect::ConfigEdit)> = Vec::new();
    for (adapter, edit) in &edits {
        if let Err(e) = edit.apply() {
            eprintln!("{} {}: {e}", "✗".red(), adapter.display);
            let mut restored_all = true;
            for (done_adapter, done) in applied.iter().rev() {
                if let Err(e) = done.undo() {
                    restored_all = false;
                    eprintln!(
                        "{} {}: could not restore {}: {e}",
                        "✗".red(),
                        done_adapter.display,
                        done.path.display()
                    );
                }
            }
            if let Some(minted) = &minted_pubkey {
                revoke_unhanded_grant(name, &key_file, minted, vault_path);
            }
            let configs = if restored_all {
                "no editor config was changed"
            } else {
                "the editor configs named above still hold the murk entry"
            };
            die(
                &if reused_scope.is_some() {
                    format!("{configs} — fix the error above and re-run (the grant is still live)")
                } else {
                    format!(
                        "rolled back: the new grant was revoked and its key file deleted; {configs} — fix the error above and re-run"
                    )
                },
                1,
            );
        }
        applied.push((*adapter, edit));
    }
    for (adapter, edit) in &applied {
        eprintln!(
            "{} {} — {} {}",
            "ok".green().bold(),
            adapter.display.bold(),
            if edit.created { "created" } else { "updated" },
            edit.path.display().to_string().dimmed()
        );
        offer_gitignore(&project_dir, &edit.path);
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
}

/// Undo a grant this run minted but never handed to an editor: drop the record
/// and its recipient, then delete the key file. Nothing outside this process
/// has seen the key, so no rotation is owed. Only the grant with public key
/// `minted_pubkey` is touched: if the name now belongs to a different key
/// (another run renewed it meanwhile), the grant and its key file are left
/// alone.
fn revoke_unhanded_grant(name: &str, key_file: &Path, minted_pubkey: &str, vault_path: &str) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    if murk.grants.get(name).map(|g| g.pubkey.as_str()) != Some(minted_pubkey) {
        eprintln!(
            "{} grant {name} was changed by another command since this run minted it — left as is",
            "⚠".yellow()
        );
        return;
    }
    let original = murk.clone();
    let mut current = murk;
    let grant = try_or_die(murk_cli::remove_grant(&mut current, name));
    try_or_die(murk_cli::revoke_recipient(
        &mut vault,
        &mut current,
        &grant.pubkey,
    ));
    save_vault(vault_path, &mut vault, &original, &current);
    let still_ours = fs::read_to_string(key_file).is_ok_and(|k| {
        murk_cli::crypto::parse_identity(k.trim())
            .and_then(|id| id.pubkey_string())
            .is_ok_and(|pk| pk == minted_pubkey)
    });
    if !still_ours {
        return;
    }
    if let Err(e) = fs::remove_file(key_file) {
        eprintln!(
            "{} could not delete key file {}: {e}",
            "✗".red(),
            key_file.display()
        );
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
    // `--rotate` revokes the grant, which an agent grant can't do; refuse before
    // touching any editor config so a refused run changes nothing.
    if rotate {
        let (_v, murk, _id) = load_vault(vault_path);
        try_or_die(murk_cli::ensure_writable(&murk));
    }

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
    if !removed_any && !failed {
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
    if let Some(path) = mint_grant(name, only, ttl, false, out, allow, vault_path).path {
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
    // Missing or unreadable counts as expired, matching the read-time gate.
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|e| e.with_timezone(&chrono::Utc) <= now)
        .unwrap_or(true)
}

/// A colored status string for a grant: time remaining, or how long expired.
/// An expired grant no longer reads and is removed by the next vault write.
pub(crate) fn grant_status(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    const GONE: &str = "removed on the next vault write";
    if expires_at.is_empty() {
        return format!("no expiry (predates grant TTLs) — {GONE}")
            .yellow()
            .to_string();
    }
    let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return format!("unreadable expiry {expires_at:?} — {GONE}")
            .yellow()
            .to_string();
    };
    let exp = exp.with_timezone(&chrono::Utc);
    if exp <= now {
        format!("expired {} ago — {GONE}", human_duration(now - exp))
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
            try_or_die(write_new_output(path, &rendered, vault_path));
            eprintln!(
                "{} wrote agent plan to {}",
                "ok".green().bold(),
                path.bold()
            );
        }
        None => print!("{rendered}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// These tests set process env (`HOME`, `MURK_KEY`) for the in-process
    /// load/save path, so they run one at a time.
    static ENV: Mutex<()> = Mutex::new(());

    /// A fresh vault with `A` set, `HOME` and `MURK_KEY` pointed at it, and
    /// every other murk context variable cleared. Returns the dir (keep it
    /// alive), the vault path and the operator key.
    fn operator_vault() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let operator = age::x25519::Identity::generate();
        let secret = age::secrecy::ExposeSecret::expose_secret(&operator.to_string()).to_string();
        // SAFETY: serialised by `ENV`; no other test in this binary touches it.
        unsafe {
            for var in [
                "MURK_KEY_FILE",
                "MURK_VAULT",
                "MURK_AGENT",
                "MURK_STRICT",
                "MURK_SELF_SCOPE",
                "MURK_NO_SIGNER_PIN",
                "CI",
            ] {
                std::env::remove_var(var);
            }
            std::env::set_var("HOME", dir.path());
            std::env::set_var("MURK_KEY", &secret);
        }
        let vault_path = dir.path().join("test.murk").display().to_string();
        let identity = murk_cli::crypto::parse_identity(&secret).unwrap();
        let vault = murk_cli::create_vault("test.murk", &identity, "alice").unwrap();
        murk_cli::vault::write(Path::new(&vault_path), &vault).unwrap();
        murk_cli::pin_created_vault(&vault_path, &vault, &identity).unwrap();
        let (mut vault, murk, _) = murk_cli::load_vault(&vault_path).unwrap();
        let mut current = murk.clone();
        murk_cli::add_secret(
            &mut vault,
            &mut current,
            "A",
            "aval",
            None,
            None,
            false,
            &[],
            None,
        );
        murk_cli::save_vault(&vault_path, &mut vault, &murk, &current).unwrap();
        (dir, vault_path, secret)
    }

    fn grant_pubkey(key: &str) -> String {
        murk_cli::crypto::parse_identity(key.trim())
            .and_then(|id| id.pubkey_string())
            .unwrap()
    }

    #[test]
    fn rollback_leaves_a_grant_renewed_since_alone() {
        let _env = ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, vault_path, operator) = operator_vault();
        let key_file = murk_cli::agent_key_file_path(&vault_path, "g").unwrap();
        let only = ["A".to_string()];

        let a = mint_grant("g", &only, "2h", false, None, None, &vault_path);
        // Another command renews `g` before this run's rollback.
        mint_grant("g", &only, "2h", true, None, None, &vault_path);
        let key_b = fs::read_to_string(&key_file).unwrap();
        assert_ne!(a.pubkey, grant_pubkey(&key_b));

        revoke_unhanded_grant("g", &key_file, &a.pubkey, &vault_path);

        let murk = murk_cli::load_vault(&vault_path).unwrap().1;
        assert_eq!(murk.grants["g"].pubkey, grant_pubkey(&key_b));
        assert_eq!(fs::read_to_string(&key_file).unwrap(), key_b);
        unsafe { std::env::set_var("MURK_KEY", key_b.trim()) };
        let (_, agent, identity) = murk_cli::load_vault(&vault_path).unwrap();
        let pubkey = identity.pubkey_string().unwrap();
        assert_eq!(murk_cli::get_secret(&agent, "A", &pubkey), Some("aval"));
        unsafe { std::env::set_var("MURK_KEY", &operator) };
    }

    #[test]
    fn rollback_revokes_the_grant_this_run_minted() {
        let _env = ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, vault_path, _) = operator_vault();
        let key_file = murk_cli::agent_key_file_path(&vault_path, "g").unwrap();

        let a = mint_grant(
            "g",
            &["A".to_string()],
            "2h",
            false,
            None,
            None,
            &vault_path,
        );
        assert_eq!(
            grant_pubkey(&fs::read_to_string(&key_file).unwrap()),
            a.pubkey
        );

        revoke_unhanded_grant("g", &key_file, &a.pubkey, &vault_path);

        let (vault, murk, _) = murk_cli::load_vault(&vault_path).unwrap();
        assert!(!murk.grants.contains_key("g"));
        assert!(!vault.recipients.contains(&a.pubkey));
        assert!(!key_file.exists());
    }
}
