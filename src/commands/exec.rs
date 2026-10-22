// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use murk_cli::EnvrcStatus;
use std::process;

/// Run `command` with vault secrets in its environment. `agent_mode` is
/// `murk agent exec`: it needs an agent grant key unless `operator_key_ok`
/// (`--allow-operator-key`), checked by identity, not by where the key came
/// from, before any secret is resolved.
pub(crate) fn cmd_exec(
    command: &[String],
    only: &[String],
    tags: &[String],
    clean_env: bool,
    agent_mode: bool,
    allow_reserved: bool,
    operator_key_ok: bool,
    vault_path: &str,
) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    if agent_mode && !murk_cli::is_agent_identity(&murk, &pubkey) {
        if !operator_key_ok {
            die(
                &"agent exec needs an agent grant key, and this key is a full recipient of the vault\n\
                  point MURK_KEY_FILE at a grant key (mint one: `murk agent init`)\n\
                  or pass --allow-operator-key to use your own key on purpose",
                1,
            );
        }
        eprintln!(
            "{} agent exec is decrypting with your personal key (--allow-operator-key)",
            "warn".yellow().bold()
        );
    }
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

    // In agent mode, for an agent grant (whatever the environment says), or
    // under self-scope, the vault's policy decides which keys may be injected.
    // Fails closed before any secret reaches the child environment.
    if agent_mode || murk_cli::agent_policy_applies(&murk, &pubkey) {
        let keys: Vec<String> = secrets.keys().cloned().collect();
        try_or_die(murk_cli::check_agent_keys(&vault, &keys));
    }

    // A vault-chosen PATH, LD_PRELOAD, GIT_SSH_COMMAND or MURK_STRICT would run
    // code as (or switch off murk's hardening for) whoever runs exec.
    refuse_reserved(secrets.keys(), allow_reserved);

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
            murk_cli::strip_key_env(cmd);
        }
        // `secrets` holds the decrypted values in `Zeroizing` and is wiped when
        // it drops. Handing them to the child's environment necessarily copies
        // the plaintext into the block passed to `execve(2)`; that copy lives in
        // the kernel/child and is outside our control, so it is intentionally
        // not zeroized here. This is the documented boundary of best-effort
        // zeroization.
        cmd.envs(&secrets);
    };

    let mut cmd = process::Command::new(program);
    cmd.args(args);
    build_cmd(&mut cmd);

    // `murk agent exec` supervises the child instead of becoming it, so it can
    // mask the injected values in the child's stdout and stderr (an accident
    // guard for `env` dumps landing in an agent transcript). See `supervise`.
    if agent_mode {
        let masker = murk_cli::mask::Masker::new(secrets.iter().map(|(k, v)| (k, v.as_bytes())));
        drop(secrets);
        super::supervise::run_masked(cmd, &masker);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        die(&err, 1);
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status().unwrap_or_else(|e| die(&e, 1));
        process::exit(status.code().unwrap_or(1));
    }
}

pub(crate) fn cmd_env(vault: &str) {
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
