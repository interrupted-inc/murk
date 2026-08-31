use super::*;
use colored::Colorize;
use murk_cli::EnvrcStatus;
use std::process;

pub(crate) fn cmd_exec(
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
