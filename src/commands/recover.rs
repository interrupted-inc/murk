use super::*;
use age::secrecy::ExposeSecret;
use colored::Colorize;
use murk_cli::{MurkIdentity, recovery, vault};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};

/// Whether the just-restored identity is a recipient of the given vault JSON.
/// `Some(true)` = recipient, `Some(false)` = not a recipient, `None` = can't
/// tell (unparseable vault, or a key with no comparable pubkey). Drives only a
/// best-effort sanity warning — never gates the restore.
pub(crate) fn restored_key_is_recipient(secret_key: &str, vault_contents: &str) -> Option<bool> {
    let vault = vault::parse(vault_contents).ok()?;
    let identity = murk_cli::crypto::parse_identity(secret_key).ok()?;
    let pubkey = identity.pubkey_string().ok()?;
    Some(vault.recipients.contains(&pubkey))
}

pub(crate) fn cmd_restore(vault: &str) {
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

pub(crate) fn cmd_recover() {
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
