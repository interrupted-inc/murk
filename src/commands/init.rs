// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use age::secrecy::{ExposeSecret, SecretString};
use colored::Colorize;
use murk_cli::{KeySource, recovery, vault};
use std::path::Path;
use std::process;

/// Generate a BIP39 keypair, write key to ~/.config/murk/keys/, reference in .env.
/// Returns (secret_key, pubkey). Secret key is wrapped in `Zeroizing` so the
/// plaintext clears when the caller drops it.
///
/// Callers check [`murk_cli::discover_stored_key`] first, so the key file this
/// writes never already exists: generation never replaces a stored identity.
pub(crate) fn generate_and_write_key(vault_name: &str) -> (zeroize::Zeroizing<String>, String) {
    // A key line in .env here names a key murk could not find in the
    // environment or ~/.config/murk/keys: an inline MURK_KEY, or a MURK_KEY_FILE
    // somewhere else. Replacing the line drops that reference, so ask first.
    if murk_cli::dotenv_has_murk_key()
        && !confirm(
            ".env already has a MURK_KEY or MURK_KEY_FILE line, but murk found no stored key for this vault.\n\
             Generate a new key and replace that line? An inline MURK_KEY value in .env is lost; copy it out first if you need it.",
        )
    {
        eprintln!("Aborted.");
        process::exit(1);
    }

    eprintln!("{} generating keypair...", "◆".magenta());
    let (phrase, secret_key, pubkey) = try_or_die(recovery::generate());

    // Write key to ~/.config/murk/keys/<hash>. The key file is created
    // exclusively: if another init stored one since the discovery check, this
    // fails and leaves that key untouched.
    let key_path = try_or_die(murk_cli::key_file_path(vault_name));
    try_or_die(murk_cli::create_key_file(&key_path, &secret_key));
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

    // Reference the key in .env only after the phrase is shown: if this write
    // fails, a retry reuses the stored key and would print no phrase.
    try_or_die(murk_cli::write_key_ref_to_dotenv(&key_path));
    eprintln!(
        "  {}",
        ".env holds only the path to your key file; keep both out of git".dimmed()
    );

    (secret_key, pubkey)
}

/// Report a reused key and, for a key file, point `.env` at it when `.env` has
/// no key line yet. An existing key line is left alone: it is the user's
/// choice. Inline `MURK_KEY` is never written to `.env`, and neither is a
/// strict-mode `MURK_KEY_FILE`: that is an agent or CI key, not the operator's
/// identity.
fn reuse_key(source: &KeySource) {
    let key_path = match source {
        KeySource::EnvVar => {
            eprintln!("{} using existing key from MURK_KEY", "◆".magenta());
            return;
        }
        KeySource::EnvFile(path) | KeySource::Auto(path) => path,
    };
    eprintln!(
        "{} using existing key {}",
        "◆".magenta(),
        key_path.display().to_string().dimmed()
    );
    let strict_env_key =
        matches!(source, KeySource::EnvFile(_)) && murk_cli::hardening::strict_mode();
    if !strict_env_key && !murk_cli::dotenv_has_murk_key() {
        try_or_die(murk_cli::write_key_ref_to_dotenv(key_path));
        eprintln!("{} added MURK_KEY_FILE reference to .env", "◆".magenta());
    }
}

/// The key init should use instead of generating one: `MURK_KEY` or
/// `MURK_KEY_FILE` from the environment first, then the key stored for this
/// vault here or in a sibling worktree (see [`murk_cli::discover_stored_key`];
/// refused in strict mode).
fn existing_key(vault_name: &str) -> Option<murk_cli::DiscoveredKey> {
    try_or_die(murk_cli::discover_existing_key())
        .or_else(|| try_or_die(murk_cli::discover_stored_key(vault_name)))
}

pub(crate) fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // If vault already exists, handle onboarding flow.
    if vault_path.exists() {
        let vault = try_or_die(vault::read(vault_path));

        eprintln!("{}", format!("{vault_name} already exists").dimmed());

        // Reuse a key the environment names, then one stored for this vault
        // (here or in a sibling worktree). Only a newcomer with neither gets a
        // new key.
        let secret_key = match existing_key(vault_name) {
            Some(dk) => {
                reuse_key(&dk.source);
                dk.secret_key
            }
            None => {
                let (secret_key, _pubkey) = generate_and_write_key(vault_name);
                eprintln!();
                SecretString::from(secret_key.as_str())
            }
        };

        let status = try_or_die(murk_cli::check_init_status(
            &vault,
            secret_key.expose_secret(),
        ));
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
            let trusted = murk_cli::pins::read(vault_name)
                .ok()
                .flatten()
                .is_some_and(|p| p.has_trust());
            if !trusted {
                eprintln!(
                    "  {}",
                    "next: review who signed the vault and run `murk trust` (once per machine)"
                        .dimmed()
                );
            }
        } else {
            eprintln!(
                "{} {}",
                "⚠".yellow(),
                "not authorized \u{2014} share your public key to get added:".yellow()
            );
            eprintln!("  {}", status.pubkey.bold());
            print_signing_fingerprint(secret_key.expose_secret());
        }
        return;
    }

    // --- New vault flow ---

    // Same lookup as above, so an explicit MURK_KEY / MURK_KEY_FILE becomes the
    // first recipient, and a key already stored for this vault path (here, say
    // after the vault file was deleted, or in a sibling worktree) is reused
    // rather than overwritten or shadowed.
    let existing = existing_key(vault_name);

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        die(&"name is required", 1);
    }

    let secret_key = match existing {
        Some(dk) => {
            reuse_key(&dk.source);
            dk.secret_key
        }
        None => SecretString::from(generate_and_write_key(vault_name).0.as_str()),
    };
    let identity = try_or_die(murk_cli::crypto::parse_identity(secret_key.expose_secret()));

    let v = try_or_die(murk_cli::create_vault(vault_name, &identity, &name));
    // Create exclusively: a vault that appeared while init waited at the
    // prompt (a `git pull` in another terminal) must not be replaced.
    match vault::create(vault_path, &v) {
        Ok(()) => {}
        Err(vault::VaultError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => die(
            &format!(
                "{vault_name} appeared while murk init was running; it was left unchanged\n\
                 run murk init again to use it"
            ),
            1,
        ),
        Err(e) => die(&e, 1),
    }
    try_or_die(murk_cli::pin_created_vault(vault_name, &v, &identity));

    eprintln!();
    eprintln!(
        "{} vault initialized — added {} as recipient",
        "◆".magenta(),
        name.bold()
    );
    eprintln!("  {}", "run: murk add KEY".dimmed());
}

/// The fingerprint teammates' `murk trust` shows for this key's first signed
/// write, so the person who authorizes it can confirm it.
fn print_signing_fingerprint(secret_key: &str) {
    let Some(sk) = murk_cli::crypto::parse_identity(secret_key)
        .ok()
        .and_then(|id| id.signing_key())
    else {
        return;
    };
    if let Some(fp) = murk_cli::signing::fingerprint(&sk.verifying_key()) {
        eprintln!(
            "  {}",
            format!("signing key {fp} — teammates confirm this on your first write").dimmed()
        );
    }
}
