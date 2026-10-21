// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk trust`: the explicit step that records a vault as trusted on this
//! machine after showing who signed it and what changed.

use super::*;
use colored::Colorize;
use murk_cli::trust::{Refusal, Verdict};
use murk_cli::types;
use std::io::IsTerminal;

pub(crate) fn cmd_trust(yes: bool, re_add: &[String], vault_path: &str) {
    // Hold the vault lock: accepting an unsigned vault re-signs it.
    let _lock = try_or_die(
        murk_cli::vault::lock(std::path::Path::new(vault_path)).map_err(murk_cli::MurkError::Vault),
    );
    let mut inspected = try_or_die(murk_cli::inspect_vault(vault_path));
    let pubkey = inspected
        .identity
        .pubkey_string()
        .unwrap_or_else(|e| die(&e, 1));
    let me = murk_cli::canonical_recipient(&pubkey).into_owned();
    let pinned_grant = inspected
        .assessment
        .pin
        .as_ref()
        .is_some_and(|p| p.grants.contains(&me));
    if pinned_grant
        || inspected
            .murk
            .grants
            .values()
            .any(|g| murk_cli::canonical_recipient(&g.pubkey).into_owned() == me)
    {
        die(
            &"an agent grant key cannot trust a vault\nask the operator to re-mint the grant",
            1,
        );
    }

    // Keys this machine recorded as removed that the vault lists or is signed
    // by: trusted again only when named with --re-add.
    let removed =
        murk_cli::trust::removed_keys_in(&inspected.loaded(), inspected.assessment.pin.as_ref());
    let readmit = readmitted_keys(re_add, &removed, &inspected.murk.recipients);
    if !readmit.is_empty() {
        try_or_die(inspected.readmit(vault_path, &readmit));
    }

    print_summary(vault_path, &inspected);

    let refusal = match &inspected.assessment.verdict {
        Verdict::Trusted if readmit.is_empty() => {
            eprintln!(
                "{} {vault_path} is already trusted on this machine",
                "ok".green().bold()
            );
            return;
        }
        Verdict::Trusted => None,
        Verdict::UnsignedAllowed => {
            eprintln!(
                "{} {vault_path} is unsigned and your key cannot sign it — nothing to record; rely on signed git commits",
                "warn".yellow().bold()
            );
            return;
        }
        Verdict::Refused(r) => Some(r.clone()),
    };
    if refusal.is_some()
        && let Some((key, at)) = removed.iter().find(|(k, _)| !readmit.contains(*k))
    {
        die(
            &format_args!(
                "{} was removed from this vault at generation {at} on this machine, and this vault lists them or is signed by them\nrefusing to trust it; to trust them again on purpose, review it and run `murk trust --vault {vault_path} --re-add {key}`",
                murk_cli::trust::label(&inspected.murk.recipients, key)
            ),
            1,
        );
    }
    let Some(refusal) = refusal else {
        // Trusted once the named keys are re-added: record that decision.
        if !yes && !confirmed("trust this vault and re-add the named keys on this machine?") {
            die(&"not trusted", 1);
        }
        try_or_die(inspected.record_trust(vault_path, false, &readmit));
        eprintln!("{} trusted {vault_path} on this machine", "◆".magenta());
        return;
    };
    let reason = inspected.refusal_message(vault_path).unwrap_or_default();
    eprintln!(
        "{} {}",
        "⚠".yellow(),
        reason.lines().next().unwrap_or_default()
    );
    if !refusal.acceptable() {
        die(
            &format_args!("refusing to trust it\nrestore {vault_path} from git"),
            1,
        );
    }

    // A murk 0.13 (v1) revision accepted after this machine saw the vault in
    // 0.14 form can only be pinned by moving it to v2: re-sign it.
    let legacy = matches!(
        &inspected.murk.signature,
        types::SignatureState::Signed { v: 1, .. }
    );
    let needs_signature = matches!(refusal, Refusal::Unsigned | Refusal::Downgraded)
        || (legacy && matches!(refusal, Refusal::RolledBack { .. }));
    let resign = needs_signature && inspected.identity.is_signing_capable();
    if needs_signature && !resign && !matches!(refusal, Refusal::Downgraded) {
        die(
            &"this vault must be re-signed to be trusted, and your key cannot sign\nask a teammate with an age or ssh-ed25519 key to review it and run `murk trust`",
            1,
        );
    }
    let question = if resign {
        "sign this vault with your key and trust it?"
    } else {
        "trust this vault on this machine?"
    };
    if !yes && !confirmed(question) {
        die(&"not trusted", 1);
    }

    if resign {
        if !readmit.is_empty() {
            // The re-signed vault lists the named keys: they are re-added on
            // purpose, so take them out of the removed set before the save.
            try_or_die(murk_cli::pins::update(vault_path, |fresh| {
                let mut pin = fresh.cloned().unwrap_or_default();
                pin.removed.retain(|k, _| !readmit.contains(k));
                Ok(Some(pin))
            }));
        }
        // Re-sign exactly the current content: save with no changes.
        let murk_cli::InspectedVault {
            mut vault, murk, ..
        } = inspected;
        save_vault(vault_path, &mut vault, &murk, &murk);
        eprintln!(
            "{} signed {vault_path} and trusted it — commit the result so teammates get the signed version",
            "◆".magenta()
        );
        return;
    }
    if matches!(refusal, Refusal::Downgraded) {
        // A key that cannot sign accepting an unsigned vault: forget that a
        // signed version was seen, so this machine loads it with a warning.
        try_or_die(murk_cli::pins::update(vault_path, |fresh| {
            let mut pin = fresh.cloned().unwrap_or_default();
            pin.was_signed = false;
            Ok(Some(pin))
        }));
    } else {
        let reset_counter = matches!(
            refusal,
            Refusal::RolledBack { .. } | Refusal::OtherVault { .. }
        );
        try_or_die(inspected.record_trust(vault_path, reset_counter, &readmit));
    }
    eprintln!("{} trusted {vault_path} on this machine", "◆".magenta());
}

/// Ask `question` on a terminal; without one, stop and point at `--yes`.
fn confirmed(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        die(
            &"murk trust needs confirmation\nreview the output above, then rerun with --yes",
            1,
        );
    }
    confirm(question)
}

/// The removed keys `re_add` names — each a public key or a recipient's name
/// in the vault — in canonical form. A name that is not a removed key this
/// vault lists is an error, so a typo never passes silently.
fn readmitted_keys(
    re_add: &[String],
    removed: &std::collections::BTreeMap<String, u64>,
    names: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeSet<String> {
    re_add
        .iter()
        .map(|arg| {
            let canonical = murk_cli::canonical_recipient(arg).into_owned();
            if removed.contains_key(&canonical) {
                return canonical;
            }
            names
                .iter()
                .filter(|(_, name)| *name == arg)
                .map(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned())
                .find(|pk| removed.contains_key(pk))
                .unwrap_or_else(|| {
                    die(
                        &format_args!(
                            "{} is not a key this machine recorded as removed that this vault lists",
                            murk_cli::terminal_text(arg, false)
                        ),
                        1,
                    )
                })
        })
        .collect()
}

/// `murk trust --print-key`: this machine's own trusted-signer entry and
/// signing-key fingerprint. Teammates compare the fingerprint with what their
/// `murk trust` shows for your first write; CI sets the entry in
/// `MURK_TRUSTED_SIGNERS`. Both are public.
pub(crate) fn cmd_trust_print_key(vault_path: &str) {
    use age::secrecy::ExposeSecret;
    let secret = try_or_die(murk_cli::resolve_key_for_vault(vault_path));
    let identity = try_or_die(murk_cli::crypto::parse_identity(secret.expose_secret()));
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let Some(sk) = identity.signing_key() else {
        die(
            &"this key cannot sign (ssh-rsa or hardware), so it has no signing key",
            1,
        );
    };
    let vk = sk.verifying_key();
    let registered = identity.registers_verifying_key();
    println!(
        "{}",
        murk_cli::trust::format_trusted_signer(&pubkey, registered.then_some(vk.as_str()))
    );
    eprintln!(
        "signing key {}",
        murk_cli::signing::fingerprint(&vk).unwrap_or_default()
    );
}

/// Show what the user is being asked to trust: the vault's identity and
/// counter, the signer's full key (its name is chosen by whoever wrote the
/// file), and every recipient with its change since this machine last trusted
/// the vault.
fn print_summary(vault_path: &str, inspected: &murk_cli::InspectedVault) {
    let vault = &inspected.vault;
    let murk = &inspected.murk;
    let pin = inspected.assessment.pin.as_ref().filter(|p| p.has_trust());

    eprintln!("{} {}", "vault".bold(), vault_path);
    eprintln!(
        "  id          {}",
        if vault.vault_id.is_empty() {
            "(none — written by murk 0.13 or older)"
        } else {
            &vault.vault_id
        }
    );
    let seen = pin.map_or_else(
        || "never trusted here".to_string(),
        |p| format!("highest trusted here: {}", p.generation),
    );
    eprintln!("  generation  {} ({seen})", vault.generation);
    let signer_vk = inspected.loaded().signer_vk.map(str::to_string);
    match &murk.signature {
        types::SignatureState::Signed { signer, .. } => {
            let name = murk_cli::trust::label(&murk.recipients, signer);
            eprintln!("  signed by   {name}");
            eprintln!("              {}", signer.dimmed());
            if let Some(vk) = &signer_vk {
                let pinned = pin.and_then(|p| {
                    p.signers
                        .get(&murk_cli::canonical_recipient(signer).into_owned())
                });
                let fp = murk_cli::signing::fingerprint(vk).unwrap_or_default();
                eprintln!("  signing key {fp}");
                if pinned.is_none() && inspected.assessment.env_signers.is_none() {
                    eprintln!(
                        "              {}",
                        "not confirmed on this machine — trust on first use: check this fingerprint with them (`murk trust --print-key` on their machine)"
                            .yellow()
                    );
                }
            }
            if inspected.assessment.env_signers.is_none()
                && pin.is_some_and(|p| {
                    !p.trusted
                        .contains(&murk_cli::canonical_recipient(signer).into_owned())
                })
            {
                eprintln!(
                    "              {}",
                    "not a trusted signer on this machine — the name above is chosen by whoever wrote the file"
                        .yellow()
                );
            }
        }
        types::SignatureState::Unsigned => {
            eprintln!("  signed by   {}", "nobody (unsigned)".yellow())
        }
    }

    let grants: std::collections::BTreeSet<String> = murk
        .grants
        .values()
        .map(|g| murk_cli::canonical_recipient(&g.pubkey).into_owned())
        .collect();
    eprintln!("{}", "recipients".bold());
    let mut shown = std::collections::BTreeSet::new();
    for r in &vault.recipients {
        let canon = murk_cli::canonical_recipient(r).into_owned();
        shown.insert(canon.clone());
        let label = murk_cli::trust::label(&murk.recipients, r);
        // The signing key each recipient's writes will be checked against —
        // pinned here, or the one this vault's registry claims.
        let fp = pin
            .and_then(|p| p.signers.get(&canon))
            .or_else(|| {
                murk.signers
                    .iter()
                    .find(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned() == canon)
                    .map(|(_, vk)| vk)
            })
            .and_then(|vk| murk_cli::signing::fingerprint(vk))
            .map(|fp| format!("  signing key {fp}").dimmed().to_string())
            .unwrap_or_default();
        if grants.contains(&canon) {
            eprintln!("    {label} (agent grant, never a signer)");
        } else if pin.is_some_and(|p| !p.trusted.contains(&canon)) {
            eprintln!("  {} {label}{fp}", "+".magenta().bold());
        } else {
            eprintln!("    {label}{fp}");
        }
    }
    if let Some(p) = pin {
        for gone in p.trusted.difference(&shown) {
            eprintln!("  {} {}", "-".red().bold(), murk_cli::truncate_pubkey(gone));
        }
    }
}
