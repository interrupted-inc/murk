// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Allowlist validation of untrusted vault input.
//!
//! A `.murk` file arrives through git from any recipient (or anyone who can
//! push), so every field is checked against what murk itself writes before the
//! vault reaches the rest of the program. `vault::parse` runs [`vault`] on every
//! header it loads — the working file, `git show` revisions for `diff`/`log`,
//! and all three sides of the merge driver. [`meta`] runs on the decrypted meta
//! blob, whose contents are only as trustworthy as whoever last re-encrypted it.
//!
//! Failures name the offending field so a rejected vault is diagnosable. Every
//! untrusted value an error repeats (including map keys inside field paths)
//! goes through [`show`], which escapes control characters and truncates, and
//! no callee's error text is forwarded — so a hostile vault cannot put terminal
//! escapes into murk's error output.
//!
//! Integrity material (`meta.mac`, `meta.sig` bytes, ciphertext contents) is not
//! interpreted here: the MAC and signature checks in `load` verify it
//! cryptographically and fail closed.

use crate::is_valid_key_name;
use crate::types::{Meta, SchemaEntry, SecretEntry, Vault};

/// Largest vault file murk will read or parse (64 MiB). Far above any real
/// vault (a 100-recipient, 500-key vault is ~15 MiB), low enough that a
/// hostile file cannot exhaust memory during deserialization.
pub const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;

/// Validate every field of a parsed vault header.
pub(crate) fn vault(v: &Vault) -> Result<(), String> {
    version(&v.version)?;
    timestamp("created", &v.created)?;
    free_text("vault_name", &v.vault_name)?;
    free_text("repo", &v.repo)?;
    for (i, r) in v.recipients.iter().enumerate() {
        recipient(&format!("recipients[{i}]"), r)?;
    }
    for (key, entry) in &v.schema {
        key_name("schema", key)?;
        schema_entry(key, entry)?;
    }
    if let Some(policy) = &v.policy {
        for (i, tag) in policy.agent_allow_tags.iter().enumerate() {
            free_text(&format!("policy.agent_allow_tags[{i}]"), tag)?;
        }
    }
    for (key, entry) in &v.secrets {
        key_name("secrets", key)?;
        secret_entry(key, entry)?;
    }
    base64("meta", &v.meta)
}

/// Validate every field of a decrypted meta blob, except the MAC and signature
/// bytes (verified cryptographically by the caller).
pub(crate) fn meta(m: &Meta) -> Result<(), String> {
    for (pk, name) in &m.recipients {
        recipient("meta.recipients key", pk)?;
        free_text(&format!("meta.recipients[{}]", show(pk)), name)?;
    }
    for (pk, vk) in &m.signers {
        recipient("meta.signers key", pk)?;
        base64(&format!("meta.signers[{}]", show(pk)), vk)?;
    }
    if let Some(sig) = &m.sig {
        recipient("meta.sig.signer", &sig.signer)?;
        base64("meta.sig.sig", &sig.sig)?;
    }
    if let Some(k) = &m.mac_key
        && crate::mac::decode_mac_key(k).is_none()
    {
        return Err("meta.mac_key: not a 64-character hex key".into());
    }
    for (user, pins) in &m.github_pins {
        if !crate::github::is_valid_username(user) {
            return Err(format!(
                "meta.github_pins key: invalid GitHub username {}",
                show(user)
            ));
        }
        for pin in pins {
            let ok = pin
                .strip_prefix("SHA256:")
                .is_some_and(|b| !b.is_empty() && b.bytes().all(is_base64_char));
            if !ok {
                return Err(format!(
                    "meta.github_pins[{}]: invalid fingerprint {}",
                    show(user),
                    show(pin)
                ));
            }
        }
    }
    for (name, members) in &m.groups {
        group_name("meta.groups key", name)?;
        for pk in members {
            recipient(&format!("meta.groups[{}] member", show(name)), pk)?;
        }
    }
    for (name, grant) in &m.grants {
        if crate::grants::validate_grant_name(name).is_err() {
            return Err(format!(
                "meta.grants key: invalid grant name {} (1–64 of [A-Za-z0-9_-])",
                show(name)
            ));
        }
        let g = show(name);
        recipient(&format!("meta.grants[{g}].pubkey"), &grant.pubkey)?;
        recipient(&format!("meta.grants[{g}].issuer"), &grant.issuer)?;
        for key in &grant.scope {
            key_name(&format!("meta.grants[{g}].scope"), key)?;
        }
        timestamp(&format!("meta.grants[{g}].issued_at"), &grant.issued_at)?;
        timestamp(&format!("meta.grants[{g}].expires_at"), &grant.expires_at)?;
    }
    Ok(())
}

fn schema_entry(key: &str, e: &SchemaEntry) -> Result<(), String> {
    let key = show(key);
    free_text(&format!("schema.{key}.description"), &e.description)?;
    if let Some(ex) = &e.example {
        free_text(&format!("schema.{key}.example"), ex)?;
    }
    for (i, tag) in e.tags.iter().enumerate() {
        free_text(&format!("schema.{key}.tags[{i}]"), tag)?;
    }
    for (field, ts) in [
        ("created", &e.created),
        ("updated", &e.updated),
        ("expires_at", &e.expires_at),
        ("revoked_at", &e.revoked_at),
    ] {
        if let Some(ts) = ts {
            timestamp(&format!("schema.{key}.{field}"), ts)?;
        }
    }
    // `describe --rotate-every 0` clears the policy, so murk never stores 0.
    if e.rotation_interval_days == Some(0) {
        return Err(format!(
            "schema.{key}.rotation_interval_days: must be at least 1"
        ));
    }
    Ok(())
}

fn secret_entry(key: &str, e: &SecretEntry) -> Result<(), String> {
    let key = show(key);
    base64(&format!("secrets.{key}.shared"), &e.shared)?;
    for (pk, ct) in &e.private {
        recipient(&format!("secrets.{key}.scoped key"), pk)?;
        base64(&format!("secrets.{key}.scoped[{}]", show(pk)), ct)?;
    }
    for (group, ct) in &e.grouped {
        group_name(&format!("secrets.{key}.grouped key"), group)?;
        base64(&format!("secrets.{key}.grouped[{}]", show(group)), ct)?;
    }
    Ok(())
}

fn group_name(field: &str, name: &str) -> Result<(), String> {
    if crate::groups::validate_group_name(name).is_ok() {
        Ok(())
    } else {
        Err(format!(
            "{field}: invalid group name {} (1–64 of [A-Za-z0-9_-], not a reserved tier name)",
            show(name)
        ))
    }
}

/// `2.MINOR` or `2.MINOR.PATCH`, decimal components without leading zeros.
/// Any other major is a format this build cannot interpret.
fn version(v: &str) -> Result<(), String> {
    let mut parts = v.split('.');
    let major = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();
    let numeric = |s: &str| {
        !s.is_empty()
            && s.len() <= 9
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'))
    };
    if major == "2" && (1..=2).contains(&rest.len()) && rest.iter().all(|p| numeric(p)) {
        return Ok(());
    }
    Err(format!(
        "unsupported vault version: {}. This build of murk supports version 2.x",
        show(v)
    ))
}

fn key_name(field: &str, key: &str) -> Result<(), String> {
    if is_valid_key_name(key) {
        Ok(())
    } else {
        Err(format!(
            "{field}: invalid key name {} (must match [A-Za-z_][A-Za-z0-9_]*)",
            show(key)
        ))
    }
}

/// An age X25519, SSH (ed25519/rsa), or age plugin public key — the forms
/// `crypto::parse_recipient` accepts for encryption.
fn recipient(field: &str, pk: &str) -> Result<(), String> {
    crate::crypto::parse_recipient(pk).map(|_| ()).map_err(|_| {
        format!(
            "{field}: not a valid age, SSH, or plugin public key: {}",
            show(pk)
        )
    })
}

/// An RFC 3339 timestamp (murk writes `YYYY-MM-DDTHH:MM:SSZ`).
fn timestamp(field: &str, ts: &str) -> Result<(), String> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|_| ())
        .map_err(|_| format!("{field}: not an RFC 3339 timestamp: {}", show(ts)))
}

/// Free text (descriptions, tags, names): any Unicode except control
/// characters other than tab and newline, so a hostile vault cannot smuggle
/// terminal escape sequences into `info`/`ls`/`doctor` output.
fn free_text(field: &str, s: &str) -> Result<(), String> {
    if s.chars()
        .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
    {
        Ok(())
    } else {
        Err(format!("{field}: contains control characters"))
    }
}

/// Standard-alphabet base64 with padding (empty allowed: an unset `shared` or
/// a skeleton's `meta`). Syntax only — decoding happens at decrypt time.
fn base64(field: &str, s: &str) -> Result<(), String> {
    let body = s.trim_end_matches('=');
    let pad = s.len() - body.len();
    if s.len().is_multiple_of(4) && pad <= 2 && body.bytes().all(is_base64_char) {
        Ok(())
    } else {
        Err(format!("{field}: not valid base64"))
    }
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Escape and truncate an untrusted value for an error message. The one place
/// untrusted text is rendered into errors; use it for every repeated value.
pub(crate) fn show(s: &str) -> String {
    const MAX: usize = 80;
    let mut out: String = s.chars().take(MAX).flat_map(char::escape_debug).collect();
    if s.chars().nth(MAX).is_some() {
        out.push('…');
    }
    out
}

/// [`show`] for a key the user typed. A private key is never echoed: pasted
/// where a public key belongs, it would otherwise land in scrollback or a CI
/// log a second time.
pub(crate) fn show_key(s: &str) -> String {
    if looks_like_private_key(s) {
        "(a private key, not shown)".into()
    } else {
        show(s)
    }
}

/// Whether `s` contains private key material: an age secret key, an age plugin
/// identity, or a PEM/OpenSSH private key block. Compared in place, so no
/// uppercased copy of the key is made.
pub(crate) fn looks_like_private_key(s: &str) -> bool {
    ["AGE-SECRET-KEY-", "AGE-PLUGIN-", "PRIVATE KEY"]
        .iter()
        .any(|marker| {
            s.as_bytes()
                .windows(marker.len())
                .any(|w| w.eq_ignore_ascii_case(marker.as_bytes()))
        })
}
