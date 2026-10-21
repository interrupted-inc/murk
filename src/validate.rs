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

/// Free text in a vault being read (descriptions, tags, names): any Unicode
/// except control characters other than tab, newline and carriage return. A
/// vault written before the stricter [`new_text`] rule must still load:
/// `murk verify` flags such text ([`unsafe_text_fields`]) and output escapes
/// it ([`terminal_text`]).
fn free_text(field: &str, s: &str) -> Result<(), String> {
    if s.chars()
        .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
    {
        Ok(())
    } else {
        Err(format!("{field}: contains control characters"))
    }
}

/// The rule for text being written now: no control characters other than tab
/// (and newline when `multiline`, for descriptions), and none of the
/// [`is_deceptive`] characters. Such text could forge or reorder lines of
/// output.
pub fn new_text(s: &str, multiline: bool) -> Result<(), &'static str> {
    let allowed = |c: char| (c == '\t' || (multiline && c == '\n')) || !c.is_control();
    if !s.chars().all(allowed) {
        Err(if multiline {
            "contains control characters (only tab and newline are allowed)"
        } else {
            "contains control characters or line breaks (only tab is allowed)"
        })
    } else if s.chars().any(is_deceptive) {
        Err("contains invisible or text-direction characters")
    } else {
        Ok(())
    }
}

/// One free-text field of a vault header (or meta recipient name).
struct TextField<'v> {
    /// Where it is, for messages: `schema.DB.tags[1]`.
    field: String,
    /// Where it is, without list positions: a value counts as already
    /// present if it was anywhere in the same list before.
    place: String,
    value: &'v str,
    multiline: bool,
}

fn text_fields<'v>(
    v: &'v Vault,
    recipient_names: impl IntoIterator<Item = (&'v String, &'v String)>,
) -> Vec<TextField<'v>> {
    let mut fields = Vec::new();
    let mut add = |field: String, place: String, value: &'v str, multiline: bool| {
        fields.push(TextField {
            field,
            place,
            value,
            multiline,
        });
    };
    add(
        "vault_name".into(),
        "vault_name".into(),
        &v.vault_name,
        false,
    );
    add("repo".into(), "repo".into(), &v.repo, false);
    if let Some(policy) = &v.policy {
        for (i, tag) in policy.agent_allow_tags.iter().enumerate() {
            let place = "policy.agent_allow_tags".to_string();
            add(format!("{place}[{i}]"), place, tag, false);
        }
    }
    for (key, e) in &v.schema {
        let key = show(key);
        let field = format!("schema.{key}.description");
        add(field.clone(), field, &e.description, true);
        if let Some(ex) = &e.example {
            let field = format!("schema.{key}.example");
            add(field.clone(), field, ex, false);
        }
        for (i, tag) in e.tags.iter().enumerate() {
            let place = format!("schema.{key}.tags");
            add(format!("{place}[{i}]"), place, tag, false);
        }
    }
    for (pk, name) in recipient_names {
        let field = format!("meta.recipients[{}]", crate::truncate_pubkey(pk));
        add(field.clone(), format!("meta.recipients[{pk}]"), name, false);
    }
    fields
}

/// Header text fields that would fail [`new_text`]: legacy or hand-edited
/// text that can forge or reorder output. Named by field, never quoted.
/// `recipient_names` is the decrypted meta's pubkey → display name map.
pub fn unsafe_text_fields<'a>(
    v: &'a Vault,
    recipient_names: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> Vec<String> {
    text_fields(v, recipient_names)
        .into_iter()
        .filter(|t| new_text(t.value, t.multiline).is_err())
        .map(|t| t.field)
        .collect()
}

/// The write-time rule, shared by every writer (CLI, bindings): text in
/// `next` must pass [`new_text`] unless `previous` already held the same
/// text in the same place, so a vault holding legacy text stays writable
/// while nothing new of the kind gets in. `previous` is `None` for a new
/// vault.
pub(crate) fn new_header_text<'a>(
    previous: Option<(&'a Vault, &'a std::collections::HashMap<String, String>)>,
    next: &Vault,
    next_names: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let before: std::collections::HashSet<(String, &str)> = previous
        .map(|(v, names)| {
            text_fields(v, names)
                .into_iter()
                .map(|t| (t.place, t.value))
                .collect()
        })
        .unwrap_or_default();
    for t in text_fields(next, next_names) {
        if let Err(why) = new_text(t.value, t.multiline)
            && !before.contains(&(t.place, t.value))
        {
            return Err(format!("{}: {why}", t.field));
        }
    }
    Ok(())
}

/// Invisible characters that change how text around them renders: bidi
/// controls (which can reorder a line, as in "Trojan Source"), zero-width
/// spaces and the byte-order mark. The zero-width joiner and non-joiner are
/// left out: emoji and several scripts need them.
pub fn is_deceptive(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// `s` made safe to print to a terminal: control characters (except tab, and
/// newline when `multiline`) and [`is_deceptive`] characters are shown as
/// escapes, so a value or header field cannot move the cursor, rewrite earlier
/// output, or reorder what is shown. Text that needs nothing is borrowed.
pub fn terminal_text(s: &str, multiline: bool) -> std::borrow::Cow<'_, str> {
    let unsafe_char =
        |c: char| (c.is_control() && c != '\t' && !(multiline && c == '\n')) || is_deceptive(c);
    if !s.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            c if !unsafe_char(c) => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
        }
    }
    std::borrow::Cow::Owned(out)
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

#[cfg(test)]
mod tests {
    use super::{new_text, terminal_text};

    #[test]
    fn new_text_may_not_forge_or_reorder_lines() {
        assert!(new_text("first line\n\tsecond line", true).is_ok());
        assert!(new_text("first line\nsecond line", false).is_err());
        assert!(new_text("a\rb", true).is_err());
        assert!(new_text("a\u{2066}b", false).is_err());
        // Emoji sequences need the zero-width joiner.
        assert!(new_text("dev \u{1f469}\u{200d}\u{1f4bb}", false).is_ok());
    }

    #[test]
    fn terminal_text_escapes_what_a_terminal_would_act_on() {
        assert_eq!(terminal_text("plain\ttext", false), "plain\ttext");
        assert_eq!(
            terminal_text("a\u{1b}]52;c;aGk=\u{7}\rb\u{202e}c\nd", false),
            "a\\u{1b}]52;c;aGk=\\u{7}\\rb\\u{202e}c\\nd"
        );
        assert_eq!(
            terminal_text("line\nline\u{1b}[2J", true),
            "line\nline\\u{1b}[2J"
        );
        assert!(matches!(
            terminal_text("-----BEGIN-----\nabc\n", true),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
