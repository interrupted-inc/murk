// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recipient management: authorize, revoke, and list vault recipients.

use crate::{crypto, types};
use std::borrow::Cow;
use std::collections::BTreeSet;

/// Maximum number of recipients per vault.
const MAX_RECIPIENTS: usize = 100;

/// A single recipient entry with resolved display info.
#[derive(Debug)]
pub struct RecipientEntry {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub is_self: bool,
}

/// Canonical form of a recipient pubkey string. SSH keys reduce to
/// `type base64`, dropping the trailing comment (which carries no key
/// material) and any extra whitespace. age X25519 and plugin recipients
/// (`age1…`) are Bech32, which is case-insensitive, so they fold to lowercase.
/// Two strings name the same recipient iff their canonical forms are equal.
pub fn canonical_recipient(pk: &str) -> Cow<'_, str> {
    let trimmed = pk.trim();
    let mut fields = trimmed.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(kind), Some(blob)) if kind.starts_with("ssh-") => {
            let single_space = trimmed.len() == kind.len() + 1 + blob.len()
                && trimmed.as_bytes()[kind.len()] == b' ';
            if single_space {
                Cow::Borrowed(trimmed)
            } else {
                Cow::Owned(format!("{kind} {blob}"))
            }
        }
        _ if is_bech32_recipient(pk) && pk.bytes().any(|b| b.is_ascii_uppercase()) => {
            Cow::Owned(pk.to_ascii_lowercase())
        }
        _ => Cow::Borrowed(pk),
    }
}

/// Whether `pk` has the `age1` prefix of an age X25519 or plugin recipient, in
/// either case.
fn is_bech32_recipient(pk: &str) -> bool {
    pk.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("age1"))
}

/// Whether two recipient strings name the same key (see [`canonical_recipient`]).
pub fn same_recipient(a: &str, b: &str) -> bool {
    a == b || canonical_recipient(a) == canonical_recipient(b)
}

/// The comment field of an SSH public key line (`type base64 comment`), if any.
fn ssh_comment(pk: &str) -> Option<&str> {
    let trimmed = pk.trim();
    if !trimmed.starts_with("ssh-") {
        return None;
    }
    let mut rest = trimmed;
    for _ in 0..2 {
        rest = rest.trim_start().split_once(char::is_whitespace)?.1;
    }
    Some(rest.trim()).filter(|c| !c.is_empty())
}

/// The stored vault recipient entry naming the same key as `pk`, if any.
pub(crate) fn find_recipient<'a>(vault: &'a types::Vault, pk: &str) -> Option<&'a String> {
    vault.recipients.iter().find(|r| same_recipient(r, pk))
}

/// The scoped ciphertext addressed to `pk` in `entry`, under any spelling of
/// the key (an older murk may have keyed it with an SSH comment or in
/// uppercase).
pub(crate) fn scoped_entry_for<'a>(entry: &'a types::SecretEntry, pk: &str) -> Option<&'a String> {
    entry.private.get(pk).or_else(|| {
        entry
            .private
            .iter()
            .find_map(|(k, v)| same_recipient(k, pk).then_some(v))
    })
}

/// Sets of vault recipient entries that name the same key (e.g. an SSH key
/// stored both with and without a comment by an older murk). Each set has at
/// least two entries, in vault order.
pub fn duplicate_recipients(vault: &types::Vault) -> Vec<Vec<&str>> {
    let mut sets: Vec<(Cow<'_, str>, Vec<&str>)> = Vec::new();
    for pk in &vault.recipients {
        let canon = canonical_recipient(pk);
        match sets.iter_mut().find(|(c, _)| *c == canon) {
            Some((_, entries)) => entries.push(pk),
            None => sets.push((canon, vec![pk])),
        }
    }
    sets.into_iter()
        .filter_map(|(_, entries)| (entries.len() > 1).then_some(entries))
        .collect()
}

/// List all recipients in the vault with optional name resolution.
///
/// If `secret_key` is provided, decrypts meta to resolve display names
/// and marks which recipient corresponds to the caller's key. Fails if the
/// meta decrypts but is invalid (see [`crate::decrypt_meta`]).
pub fn list_recipients(
    vault: &types::Vault,
    secret_key: Option<&str>,
) -> Result<Vec<RecipientEntry>, String> {
    let identity = secret_key
        .filter(|k| !k.is_empty())
        .and_then(|sk| crypto::parse_identity(sk).ok());
    let meta_data = match identity {
        Some(identity) => match (
            crate::decrypt_meta(vault, &identity)?,
            identity.pubkey_string(),
        ) {
            (Some(meta), Ok(my_pubkey)) => Some((meta, my_pubkey)),
            _ => None,
        },
        None => None,
    };

    Ok(vault
        .recipients
        .iter()
        .map(|pk| {
            let (display_name, is_self) = match &meta_data {
                Some((meta, my_pubkey)) => {
                    let name = meta.recipients.get(pk).filter(|n| !n.is_empty()).cloned();
                    (name, same_recipient(pk, my_pubkey))
                }
                None => (None, false),
            };
            RecipientEntry {
                pubkey: pk.clone(),
                display_name,
                is_self,
            }
        })
        .collect())
}

/// Add a recipient to the vault and return the stored (canonical) pubkey.
///
/// SSH keys are stored as `type base64`; a trailing comment becomes the display
/// name when `name` is not given. Returns an error if the pubkey is invalid or
/// the same key is already present, in any form.
pub fn authorize_recipient(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    pubkey: &str,
    name: Option<&str>,
) -> Result<String, crate::error::MurkError> {
    use crate::error::MurkError;

    let canonical = canonical_recipient(pubkey).into_owned();
    // SSH keys are checked in canonical form; anything else as given, so a
    // mixed-case Bech32 key (invalid per BIP-173) is refused, not folded.
    let as_given = if canonical.starts_with("ssh-") {
        &canonical
    } else {
        pubkey
    };
    let parsed = crypto::parse_recipient(as_given).and(crypto::parse_recipient(&canonical));
    let Ok(parsed) = parsed else {
        return Err(MurkError::Recipient(format!(
            "invalid public key: {pubkey}"
        )));
    };
    if let Some(why) = parsed.weakness() {
        return Err(MurkError::Recipient(format!(
            "invalid public key: {pubkey}: {why}"
        )));
    }

    if find_recipient(vault, &canonical).is_some() {
        return Err(MurkError::Recipient(format!(
            "{canonical} is already a recipient"
        )));
    }

    if vault.recipients.len() >= MAX_RECIPIENTS {
        return Err(MurkError::Recipient(format!(
            "vault already has {MAX_RECIPIENTS} recipients — remove unused recipients before adding more"
        )));
    }

    vault.recipients.push(canonical.clone());

    if let Some(n) = name.or_else(|| ssh_comment(pubkey)) {
        murk.recipients.insert(canonical.clone(), n.into());
    }

    Ok(canonical)
}

/// Result of revoking a recipient.
#[derive(Debug)]
pub struct RevokeResult {
    /// The display name of the revoked recipient, if known.
    pub display_name: Option<String>,
    /// Keys the revoked recipient had access to (for rotation warnings).
    pub exposed_keys: Vec<String>,
}

/// Resolve `recipient` (a pubkey, a display name, or `github:<user>`) to the
/// stored vault entries a revoke would remove.
///
/// A pubkey matches every entry naming the same key, so duplicates left by an
/// older murk (the same SSH key with and without a comment) go together. A
/// display name matches every key carrying it; more than one distinct key is
/// ambiguous unless it names a GitHub user (`<user>@github`), whose keys all
/// belong to one person. Returns the entries grouped by key, in vault order.
pub fn revoke_targets(
    vault: &types::Vault,
    murk: &types::Murk,
    recipient: &str,
) -> Result<Vec<Vec<String>>, crate::error::MurkError> {
    use crate::error::MurkError;

    let github_name = recipient
        .strip_prefix("github:")
        .map(|user| format!("{user}@github"));
    let name = github_name.as_deref().unwrap_or(recipient);

    let canon = canonical_recipient(recipient);
    let keys: BTreeSet<Cow<'_, str>> = if vault
        .recipients
        .iter()
        .any(|pk| canonical_recipient(pk) == canon)
    {
        BTreeSet::from([canon])
    } else {
        murk.recipients
            .iter()
            .filter(|(_, n)| n.as_str() == name)
            .map(|(pk, _)| canonical_recipient(pk))
            .collect()
    };
    if keys.is_empty() {
        return Err(MurkError::Recipient(format!(
            "recipient not found: {recipient}"
        )));
    }
    if keys.len() > 1 && !name.ends_with("@github") {
        return Err(MurkError::Recipient(format!(
            "ambiguous name \"{recipient}\" matches {} recipients — use a pubkey to revoke",
            keys.len()
        )));
    }

    // Entries per key: every vault entry for it, plus any name-map entry not
    // in the vault header so its display name goes too.
    let mut groups: Vec<(Cow<'_, str>, Vec<String>)> = Vec::new();
    let stored = vault.recipients.iter().chain(
        murk.recipients
            .keys()
            .filter(|pk| !vault.recipients.contains(pk)),
    );
    for pk in stored {
        let canon = canonical_recipient(pk);
        if !keys.contains(&canon) {
            continue;
        }
        match groups.iter_mut().find(|(c, _)| *c == canon) {
            Some((_, entries)) => entries.push(pk.clone()),
            None => groups.push((canon, vec![pk.clone()])),
        }
    }
    Ok(groups.into_iter().map(|(_, entries)| entries).collect())
}

/// Remove a recipient from the vault. `recipient` can be a pubkey, a display
/// name, or `github:<user>`; see [`revoke_targets`] for what it matches.
///
/// Every matched entry goes, with its display name, scoped overrides, group
/// memberships and agent grants. Returns an error if the recipient is not
/// found, the name is ambiguous, or it would remove the last recipient.
pub fn revoke_recipient(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    recipient: &str,
) -> Result<RevokeResult, crate::error::MurkError> {
    use crate::error::MurkError;

    // Match every map by canonical key, not by the spellings found in the
    // header and name map: a scoped override, group member or grant may be
    // keyed by yet another spelling of the same key.
    let keys: BTreeSet<String> = revoke_targets(vault, murk, recipient)?
        .into_iter()
        .flatten()
        .map(|pk| canonical_recipient(&pk).into_owned())
        .collect();
    let revoked = |pk: &str| keys.contains(canonical_recipient(pk).as_ref());

    if vault.recipients.iter().all(|pk| revoked(pk)) {
        return Err(MurkError::Recipient(
            "cannot revoke last recipient — vault would become permanently inaccessible".into(),
        ));
    }

    // Groups any revoked pubkey belonged to (captured before removal below).
    let revoked_groups: BTreeSet<String> = murk
        .groups
        .iter()
        .filter(|(_, members)| members.iter().any(|pk| revoked(pk)))
        .map(|(name, _)| name.clone())
        .collect();

    // Report keys the revoked recipient could actually decrypt — computed
    // BEFORE the removal below, which strips their scoped entries. Covers
    // shared secrets (every recipient can read), their scoped entries, and any
    // group they belonged to.
    let exposed_keys: Vec<String> = vault
        .secrets
        .iter()
        .filter(|(_, entry)| {
            !entry.shared.is_empty()
                || entry.private.keys().any(|pk| revoked(pk))
                || entry.grouped.keys().any(|g| revoked_groups.contains(g))
        })
        .map(|(key, _)| key.clone())
        .collect();

    // Name the recipient after its first header entry that has one.
    let display_name = vault
        .recipients
        .iter()
        .chain(murk.recipients.keys())
        .filter(|pk| revoked(pk))
        .find_map(|pk| murk.recipients.get(pk).cloned());
    vault.recipients.retain(|pk| !revoked(pk));
    murk.recipients.retain(|pk, _| !revoked(pk));

    // Remove their scoped entries.
    for scoped_map in murk.private.values_mut() {
        scoped_map.retain(|pk, _| !revoked(pk));
    }
    for entry in vault.secrets.values_mut() {
        entry.private.retain(|pk, _| !revoked(pk));
    }

    // Remove them from any groups they belonged to. save_vault re-encrypts
    // affected groups (when the operator is a member and can read them).
    for members in murk.groups.values_mut() {
        members.retain(|pk| !revoked(pk));
    }

    // Drop any agent grant whose ephemeral pubkey was just revoked, so revoking
    // an agent recipient (directly or via `agent revoke`) never leaves an
    // orphaned grant record pointing at a pubkey that is no longer a recipient.
    murk.grants.retain(|_, grant| !revoked(&grant.pubkey));

    Ok(RevokeResult {
        display_name,
        exposed_keys,
    })
}

/// Truncate a pubkey for display, keeping start and end.
pub fn truncate_pubkey(pk: &str) -> String {
    if let Some(key_data) = pk.strip_prefix("ssh-ed25519 ") {
        return truncate_raw(key_data);
    }
    if let Some(key_data) = pk.strip_prefix("ssh-rsa ") {
        return truncate_raw(key_data);
    }
    truncate_raw(pk)
}

fn truncate_raw(s: &str) -> String {
    if s.len() <= 13 {
        return s.to_string();
    }
    let start: String = s.chars().take(8).collect();
    let end: String = s
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}…{end}")
}

/// Return the key type label for a pubkey string.
pub fn key_type_label(pk: &str) -> &'static str {
    if pk.starts_with("ssh-ed25519 ") {
        "ed25519"
    } else if pk.starts_with("ssh-rsa ") {
        "rsa"
    } else {
        "age"
    }
}

/// A group of recipients sharing a display name.
pub struct RecipientGroup<'a> {
    pub name: Option<&'a str>,
    pub entries: Vec<&'a RecipientEntry>,
    pub is_self: bool,
}

/// Group recipient entries by display name and format for display.
/// Returns plain-text lines (no ANSI colors).
pub fn format_recipient_lines(entries: &[RecipientEntry]) -> Vec<String> {
    let has_names = entries.iter().any(|e| e.display_name.is_some());
    if !has_names {
        return entries.iter().map(|e| e.pubkey.clone()).collect();
    }

    let groups = group_recipients(entries);

    let name_width = groups
        .iter()
        .map(|g| g.name.map_or(0, str::len))
        .max()
        .unwrap_or(0);

    groups
        .iter()
        .map(|g| {
            let marker = if g.is_self { "◆" } else { " " };
            let label = g.name.unwrap_or("");
            let label_padded = format!("{label:<name_width$}");
            let key_type = key_type_label(&g.entries[0].pubkey);
            let key_info = if g.entries.len() == 1 {
                truncate_pubkey(&g.entries[0].pubkey)
            } else {
                format!("({} keys)", g.entries.len())
            };
            format!("{marker} {label_padded}  {key_info}  {key_type}")
        })
        .collect()
}

fn group_recipients(entries: &[RecipientEntry]) -> Vec<RecipientGroup<'_>> {
    let mut groups: Vec<RecipientGroup<'_>> = Vec::new();
    for entry in entries {
        let name = entry.display_name.as_deref();
        if let Some(group) = groups.iter_mut().find(|g| g.name == name && name.is_some()) {
            group.entries.push(entry);
            if entry.is_self {
                group.is_self = true;
            }
        } else {
            groups.push(RecipientGroup {
                name,
                entries: vec![entry],
                is_self: entry.is_self,
            });
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::types;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn authorize_recipient_success() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, &pubkey, Some("alice"));
        assert!(result.is_ok());
        assert!(vault.recipients.contains(&pubkey));
        assert_eq!(murk.recipients[&pubkey], "alice");
    }

    #[test]
    fn authorize_recipient_no_name() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        authorize_recipient(&mut vault, &mut murk, &pubkey, None).unwrap();
        assert!(vault.recipients.contains(&pubkey));
        assert!(!murk.recipients.contains_key(&pubkey));
    }

    #[test]
    fn authorize_recipient_duplicate_fails() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients.push(pubkey.clone());
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, &pubkey, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("already a recipient")
        );
    }

    #[test]
    fn authorize_recipient_invalid_key_fails() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, "not-a-valid-key", None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid public key")
        );
    }

    #[test]
    fn revoke_recipient_by_pubkey() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                private: std::collections::BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
        assert!(vault.recipients.contains(&pk1));
        assert_eq!(result.exposed_keys, vec!["KEY"]);
    }

    #[test]
    fn revoke_recipient_by_name() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, "bob").unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
    }

    #[test]
    fn revoke_recipient_last_fails() {
        let (_, pk) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk.clone()];
        let mut murk = empty_murk();

        let result = revoke_recipient(&mut vault, &mut murk, &pk);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot revoke last recipient")
        );
    }

    #[test]
    fn revoke_recipient_unknown_fails() {
        let (_, pk) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk.clone()];
        let mut murk = empty_murk();

        let result = revoke_recipient(&mut vault, &mut murk, "nobody");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("recipient not found")
        );
    }

    #[test]
    fn revoke_recipient_removes_scoped() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ct".into(),
                private: BTreeMap::from([(pk2.clone(), "scoped_ct".into())]),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut murk = empty_murk();
        let mut scoped = HashMap::new();
        scoped.insert(pk2.clone(), secret("scoped_val"));
        murk.private.insert("KEY".into(), scoped);

        revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();

        assert!(vault.secrets["KEY"].private.is_empty());
        assert!(murk.private["KEY"].is_empty());
    }

    #[test]
    fn revoke_recipient_reports_exposed_keys() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        // exposed_keys returns all schema keys, so we need schema entries.
        vault.schema.insert(
            "DB_URL".into(),
            types::SchemaEntry {
                description: "db".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "api".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.secrets.insert(
            "DB_URL".into(),
            types::SecretEntry {
                shared: "ct".into(),
                private: BTreeMap::from([(pk2.clone(), "scoped_db".into())]),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        vault.secrets.insert(
            "API_KEY".into(),
            types::SecretEntry {
                shared: "ct2".into(),
                private: BTreeMap::from([(pk2.clone(), "scoped_api".into())]),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut murk = empty_murk();
        murk.private
            .insert("DB_URL".into(), HashMap::from([(pk2.clone(), secret("v"))]));
        murk.private.insert(
            "API_KEY".into(),
            HashMap::from([(pk2.clone(), secret("v2"))]),
        );

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();
        let mut keys = result.exposed_keys.clone();
        keys.sort();
        assert_eq!(keys, vec!["API_KEY", "DB_URL"]);
        assert!(vault.secrets["DB_URL"].private.is_empty());
        assert!(vault.secrets["API_KEY"].private.is_empty());
    }

    // ── list_recipients tests ──

    #[test]
    fn list_recipients_with_meta() {
        let (secret, pubkey) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let mut names = std::collections::HashMap::new();
        names.insert(pubkey.clone(), "Alice".to_string());
        names.insert(pk2.clone(), "Bob".to_string());
        let meta = types::Meta {
            recipients: names,
            mac: String::new(),
            mac_key: None,
            github_pins: HashMap::new(),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let r2 = make_recipient(&pk2);
        let meta_enc = crate::encrypt_value(&meta_json, &[recipient, r2]).unwrap();

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone(), pk2.clone()];
        vault.meta = meta_enc;

        let entries = list_recipients(&vault, Some(&secret)).unwrap();
        assert_eq!(entries.len(), 2);
        let me = entries.iter().find(|e| e.pubkey == pubkey).unwrap();
        assert!(me.is_self);
        assert_eq!(me.display_name.as_deref(), Some("Alice"));
        let other = entries.iter().find(|e| e.pubkey == pk2).unwrap();
        assert!(!other.is_self);
        assert_eq!(other.display_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn list_recipients_without_key() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone()];

        let entries = list_recipients(&vault, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pubkey, pubkey);
        assert!(entries[0].display_name.is_none());
        assert!(!entries[0].is_self);
    }

    #[test]
    fn list_recipients_wrong_key() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();

        let meta = types::Meta {
            recipients: std::collections::HashMap::from([(pubkey.clone(), "Alice".into())]),
            mac: String::new(),
            mac_key: None,
            github_pins: HashMap::new(),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let meta_enc = crate::encrypt_value(&meta_json, &[recipient]).unwrap();

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone()];
        vault.meta = meta_enc;

        let entries = list_recipients(&vault, Some(&wrong_secret)).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].display_name.is_none());
        assert!(!entries[0].is_self);
    }

    #[test]
    fn list_recipients_empty_vault() {
        let vault = empty_vault();
        let entries = list_recipients(&vault, None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn revoke_recipient_no_scoped() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
    }

    #[test]
    fn revoke_by_name_rejects_ambiguous_match() {
        let (_, pk_owner) = generate_keypair();
        let (_, pk_laptop) = generate_keypair();
        let (_, pk_desktop) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk_owner.clone(), pk_laptop.clone(), pk_desktop.clone()];
        let mut murk = empty_murk();
        murk.recipients.insert(pk_laptop.clone(), "alice".into());
        murk.recipients.insert(pk_desktop.clone(), "alice".into());

        let result = revoke_recipient(&mut vault, &mut murk, "alice");
        assert!(result.unwrap_err().to_string().contains("ambiguous name"));
        assert_eq!(vault.recipients.len(), 3);
    }

    /// Every key fetched for a GitHub user carries `<user>@github`, so that
    /// name (or `github:<user>`) names one person and revokes all their keys.
    #[test]
    fn revoke_github_user_by_name_removes_every_key() {
        for spec in ["alice@github", "github:alice"] {
            let (_, pk_owner) = generate_keypair();
            let (_, pk_ssh1) = generate_keypair();
            let (_, pk_ssh2) = generate_keypair();
            let mut vault = empty_vault();
            vault.recipients = vec![pk_owner.clone(), pk_ssh1.clone(), pk_ssh2.clone()];
            let mut murk = empty_murk();
            murk.recipients
                .insert(pk_ssh1.clone(), "alice@github".into());
            murk.recipients
                .insert(pk_ssh2.clone(), "alice@github".into());

            let result = revoke_recipient(&mut vault, &mut murk, spec).unwrap();
            assert_eq!(result.display_name.as_deref(), Some("alice@github"));
            assert_eq!(vault.recipients, vec![pk_owner], "{spec}");
            assert!(murk.recipients.is_empty(), "{spec}");
        }
    }

    #[test]
    fn authorize_ssh_key_stores_canonical_form_and_refuses_twins() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let commented = format!("{SSH_ED25519_PK} bob@laptop");
        assert!(authorize_recipient(&mut vault, &mut murk, &commented, None).is_ok());
        assert_eq!(vault.recipients, vec![SSH_ED25519_PK.to_string()]);
        assert_eq!(murk.recipients[SSH_ED25519_PK], "bob@laptop");

        let spaced = SSH_ED25519_PK.replace(' ', "   ") + "\tbob@desktop";
        for twin in [
            SSH_ED25519_PK.to_string(),
            format!("{SSH_ED25519_PK} other"),
            spaced,
        ] {
            let err = authorize_recipient(&mut vault, &mut murk, &twin, Some("bob"))
                .expect_err(&twin)
                .to_string();
            assert!(err.contains("already a recipient"), "{twin}: {err}");
        }
        assert_eq!(vault.recipients.len(), 1);
        assert_eq!(murk.recipients[SSH_ED25519_PK], "bob@laptop");
    }

    /// An older murk stored SSH keys verbatim, so a vault can hold the same key
    /// twice. Revoking either form removes every copy along with each copy's
    /// name, scoped overrides and group memberships.
    #[test]
    fn revoke_removes_every_copy_of_a_duplicated_ssh_key() {
        let commented = format!("{SSH_ED25519_PK} bob@laptop");
        for spec in [
            SSH_ED25519_PK.to_string(),
            format!("{SSH_ED25519_PK} other"),
        ] {
            let (_, pk_owner) = generate_keypair();
            let mut vault = empty_vault();
            vault.recipients = vec![
                pk_owner.clone(),
                SSH_ED25519_PK.to_string(),
                commented.clone(),
            ];
            vault.secrets.insert(
                "KEY".into(),
                types::SecretEntry {
                    shared: "ct".into(),
                    private: BTreeMap::from([
                        (SSH_ED25519_PK.to_string(), "scoped_ct".into()),
                        (commented.clone(), "scoped_ct".into()),
                    ]),
                    grouped: BTreeMap::default(),
                },
            );
            let mut murk = empty_murk();
            murk.recipients.insert(commented.clone(), "bob".into());
            murk.private.insert(
                "KEY".into(),
                HashMap::from([(commented.clone(), secret("bob's override"))]),
            );
            murk.groups.insert(
                "ops".into(),
                vec![pk_owner.clone(), commented.clone(), SSH_ED25519_PK.into()],
            );

            revoke_recipient(&mut vault, &mut murk, &spec).unwrap();

            assert_eq!(vault.recipients, vec![pk_owner.clone()], "{spec}");
            assert!(vault.secrets["KEY"].private.is_empty(), "{spec}");
            assert!(murk.private["KEY"].is_empty(), "{spec}");
            assert!(murk.recipients.is_empty(), "{spec}");
            assert_eq!(murk.groups["ops"], vec![pk_owner], "{spec}");
        }
    }

    /// Overrides and group memberships may be keyed by a spelling of the key
    /// that is in neither the header nor the name map (here the bare key, while
    /// the header lists two commented twins). Revoke still removes them.
    #[test]
    fn revoke_removes_entries_keyed_by_any_spelling_of_the_key() {
        let (_, pk_owner) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![
            pk_owner.clone(),
            format!("{SSH_ED25519_PK} bob@laptop"),
            format!("{SSH_ED25519_PK} bob@desktop"),
        ];
        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ct".into(),
                private: BTreeMap::from([(SSH_ED25519_PK.to_string(), "scoped_ct".into())]),
                grouped: BTreeMap::default(),
            },
        );
        let mut murk = empty_murk();
        murk.private.insert(
            "KEY".into(),
            HashMap::from([(SSH_ED25519_PK.to_string(), secret("bob's override"))]),
        );
        murk.groups
            .insert("ops".into(), vec![pk_owner.clone(), SSH_ED25519_PK.into()]);

        let result = revoke_recipient(
            &mut vault,
            &mut murk,
            &format!("{SSH_ED25519_PK} bob@laptop"),
        )
        .unwrap();

        assert_eq!(vault.recipients, vec![pk_owner.clone()]);
        assert!(vault.secrets["KEY"].private.is_empty());
        assert!(murk.private["KEY"].is_empty());
        assert_eq!(murk.groups["ops"], vec![pk_owner]);
        assert_eq!(result.exposed_keys, vec!["KEY"]);
    }

    /// Bech32 is case-insensitive: an uppercase age key is the same recipient
    /// as its lowercase form. It is stored lowercase, a twin in the other case
    /// is refused, and a mixed-case key (invalid Bech32) is rejected.
    #[test]
    fn authorize_age_key_folds_case_and_refuses_twins() {
        let (_, pubkey) = generate_keypair();
        let upper = pubkey.to_ascii_uppercase();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        assert!(authorize_recipient(&mut vault, &mut murk, &upper, Some("bob")).is_ok());
        assert_eq!(vault.recipients, vec![pubkey.clone()]);
        assert_eq!(murk.recipients[&pubkey], "bob");

        let err = authorize_recipient(&mut vault, &mut murk, &pubkey, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already a recipient"), "{err}");

        let (_, other) = generate_keypair();
        let mixed = format!("AGE1{}", &other[4..]);
        let err = authorize_recipient(&mut vault, &mut murk, &mixed, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid public key"), "{err}");
        assert_eq!(vault.recipients.len(), 1);
    }

    /// A vault can hold an age key in both cases (an older murk stored keys
    /// verbatim). Revoking either spelling removes both and their overrides.
    #[test]
    fn revoke_removes_both_cases_of_an_age_key() {
        let (_, pk_owner) = generate_keypair();
        let (_, bob) = generate_keypair();
        let bob_upper = bob.to_ascii_uppercase();
        for spec in [&bob, &bob_upper] {
            let mut vault = empty_vault();
            vault.recipients = vec![pk_owner.clone(), bob.clone(), bob_upper.clone()];
            vault.secrets.insert(
                "KEY".into(),
                types::SecretEntry {
                    shared: "ct".into(),
                    private: BTreeMap::from([(bob_upper.clone(), "scoped_ct".into())]),
                    grouped: BTreeMap::default(),
                },
            );
            let mut murk = empty_murk();
            murk.recipients.insert(bob_upper.clone(), "bob".into());

            let result = revoke_recipient(&mut vault, &mut murk, spec).unwrap();
            assert_eq!(result.display_name.as_deref(), Some("bob"), "{spec}");
            assert_eq!(vault.recipients, vec![pk_owner.clone()], "{spec}");
            assert!(vault.secrets["KEY"].private.is_empty(), "{spec}");
            assert!(murk.recipients.is_empty(), "{spec}");
        }
    }

    // ── formatting tests ──

    #[test]
    fn truncate_age_key() {
        let pk = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let truncated = truncate_pubkey(pk);
        assert!(truncated.len() < pk.len());
        assert!(truncated.starts_with("age1ql3z"));
        assert!(truncated.contains('…'));
    }

    #[test]
    fn truncate_ssh_key() {
        let pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVsample";
        let truncated = truncate_pubkey(pk);
        assert!(!truncated.starts_with("ssh-ed25519"));
        assert!(truncated.contains('…'));
    }

    #[test]
    fn truncate_short_key_unchanged() {
        assert_eq!(truncate_pubkey("age1short"), "age1short");
    }

    #[test]
    fn key_type_labels() {
        assert_eq!(key_type_label("age1abc"), "age");
        assert_eq!(key_type_label("ssh-ed25519 AAAA"), "ed25519");
        assert_eq!(key_type_label("ssh-rsa AAAA"), "rsa");
    }

    #[test]
    fn format_recipients_no_names() {
        let entries = vec![
            RecipientEntry {
                pubkey: "age1abc".into(),
                display_name: None,
                is_self: false,
            },
            RecipientEntry {
                pubkey: "age1xyz".into(),
                display_name: None,
                is_self: false,
            },
        ];
        let lines = format_recipient_lines(&entries);
        assert_eq!(lines, vec!["age1abc", "age1xyz"]);
    }

    #[test]
    fn format_recipients_with_names() {
        let entries = vec![
            RecipientEntry {
                pubkey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".into(),
                display_name: Some("alice".into()),
                is_self: true,
            },
            RecipientEntry {
                pubkey: "age1xyz7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".into(),
                display_name: Some("bob".into()),
                is_self: false,
            },
        ];
        let lines = format_recipient_lines(&entries);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("◆"));
        assert!(lines[0].contains("alice"));
        assert!(lines[1].starts_with(' '));
        assert!(lines[1].contains("bob"));
    }

    #[test]
    fn format_recipients_groups_multi_key() {
        let entries = vec![
            RecipientEntry {
                pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkey1sample".into(),
                display_name: Some("alice@github".into()),
                is_self: false,
            },
            RecipientEntry {
                pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkey2sample".into(),
                display_name: Some("alice@github".into()),
                is_self: false,
            },
        ];
        let lines = format_recipient_lines(&entries);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("(2 keys)"));
    }

    #[test]
    fn revoke_recipient_preserves_other_group_members() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        let mut murk = empty_murk();
        // A group holding both the survivor and the recipient being revoked.
        murk.groups
            .insert("team".into(), vec![pk1.clone(), pk2.clone()]);

        revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();

        // Only the revoked key leaves the group; the other member stays.
        assert_eq!(murk.groups["team"], vec![pk1.clone()]);
    }

    #[test]
    fn revoke_recipient_keeps_unrelated_grants() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair(); // revoked agent
        let (_, pk3) = generate_keypair(); // unrelated agent
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone(), pk3.clone()];
        let mut murk = empty_murk();
        murk.grants.insert(
            "revoked".into(),
            types::GrantEntry {
                pubkey: pk2.clone(),
                ..Default::default()
            },
        );
        murk.grants.insert(
            "other".into(),
            types::GrantEntry {
                pubkey: pk3.clone(),
                ..Default::default()
            },
        );

        revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();

        // The revoked agent's grant is dropped; the unrelated grant survives.
        assert!(!murk.grants.contains_key("revoked"));
        assert!(murk.grants.contains_key("other"));
    }

    #[test]
    fn revoke_recipient_reports_scoped_only_exposed_key() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        // A secret with NO shared value, readable by pk2 only via a scoped entry.
        // The empty shared value is what exercises the private clause of the
        // exposed-keys OR (a shared value would short-circuit it true).
        vault.secrets.insert(
            "SCOPED_ONLY".into(),
            types::SecretEntry {
                shared: String::new(),
                private: BTreeMap::from([(pk2.clone(), "scoped_ct".into())]),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut murk = empty_murk();
        murk.private.insert(
            "SCOPED_ONLY".into(),
            HashMap::from([(pk2.clone(), secret("v"))]),
        );

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();

        // The revoked recipient could read this scoped-only key, so it must be
        // reported as exposed even though it has no shared value.
        assert_eq!(result.exposed_keys, vec!["SCOPED_ONLY"]);
    }
}
