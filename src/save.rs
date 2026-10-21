// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault save path: re-encrypt only what changed, rebuild the meta blob, and
//! re-MAC / re-sign it so the on-disk vault stays integrity-anchored.

use crate::{
    MurkError, compute_mac, crypto, decode_mac_key, encrypt_value, generate_mac_key,
    parse_recipients, register_signer, sign_vault, signing_identity, types, vault,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Re-encrypt a key's shared (everyone) ciphertext, reusing the existing one
/// when the value and recipient set are unchanged (for minimal git diffs).
///
/// A shared value the writer couldn't decrypt at load (an agent grant is
/// excluded from the shared tier) keeps its stored ciphertext unchanged.
/// [`unreadable_reencrypts`] has already refused the save if that ciphertext
/// would need new recipients.
fn rebuild_shared(
    key: &str,
    vault: &types::Vault,
    recipients: &[crypto::MurkRecipient],
    recipients_changed: bool,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<String, MurkError> {
    let existing = vault.secrets.get(key).map(|e| e.shared.as_str());
    let Some(value) = current.values.get(key) else {
        // The writer read a shared value at load and it's gone now: deleted, or
        // moved to another tier. Otherwise it's a scoped/group-only key (no
        // shared ciphertext) or one the writer can't read, so keep what's stored.
        if original.values.contains_key(key) {
            return Ok(String::new());
        }
        return Ok(existing.unwrap_or_default().to_owned());
    };
    // Reuse the stored ciphertext when the value and recipient set are unchanged.
    if !recipients_changed
        && original.values.get(key) == Some(value)
        && let Some(existing) = existing
    {
        return Ok(existing.to_owned());
    }
    encrypt_value(value.as_bytes(), recipients)
}

/// Name every stored value the writer couldn't decrypt at load whose tier
/// gained a recipient since: carrying its old ciphertext over would leave the
/// new recipient unable to read it, and the writer can't re-encrypt it. Returns
/// one `KEY (tier)` label per value, empty when the save is safe.
///
/// A tier that only lost recipients (a revoke) is not listed: the removed
/// recipient could already read that exact value, revoke marks it as owed a
/// rotation, and the next value change goes through a reader who re-encrypts it.
/// Keys the writer deleted outright are skipped; deletion is deliberate.
fn unreadable_reencrypts(
    vault: &types::Vault,
    original: &types::Murk,
    current: &types::Murk,
    keys: &BTreeSet<&String>,
    shared_gained: bool,
) -> Vec<String> {
    let gained_member = |group: &str| {
        let before = original.groups.get(group);
        current.groups.get(group).is_some_and(|members| {
            members
                .iter()
                .any(|pk| !before.is_some_and(|m| m.contains(pk)))
        })
    };
    let mut blocked = Vec::new();
    for key in keys {
        let Some(entry) = vault.secrets.get(key.as_str()) else {
            continue;
        };
        if shared_gained
            && !entry.shared.is_empty()
            && !original.values.contains_key(key.as_str())
            && !current.values.contains_key(key.as_str())
        {
            blocked.push(format!("{key} (shared)"));
        }
        let read_at_load = original.grouped.get(key.as_str());
        let written_now = current.grouped.get(key.as_str());
        for group in entry.grouped.keys() {
            if gained_member(group)
                && !read_at_load.is_some_and(|m| m.contains_key(group))
                && !written_now.is_some_and(|m| m.contains_key(group))
            {
                blocked.push(format!("{key} (group {group})"));
            }
        }
    }
    blocked
}

/// Re-encrypt a key's scoped (per-recipient) ciphertexts, keeping unchanged
/// entries and dropping ones removed since load.
fn rebuild_private(
    key: &str,
    vault: &types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<BTreeMap<String, String>, MurkError> {
    let mut scoped = vault
        .secrets
        .get(key)
        .map(|e| e.private.clone())
        .unwrap_or_default();

    // Loading files a legacy alias spelling (SSH comment, uppercase age key)
    // under the canonical pubkey, so a rewrite or removal replaces every
    // spelling of that key, never leaving a stale copy behind.
    let drop_spellings = |scoped: &mut BTreeMap<String, String>, pk: &str| {
        scoped.retain(|k, _| !crate::recipients::same_recipient(k, pk));
    };

    if let Some(key_scoped) = current.private.get(key) {
        for (pk, val) in key_scoped {
            let original_val = original.private.get(key).and_then(|m| m.get(pk));
            if original_val != Some(val) {
                let recipient = crypto::parse_recipient(pk)?;
                drop_spellings(&mut scoped, pk);
                scoped.insert(pk.clone(), encrypt_value(val.as_bytes(), &[recipient])?);
            }
        }
    }

    if let Some(orig_key_scoped) = original.private.get(key) {
        for pk in orig_key_scoped.keys() {
            let still_present = current.private.get(key).is_some_and(|m| m.contains_key(pk));
            if !still_present {
                drop_spellings(&mut scoped, pk);
            }
        }
    }

    Ok(canonical_keys(scoped).into_iter().collect())
}

/// Re-encrypt a key's named-group ciphertexts to each group's current members.
/// Re-encrypts when the value changed or the group's membership changed; drops
/// groups removed since load.
fn rebuild_grouped(
    key: &str,
    vault: &types::Vault,
    changed_groups: &BTreeSet<&str>,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<BTreeMap<String, String>, MurkError> {
    let mut grouped = vault
        .secrets
        .get(key)
        .map(|e| e.grouped.clone())
        .unwrap_or_default();

    if let Some(key_grouped) = current.grouped.get(key) {
        for (group, val) in key_grouped {
            let members = current.groups.get(group).ok_or_else(|| {
                MurkError::Secret(format!("secret {key} references unknown group {group}"))
            })?;
            let original_val = original.grouped.get(key).and_then(|m| m.get(group));
            if original_val != Some(val) || changed_groups.contains(group.as_str()) {
                let group_recipients = parse_recipients(members)?;
                grouped.insert(
                    group.clone(),
                    encrypt_value(val.as_bytes(), &group_recipients)?,
                );
            }
        }
    }

    if let Some(orig_key_grouped) = original.grouped.get(key) {
        for group in orig_key_grouped.keys() {
            let still_present = current
                .grouped
                .get(key)
                .is_some_and(|m| m.contains_key(group));
            if !still_present {
                grouped.remove(group);
            }
        }
    }

    Ok(grouped)
}

/// Keep each active grant's private copy of `key` in sync with the key's current
/// shared value. A grant stages a per-agent private copy at grant time; without
/// this, rotating a granted key would leave the agent reading the stale value
/// (the operator can't see the agent's ciphertext to re-encrypt it, and
/// `rebuild_private` preserves it as-is). When the value changed since load and
/// the operator can read it, re-encrypt the agent's copy; unchanged values keep
/// their preserved ciphertext (no churn), and keys the operator can't read are
/// left untouched.
fn resync_grant_private(
    key: &str,
    private: &mut BTreeMap<String, String>,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    let Some(value) = current.values.get(key) else {
        return Ok(());
    };
    if original.values.get(key) == Some(value) {
        return Ok(());
    }
    for grant in current.grants.values() {
        if grant.scope.iter().any(|k| k == key) {
            let recipient = crypto::parse_recipient(&grant.pubkey)?;
            private.insert(
                grant.pubkey.clone(),
                encrypt_value(value.as_bytes(), &[recipient])?,
            );
        }
    }
    Ok(())
}

/// The key this save is made with: it must exist and be one of the vault's
/// recipients, or the write would encrypt secrets the saver can't read back.
fn saving_identity(
    vault_path: &str,
    vault: &types::Vault,
) -> Result<crypto::MurkIdentity, MurkError> {
    let saver = signing_identity(vault_path).ok_or_else(|| {
        MurkError::Key(
            "refusing to save: no usable key to save with. Set MURK_KEY or MURK_KEY_FILE".into(),
        )
    })?;
    let saver_pubkey = saver.pubkey_string()?;
    if !crate::load::is_listed_recipient(vault, &saver_pubkey) {
        return Err(MurkError::Recipient(format!(
            "refusing to save: your key ({}) is not a recipient of this vault, so the write would \
             encrypt secrets you can't read back. Run `murk circle` to check, or ask a recipient \
             to authorize you",
            crate::validate::show(&saver_pubkey)
        )));
    }
    Ok(saver)
}

/// Set the vault's identity and rollback counter for this save, both covered
/// by the signature. The counter moves past the highest this machine
/// accepted, so a deliberate revert (an older file restored, then saved)
/// reads as newer to everyone.
fn advance_identity(vault: &mut types::Vault, prior_pin: Option<&crate::pins::TrustPin>) {
    if vault.vault_id.is_empty() {
        // A vault written by murk 0.13 gets its id on the first 0.14 save. Use
        // the one this machine already pinned, else derive it from the
        // vault's own creation stamp and name, so teammates upgrading
        // separately (or on different branches) arrive at the same id.
        vault.vault_id = prior_pin
            .map(|p| p.vault_id.clone())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| derived_vault_id(vault));
    }
    vault.generation = vault
        .generation
        .max(prior_pin.map_or(0, |p| p.generation))
        .saturating_add(1);
}

/// Drop or narrow grants before a save, so a grant only ever receives values
/// it is still entitled to. Returns the adjusted state, or `None` when nothing
/// changed (the common case, so no clone).
///
/// - An expired grant (or one with an unreadable or missing expiry) is removed
///   with its recipient entry and scoped copies, so a rotation after the TTL
///   never re-encrypts to it. Scope keys whose value this save leaves unchanged
///   are marked as owed a rotation, like any revoke; a key rotated in this very
///   save is not, since the agent never gets the new value.
/// - A scoped key that no longer has a shared value (moved to a group, or
///   removed) leaves the grant's scope, and the grant's copy of it is deleted:
///   scope binds to the shared secret it was granted, not to the key name, so
///   a later key of the same name is not handed to the agent. A grant whose
///   scope empties is removed.
fn prune_grants(
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<types::Murk>, MurkError> {
    let expired = |name: &str, grant: &types::GrantEntry| {
        crate::policy::check_grant_expiry(name, grant, now).is_err()
    };
    // A key "left the shared tier" only if the writer read it and it's gone.
    // A shared value the writer never could read (the carry-over case) still
    // stands, so its grants are left alone.
    let unreadable_shared: BTreeSet<String> = vault
        .secrets
        .iter()
        .filter(|(k, e)| !e.shared.is_empty() && !original.values.contains_key(k.as_str()))
        .map(|(k, _)| k.clone())
        .collect();
    let still_shared =
        |key: &String| current.values.contains_key(key) || unreadable_shared.contains(key);
    if !current
        .grants
        .iter()
        .any(|(name, g)| expired(name, g) || !g.scope.iter().all(still_shared))
    {
        return Ok(None);
    }

    let mut pruned = current.clone();
    for (name, grant) in &current.grants {
        let (kept, gone): (Vec<String>, Vec<String>) =
            grant.scope.iter().cloned().partition(still_shared);
        if expired(name, grant) || kept.is_empty() {
            crate::remove_grant(&mut pruned, name)?;
            if vault.recipients.contains(&grant.pubkey) {
                crate::revoke_recipient(vault, &mut pruned, &grant.pubkey)?;
            } else {
                // A save earlier in this command already revoked it (a caller
                // that saves twice from one loaded state): clear what's left.
                pruned.recipients.remove(&grant.pubkey);
                for members in pruned.groups.values_mut() {
                    members.retain(|pk| pk != &grant.pubkey);
                }
                for entry in vault.secrets.values_mut() {
                    entry.private.remove(&grant.pubkey);
                }
            }
            if expired(name, grant) {
                let unchanged: Vec<String> = kept
                    .into_iter()
                    .filter(|k| original.values.get(k) == current.values.get(k))
                    .collect();
                crate::mark_revoked(vault, &unchanged, now);
            }
            continue;
        }
        for key in &gone {
            if let Some(entry) = vault.secrets.get_mut(key) {
                entry.private.remove(&grant.pubkey);
            }
        }
        if let Some(g) = pruned.grants.get_mut(name) {
            g.scope = kept;
        }
    }
    Ok(Some(pruned))
}

/// How the *shared* recipient set (recipients minus agent grants) moved since
/// load: `(changed, gained)`. Any change forces full re-encryption of shared
/// values. Adding or removing an agent doesn't change this set, so it doesn't
/// needlessly churn shared ciphertext (and never pulls an agent into the
/// shared layer).
fn shared_recipient_change(
    vault: &types::Vault,
    original: &types::Murk,
    grant_pubkeys: &BTreeSet<&str>,
) -> (bool, bool) {
    let orig_grant_pubkeys: BTreeSet<&str> = original
        .grants
        .values()
        .map(|g| g.pubkey.as_str())
        .collect();
    let now: BTreeSet<&str> = vault
        .recipients
        .iter()
        .map(String::as_str)
        .filter(|pk| !grant_pubkeys.contains(pk))
        .collect();
    let before: BTreeSet<&str> = original
        .recipients
        .keys()
        .map(String::as_str)
        .filter(|pk| !orig_grant_pubkeys.contains(pk))
        .collect();
    (now != before, !now.is_subset(&before))
}

/// Who the meta blob is encrypted to: every recipient except agent grants. The
/// meta holds the MAC key, names, groups and every grant; a grant gets only its
/// own record, in its `agents` blob (see [`crate::agents`]).
fn meta_recipients(
    vault: &types::Vault,
    current: &types::Murk,
) -> Result<Vec<crypto::MurkRecipient>, MurkError> {
    parse_recipients(&crate::agents::meta_recipients(
        &vault.recipients,
        &current.grants,
    ))
}

/// Write each recipient once, in its canonical spelling. murk ≤ 0.13 compared
/// keys as exact strings, so a 2.x header can list one key twice (an SSH key
/// with and without its comment); a 3.x header never does.
fn canonicalise_recipients(vault: &mut types::Vault) {
    let mut seen = BTreeSet::new();
    vault.recipients = std::mem::take(&mut vault.recipients)
        .into_iter()
        .filter_map(|r| {
            let canonical = crate::recipients::canonical_recipient(&r).into_owned();
            seen.insert(canonical.clone()).then_some(canonical)
        })
        .collect();
}

/// `map` with every key in its canonical spelling. Where two spellings of one
/// key both have an entry, the one already spelled canonically wins.
fn canonical_keys<V>(map: impl IntoIterator<Item = (String, V)>) -> Vec<(String, V)> {
    let mut out: BTreeMap<String, (bool, V)> = BTreeMap::new();
    for (k, v) in map {
        let canonical = crate::recipients::canonical_recipient(&k);
        let exact = canonical == k.as_str();
        let canonical = canonical.into_owned();
        match out.get(&canonical) {
            Some((true, _)) => {}
            Some((false, _)) if !exact => {}
            _ => {
                out.insert(canonical, (exact, v));
            }
        }
    }
    out.into_iter().map(|(k, (_, v))| (k, v)).collect()
}

/// Refuse to save to a vault listing an unsafe (low-order or torsion)
/// recipient. age panics when encrypting to a low-order point, and an
/// unchanged save may not encrypt at all, so check every recipient up front.
fn refuse_unsafe_recipients(vault: &types::Vault) -> Result<(), MurkError> {
    match parse_recipients(&vault.recipients)?
        .iter()
        .find_map(|r| r.weakness().map(|why| (r.to_string(), why)))
    {
        Some((r, why)) => Err(MurkError::Recipient(format!(
            "refusing to save: recipient {r} is unsafe ({why}) — revoke it first with `murk circle revoke \"{r}\"`"
        ))),
        None => Ok(()),
    }
}

/// Save the vault: compare against original state and only re-encrypt changed values.
/// Unchanged values keep their original ciphertext for minimal git diffs.
///
/// Refuses unless the saving identity (the key resolved for `vault_path`) is in
/// `vault.recipients`: writing as a non-recipient would encrypt values to a
/// recipient set the saver can't read back, and possibly one an attacker chose.
/// Flows that onboard a key add it to the recipients before saving.
///
/// Also refuses, writing nothing, when the state was loaded by an agent grant
/// ([`crate::ensure_writable`]), or when the change adds recipients to a value
/// the writer couldn't decrypt.
pub fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    crate::ensure_writable(original)?;
    // Text a write adds to the header (descriptions, examples, tags, names,
    // policy tags) must not be able to forge or reorder output. Every writer
    // goes through here, the bindings included. Text already in the vault on
    // disk is kept, so a vault holding older text stays writable.
    let on_disk = vault::read(Path::new(vault_path)).ok();
    crate::validate::new_header_text(
        on_disk.as_ref().map(|v| (v, &original.recipients)),
        vault,
        &current.recipients,
    )
    .map_err(|e| MurkError::Secret(format!("refusing to write {e}")))?;

    let saver = saving_identity(vault_path, vault)?;
    // This build MACs and signs in the 3.x format, so the header says so.
    types::VAULT_VERSION.clone_into(&mut vault.version);
    canonicalise_recipients(vault);
    let pruned = prune_grants(vault, original, current, chrono::Utc::now())?;
    let current = pruned.as_ref().unwrap_or(current);

    let recipients = meta_recipients(vault, current)?;
    refuse_unsafe_recipients(vault)?;

    let prior_pin = refuse_carried_removed_keys(vault_path, vault, on_disk.as_ref(), current)?;
    advance_identity(vault, prior_pin.as_ref());

    announce_new_group_members(original, current);

    // Agent grant pubkeys are deliberately excluded from the shared "everyone"
    // layer: a granted agent must read only the scoped values granted to it, not
    // every shared secret. (Nor are they meta recipients; see above.)
    let grant_pubkeys: BTreeSet<&str> =
        current.grants.values().map(|g| g.pubkey.as_str()).collect();
    let shared_recipients: Vec<crypto::MurkRecipient> = vault
        .recipients
        .iter()
        .filter(|pk| !grant_pubkeys.contains(pk.as_str()))
        .map(|pk| crypto::parse_recipient(pk))
        .collect::<Result<_, _>>()?;

    let (shared_recipients_changed, shared_recipients_gained) =
        shared_recipient_change(vault, original, &grant_pubkeys);

    // Groups whose membership changed since load — their secrets must be
    // re-encrypted even when the plaintext is unchanged, so a removed member
    // loses access (and a new one gains it).
    let changed_groups: BTreeSet<&str> = current
        .groups
        .keys()
        .chain(original.groups.keys())
        .filter(|g| current.groups.get(*g) != original.groups.get(*g))
        .map(String::as_str)
        .collect();

    let mut new_secrets = BTreeMap::new();

    // Collect all keys with a shared, scoped, or grouped value in the operator's
    // working state.
    let mut all_keys: BTreeSet<&String> = current.values.keys().collect();
    all_keys.extend(current.private.keys());
    all_keys.extend(current.grouped.keys());

    // Preserve on-disk secrets the operator can't see (other groups' values,
    // other recipients' scoped entries, or shared values for an agent grant).
    // These never enter the decrypted `Murk`, so without this they'd be silently
    // dropped when a non-member saves; each rebuild_* step carries the stored
    // ciphertext over. A key the operator *deleted* was visible at load (in
    // `original`) and is excluded, so deletions still take effect.
    let original_visible: BTreeSet<&String> = original
        .values
        .keys()
        .chain(original.private.keys())
        .chain(original.grouped.keys())
        .collect();
    for key in vault.secrets.keys() {
        if !original_visible.contains(key) {
            all_keys.insert(key);
        }
    }

    let blocked = unreadable_reencrypts(
        vault,
        original,
        current,
        &all_keys,
        shared_recipients_gained,
    );
    if !blocked.is_empty() {
        return Err(MurkError::Secret(format!(
            "refusing to save: this change adds recipients to values your key can't read, so it can't re-encrypt them: {}\nnothing was written\nrun it with a key that can read them (a member of the group, or a recipient rather than an agent grant)",
            blocked.join(", ")
        )));
    }

    for key in all_keys {
        let shared = rebuild_shared(
            key,
            vault,
            &shared_recipients,
            shared_recipients_changed,
            original,
            current,
        )?;
        let mut private = rebuild_private(key, vault, original, current)?;
        resync_grant_private(key, &mut private, original, current)?;
        let grouped = rebuild_grouped(key, vault, &changed_groups, original, current)?;
        new_secrets.insert(
            key.clone(),
            types::SecretEntry {
                shared,
                private,
                grouped,
            },
        );
    }

    vault.secrets = new_secrets;
    crate::agents::rebuild(vault, original, current)?;

    let meta = build_meta(vault, current, &saver, prior_pin.as_ref());
    crate::validate::meta(&meta)
        .map_err(|e| MurkError::Secret(format!("refusing to write invalid vault meta: {e}")))?;
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &recipients)?;

    // Sign last: signed view v2 covers the finished file, meta ciphertext
    // included. SSH-RSA/hardware identities can't sign, so the vault is then
    // written unsigned.
    vault.sig = None;
    vault.sig = sign_vault(vault, &saver);

    vault::write(Path::new(vault_path), vault)?;
    record_own_save(vault_path, vault, current, &meta.signers, on_disk.as_ref());
    Ok(())
}

/// Read the trust pin for a save, refusing one that would write back a key
/// this machine recorded as removed only because the file it replaces — an
/// older revision, numbered at or below the removal — still lists it: the
/// save is numbered past the removal and signed by a trusted key, so every
/// machine would take it as the key re-added. A save that adds the key itself
/// (`circle authorize`) re-adds it on purpose and is allowed, and so is a save
/// on a branch the removal has not reached (see
/// [`crate::trust::removal_applies`]), where the key is still a member.
fn refuse_carried_removed_keys(
    vault_path: &str,
    vault: &types::Vault,
    on_disk: Option<&types::Vault>,
    current: &types::Murk,
) -> Result<Option<crate::pins::TrustPin>, MurkError> {
    let prior_pin = crate::pins::read(vault_path).map_err(MurkError::Trust)?;
    let (Some(pin), Some(on_disk)) = (prior_pin.as_ref(), on_disk) else {
        return Ok(prior_pin);
    };
    let checkout = crate::trust::Checkout::of(vault_path, Some(pin));
    let canonical = |r: &String| crate::recipients::canonical_recipient(r).into_owned();
    let before: BTreeSet<String> = on_disk.recipients.iter().map(canonical).collect();
    let carried = vault.recipients.iter().find_map(|r| {
        let key = canonical(r);
        let at = *pin.removed.get(&key)?;
        let applies = crate::trust::removal_applies(pin, &key, &checkout);
        (applies && before.contains(&key) && on_disk.generation <= at).then_some((r, at))
    });
    match carried {
        Some((key, at)) => Err(MurkError::Secret(format!(
            "refusing to save: this vault still lists {}, who was removed from it at generation {at} on this machine, and it is an older revision (generation {}) — saving would add them back\nnothing was written\nupdate to the vault that removed them (pull, or merge the removal into this branch), then make the change again; to re-add them on purpose, run `murk circle authorize` for them",
            crate::trust::label(&current.recipients, key),
            on_disk.generation
        ))),
        None => Ok(prior_pin),
    }
}

/// A fresh random vault identity: 16 bytes as 32 lowercase hex characters.
pub(crate) fn new_vault_id() -> String {
    let id: [u8; 16] = rand::random();
    id.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The vault id for a vault written by murk 0.13, derived from fields every
/// copy shares (`created`, `vault_name`), so independent first saves agree.
/// New vaults get a random id from [`new_vault_id`] at `murk init`.
pub(crate) fn derived_vault_id(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"murk.vault_id.v1\0");
    h.update(vault.created.as_bytes());
    h.update(b"\0");
    h.update(vault.vault_name.as_bytes());
    h.finalize()
        .iter()
        .take(16)
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Say which recipients a group gains in this save, before their ciphertexts
/// are written: a membership change should never be silent.
fn announce_new_group_members(original: &types::Murk, current: &types::Murk) {
    for (group, members) in &current.groups {
        let before = original.groups.get(group);
        for member in members {
            if !before.is_some_and(|b| b.contains(member)) {
                eprintln!(
                    "◆ group {group} gained {}",
                    crate::trust::label(&current.recipients, member)
                );
            }
        }
    }
}

/// Record this machine's own write in the trust pin: a signed save is accepted
/// as this machine's decision, changing the trusted set by what the save
/// added and removed relative to `before`, the recipients of the file it
/// replaced (see [`crate::trust::Acceptance::OwnSave`]). An unsigned save —
/// the key cannot sign — clears `was_signed`, since the next load here would
/// otherwise refuse the operator's own write. The pin is re-read under its
/// lock. Best-effort: the vault is already written, so a pin failure only
/// warns.
fn record_own_save(
    vault_path: &str,
    vault: &types::Vault,
    current: &types::Murk,
    registry: &BTreeMap<String, String>,
    replaced: Option<&types::Vault>,
) {
    if !crate::pins::signer_pin_available() {
        return;
    }
    let before: Option<BTreeSet<String>> = replaced.map(|v| {
        v.recipients
            .iter()
            .map(|r| crate::recipients::canonical_recipient(r).into_owned())
            .collect()
    });
    let result = crate::pins::update(vault_path, |prior| {
        let pin = if let Some(sig) = &vault.sig {
            let signature = types::SignatureState::Signed {
                signer: sig.signer.clone(),
                v: sig.v,
            };
            let loaded = crate::trust::Loaded {
                vault,
                signature: &signature,
                signer_vk: crate::signature::registry_entry(registry, &sig.signer)
                    .map(String::as_str),
                registry,
                names: &current.recipients,
                groups: &current.groups,
                grants: &current.grants,
                loader_can_sign: true,
                operator_key: None,
            };
            crate::trust::accepted_pin(
                &loaded,
                prior,
                crate::trust::Acceptance::OwnSave {
                    before: before.as_ref(),
                },
                &crate::trust::head_of(vault_path),
            )
        } else {
            let Some(prior) = prior else { return Ok(None) };
            if prior.was_signed {
                eprintln!(
                    "warn {vault_path} was written unsigned (this key cannot sign) — teammates' murk will refuse it until someone with an age or ssh-ed25519 key reviews it and runs `murk trust`"
                );
            }
            let mut pin = prior.clone();
            pin.was_signed = false;
            pin.generation = pin.generation.max(vault.generation);
            pin
        };
        Ok(Some(pin))
    });
    if let Err(e) = result {
        eprintln!("warn {e}");
    }
}

/// Build the meta blob for a save: a fresh MAC key + MAC, and the signer
/// registry (see [`vouched_registry`]). The signature itself lives outside
/// the meta, in `Vault::sig`.
fn build_meta(
    vault: &types::Vault,
    current: &types::Murk,
    saver: &crypto::MurkIdentity,
    pin: Option<&crate::pins::TrustPin>,
) -> types::Meta {
    // Always generate a fresh BLAKE3 key on save.
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(vault, &current.groups, &current.grants, Some(&mac_key));

    types::Meta {
        recipients: canonical_keys(current.recipients.clone())
            .into_iter()
            .collect(),
        mac,
        mac_key: Some(mac_key_hex),
        github_pins: current.github_pins.clone(),
        groups: current.groups.clone(),
        grants: current.grants.clone(),
        signers: vouched_registry(vault, &current.signers, pin, saver),
        sig: None,
    }
}

/// The signer registry (age pubkey → verifying key) a writer signs for
/// `vault`'s current recipients. Signing vouches for every entry, so with a
/// trust pin only the keys this machine pinned are written — an entry the
/// loaded file claimed but this machine never confirmed (one another signer
/// was not entitled to vouch for, say) is dropped rather than re-signed —
/// plus the writer's own (see [`register_signer`]). An entry this machine
/// pinned on another signer's word (`added_by`) is never written: signing it
/// would vouch for it under the writer's name, so other machines would keep
/// believing it after its adder is removed. Such a key reaches other machines
/// through a write by someone who confirmed it. The loaded entries are carried
/// forward as they are only when this machine has no pin file at all
/// (`MURK_NO_SIGNER_PIN`, or no home directory). A load trusted through
/// `MURK_TRUSTED_SIGNERS` still writes a pin, with no keys added to `signers`,
/// so a later save there writes only the pinned keys and the writer's own.
pub(crate) fn vouched_registry(
    vault: &types::Vault,
    loaded: &BTreeMap<String, String>,
    pin: Option<&crate::pins::TrustPin>,
    writer: &crypto::MurkIdentity,
) -> BTreeMap<String, String> {
    let recipients: BTreeSet<String> = vault
        .recipients
        .iter()
        .map(|r| crate::recipients::canonical_recipient(r).into_owned())
        .collect();
    let source: BTreeMap<String, String> = pin.map_or_else(
        || {
            loaded
                .iter()
                .map(|(pk, vk)| {
                    (
                        crate::recipients::canonical_recipient(pk).into_owned(),
                        vk.clone(),
                    )
                })
                .collect()
        },
        |pin| {
            pin.signers
                .iter()
                .filter(|(pk, _)| !pin.added_by.contains_key(*pk))
                .map(|(pk, vk)| (pk.clone(), vk.clone()))
                .collect()
        },
    );
    let mut signers: BTreeMap<String, String> = source
        .into_iter()
        .filter(|(pk, _)| recipients.contains(pk))
        .collect();
    register_signer(vault, &mut signers, writer);
    signers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    use crate::testutil::ENV_LOCK;
    use crate::testutil::*;
    use std::collections::{BTreeMap, HashMap};
    use std::fs;

    #[test]
    fn ssh_end_to_end_save_and_load_reports_signed() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recipient = make_recipient(SSH_ED25519_PK);

        let dir = std::env::temp_dir().join("murk_test_ssh_e2e_sign");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(SSH_ED25519_PK.to_string(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", SSH_ED25519_SK) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        let murk = load_vault(path.to_str().unwrap()).unwrap().1;
        unsafe { std::env::remove_var("MURK_KEY") };
        assert_eq!(
            murk.signature,
            types::SignatureState::Signed {
                signer: SSH_ED25519_PK.to_string(),
                v: crate::signature::SIGNED_VIEW_VERSION,
            }
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_save_never_re_signs_a_key_binding_this_machine_did_not_confirm() {
        // Mallory's accepted vault claimed Bob → her own key, but this
        // machine refused to pin it (she may not vouch for Bob). A routine
        // save by a teammate must not sign that entry, or every machine that
        // trusts the teammate would then believe it.
        let (writer_secret, writer) = generate_keypair();
        let (_, bob) = generate_keypair();
        let writer_id = make_identity(&writer_secret);
        let mut vault = signed_test_vault(&writer, &make_recipient(&writer));
        vault.recipients.push(bob.clone());
        let mallory_vk = make_identity(&generate_keypair().0)
            .signing_key()
            .unwrap()
            .verifying_key();
        let loaded = BTreeMap::from([(bob.clone(), mallory_vk)]);
        let pin = crate::pins::TrustPin {
            trusted: [writer.clone(), bob.clone()].into(),
            ..Default::default()
        };
        let registry = vouched_registry(&vault, &loaded, Some(&pin), &writer_id);
        assert!(!registry.contains_key(&bob), "{registry:?}");
        assert!(
            registry.contains_key(&writer),
            "the writer's own key is registered"
        );
    }

    #[test]
    fn save_registers_the_savers_key_and_prunes_revoked_entries() {
        // The registry the saver signs holds their real verifying key (a stale
        // entry for them is replaced) and nothing for keys no longer in the
        // vault.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        let (secret, pubkey) = generate_keypair();
        let (_, gone) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");

        let mut vault = signed_test_vault(&pubkey, &recipient);
        let current = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            signers: BTreeMap::from([
                (pubkey.clone(), BASE64.encode([9u8; 32])),
                (gone, BASE64.encode([8u8; 32])),
            ]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &current, &current).unwrap();

        let murk = load_vault(path.to_str().unwrap()).unwrap().1;
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let own = make_identity(&secret)
            .signing_key()
            .unwrap()
            .verifying_key();
        assert_eq!(murk.signers, BTreeMap::from([(pubkey.clone(), own)]));
        assert!(matches!(
            murk.signature,
            types::SignatureState::Signed { signer, .. } if signer == pubkey
        ));
    }

    /// An older murk stored age keys as typed, so a signer's own header entry
    /// may be uppercase while its identity's pubkey is lowercase. The signature
    /// still verifies and the signer keeps its registry entry, so the vault
    /// loads (and can be repaired or revoked from).
    #[test]
    fn signed_vault_with_uppercase_signer_header_loads() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };

        let (secret, pubkey) = generate_keypair();
        let upper = pubkey.to_ascii_uppercase();
        let recipient = make_recipient(&pubkey);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");
        let ps = path.to_str().unwrap();

        let mut vault = signed_test_vault(&upper, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(upper.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let saved = save_vault(ps, &mut vault, &original, &original);
        let loaded = load_vault(ps).map(|(_, murk, _)| murk);
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        saved.unwrap();
        let murk = loaded.unwrap();
        assert!(murk.signers.contains_key(&pubkey));
        assert!(matches!(
            murk.signature,
            types::SignatureState::Signed { signer, .. } if signer == pubkey
        ));
    }

    /// The save-time guard against a low-order recipient, which the CLI can no
    /// longer reach (authorize refuses the key, and a hand-added one breaks the
    /// signature): each of the five refuses with an error naming the key, and
    /// nothing reaches age, which would panic.
    #[test]
    fn save_refuses_a_low_order_recipient_instead_of_panicking() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let (sk, pubkey) = generate_keypair();
        unsafe { std::env::set_var("MURK_KEY", &sk) };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");
        let results: Vec<_> = crate::testutil::LOW_ORDER_AGE_RECIPIENTS
            .iter()
            .map(|weak| {
                let mut vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
                vault.recipients.push((*weak).to_string());
                let murk = types::Murk {
                    values: HashMap::from([("API_KEY".into(), secret("REAL"))]),
                    ..Default::default()
                };
                let before = vault.clone();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    save_vault(path.to_str().unwrap(), &mut vault, &murk, &murk)
                }));
                (*weak, r, path.exists(), vault.meta == before.meta)
            })
            .collect();
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        for (weak, r, written, meta_unchanged) in results {
            let err = r.unwrap_or_else(|_| panic!("{weak}: save panicked"));
            let err = err.expect_err(weak).to_string();
            assert!(
                err.contains("unsafe") && err.contains(weak),
                "{weak}: {err}"
            );
            assert!(!written && meta_unchanged, "{weak}");
        }
    }

    /// A `me` override written by an older murk under another spelling of the
    /// owner's key (here uppercase age) is still the owner's: it loads under
    /// their canonical pubkey, and rewriting or removing it replaces that
    /// spelling rather than leaving a stale, still-decryptable copy.
    #[test]
    fn own_override_keyed_by_a_legacy_spelling_loads_and_is_replaced() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };

        let (sk, pubkey) = generate_keypair();
        // save_vault signs with MURK_KEY.
        unsafe { std::env::set_var("MURK_KEY", &sk) };
        let upper = pubkey.to_ascii_uppercase();
        let identity = make_identity(&sk);
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("test.murk");
        let ps = ps.to_str().unwrap();

        let mut vault = signed_test_vault(&upper, &make_recipient(&pubkey));
        let empty = types::Murk::default();
        let legacy = types::Murk {
            values: HashMap::from([("API_KEY".into(), secret("shared"))]),
            private: HashMap::from([(
                "API_KEY".into(),
                HashMap::from([(upper.clone(), secret("mine"))]),
            )]),
            ..Default::default()
        };
        let results = (|| {
            save_vault(ps, &mut vault, &empty, &legacy)?;
            let loaded = decrypt_vault(&vault, &identity)?;
            let mut changed = loaded.clone();
            changed
                .private
                .get_mut("API_KEY")
                .unwrap()
                .insert(pubkey.clone(), secret("new"));
            save_vault(ps, &mut vault, &loaded, &changed)?;
            let after_change: Vec<String> =
                vault.secrets["API_KEY"].private.keys().cloned().collect();
            let reloaded = decrypt_vault(&vault, &identity)?;
            let mut removed = reloaded.clone();
            removed.private.remove("API_KEY");
            save_vault(ps, &mut vault, &reloaded, &removed)?;
            Ok::<_, MurkError>((loaded, after_change, reloaded))
        })();
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        let (loaded, after_change, reloaded) = results.unwrap();
        assert_eq!(loaded.private["API_KEY"][&pubkey].as_str(), "mine");
        assert_eq!(after_change, vec![pubkey.clone()]);
        assert_eq!(reloaded.private["API_KEY"][&pubkey].as_str(), "new");
        assert!(vault.secrets["API_KEY"].private.is_empty());
    }

    #[test]
    fn saves_move_the_counter_past_the_highest_accepted() {
        // Each save writes max(loaded, pinned) + 1, so a revert to an older
        // file followed by a save is newer than anything teammates accepted.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");
        let ps = path.to_str().unwrap();

        let mut vault = signed_test_vault(&pubkey, &recipient);
        let state = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(ps, &mut vault, &state, &state).unwrap();
        let first = vault.clone();
        save_vault(ps, &mut vault, &state, &state).unwrap();
        assert_eq!((first.generation, vault.generation), (1, 2));
        assert_eq!(first.vault_id, vault.vault_id);

        // Revert to the first revision: refused as a rollback...
        vault::write(&path, &first).unwrap();
        assert!(
            load_vault(ps)
                .unwrap_err()
                .to_string()
                .contains("rolled back")
        );
        // ...and saving it deliberately produces generation 3.
        let mut reverted = first.clone();
        save_vault(ps, &mut reverted, &state, &state).unwrap();
        assert_eq!(reverted.generation, 3);
        assert!(load_vault(ps).is_ok());

        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn save_vault_refuses_new_text_that_can_forge_output_but_keeps_old() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let dir = std::env::temp_dir().join("murk_test_save_new_text");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");
        let path = path.to_str().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };
        // save_vault signs with MURK_KEY.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };

        let mut vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
        let murk = types::Murk {
            recipients: HashMap::from([(pubkey.clone(), "alice".into())]),
            ..Default::default()
        };
        let refused = |vault: &mut types::Vault, current: &types::Murk, field: &str| {
            let err = save_vault(path, vault, &murk, current)
                .unwrap_err()
                .to_string();
            assert!(err.contains(field), "want {field:?}, got {err:?}");
        };

        // The same library calls the bindings make.
        let mut current = murk.clone();
        add_secret(
            &mut vault,
            &mut current,
            "DB",
            "v",
            Some("a\u{202e}b"),
            None,
            false,
            &[],
            None,
        );
        refused(
            &mut vault,
            &current,
            "schema.DB.description: contains invisible",
        );
        describe_key(&mut vault, "DB", "db", Some("x\ry"), &[], None, None);
        refused(&mut vault, &current, "schema.DB.example: contains control");
        describe_key(
            &mut vault,
            "DB",
            "db",
            None,
            &["t\u{200b}".into()],
            None,
            None,
        );
        refused(&mut vault, &current, "schema.DB.tags[0]");
        describe_key(
            &mut vault,
            "DB",
            "db\nsecond line",
            None,
            &["t".into()],
            None,
            None,
        );
        let mut renamed = current.clone();
        renamed
            .recipients
            .insert(pubkey.clone(), "alice\nwarn: none".into());
        refused(&mut vault, &renamed, "meta.recipients");
        save_vault(path, &mut vault, &murk, &current).unwrap();

        // Text already in the vault on disk (written by an older murk) stays
        // writable; new text of the kind is still refused.
        vault.schema.get_mut("DB").unwrap().description = "old\u{202e}text".into();
        vault::write(Path::new(path), &vault).unwrap();
        save_vault(path, &mut vault, &murk, &current).unwrap();
        vault.schema.get_mut("DB").unwrap().description = "new\u{202e}text".into();
        refused(&mut vault, &current, "schema.DB.description");

        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_preserves_unchanged_ciphertext() {
        let (secret, pubkey) = generate_keypair();
        let _key = murk_key_env(&secret);
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_unchanged");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"original", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("original"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let current = original.clone();
        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_eq!(vault.secrets["KEY1"].shared, shared);

        let mut changed = current.clone();
        changed
            .values
            .insert("KEY1".into(), crate::testutil::secret("modified"));
        save_vault(path.to_str().unwrap(), &mut vault, &original, &changed).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity).unwrap();
        assert_eq!(&decrypted[..], b"modified");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_adds_new_secret() {
        let (secret, pubkey) = generate_keypair();
        let _key = murk_key_env(&secret);
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_add");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current = original.clone();
        current
            .values
            .insert("KEY2".into(), crate::testutil::secret("val2"));

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_removes_deleted_secret() {
        let (secret, pubkey) = generate_keypair();
        let _key = murk_key_env(&secret);
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_remove");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val2", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([
                ("KEY1".into(), crate::testutil::secret("val1")),
                ("KEY2".into(), crate::testutil::secret("val2")),
            ]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current = original.clone();
        current.values.remove("KEY2");

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(!vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_reencrypts_all_on_recipient_change() {
        let (secret1, pubkey1) = generate_keypair();
        let _key = murk_key_env(&secret1);
        let (_, pubkey2) = generate_keypair();
        let recipient1 = make_recipient(&pubkey1);

        let dir = std::env::temp_dir().join("murk_test_save_reencrypt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", std::slice::from_ref(&recipient1)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![pubkey1.clone(), pubkey2.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey1.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current_recipients = HashMap::new();
        current_recipients.insert(pubkey1.clone(), "alice".into());
        current_recipients.insert(pubkey2.clone(), "bob".into());
        let current = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: current_recipients,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let identity1 = make_identity(&secret1);
        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity1).unwrap();
        assert_eq!(&decrypted[..], b"val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_scoped_entry_lifecycle() {
        let (secret, pubkey) = generate_keypair();
        let _key = murk_key_env(&secret);
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_scoped");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"shared_val", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("shared_val"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        // Add a scoped override.
        let mut current = original.clone();
        let mut key_scoped = HashMap::new();
        key_scoped.insert(pubkey.clone(), crate::testutil::secret("my_override"));
        current.private.insert("KEY1".into(), key_scoped);

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets["KEY1"].private.contains_key(&pubkey));
        let scoped_val = decrypt_value(&vault.secrets["KEY1"].private[&pubkey], &identity).unwrap();
        assert_eq!(&scoped_val[..], b"my_override");

        // Now remove the scoped override.
        let original_with_scoped = current.clone();
        let mut current_no_scoped = original_with_scoped.clone();
        current_no_scoped.private.remove("KEY1");

        save_vault(
            path.to_str().unwrap(),
            &mut vault,
            &original_with_scoped,
            &current_no_scoped,
        )
        .unwrap();

        assert!(vault.secrets["KEY1"].private.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_refuses_when_saver_is_not_a_recipient() {
        // A vault whose recipients exclude the saver (e.g. a planted skeleton
        // listing only an attacker) must not be written: the values would be
        // encrypted only to keys the saver didn't choose.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (saver_secret, _saver_pub) = generate_keypair();
        let (_, attacker_pub) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");

        let mut vault = empty_vault();
        vault.recipients = vec![attacker_pub.clone()];
        let original = empty_murk();
        let mut current = original.clone();
        current.values.insert(
            "DB_PASSWORD".into(),
            crate::testutil::secret("hunter2hunter2"),
        );

        unsafe { std::env::set_var("MURK_KEY", &saver_secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let result = save_vault(path.to_str().unwrap(), &mut vault, &original, &current);
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("a non-recipient save must be refused");
        assert!(
            err.to_string().contains("not a recipient"),
            "unexpected error: {err}"
        );
        assert!(!path.exists(), "nothing may be written");
    }

    /// Three recipients; bob writes SHARED (everyone) and PROD (group `ops` =
    /// bob + carol), so alice can read SHARED but not PROD. Returns the vault
    /// path and alice's/bob's secret keys. Caller holds `ENV_LOCK`.
    fn vault_with_foreign_group(name: &str) -> (std::path::PathBuf, String, String, String) {
        let (alice_sk, alice_pk) = generate_keypair();
        let (bob_sk, bob_pk) = generate_keypair();
        let (_, carol_pk) = generate_keypair();

        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = empty_vault();
        vault.recipients = vec![alice_pk.clone(), bob_pk.clone(), carol_pk.clone()];
        let names = HashMap::from([
            (alice_pk.clone(), "alice".to_string()),
            (bob_pk.clone(), "bob".to_string()),
            (carol_pk.clone(), "carol".to_string()),
        ]);
        let original = types::Murk {
            recipients: names.clone(),
            ..Default::default()
        };
        let current = types::Murk {
            recipients: names,
            values: HashMap::from([("SHARED".into(), secret("s"))]),
            grouped: HashMap::from([("PROD".into(), HashMap::from([("ops".into(), secret("p"))]))]),
            groups: BTreeMap::from([("ops".into(), vec![bob_pk, carol_pk.clone()])]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &bob_sk) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();
        (path, alice_sk, bob_sk, carol_pk)
    }

    #[test]
    fn save_carries_over_values_the_writer_cannot_read() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (path, alice_sk, bob_sk, carol_pk) =
            vault_with_foreign_group("murk_test_carry_over_unreadable");
        let ps = path.to_str().unwrap();

        unsafe { std::env::set_var("MURK_KEY", &alice_sk) };
        let (mut vault, mut original, _) = load_vault(ps).unwrap();
        assert!(!original.grouped.contains_key("PROD"));
        let shared_before = vault.secrets["SHARED"].shared.clone();
        let prod_before = vault.secrets["PROD"].grouped["ops"].clone();

        // A writer that couldn't decrypt SHARED (as an agent grant can't) adds
        // an unrelated key while carol leaves `ops`, a change that only removes
        // recipients.
        original.values.remove("SHARED");
        original.loaded_by = None;
        let mut current = original.clone();
        current.values.insert("NEW".into(), secret("n"));
        current
            .groups
            .get_mut("ops")
            .unwrap()
            .retain(|pk| pk != &carol_pk);
        save_vault(ps, &mut vault, &original, &current).unwrap();

        assert_eq!(vault.secrets["SHARED"].shared, shared_before);
        assert_eq!(vault.secrets["PROD"].grouped["ops"], prod_before);
        unsafe { std::env::set_var("MURK_KEY", &bob_sk) };
        let bob = load_vault(ps).unwrap().1;
        unsafe { std::env::remove_var("MURK_KEY") };
        assert_eq!(bob.values["SHARED"].as_str(), "s");
        assert_eq!(bob.grouped["PROD"]["ops"].as_str(), "p");

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn save_refuses_to_add_recipients_to_a_value_the_writer_cannot_read() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (path, alice_sk, _, _) =
            vault_with_foreign_group("murk_test_refuse_unreadable_reencrypt");
        let ps = path.to_str().unwrap();

        unsafe { std::env::set_var("MURK_KEY", &alice_sk) };
        let (mut vault, original, identity) = load_vault(ps).unwrap();
        let on_disk = fs::read(&path).unwrap();

        // alice joins `ops` without being able to read PROD: carrying the old
        // ciphertext over would leave her membership hollow, and she can't
        // re-encrypt it.
        let mut current = original.clone();
        current
            .groups
            .get_mut("ops")
            .unwrap()
            .push(identity.pubkey_string().unwrap());
        let err = save_vault(ps, &mut vault, &original, &current).unwrap_err();
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(err.to_string().contains("PROD (group ops)"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), on_disk);

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_grant_without_expiry_loads_for_the_operator_but_never_reads() {
        // A grant minted before TTLs existed has an empty `expires_at`. It must
        // not make the vault unloadable for everyone (0.13.0 rejected the whole
        // meta), and it must not read either: no expiry fails closed.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (sk, pk) = generate_keypair();
        let (agent_sk, agent_pk) = generate_keypair();
        let dir = std::env::temp_dir().join("murk_test_legacy_grant_expiry");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");
        let ps = path.to_str().unwrap();

        let mut vault = signed_test_vault(&pk, &make_recipient(&pk));
        let state = types::Murk {
            values: HashMap::from([("API_KEY".into(), secret("REAL"))]),
            recipients: HashMap::from([(pk.clone(), "alice".to_string())]),
            ..Default::default()
        };
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::set_var("MURK_KEY", &sk) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };
        save_vault(ps, &mut vault, &state, &state).unwrap();
        // First load pins the operator as this machine's trusted signer.
        load_vault(ps).unwrap();

        // Add the legacy grant the way an older murk wrote it (no expiry), in
        // the 3.x layout (meta to the operator only, the grant's own record in
        // `agents`), then re-MAC and re-sign as the operator so the vault is
        // otherwise intact.
        let operator = make_identity(&sk);
        let mut meta = decrypt_meta(&vault, &operator).unwrap().unwrap();
        let grant = types::GrantEntry {
            pubkey: agent_pk.clone(),
            scope: vec!["API_KEY".into()],
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: String::new(),
            issuer: pk.clone(),
            anchors: Vec::new(),
        };
        meta.grants.insert("old".into(), grant.clone());
        // A grant's key is minted for it: it joins the vault with the grant,
        // never as a teammate first.
        vault.recipients.push(agent_pk.clone());
        meta.recipients.insert(agent_pk.clone(), "agent:old".into());
        vault.agents = crate::agents::blobs_for(&meta.grants, &[]).unwrap();
        vault.secrets.get_mut("API_KEY").unwrap().private.insert(
            agent_pk.clone(),
            encrypt_value(b"REAL", &[make_recipient(&agent_pk)]).unwrap(),
        );
        vault.generation += 1;
        let mac_key = decode_mac_key(meta.mac_key.as_deref().unwrap()).unwrap();
        meta.mac = compute_mac(&vault, &meta.groups, &meta.grants, Some(&mac_key));
        vault.meta =
            encrypt_value(&serde_json::to_vec(&meta).unwrap(), &[make_recipient(&pk)]).unwrap();
        vault.sig = None;
        vault.sig = sign_vault(&vault, &operator);
        vault::write(&path, &vault).unwrap();

        let as_operator = load_vault(ps);
        // The agent's key file names the operator as its trusted signer.
        let vk = operator.signing_key().unwrap().verifying_key();
        let agent_key_file = format!("{} {pk}:{vk}\n{agent_sk}\n", crate::agents::ANCHOR_PREFIX);
        unsafe { std::env::set_var("MURK_KEY", &agent_key_file) };
        let as_agent = load_vault(ps);
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        let (_, murk, _) = as_operator.expect("the operator must still load the vault");
        assert_eq!(murk.values["API_KEY"].as_str(), "REAL");
        let Err(err) = as_agent else {
            panic!("a grant without expiry must not read");
        };
        assert!(err.to_string().contains("grant old has no expiry"), "{err}");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_grant_record_bound_to_the_operators_key_is_refused_as_tampering() {
        // A meta writer could bind a grant record to an operator's own key (a
        // "ghost" grant) to make the operator read-only, or, expired, lock them
        // out. Here bob, a second recipient and trusted signer, writes one for
        // alice's key and signs it. Grants get freshly minted keys, so a record
        // naming a trusted signer is tampering: alice's load refuses the vault
        // rather than treating her as a grant.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (sk, pk) = generate_keypair();
        let (bob_sk, bob_pk) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");
        let ps = path.to_str().unwrap();
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::set_var("MURK_KEY", &sk) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let operator = make_identity(&sk);
        let bob = make_identity(&bob_sk);
        let entry = |id: &crypto::MurkIdentity, pk: &str| {
            crate::trust::format_trusted_signer(
                pk,
                Some(&id.signing_key().unwrap().verifying_key()),
            )
        };
        let signers = format!("{},{}", entry(&operator, &pk), entry(&bob, &bob_pk));
        unsafe { std::env::set_var("MURK_TRUSTED_SIGNERS", &signers) };

        let mut vault = signed_test_vault(&pk, &make_recipient(&pk));
        vault.recipients.push(bob_pk.clone());
        let state = types::Murk {
            values: HashMap::from([("API_KEY".into(), secret("REAL"))]),
            recipients: HashMap::from([
                (pk.clone(), "alice".to_string()),
                (bob_pk.clone(), "bob".to_string()),
            ]),
            ..Default::default()
        };
        save_vault(ps, &mut vault, &state, &state).unwrap();
        load_vault(ps).unwrap();

        let mut meta = decrypt_meta(&vault, &bob).unwrap().unwrap();
        meta.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: pk.clone(),
                scope: vec!["API_KEY".into()],
                issued_at: "2026-01-01T00:00:00Z".into(),
                expires_at: "2026-01-02T00:00:00Z".into(),
                issuer: bob_pk.clone(),
                anchors: Vec::new(),
            },
        );
        // A matching `agents` blob too, so the planted record would route
        // alice into the grant path if that were decided before the meta.
        vault.agents = crate::agents::blobs_for(&meta.grants, &[]).unwrap();
        crate::register_signer(&vault, &mut meta.signers, &bob);
        vault.generation += 1;
        let mac_key = decode_mac_key(meta.mac_key.as_deref().unwrap()).unwrap();
        meta.mac = compute_mac(&vault, &meta.groups, &meta.grants, Some(&mac_key));
        vault.meta = encrypt_value(
            &serde_json::to_vec(&meta).unwrap(),
            &[make_recipient(&pk), make_recipient(&bob_pk)],
        )
        .unwrap();
        vault.sig = None;
        vault.sig = sign_vault(&vault, &bob);
        vault::write(&path, &vault).unwrap();

        let loaded = load_vault(ps);
        unsafe { std::env::remove_var("MURK_KEY") };
        unsafe { std::env::remove_var("MURK_TRUSTED_SIGNERS") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        let Err(err) = loaded else {
            panic!("a grant record bound to a trusted signer must be refused");
        };
        assert!(
            matches!(err, MurkError::Trust(_))
                && err.to_string().contains("binds agent grant ghost"),
            "{err}"
        );
        assert!(err.to_string().contains("tampered with"), "{err}");
    }
}
