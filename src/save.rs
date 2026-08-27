//! Vault save path: re-encrypt only what changed, rebuild the meta blob, and
//! re-MAC / re-sign it so the on-disk vault stays integrity-anchored.

use crate::{
    MurkError, compute_mac, crypto, decode_mac_key, encrypt_value, generate_mac_key,
    parse_recipients, sign_vault, signing_identity, types, vault,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Re-encrypt a key's shared (everyone) ciphertext, reusing the existing one
/// when the value and recipient set are unchanged (for minimal git diffs).
fn rebuild_shared(
    key: &str,
    vault: &types::Vault,
    recipients: &[crypto::MurkRecipient],
    recipients_changed: bool,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<String, MurkError> {
    let Some(value) = current.values.get(key) else {
        // Scoped/group-only key — no shared ciphertext.
        return Ok(String::new());
    };
    // Reuse the stored ciphertext when the value and recipient set are unchanged.
    if !recipients_changed
        && original.values.get(key) == Some(value)
        && let Some(existing) = vault.secrets.get(key)
    {
        return Ok(existing.shared.clone());
    }
    encrypt_value(value.as_bytes(), recipients)
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

    if let Some(key_scoped) = current.private.get(key) {
        for (pk, val) in key_scoped {
            let original_val = original.private.get(key).and_then(|m| m.get(pk));
            if original_val != Some(val) {
                let recipient = crypto::parse_recipient(pk)?;
                scoped.insert(pk.clone(), encrypt_value(val.as_bytes(), &[recipient])?);
            }
        }
    }

    if let Some(orig_key_scoped) = original.private.get(key) {
        for pk in orig_key_scoped.keys() {
            let still_present = current.private.get(key).is_some_and(|m| m.contains_key(pk));
            if !still_present {
                scoped.remove(pk);
            }
        }
    }

    Ok(scoped)
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

/// Save the vault: compare against original state and only re-encrypt changed values.
/// Unchanged values keep their original ciphertext for minimal git diffs.
pub fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    // The full recipient set encrypts the meta blob, so every recipient —
    // including agent grants — can verify integrity and read group/grant state.
    let recipients = parse_recipients(&vault.recipients)?;

    // Agent grant pubkeys are deliberately excluded from the shared "everyone"
    // layer: a granted agent must read only the scoped values granted to it, not
    // every shared secret. They remain meta recipients (above) but never receive
    // the shared ciphertext.
    let grant_pubkeys: BTreeSet<&str> =
        current.grants.values().map(|g| g.pubkey.as_str()).collect();
    let shared_recipients: Vec<crypto::MurkRecipient> = vault
        .recipients
        .iter()
        .filter(|pk| !grant_pubkeys.contains(pk.as_str()))
        .map(|pk| crypto::parse_recipient(pk))
        .collect::<Result<_, _>>()?;

    // Check if the *shared* recipient set (recipients minus agent grants) changed
    // — that forces full re-encryption of shared values. Adding or removing an
    // agent doesn't change this set, so it doesn't needlessly churn shared
    // ciphertext (and never pulls an agent into the shared layer).
    let shared_recipients_changed = {
        let orig_grant_pubkeys: BTreeSet<&str> = original
            .grants
            .values()
            .map(|g| g.pubkey.as_str())
            .collect();
        let mut current_pks: Vec<&str> = vault
            .recipients
            .iter()
            .map(String::as_str)
            .filter(|pk| !grant_pubkeys.contains(pk))
            .collect();
        let mut original_pks: Vec<&str> = original
            .recipients
            .keys()
            .map(String::as_str)
            .filter(|pk| !orig_grant_pubkeys.contains(pk))
            .collect();
        current_pks.sort_unstable();
        original_pks.sort_unstable();
        current_pks != original_pks
    };

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

    // Preserve on-disk secrets the operator can't see (other groups' values, or
    // other recipients' scoped entries). These never enter the decrypted `Murk`,
    // so without this they'd be silently dropped when a non-member saves. A key
    // the operator *deleted* was visible at load (in `original`) and is excluded,
    // so deletions still take effect.
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

    let meta = build_meta(vault_path, vault, current);
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &recipients)?;

    Ok(vault::write(Path::new(vault_path), vault)?)
}

/// Build the meta blob for a save: a fresh MAC key + MAC, and a signature when
/// the operator holds a signing-capable identity (see [`sign_vault`]). The
/// signer registry is carried forward from `current` so every recipient's
/// verifying key persists across saves.
fn build_meta(vault_path: &str, vault: &types::Vault, current: &types::Murk) -> types::Meta {
    // Always generate a fresh BLAKE3 key on save.
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(vault, &current.groups, &current.grants, Some(&mac_key));

    // SSH/hardware identities can't sign, so the vault is written unsigned (a
    // warning surfaced on next load).
    let mut signers = current.signers.clone();
    // Drop registry entries for pubkeys no longer in the recipient set — a
    // revoked recipient's verifying key is inert (verify requires the signer to
    // be a current recipient) but shouldn't linger. Prune BEFORE signing so the
    // signed message matches the stored `signers`. (ssh-ed25519 signers are never
    // registered, so only age entries are affected.)
    signers.retain(|pk, _| vault.recipients.iter().any(|r| r == pk));
    let sig = signing_identity(vault_path).and_then(|identity| {
        sign_vault(
            vault,
            &current.groups,
            &current.grants,
            &current.github_pins,
            &mut signers,
            &identity,
        )
    });

    types::Meta {
        recipients: current.recipients.clone(),
        mac,
        mac_key: Some(mac_key_hex),
        github_pins: current.github_pins.clone(),
        groups: current.groups.clone(),
        grants: current.grants.clone(),
        signers,
        sig,
    }
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
        // ssh-ed25519 signers are self-authenticating, so anchored even on first load.
        assert_eq!(
            murk.signature,
            types::SignatureState::Signed {
                signer: SSH_ED25519_PK.to_string(),
                anchored: true,
            }
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_prunes_stale_signer_registry_entries() {
        // A signer entry for a pubkey no longer in the recipient set is dropped on
        // the next write, and the vault still verifies (prune happens before sign).
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_prune_signers");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = signed_test_vault(&pubkey, &recipient);
        let current = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            // A stale registry entry for a pubkey that is NOT a recipient.
            signers: BTreeMap::from([(
                "age1stalerevokedrecipient".to_string(),
                BASE64.encode([9u8; 32]),
            )]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &current, &current).unwrap();

        let murk = load_vault(path.to_str().unwrap()).unwrap().1;
        unsafe { std::env::remove_var("MURK_KEY") };
        assert!(
            !murk.signers.contains_key("age1stalerevokedrecipient"),
            "stale non-recipient signer entry must be pruned"
        );
        assert!(
            murk.signers.contains_key(&pubkey),
            "live signer must remain"
        );
        assert!(matches!(
            murk.signature,
            types::SignatureState::Signed { signer, .. } if signer == pubkey
        ));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn age_signature_first_use_then_anchored() {
        // An age signature is trust-on-first-use until its key is pinned: the
        // first load reports it unanchored, a later load (key matches the pin)
        // reports it anchored.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let dir = std::env::temp_dir().join("murk_test_anchor_transition");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");
        let ps = path.to_str().unwrap();

        let mut vault = signed_test_vault(&pubkey, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(ps, &mut vault, &original, &original).unwrap();

        let first = load_vault(ps).unwrap().1;
        let second = load_vault(ps).unwrap().1;
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert_eq!(
            first.signature,
            types::SignatureState::Signed {
                signer: pubkey.clone(),
                anchored: false,
            },
            "first load of an age key is trust-on-first-use"
        );
        assert_eq!(
            second.signature,
            types::SignatureState::Signed {
                signer: pubkey,
                anchored: true,
            },
            "second load is anchored by the pin"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_preserves_unchanged_ciphertext() {
        let (secret, pubkey) = generate_keypair();
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
        let (_, pubkey) = generate_keypair();
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
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_remove");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
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
}
