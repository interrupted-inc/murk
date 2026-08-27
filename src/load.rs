//! Vault load path: decrypt the meta blob, verify its MAC and signature under
//! the version-gating rules, and materialize the caller's view of the secrets.

use crate::{
    MurkError, compute_mac, crypto, decode_mac_key, decrypt_value, env, pins,
    plaintext_bytes_to_zeroizing_string, policy, read_vault, types, verify_mac,
    verify_vault_signature,
};
use age::secrecy::ExposeSecret;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroizing;

/// The non-secret state carried out of the encrypted meta blob after integrity
/// verification: recipient names, group membership, agent grants, the
/// legacy-MAC flag, and pinned GitHub fingerprints.
struct MetaState {
    recipients: HashMap<String, String>,
    groups: BTreeMap<String, Vec<String>>,
    grants: BTreeMap<String, types::GrantEntry>,
    legacy_mac: bool,
    github_pins: HashMap<String, Vec<String>>,
    signers: BTreeMap<String, String>,
    signature: types::SignatureState,
}

/// Determine the signature state of a decrypted meta, treating a present-but-
/// invalid signature as tampering (hard error). An absent signature is
/// `Unsigned` — integrity then rests on git, and the caller warns.
fn check_signature(
    vault: &types::Vault,
    meta: &types::Meta,
) -> Result<types::SignatureState, MurkError> {
    match &meta.sig {
        Some(sig) => {
            if verify_vault_signature(
                vault,
                &meta.groups,
                &meta.grants,
                &meta.github_pins,
                &meta.signers,
                sig,
            ) {
                Ok(types::SignatureState::Signed {
                    signer: sig.signer.clone(),
                    // ssh-ed25519 keys are self-authenticating (vk in the recipient
                    // string). age keys are anchored only by a matching local pin,
                    // which `load_vault` confirms; default to not-yet-anchored here.
                    anchored: sig.signer.starts_with("ssh-ed25519 "),
                })
            } else {
                Err(MurkError::Integrity(
                    "vault signature is invalid — it may have been tampered with, or a signer's \
                     verifying key changed. Run `murk verify` for details"
                        .into(),
                ))
            }
        }
        None => Ok(types::SignatureState::Unsigned),
    }
}

/// Decrypt the meta blob and verify the vault's integrity MAC, returning the
/// recipient/group/grant state. Errors if the vault has secrets but a missing or
/// invalid MAC — a tampered or inconsistent vault should fail loudly here rather
/// than surface a misleading decryption error later. An identity that cannot
/// decrypt an intact meta blob is simply not a recipient (revoked or never
/// authorized) and gets a "not a recipient" error, not a tamper warning.
fn resolve_meta_state(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<MetaState, MurkError> {
    if vault.meta.is_empty() {
        if vault.secrets.is_empty() {
            return Ok(MetaState {
                recipients: HashMap::new(),
                groups: BTreeMap::new(),
                grants: BTreeMap::new(),
                legacy_mac: false,
                github_pins: HashMap::new(),
                signers: BTreeMap::new(),
                signature: types::SignatureState::Unsigned,
            });
        }
        return Err(MurkError::Integrity(
            "vault has secrets but no meta — vault may have been tampered with".into(),
        ));
    }

    // The meta blob is present, so failing to decrypt it usually means this
    // identity is not in the recipient set — revoked or never authorized. That
    // is an access problem, not tampering. But the public header lists who
    // SHOULD be able to decrypt: if our key is listed there and still can't
    // open the meta, the header and ciphertext disagree — that reads as
    // tampering, and saying "not a recipient" would hide it. Garbled base64 or
    // JSON likewise means the blob itself was damaged.
    //
    // Accepted residual: an attacker who replaces the meta AND removes a key
    // from the header produces a vault indistinguishable from a legitimate
    // revocation — no client-side check can tell those apart, for any choice
    // of message here. Git history is the audit trail for that case (see
    // THREAT_MODEL.md).
    let ciphertext = BASE64.decode(&vault.meta).map_err(|_| {
        MurkError::Integrity("vault meta is corrupt — vault may have been tampered with".into())
    })?;
    let plaintext = match crypto::decrypt(&ciphertext, identity) {
        Ok(plaintext) => plaintext,
        // A plugin failure (missing age-plugin binary, declined touch) is an
        // environment problem — report it as-is, not as an access verdict.
        Err(e) if matches!(identity, crypto::MurkIdentity::Plugin { .. }) => {
            return Err(e.into());
        }
        Err(_) => {
            if identity
                .pubkey_string()
                .is_ok_and(|pk| is_listed_recipient(vault, &pk))
            {
                return Err(MurkError::Integrity(
                    "your key is listed as a recipient but cannot decrypt the vault meta — vault may have been tampered with".into(),
                ));
            }
            return Err(MurkError::Crypto(crypto::CryptoError::Decrypt(
                "you are not a recipient of this vault. Run `murk circle` to check, or ask a recipient to authorize you".into(),
            )));
        }
    };
    let meta: types::Meta = serde_json::from_slice(&plaintext).map_err(|_| {
        MurkError::Integrity("vault meta is corrupt — vault may have been tampered with".into())
    })?;

    if meta.mac.is_empty() {
        if !vault.secrets.is_empty() {
            return Err(MurkError::Integrity(
                "vault has secrets but MAC is empty — vault may have been tampered with".into(),
            ));
        }
        let signature = check_signature(vault, &meta)?;
        return Ok(MetaState {
            recipients: meta.recipients,
            groups: meta.groups,
            grants: meta.grants,
            legacy_mac: false,
            github_pins: meta.github_pins,
            signers: meta.signers,
            signature,
        });
    }

    let mac_key = meta.mac_key.as_deref().and_then(decode_mac_key);
    if !verify_mac(
        vault,
        &meta.groups,
        &meta.grants,
        &meta.mac,
        mac_key.as_ref(),
    ) {
        let expected = compute_mac(vault, &meta.groups, &meta.grants, mac_key.as_ref());
        return Err(MurkError::Integrity(format!(
            "vault may have been tampered with (expected {expected}, got {})",
            meta.mac
        )));
    }
    let legacy_mac = meta.mac.starts_with("sha256:") || meta.mac.starts_with("sha256v2:");
    let signature = check_signature(vault, &meta)?;
    Ok(MetaState {
        recipients: meta.recipients,
        groups: meta.groups,
        grants: meta.grants,
        legacy_mac,
        github_pins: meta.github_pins,
        signers: meta.signers,
        signature,
    })
}

/// Whether `pubkey` names one of the vault's public header recipients. SSH
/// entries may be stored with a trailing comment while `pubkey_string()` drops
/// it, so ssh keys compare by key type and blob only.
fn is_listed_recipient(vault: &types::Vault, pubkey: &str) -> bool {
    fn ssh_head(s: &str) -> Option<(&str, &str)> {
        let mut it = s.split_whitespace();
        match (it.next(), it.next()) {
            (Some(kind), Some(blob)) if kind.starts_with("ssh-") => Some((kind, blob)),
            _ => None,
        }
    }
    vault.recipients.iter().any(|r| {
        r == pubkey || matches!((ssh_head(r), ssh_head(pubkey)), (Some(a), Some(b)) if a == b)
    })
}

/// Decrypt a vault using the given identity. Verifies integrity, decrypts all
/// shared and scoped values, and returns the working state.
///
/// Use this when you already have a key (e.g. from a Python SDK or test harness).
/// For the common CLI case where the key comes from the environment, use `load_vault`.
pub fn decrypt_vault(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<types::Murk, MurkError> {
    let pubkey = identity.pubkey_string()?;

    // Verify integrity BEFORE decrypting secrets — a tampered vault should fail
    // with an integrity error, not a misleading "you are not a recipient" message.
    let MetaState {
        recipients,
        groups,
        grants,
        legacy_mac,
        github_pins,
        signers,
        signature,
    } = resolve_meta_state(vault, identity)?;

    // An agent grant is a recipient of the meta blob (so it can verify integrity
    // and read its grant) but is deliberately excluded from the shared "everyone"
    // layer. Such an identity legitimately cannot decrypt shared ciphertexts, so
    // it skips them rather than erroring. A normal recipient that fails to decrypt
    // shared is a genuine problem (a true outsider already failed at meta
    // decryption above), so it still gets the clear "not a recipient" error.
    //
    // A granted agent past its TTL fails closed right here, before any secret is
    // decrypted, so every command and binding that loads a vault enforces the
    // expiry. Every grant bound to the pubkey is checked — `create_grant` refuses
    // duplicate bindings, but a hand-built vault could carry them, and an expired
    // duplicate must not hide behind a valid one. Long-lived holders of decrypted
    // state (the MCP server, bindings) re-check per read in `enforce_agent_policy`.
    let mut is_agent = false;
    let now = chrono::Utc::now();
    for (name, grant) in grants.iter().filter(|(_, g)| g.pubkey == pubkey) {
        is_agent = true;
        policy::check_grant_expiry(name, grant, now)?;
    }

    // Decrypt shared values (skip scoped-only entries with empty shared ciphertext).
    let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        if entry.shared.is_empty() {
            continue;
        }
        let plaintext = match decrypt_value(&entry.shared, identity) {
            Ok(plaintext) => plaintext,
            Err(_) if is_agent => continue,
            Err(_) => {
                return Err(MurkError::Crypto(crypto::CryptoError::Decrypt(
                    "you are not a recipient of this vault. Run `murk circle` to check, or ask a recipient to authorize you".into(),
                )));
            }
        };
        let value = plaintext_bytes_to_zeroizing_string(&plaintext)
            .map_err(|e| MurkError::Secret(format!("invalid UTF-8 in secret {key}: {e}")))?;
        values.insert(key.clone(), value);
    }

    // Decrypt our private (per-recipient) overrides — the `me` tier.
    let mut private: HashMap<String, HashMap<String, Zeroizing<String>>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        if let Some(encoded) = entry.private.get(&pubkey)
            && let Ok(value) = decrypt_value(encoded, identity).and_then(|pt| {
                plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| MurkError::Secret(e.to_string()))
            })
        {
            private
                .entry(key.clone())
                .or_default()
                .insert(pubkey.clone(), value);
        }
    }

    // Decrypt named-group values we're a member of. age tells us whether our
    // identity is a recipient, so we just try each group ciphertext and keep the
    // ones that decrypt — non-members silently fall through.
    let mut grouped: HashMap<String, HashMap<String, Zeroizing<String>>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        for (group, encoded) in &entry.grouped {
            if let Ok(value) = decrypt_value(encoded, identity).and_then(|pt| {
                plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| MurkError::Secret(e.to_string()))
            }) {
                grouped
                    .entry(key.clone())
                    .or_default()
                    .insert(group.clone(), value);
            }
        }
    }

    Ok(types::Murk {
        values,
        recipients,
        private,
        grouped,
        groups,
        grants,
        legacy_mac,
        github_pins,
        signers,
        signature,
        signature_downgraded: false,
    })
}

/// Resolve the key from the environment, read the vault, and decrypt it.
///
/// Convenience wrapper combining `resolve_key` + `read_vault` + `decrypt_vault`.
pub fn load_vault(
    vault_path: &str,
) -> Result<(types::Vault, types::Murk, crypto::MurkIdentity), MurkError> {
    let secret_key = env::resolve_key_for_vault(vault_path).map_err(MurkError::Key)?;

    let identity = crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
        // Same shape as the not-set error: summary first, one action per line.
        MurkError::Key(format!(
            "{e}\nfor an age key, set MURK_KEY\nfor an SSH key, set MURK_KEY_FILE=~/.ssh/id_ed25519"
        ))
    })?;

    let vault = read_vault(vault_path)?;
    let mut murk = decrypt_vault(&vault, &identity)?;

    // Enforce the signer-registry pin as part of the trusted load path, so
    // bindings get it too — not just the CLI. The age `signers` registry lives in
    // the re-encryptable meta, so a repo-writer could register their own verifying
    // key under an existing recipient's pubkey and forge that recipient's
    // signature (`verify_vault_signature` would accept it against the swapped
    // key). A pubkey's verifying key is a fixed derivation, so a *changed* key for
    // an already-pinned pubkey is never legitimate: fail hard. `MURK_NO_SIGNER_PIN`
    // opts out.
    let currently_signed = matches!(murk.signature, types::SignatureState::Signed { .. });
    match pins::reconcile(vault_path, &murk.signers, currently_signed) {
        pins::PinVerdict::Conflict { signer } => {
            return Err(MurkError::Integrity(format!(
                "signer {signer}'s verifying key changed since first seen — the signer registry \
                 may have been tampered with to forge a signature. Inspect \
                 `git log -p -- {vault_path}`; if the change is legitimate, clear the pin under \
                 ~/.config/murk/signer-pins/ or set MURK_NO_SIGNER_PIN=1"
            )));
        }
        pins::PinVerdict::Ok {
            first_use,
            downgraded,
        } => {
            // An age signature is authenticated authorship only once its key is
            // anchored by a matching prior pin. On a fresh clone (first-use) the
            // registry key is trust-on-first-use, so mark it not-yet-anchored —
            // git commit signing is the real anchor there. (ssh signers were
            // already anchored=true in `check_signature`.)
            if let types::SignatureState::Signed { signer, anchored } = &mut murk.signature
                && !*anchored
                && !first_use.contains(signer.as_str())
            {
                *anchored = true;
            }
            // A vault signed before on this machine but unsigned now was
            // downgraded — the signature was stripped, or a merge left it
            // unsigned. Not auto-fatal (the merge driver writes `sig: None` on
            // purpose, so unsigned is a legit transient state), but MURK_STRICT
            // refuses it, and every caller sees the flag on `Murk`.
            if downgraded {
                if crate::hardening::strict_mode() {
                    return Err(MurkError::Integrity(format!(
                        "vault {vault_path} was signed before and is now unsigned — the \
                         signature was stripped, or a merge left it unsigned. Refusing under \
                         MURK_STRICT. Review `git log -p -- {vault_path}` and re-sign after \
                         checking `murk diff`; if you deliberately moved to a non-signing key, \
                         clear the pin under ~/.config/murk/signer-pins/ or set \
                         MURK_NO_SIGNER_PIN=1."
                    )));
                }
                murk.signature_downgraded = true;
            }
        }
    }

    Ok((vault, murk, identity))
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
    fn end_to_end_forged_signature_fails_load() {
        // The full attack from the review, now defeated: outsider tampers a
        // ciphertext, re-MACs with a fresh key, re-encrypts meta to the victim's
        // public key — but keeps the now-stale signature (they can't produce a
        // valid one). load must fail with an integrity error.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_forged_sig_load");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Create and sign the vault through the real save path.
        let mut vault = signed_test_vault(&pubkey, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Sanity: it loads clean and reports a signer.
        let murk = load_vault(path.to_str().unwrap()).unwrap().1;
        assert!(matches!(
            &murk.signature,
            types::SignatureState::Signed { signer, .. } if *signer == pubkey
        ));

        // Attacker tampers on disk: poison the value, keep the stale signature,
        // re-MAC + re-encrypt meta using only the (public) recipient key.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let stale_meta = decrypt_meta(&tampered, &identity).unwrap();
        tampered.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        let mac_key_hex = generate_mac_key();
        let mac_key = decode_mac_key(&mac_key_hex).unwrap();
        let forged_mac = compute_mac(
            &tampered,
            &stale_meta.groups,
            &stale_meta.grants,
            Some(&mac_key),
        );
        let forged_meta = types::Meta {
            mac: forged_mac,
            mac_key: Some(mac_key_hex),
            sig: stale_meta.sig.clone(), // stale — over the pre-poison content
            signers: stale_meta.signers.clone(),
            ..stale_meta
        };
        tampered.meta =
            encrypt_value(&serde_json::to_vec(&forged_meta).unwrap(), &[recipient]).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };
        let err = result.expect_err("forged-MAC + stale-signature vault must fail to load");
        assert!(
            err.to_string().contains("signature is invalid"),
            "expected signature failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn registry_vk_swap_rejected_by_pin_on_load() {
        // The signer registry lives in the re-encryptable meta. An attacker can
        // register their OWN verifying key under an existing recipient's pubkey
        // and forge a signature the signature layer accepts. The TOFU pin, now
        // enforced hard inside load_vault, must catch the changed key.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Isolate the pin store under a temp HOME.
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_vk_swap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");
        let ps = path.to_str().unwrap();

        // Legit signed vault; first load pins pubkey -> the real verifying key.
        let mut vault = signed_test_vault(&pubkey, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(ps, &mut vault, &original, &original).unwrap();
        load_vault(ps).unwrap(); // establishes the pin

        // Attacker registers their own verifying key under `pubkey` and re-signs
        // the poisoned vault with their own key, then re-MACs + re-encrypts meta.
        let att_sk = signing::signing_key_from_age_bytes(&[42u8; 32]);
        let att_vk = signing::verifying_key_b64(&att_sk);
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let stale = decrypt_meta(&tampered, &identity).unwrap();
        tampered.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        let mut signers = stale.signers.clone();
        signers.insert(pubkey.clone(), att_vk);
        let msg = signing_message(
            &tampered,
            &stale.groups,
            &stale.grants,
            &stale.github_pins,
            &signers,
        );
        let forged_sig = types::VaultSignature {
            signer: pubkey.clone(),
            v: SIGNED_VIEW_VERSION,
            sig: signing::sign(&att_sk, &msg),
        };
        // The signature layer alone IS fooled — it verifies against the swapped key.
        assert!(verify_vault_signature(
            &tampered,
            &stale.groups,
            &stale.grants,
            &stale.github_pins,
            &signers,
            &forged_sig
        ));
        let mac_key_hex = generate_mac_key();
        let mac_key = decode_mac_key(&mac_key_hex).unwrap();
        let mac = compute_mac(&tampered, &stale.groups, &stale.grants, Some(&mac_key));
        let forged_meta = types::Meta {
            mac,
            mac_key: Some(mac_key_hex),
            sig: Some(forged_sig),
            signers,
            ..stale
        };
        tampered.meta = encrypt_value(
            &serde_json::to_vec(&forged_meta).unwrap(),
            std::slice::from_ref(&recipient),
        )
        .unwrap();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // The pin catches the changed verifying key even though the signature verifies.
        let err = load_vault(ps).unwrap_err();
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(
            err.to_string().contains("verifying key changed"),
            "expected pin failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_validates_mac() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let _identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_load_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret, save it (computes valid MAC).
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

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        // save_vault needs MURK_KEY set to encrypt meta.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now tamper: change the ciphertext in the saved vault file.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.secrets.get_mut("KEY1").unwrap().shared =
            encrypt_value(b"tampered", &[recipient]).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail MAC validation.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_succeeds_with_valid_mac() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_valid_mac");
        let _ = fs::remove_dir_all(&dir);
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
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Load should succeed.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert_eq!(murk.values["KEY1"].as_str(), "val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_detects_signature_downgrade() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_sig_downgrade");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");
        let path_str = path.to_str().unwrap();

        // Sandbox HOME so the signer pin starts fresh (never-signed) and isolated.
        let prev_home = std::env::var_os("HOME");
        let home = dir.join("home");
        fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("MURK_NO_SIGNER_PIN");
            std::env::remove_var("MURK_AGENT");
            std::env::set_var("MURK_KEY", &secret);
            std::env::remove_var("MURK_KEY_FILE");
        }

        // One-secret vault, saved with an age key → lands signed.
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
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        save_vault(path_str, &mut vault, &original, &original).unwrap();

        // First load: signed, and records was_signed in the (fresh) pin.
        let (_, murk, _) = load_vault(path_str).unwrap();
        assert!(matches!(
            murk.signature,
            types::SignatureState::Signed { .. }
        ));
        assert!(!murk.signature_downgraded);

        // Strip the signature: decrypt meta, clear sig, re-encrypt. The MAC does
        // not cover the sig, so it stays valid — a clean unsigned downgrade.
        let mut on_disk = read_vault(path_str).unwrap();
        let mut meta = decrypt_meta(&on_disk, &identity).unwrap();
        meta.sig = None;
        let meta_json = serde_json::to_vec(&meta).unwrap();
        on_disk.meta = encrypt_value(&meta_json, std::slice::from_ref(&recipient)).unwrap();
        vault::write(std::path::Path::new(path_str), &on_disk).unwrap();

        // Second load: unsigned now, flagged as a downgrade (not a hard fail).
        let (_, murk2, _) = load_vault(path_str).unwrap();
        assert!(matches!(murk2.signature, types::SignatureState::Unsigned));
        assert!(
            murk2.signature_downgraded,
            "a previously-signed vault loading unsigned must flag a downgrade"
        );

        // Under MURK_STRICT the same load fails closed.
        unsafe { std::env::set_var("MURK_STRICT", "1") };
        let strict = load_vault(path_str);
        unsafe { std::env::remove_var("MURK_STRICT") };
        assert!(
            strict.is_err(),
            "MURK_STRICT must refuse a signed->unsigned downgrade"
        );

        unsafe {
            std::env::remove_var("MURK_KEY");
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_not_a_recipient() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, _pubkey) = generate_keypair();
        let (other_secret, other_pubkey) = generate_keypair();
        let other_recipient = make_recipient(&other_pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_not_recipient");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault encrypted to `other`, not to `secret`.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![other_pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[other_recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        // Save via save_vault (needs the other key for re-encryption).
        let mut recipients_map = HashMap::new();
        recipients_map.insert(other_pubkey.clone(), "other".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &other_secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now try to load with a key that is NOT a recipient.
        unsafe { std::env::set_var("MURK_KEY", secret) };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let Err(err) = result else {
            panic!("expected load_vault to fail for non-recipient");
        };
        // A non-recipient key gets a clean "not a recipient" error, not a
        // tamper warning — the meta blob is intact, it just isn't ours to read.
        let msg = err.to_string();
        assert!(
            msg.contains("not a recipient"),
            "expected not-a-recipient error, got: {err}"
        );
        assert!(
            !msg.contains("tampered"),
            "unauthorized key must not look like tampering, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_meta_state_plugin_failure_is_environment_error_not_access_verdict() {
        // When the meta blob is present and decrypt fails for a *plugin*
        // identity (missing `age-plugin-<name>` binary / declined touch), that
        // is an environment problem and must be surfaced verbatim — NOT reported
        // as "you are not a recipient". The mutant that flips the
        // `matches!(.., Plugin)` guard to `false` would misroute it into the
        // not-a-recipient branch; asserting the plugin error survives kills it.
        use bech32::{Bech32, Hrp};

        // Meta present: a valid age ciphertext so base64 + age-header parsing
        // succeed and `decrypt` reaches the guard.
        let (_, other_pubkey) = generate_keypair();
        let recipient = crypto::parse_recipient(&other_pubkey).unwrap();
        let mut vault = empty_vault();
        vault.meta = encrypt_value(b"{}", std::slice::from_ref(&recipient)).unwrap();

        // Plugin identity for a plugin that is not installed (obscure name so an
        // installed plugin cannot pass this for the wrong reason).
        let hrp = Hrp::parse("age-plugin-murknosuchpluginxyz-").unwrap();
        let identity_str = bech32::encode::<Bech32>(hrp, &[0u8; 20])
            .unwrap()
            .to_uppercase();
        let plugin_identity: age::plugin::Identity = identity_str.parse().unwrap();
        let identity = crypto::MurkIdentity::Plugin {
            identity: plugin_identity,
            pubkey: other_pubkey,
        };

        let Err(err) = resolve_meta_state(&vault, &identity) else {
            panic!("plugin decrypt failure must not resolve to a valid MetaState");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("age-plugin-murknosuchpluginxyz"),
            "a plugin decrypt failure must surface the environment error, got: {msg}"
        );
        assert!(
            !msg.contains("not a recipient"),
            "a plugin/environment failure must not be reported as an access verdict, got: {msg}"
        );
    }

    #[test]
    fn load_vault_zero_secrets() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();

        let dir = std::env::temp_dir().join("murk_test_load_zero_secrets");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with no secrets at all.
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

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::new(),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert!(murk.values.is_empty());
        assert!(murk.private.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_stripped_meta_with_secrets_fails() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_stripped_meta");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret and a valid MAC via save_vault.
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
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Tamper: strip meta field entirely.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.meta = String::new();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail: secrets present but no meta.
        let result = load_vault(path.to_str().unwrap());

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        // Tamper differently: garble the meta blob so it no longer decodes.
        // A recipient hitting damaged meta should still see an integrity
        // error, not "not a recipient".
        let mut garbled: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        garbled.meta = "not-base64!!".into();
        fs::write(&path, serde_json::to_string_pretty(&garbled).unwrap()).unwrap();

        let result = load_vault(path.to_str().unwrap());

        let err = result.expect_err("expected corrupt meta to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        // Tamper again: valid base64 that fails authenticated decryption (a
        // byte-flipped meta blob). Our key is listed in the public header, so
        // this must read as tampering, not "not a recipient".
        let mut flipped: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        flipped.meta = BASE64.encode(b"flipped ciphertext bytes");
        fs::write(&path, serde_json::to_string_pretty(&flipped).unwrap()).unwrap();

        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected flipped meta to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_empty_mac_with_secrets_fails() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_empty_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret.
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

        // Manually create meta with empty MAC and encrypt it.
        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let meta = types::Meta {
            recipients: recipients_map,
            mac: String::new(),
            mac_key: None,
            github_pins: HashMap::new(),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        vault.meta = encrypt_value(&meta_json, &[recipient]).unwrap();

        // Write the vault to disk.
        crate::vault::write(Path::new(path.to_str().unwrap()), &vault).unwrap();

        // Load should fail: secrets present but MAC is empty.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}
