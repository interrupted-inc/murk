// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical signed view of a vault plus sign/verify over it. Version-gated
//! (`SIGNED_VIEW_VERSION`) so an older binary refuses a newer signature.
//!
//! Two views exist. v2 (written by this murk) is the whole vault file minus
//! `sig`, so it covers the vault identity, the rollback counter and, through
//! the meta ciphertext, the signer registry. v1 (murk ≤ 0.13) is still
//! verified for vaults written by older releases. In both, an age signer's
//! verifying key comes from the registry, which the vault's author chose: the
//! trust check ([`crate::trust`]) accepts the signature only when that key is
//! the one this machine pinned for the signer.

use crate::{crypto, env, signing, types};
use std::collections::{BTreeMap, HashMap};

/// Version of the canonical signed-view serialization that `sign_vault` writes.
/// Bumped if the set of covered fields or their encoding changes, so an older
/// binary refuses a newer signature rather than misverifying it (mirrors the
/// MAC-prefix downgrade guard). Version 1 is still verified for older vaults.
pub(crate) const SIGNED_VIEW_VERSION: u32 = 2;

/// The murk ≤ 0.13 signed view, still verified on load.
pub(crate) const LEGACY_SIGNED_VIEW_VERSION: u32 = 1;

/// Build the version-1 signed message: what vaults written before signed view
/// v2 carry. Kept byte-for-byte so those signatures still verify.
///
/// Covers recipients, schema, secrets (all tiers), policy, groups, grants,
/// github pins, and the signer registry, but not the header identity fields.
/// It excludes the `sig` field it produces and the MAC/`mac_key` (a shared
/// secret the signature supersedes for authenticity). Determinism comes from
/// sorted maps (`BTreeMap`) and an explicitly sorted recipient list.
pub(crate) fn signing_message(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    github_pins: &HashMap<String, Vec<String>>,
    signers: &BTreeMap<String, String>,
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SignedView<'a> {
        v: u32,
        version: &'a str,
        recipients: Vec<&'a str>,
        schema: &'a BTreeMap<String, types::SchemaEntry>,
        secrets: &'a BTreeMap<String, types::SecretEntry>,
        policy: &'a Option<types::Policy>,
        groups: &'a BTreeMap<String, Vec<String>>,
        grants: &'a BTreeMap<String, types::GrantEntry>,
        github_pins: BTreeMap<&'a str, &'a Vec<String>>,
        signers: &'a BTreeMap<String, String>,
    }

    let view = SignedView {
        v: 1,
        version: &vault.version,
        recipients: sorted_recipients(vault),
        schema: &vault.schema,
        secrets: &vault.secrets,
        policy: &vault.policy,
        groups,
        grants,
        github_pins: sorted_pins(github_pins),
        signers,
    };

    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(b"murk.vault.sig.v1\n");
    serde_json::to_writer(&mut msg, &view).expect("canonical vault view serializes");
    msg
}

/// Build the version-2 signed message, the one `sign_vault` writes:
/// `murk.vault.sig.v2\n` followed by the vault's JSON serialization with the
/// `sig` field omitted.
///
/// That covers every header field (including `vault_name`, `repo`, `created`,
/// `vault_id`, and `generation`), the `agents` ciphertexts, and the `meta`
/// ciphertext, so the decrypted meta (MAC, names, groups, grants, pins, signer
/// registry) is authentic because its ciphertext is. Nothing has to be
/// decrypted to rebuild the message.
///
/// The view borrows every field and serializes it exactly as `Vault` does
/// (same order and serde attributes), so the bytes equal
/// `serde_json::to_vec(&vault_without_sig)` without copying the vault. The
/// exhaustive destructure makes a new `Vault` field a compile error here until
/// it is covered.
pub(crate) fn signing_message_v2(vault: &types::Vault) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SignedView<'a> {
        version: &'a str,
        created: &'a str,
        vault_name: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        repo: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        vault_id: &'a str,
        #[serde(skip_serializing_if = "is_zero")]
        generation: u64,
        recipients: &'a [String],
        schema: &'a BTreeMap<String, types::SchemaEntry>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy: Option<&'a types::Policy>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        agents: &'a BTreeMap<String, String>,
        secrets: &'a BTreeMap<String, types::SecretEntry>,
        meta: &'a str,
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes `&T`
    fn is_zero(n: &u64) -> bool {
        *n == 0
    }

    let types::Vault {
        version,
        created,
        vault_name,
        repo,
        vault_id,
        generation,
        recipients,
        schema,
        policy,
        agents,
        secrets,
        meta,
        sig: _,
    } = vault;
    let view = SignedView {
        version,
        created,
        vault_name,
        repo,
        vault_id,
        generation: *generation,
        recipients,
        schema,
        policy: policy.as_ref(),
        agents,
        secrets,
        meta,
    };

    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(b"murk.vault.sig.v2\n");
    serde_json::to_writer(&mut msg, &view).expect("canonical vault view serializes");
    msg
}

fn sorted_recipients(vault: &types::Vault) -> Vec<&str> {
    let mut recipients: Vec<&str> = vault.recipients.iter().map(String::as_str).collect();
    recipients.sort_unstable();
    recipients
}

fn sorted_pins(github_pins: &HashMap<String, Vec<String>>) -> BTreeMap<&str, &Vec<String>> {
    github_pins.iter().map(|(k, v)| (k.as_str(), v)).collect()
}

/// Record `identity`'s verifying key in `signers` when it is an age key of a
/// current recipient. Call before the meta (which holds `signers`) is
/// encrypted, so the signature over the meta ciphertext covers the entry.
/// ssh-ed25519 keys are never registered: their verifying key is the
/// recipient string itself.
pub(crate) fn register_signer(
    vault: &types::Vault,
    signers: &mut BTreeMap<String, String>,
    identity: &crypto::MurkIdentity,
) {
    if !identity.registers_verifying_key() {
        return;
    }
    let Ok(signer) = identity.pubkey_string() else {
        return;
    };
    if !signer_is_recipient(vault, &signer) {
        return;
    }
    if let Some(sk) = identity.signing_key() {
        signers.insert(signer, sk.verifying_key());
    }
}

/// Sign the finished vault (meta already encrypted, `sig` unset) with
/// `identity` over signed view v2. Returns `None` for SSH/hardware identities
/// that cannot sign — the caller leaves the vault unsigned — and for a
/// non-recipient, whose signature would self-invalidate on load.
pub(crate) fn sign_vault(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Option<types::VaultSignature> {
    let signer = identity.pubkey_string().ok()?;
    if !signer_is_recipient(vault, &signer) {
        return None;
    }
    let sk = identity.signing_key()?;
    Some(types::VaultSignature {
        signer,
        v: SIGNED_VIEW_VERSION,
        sig: sk.sign(&signing_message_v2(vault)),
    })
}

/// Whether `signer` names a current recipient, comparing canonical spellings
/// (bech32 case, ssh comments).
fn signer_is_recipient(vault: &types::Vault, signer: &str) -> bool {
    let signer = crypto::canonical_recipient(signer);
    vault
        .recipients
        .iter()
        .any(|r| crypto::canonical_recipient(r) == signer)
}

/// A signature that verified. `vk` is the registry verifying key an age
/// signature verified against — the caller must check it against the trust
/// pin, since the registry is written by the vault's author. `None` for
/// ssh-ed25519 signers, whose verifying key is the public key itself.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedSignature {
    pub vk: Option<String>,
}

/// Verify a vault signature. Returns `Some` only when the signed-view version
/// is understood and allowed for this vault, the signer is a current
/// recipient, and the signature matches the recomputed message under the
/// signer's verifying key (from the recipient string for ssh-ed25519, from
/// `signers` for age).
///
/// View 2 (the top-level `sig`) covers the whole vault file. View 1 (a
/// signature inside the meta, murk ≤ 0.13) covers the decrypted `groups`,
/// `grants`, `github_pins` and `signers`, but not the header identity fields,
/// so it is refused on a 3.x vault and on any vault carrying a vault id or
/// counter: there it would leave them forgeable (an old revision dressed up as
/// current).
pub(crate) fn verify_vault_signature(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    github_pins: &HashMap<String, Vec<String>>,
    signers: &BTreeMap<String, String>,
    sig: &types::VaultSignature,
) -> Option<VerifiedSignature> {
    if !signer_is_recipient(vault, &sig.signer) {
        return None;
    }
    let msg = match sig.v {
        SIGNED_VIEW_VERSION => signing_message_v2(vault),
        LEGACY_SIGNED_VIEW_VERSION => {
            if crate::validate::is_v3_version(&vault.version)
                || !vault.vault_id.is_empty()
                || vault.generation != 0
            {
                return None;
            }
            signing_message(vault, groups, grants, github_pins, signers)
        }
        _ => return None,
    };
    if sig.signer.starts_with("ssh-ed25519 ") {
        let vk = signing::ed25519_verifying_key_b64_from_ssh_recipient(&sig.signer)?;
        signing::verify(&vk, &sig.sig, &msg).then_some(VerifiedSignature { vk: None })
    } else {
        let vk = registry_entry(signers, &sig.signer)?;
        signing::verify(vk, &sig.sig, &msg).then(|| VerifiedSignature {
            vk: Some(vk.clone()),
        })
    }
}

/// The registry entry for `signer`, matched by canonical spelling.
pub(crate) fn registry_entry<'a>(
    signers: &'a BTreeMap<String, String>,
    signer: &str,
) -> Option<&'a String> {
    let signer = crypto::canonical_recipient(signer);
    signers
        .iter()
        .find(|(pk, _)| crypto::canonical_recipient(pk) == signer)
        .map(|(_, vk)| vk)
}

/// Resolve the operator's identity from the environment for signing on save.
/// Returns `None` when no key is configured — the vault is then written unsigned
/// rather than failing the save.
pub(crate) fn signing_identity(vault_path: &str) -> Option<crypto::MurkIdentity> {
    use age::secrecy::ExposeSecret;
    let secret = env::resolve_key_for_vault(vault_path).ok()?;
    crypto::parse_identity(secret.expose_secret()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    use crate::testutil::*;

    use std::collections::{BTreeMap, HashMap};

    type MetaParts = (
        BTreeMap<String, Vec<String>>,
        BTreeMap<String, types::GrantEntry>,
        HashMap<String, Vec<String>>,
        BTreeMap<String, String>,
    );

    fn empty() -> MetaParts {
        (
            BTreeMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
        )
    }

    /// How murk 0.13 signed an age vault: a KDF-derived Ed25519 key whose
    /// verifying key is published in the registry. Returns the signature and
    /// that registry.
    fn v1_age_signature(
        vault: &types::Vault,
        secret: &str,
        pubkey: &str,
    ) -> (types::VaultSignature, BTreeMap<String, String>) {
        let (g, gr, pins, _) = empty();
        let crypto::MurkIdentity::Age(id) = make_identity(secret) else {
            unreachable!()
        };
        let bytes = crypto::age_secret_bytes(&id).unwrap();
        let sk = signing::signing_key_from_age_bytes(bytes.as_slice());
        let signers = BTreeMap::from([(pubkey.to_string(), signing::verifying_key_b64(&sk))]);
        let sig = types::VaultSignature {
            signer: pubkey.to_string(),
            v: LEGACY_SIGNED_VIEW_VERSION,
            sig: signing::sign(&sk, &signing_message(vault, &g, &gr, &pins, &signers)),
        };
        (sig, signers)
    }

    #[test]
    fn sign_and_verify_vault_roundtrips() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
        let (g, gr, pins, mut signers) = empty();

        register_signer(&vault, &mut signers, &identity);
        let sig = sign_vault(&vault, &identity).unwrap();
        assert_eq!(sig.signer, pubkey);
        assert_eq!(sig.v, SIGNED_VIEW_VERSION);
        // An age signature reports the registry key it verified against, for
        // the trust check to compare with the pinned one.
        assert_eq!(
            verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig),
            Some(VerifiedSignature {
                vk: Some(signers[&pubkey].clone())
            })
        );
        // Without a registry entry an age signature cannot be checked at all.
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &BTreeMap::new(), &sig).is_none());
    }

    #[test]
    fn signature_detects_ciphertext_tampering() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let recipient = make_recipient(&pubkey);
        let mut vault = signed_test_vault(&pubkey, &recipient);
        let (g, gr, pins, mut signers) = empty();

        register_signer(&vault, &mut signers, &identity);
        let sig = sign_vault(&vault, &identity).unwrap();

        // Attacker swaps in a different (still readable) ciphertext but cannot
        // re-sign without a recipient's signing key.
        vault.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        assert!(
            verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_none(),
            "tampered ciphertext must fail signature verification"
        );
    }

    #[test]
    fn signature_rejects_non_recipient_signer() {
        // Outsider knows the victim's pubkey and tampers, then signs with THEIR
        // OWN key. Verification rejects it because the signer is not a current
        // recipient of the vault. (A signer who IS listed is the trust check's
        // problem, not this function's.)
        let (_victim_secret, victim_pub) = generate_keypair();
        let (attacker_secret, attacker_pub) = generate_keypair();
        let attacker = make_identity(&attacker_secret);
        let vault = signed_test_vault(&victim_pub, &make_recipient(&victim_pub));
        let (g, gr, pins, _) = empty();

        assert!(sign_vault(&vault, &attacker).is_none());

        let sk = attacker.signing_key().unwrap();
        let forged = types::VaultSignature {
            signer: attacker_pub.clone(),
            v: SIGNED_VIEW_VERSION,
            sig: sk.sign(&signing_message_v2(&vault)),
        };
        let signers = BTreeMap::from([(attacker_pub.clone(), sk.verifying_key())]);
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &forged).is_none());
    }

    #[test]
    fn a_poisoned_registry_entry_is_reported_for_the_trust_check() {
        // The registry is written by the vault's author, so a forger can map a
        // victim's pubkey to the forger's own verifying key. The signature
        // layer verifies against it — and reports that key, which the trust
        // check then compares with the key pinned for the victim.
        let (_, victim_pub) = generate_keypair();
        let (attacker_secret, _) = generate_keypair();
        let vault = signed_test_vault(&victim_pub, &make_recipient(&victim_pub));
        let (g, gr, pins, _) = empty();
        let attacker_sk = make_identity(&attacker_secret).signing_key().unwrap();
        let poisoned = BTreeMap::from([(victim_pub.clone(), attacker_sk.verifying_key())]);
        let forged = types::VaultSignature {
            signer: victim_pub,
            v: SIGNED_VIEW_VERSION,
            sig: attacker_sk.sign(&signing_message_v2(&vault)),
        };
        assert_eq!(
            verify_vault_signature(&vault, &g, &gr, &pins, &poisoned, &forged),
            Some(VerifiedSignature {
                vk: Some(attacker_sk.verifying_key())
            })
        );
    }

    #[test]
    fn legacy_v1_signature_verifies_against_the_registry_and_reports_its_key() {
        let (secret, pubkey) = generate_keypair();
        let mut vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
        vault.version = "2.0".into();
        let (g, gr, pins, _) = empty();
        let (sig, signers) = v1_age_signature(&vault, &secret, &pubkey);
        assert_eq!(
            verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig),
            Some(VerifiedSignature {
                vk: Some(signers[&pubkey].clone())
            })
        );
    }

    #[test]
    fn a_v1_signature_does_not_cover_a_forged_id_counter_or_3x_version() {
        // v1 covers none of these, so a v1 signature on a vault carrying them
        // would let an old revision pose as current. It must not verify.
        let (secret, pubkey) = generate_keypair();
        let mut vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
        vault.version = "2.0".into();
        let (g, gr, pins, _) = empty();
        let (sig, signers) = v1_age_signature(&vault, &secret, &pubkey);
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_some());
        let forgeries: [(&str, VaultRewrite); 3] = [
            ("generation", |v| v.generation = 99),
            ("vault_id", |v| {
                v.vault_id = "00112233445566778899aabbccddeeff".into();
            }),
            ("version", |v| v.version = "3.0".into()),
        ];
        for (field, rewrite) in forgeries {
            let mut forged = vault.clone();
            rewrite(&mut forged);
            // Re-sign v1 over the rewritten vault: v1 itself would accept it.
            let (sig, signers) = v1_age_signature(&forged, &secret, &pubkey);
            assert!(
                verify_vault_signature(&forged, &g, &gr, &pins, &signers, &sig).is_none(),
                "a v1 signature must not verify with `{field}` set"
            );
        }
    }

    #[test]
    fn ssh_signed_vault_verifies_without_registry() {
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let (g, gr, pins, signers) = empty();

        let sig = sign_vault(&vault, &identity).unwrap();
        assert_eq!(sig.signer, SSH_ED25519_PK);
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_some());
    }

    #[test]
    fn ssh_signed_vault_detects_tampering() {
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let (g, gr, pins, signers) = empty();

        let sig = sign_vault(&vault, &identity).unwrap();
        vault.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_none());
    }

    #[test]
    fn ssh_recipient_stored_with_comment_still_signs_and_verifies() {
        // Regression for the comment-mismatch bug: recipient stored WITH a comment
        // while the identity's pubkey_string() is comment-stripped. Normalized
        // matching must let it sign and verify.
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        vault.recipients = vec![format!("{SSH_ED25519_PK} someone@host")];
        let (g, gr, pins, signers) = empty();

        let sig = sign_vault(&vault, &identity).expect("comment-bearing recipient must still sign");
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_some());
    }

    #[test]
    fn signed_view_v2_covers_header_fields_and_ciphertexts() {
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        vault.meta = encrypt_value(b"{}", std::slice::from_ref(&recipient)).unwrap();
        let (g, gr, pins, signers) = (
            BTreeMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
        );
        let sig = sign_vault(&vault, &identity).unwrap();
        assert_eq!(sig.v, 2);
        assert!(verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig).is_some());

        let rewrites: [(&str, VaultRewrite); 8] = [
            ("vault_name", |v| v.vault_name = "payments-prod".into()),
            ("repo", |v| v.repo = "https://github.com/evil/fork".into()),
            ("created", |v| v.created = "2020-01-01T00:00:00Z".into()),
            ("vault_id", |v| {
                v.vault_id = "0123456789abcdef0123456789abcdef".into();
            }),
            ("generation", |v| v.generation = 7),
            ("agents", |v| {
                v.agents
                    .insert("age1agent".into(), "Y2lwaGVydGV4dA==".into());
            }),
            ("meta", |v| v.meta = "cmVwbGFjZWQ=".into()),
            ("version", |v| v.version = "3.1".into()),
        ];
        for (field, rewrite) in rewrites {
            let mut forged = vault.clone();
            rewrite(&mut forged);
            assert!(
                verify_vault_signature(&forged, &g, &gr, &pins, &signers, &sig).is_none(),
                "rewriting `{field}` must invalidate a view-2 signature"
            );
        }

        // The signature field itself is outside the signed bytes.
        let mut with_sig = vault.clone();
        with_sig.sig = Some(sig.clone());
        assert_eq!(signing_message_v2(&with_sig), signing_message_v2(&vault));
    }

    #[test]
    fn signed_view_v2_matches_vault_serialization_without_sig() {
        // The borrowed view must serialize exactly like the vault itself (minus
        // `sig`), optional fields included, so it is the whole file.
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let plain = serde_json::to_vec(&vault).unwrap();
        assert_eq!(signing_message_v2(&vault)[18..], plain[..]);

        vault.repo = "https://github.com/org/repo".into();
        vault.vault_id = "0123456789abcdef0123456789abcdef".into();
        vault.generation = 4;
        vault.policy = Some(types::Policy {
            agent_allow_tags: vec!["ci".into()],
        });
        vault
            .agents
            .insert("age1agent".into(), "Y2lwaGVydGV4dA==".into());
        let full = serde_json::to_vec(&vault).unwrap();
        assert_eq!(signing_message_v2(&vault)[18..], full[..]);
    }
}
