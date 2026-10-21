// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical signed view of a vault plus sign/verify over it. Version-gated
//! (`SIGNED_VIEW_VERSION`) so an older binary refuses a newer signature.

use crate::{crypto, env, signing, types};
use std::collections::{BTreeMap, HashMap};

/// Version of the canonical signed-view serialization that `sign_vault` writes.
/// Bumped if the set of covered fields or their encoding changes, so an older
/// binary refuses a newer signature rather than misverifying it (mirrors the
/// MAC-prefix downgrade guard). Version 1 is still verified for older vaults.
pub(crate) const SIGNED_VIEW_VERSION: u32 = 2;

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

/// Register `identity`'s verifying key in `signers` when it is an age key of a
/// current recipient. Call before the meta (which holds `signers`) is
/// encrypted, so the signature over the meta ciphertext covers the entry.
/// ssh-ed25519 keys are never registered: their verifying key is recoverable
/// from the recipient string.
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
        signers.insert(signer, signing::verifying_key_b64(&sk));
    }
}

/// Sign the finished vault (meta already encrypted) with `identity` over signed
/// view v2. Returns `None` for SSH/hardware identities that cannot sign — the
/// caller leaves the vault unsigned (a warning, not an error) — and for a
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
    let msg = signing_message_v2(vault);
    Some(types::VaultSignature {
        signer,
        v: SIGNED_VIEW_VERSION,
        sig: signing::sign(&sk, &msg),
    })
}

/// Whether `signer` names a current recipient. ssh-ed25519 signers are matched
/// ignoring any comment on the stored recipient (a recipient may be stored as
/// `ssh-ed25519 <b64> user@host` while `signer` is the comment-stripped form).
fn signer_is_recipient(vault: &types::Vault, signer: &str) -> bool {
    if signer.starts_with("ssh-ed25519 ") {
        vault
            .recipients
            .iter()
            .any(|r| signing::ssh_ed25519_key_eq(r, signer))
    } else {
        vault.recipients.iter().any(|r| r == signer)
    }
}

/// Verify a vault signature. Returns `true` only when the signed-view version is
/// understood and allowed for this vault, the signer is a current recipient, and
/// the signature matches the recomputed canonical message. The verifying key
/// comes from the recipient string for ssh-ed25519 signers (self-authenticating),
/// or the `signers` registry for age signers.
///
/// View 1 (a signature inside the meta) covers the decrypted `groups`,
/// `grants`, `github_pins`, and `signers`; view 2 (the top-level `sig`) covers
/// the whole vault file and ignores them. A 3.x vault is only ever signed with
/// view 2, so a view-1 signature on one is refused: view 1 does not cover the
/// header identity fields.
pub(crate) fn verify_vault_signature(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    github_pins: &HashMap<String, Vec<String>>,
    signers: &BTreeMap<String, String>,
    sig: &types::VaultSignature,
) -> bool {
    let msg = match sig.v {
        1 if !crate::validate::is_v3_version(&vault.version) => {
            signing_message(vault, groups, grants, github_pins, signers)
        }
        2 => signing_message_v2(vault),
        _ => return false,
    };
    if !signer_is_recipient(vault, &sig.signer) {
        return false;
    }
    let vk = if sig.signer.starts_with("ssh-ed25519 ") {
        // Self-authenticating: the verifying key is in the signer string itself.
        match signing::ed25519_verifying_key_b64_from_ssh_recipient(&sig.signer) {
            Some(vk) => vk,
            None => return false,
        }
    } else {
        match signers.get(&sig.signer) {
            Some(vk) => vk.clone(),
            None => return false,
        }
    };
    signing::verify(&vk, &sig.sig, &msg)
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

    #[test]
    fn sign_and_verify_vault_roundtrips() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let vault = signed_test_vault(&pubkey, &make_recipient(&pubkey));
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        let mut signers = BTreeMap::new();
        let sig = {
            register_signer(&vault, &mut signers, &identity);
            sign_vault(&vault, &identity)
        }
        .unwrap();
        assert_eq!(sig.signer, pubkey);
        assert!(verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &sig
        ));
    }

    #[test]
    fn signature_detects_ciphertext_tampering() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let recipient = make_recipient(&pubkey);
        let mut vault = signed_test_vault(&pubkey, &recipient);
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        let mut signers = BTreeMap::new();
        let sig = {
            register_signer(&vault, &mut signers, &identity);
            sign_vault(&vault, &identity)
        }
        .unwrap();

        // Attacker swaps in a different (still readable) ciphertext but cannot
        // re-sign without a recipient's signing key.
        vault.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        assert!(
            !verify_vault_signature(&vault, &g, &gr, &pins, &signers, &sig),
            "tampered ciphertext must fail signature verification"
        );
    }

    #[test]
    fn signature_rejects_non_recipient_signer() {
        // Outsider knows the victim's pubkey and tampers, then signs with THEIR
        // OWN key and registers their own verifying key. Verification rejects it
        // because the signer is not a current recipient of the vault.
        let (_victim_secret, victim_pub) = generate_keypair();
        let (attacker_secret, attacker_pub) = generate_keypair();
        let attacker = make_identity(&attacker_secret);
        let vault = signed_test_vault(&victim_pub, &make_recipient(&victim_pub));
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        // sign_vault refuses because the attacker isn't a recipient.
        let mut signers = BTreeMap::new();
        assert!(sign_vault(&vault, &attacker).is_none());

        // Even a hand-forged registry + signature is rejected: signer ∉ recipients.
        let sk = attacker.signing_key().unwrap();
        signers.insert(attacker_pub.clone(), signing::verifying_key_b64(&sk));
        let msg = signing_message_v2(&vault);
        let forged = types::VaultSignature {
            signer: attacker_pub,
            v: SIGNED_VIEW_VERSION,
            sig: signing::sign(&sk, &msg),
        };
        assert!(!verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &forged
        ));
    }

    #[test]
    fn ssh_signed_vault_verifies_without_registry() {
        // The self-authenticating property: an ssh-ed25519 signer is NOT added to
        // the registry, and verification succeeds against an EMPTY registry
        // because the verifying key comes from the recipient string.
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        let mut signers = BTreeMap::new();
        let sig = {
            register_signer(&vault, &mut signers, &identity);
            sign_vault(&vault, &identity)
        }
        .unwrap();
        assert_eq!(sig.signer, SSH_ED25519_PK);
        assert!(signers.is_empty(), "ssh signer must not be registered");
        assert!(verify_vault_signature(
            &vault,
            &g,
            &gr,
            &pins,
            &BTreeMap::new(),
            &sig
        ));
    }

    #[test]
    fn ssh_signed_vault_detects_tampering() {
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        let mut signers = BTreeMap::new();
        let sig = {
            register_signer(&vault, &mut signers, &identity);
            sign_vault(&vault, &identity)
        }
        .unwrap();
        vault.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        assert!(!verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &sig
        ));
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
        let (g, gr, pins) = (BTreeMap::new(), BTreeMap::new(), HashMap::new());

        let mut signers = BTreeMap::new();
        let sig = {
            register_signer(&vault, &mut signers, &identity);
            sign_vault(&vault, &identity)
        }
        .expect("comment-bearing recipient must still sign");
        assert!(verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &sig
        ));
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
        assert!(verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &sig
        ));

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
                !verify_vault_signature(&forged, &g, &gr, &pins, &signers, &sig),
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

    #[test]
    fn view_1_signature_verifies_on_2x_vault_only() {
        // Pre-3.0 vaults keep verifying under view 1; on a 3.x vault a view-1
        // signature is refused, since view 1 leaves the header uncovered.
        let identity = make_identity(SSH_ED25519_SK);
        let recipient = make_recipient(SSH_ED25519_PK);
        let mut vault = signed_test_vault(SSH_ED25519_PK, &recipient);
        vault.version = "2.0".into();
        let (g, gr, pins, signers) = (
            BTreeMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
        );
        let sk = identity.signing_key().unwrap();
        let v1 = types::VaultSignature {
            signer: SSH_ED25519_PK.into(),
            v: 1,
            sig: signing::sign(&sk, &signing_message(&vault, &g, &gr, &pins, &signers)),
        };
        assert!(verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &v1
        ));

        vault.version = "3.0".into();
        let v1_on_3x = types::VaultSignature {
            sig: signing::sign(&sk, &signing_message(&vault, &g, &gr, &pins, &signers)),
            ..v1
        };
        assert!(!verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &v1_on_3x
        ));
    }
}
