//! Canonical signed view of a vault plus sign/verify over it. Version-gated
//! (`SIGNED_VIEW_VERSION`) so an older binary refuses a newer signature.

use crate::{crypto, env, signing, types};
use std::collections::{BTreeMap, HashMap};

/// Version of the canonical signed-view serialization. Bumped if the set of
/// covered fields or their encoding changes, so an older binary refuses a newer
/// signature rather than misverifying it (mirrors the MAC-prefix downgrade guard).
pub(crate) const SIGNED_VIEW_VERSION: u32 = 1;

/// Build the canonical, domain-tagged byte message that vault signatures cover.
///
/// Covers every security-relevant field — recipients, schema, secrets (all
/// tiers), policy, groups, grants, github pins, and the signer registry itself
/// (so a rogue verifying key can't be registered without breaking the signature).
/// It excludes the `sig` field it produces and the MAC/`mac_key` (a shared secret
/// the signature supersedes for authenticity). Determinism comes from sorted
/// maps (`BTreeMap`) and an explicitly sorted recipient list.
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

    let mut recipients: Vec<&str> = vault.recipients.iter().map(String::as_str).collect();
    recipients.sort_unstable();
    let pins: BTreeMap<&str, &Vec<String>> =
        github_pins.iter().map(|(k, v)| (k.as_str(), v)).collect();

    let view = SignedView {
        v: SIGNED_VIEW_VERSION,
        version: &vault.version,
        recipients,
        schema: &vault.schema,
        secrets: &vault.secrets,
        policy: &vault.policy,
        groups,
        grants,
        github_pins: pins,
        signers,
    };

    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(b"murk.vault.sig.v1\n");
    serde_json::to_writer(&mut msg, &view).expect("canonical vault view serializes");
    msg
}

/// Sign the vault with `identity` if it is signing-capable, registering its
/// verifying key in `signers`. Returns `None` for SSH/hardware identities that
/// cannot sign — the caller leaves the vault unsigned (a warning, not an error).
pub(crate) fn sign_vault(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    github_pins: &HashMap<String, Vec<String>>,
    signers: &mut BTreeMap<String, String>,
    identity: &crypto::MurkIdentity,
) -> Option<types::VaultSignature> {
    let signer = identity.pubkey_string().ok()?;
    // Only a current recipient's signature is meaningful — and verifiable, since
    // `verify_vault_signature` requires the signer to be a recipient. Signing as
    // a non-recipient would produce a signature that self-invalidates on load.
    if !signer_is_recipient(vault, &signer) {
        return None;
    }
    let sk = identity.signing_key()?;
    // age keys publish their verifying key in the registry (it can't be derived
    // from the public recipient). ssh-ed25519 keys don't: their verifying key is
    // recoverable from the recipient string, so they stay out of the registry.
    if identity.registers_verifying_key() {
        signers.insert(signer.clone(), signing::verifying_key_b64(&sk));
    }
    let msg = signing_message(vault, groups, grants, github_pins, signers);
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
/// understood, the signer is a current recipient, and the signature matches the
/// recomputed canonical message. The verifying key comes from the recipient
/// string for ssh-ed25519 signers (self-authenticating), or the `signers`
/// registry for age signers.
pub(crate) fn verify_vault_signature(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    github_pins: &HashMap<String, Vec<String>>,
    signers: &BTreeMap<String, String>,
    sig: &types::VaultSignature,
) -> bool {
    if sig.v != SIGNED_VIEW_VERSION {
        return false;
    }
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
    let msg = signing_message(vault, groups, grants, github_pins, signers);
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
        let sig = sign_vault(&vault, &g, &gr, &pins, &mut signers, &identity).unwrap();
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
        let sig = sign_vault(&vault, &g, &gr, &pins, &mut signers, &identity).unwrap();

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
        assert!(sign_vault(&vault, &g, &gr, &pins, &mut signers, &attacker).is_none());

        // Even a hand-forged registry + signature is rejected: signer ∉ recipients.
        let sk = attacker.signing_key().unwrap();
        signers.insert(attacker_pub.clone(), signing::verifying_key_b64(&sk));
        let msg = signing_message(&vault, &g, &gr, &pins, &signers);
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
        let sig = sign_vault(&vault, &g, &gr, &pins, &mut signers, &identity).unwrap();
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
        let sig = sign_vault(&vault, &g, &gr, &pins, &mut signers, &identity).unwrap();
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
        let sig = sign_vault(&vault, &g, &gr, &pins, &mut signers, &identity)
            .expect("comment-bearing recipient must still sign");
        assert!(verify_vault_signature(
            &vault, &g, &gr, &pins, &signers, &sig
        ));
    }
}
