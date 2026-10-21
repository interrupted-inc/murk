// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 signatures over the vault — integrity against an active attacker
//! with write access to the repo.
//!
//! The keyed BLAKE3 MAC (see `lib.rs`) binds ciphertexts together but does NOT
//! authenticate the *author*. The MAC key lives inside the age-encrypted `meta`
//! blob, and age encryption needs only the recipients' public keys — which sit
//! in the plaintext header. So anyone who can write to the repo can mint a fresh
//! MAC key, recompute a valid MAC over tampered content, and re-encrypt `meta`;
//! the MAC then verifies clean. See `THREAT_MODEL.md`.
//!
//! Signatures close this for non-recipient attackers: a writer signs the vault
//! with an Ed25519 key derived from the same BIP39 seed as their age key, and
//! loaders verify the signature against the signer's registered verifying key.
//! An attacker holding no recipient private key cannot forge a valid signature.
//!
//! "Sign-when-capable": native age keys (the `murk init` default) derive a
//! signing key deterministically, and ssh-ed25519 keys sign with the key itself
//! (see the ssh-ed25519 section below). `ssh-rsa` and hardware/plugin identities
//! cannot sign, so their saves are left unsigned (a warning, not an error). A
//! *present* signature must verify — an invalid one is tampering and hard-fails.
//!
//! Every verifying key passes [`checked_verifying_key`] before murk trusts it
//! or checks a signature with it, and signatures are checked with
//! `verify_strict`: a small-order key admits signatures that verify for any
//! message, and a non-canonical encoding is a second spelling of a key.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// Domain-separation context for deriving the Ed25519 signing seed from the raw
/// age x25519 key bytes. Versioned so the derivation can change without silently
/// colliding with a future scheme. Using a KDF (not the raw key bytes) keeps the
/// signing key cryptographically independent of the encryption key.
const SIGNING_KDF_CONTEXT: &str = "murk.vault.signing.ed25519.v1";

/// Derive an Ed25519 signing key from the raw 32-byte age x25519 secret.
///
/// The BIP39 mnemonic encodes these same 32 bytes, so the signing key recovers
/// for free from the recovery phrase — no extra words to back up.
pub fn signing_key_from_age_bytes(age_key_bytes: &[u8]) -> SigningKey {
    let seed = Zeroizing::new(blake3::derive_key(SIGNING_KDF_CONTEXT, age_key_bytes));
    SigningKey::from_bytes(&seed)
}

/// The base64-encoded Ed25519 verifying (public) key for a signing key.
pub fn verifying_key_b64(sk: &SigningKey) -> String {
    BASE64.encode(sk.verifying_key().to_bytes())
}

/// Sign a message, returning the base64-encoded 64-byte signature.
pub fn sign(sk: &SigningKey, message: &[u8]) -> String {
    BASE64.encode(sk.sign(message).to_bytes())
}

/// The one check every Ed25519 verifying key passes before murk trusts it or
/// verifies a signature with it, wherever it comes from: the vault's signer
/// registry, a trust pin, `MURK_TRUSTED_SIGNERS`, a grant key file's anchor,
/// or an ssh-ed25519 public key. Refuses a key that is not a curve point, a
/// non-canonical encoding of one (a second spelling of the same key), and a
/// weak (small-order) key, under which a forged signature verifies for any
/// message. An honestly generated key is never any of these. The error says
/// which.
pub fn checked_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, &'static str> {
    let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
        return Err("not a 32-byte Ed25519 key");
    };
    let Ok(vk) = VerifyingKey::from_bytes(&bytes) else {
        return Err("not a point on the Ed25519 curve");
    };
    if vk.to_edwards().compress().to_bytes() != bytes {
        return Err("non-canonical Ed25519 point encoding");
    }
    if vk.is_weak() {
        return Err("weak (small-order) Ed25519 key");
    }
    Ok(vk)
}

/// [`checked_verifying_key`] for a base64-encoded verifying key.
pub fn check_verifying_key(verifying_key_b64: &str) -> Result<VerifyingKey, &'static str> {
    let Ok(bytes) = BASE64.decode(verifying_key_b64) else {
        return Err("not base64");
    };
    checked_verifying_key(&bytes)
}

/// Verify a base64-encoded signature against a base64-encoded verifying key,
/// with `verify_strict`.
///
/// Returns false on any decode error, wrong length, a key
/// [`checked_verifying_key`] refuses, or signature mismatch — callers treat a
/// present-but-invalid signature as tampering.
pub fn verify(verifying_key_b64: &str, signature_b64: &str, message: &[u8]) -> bool {
    let Ok(vk) = check_verifying_key(verifying_key_b64) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(message, &sig).is_ok()
}

// -- the seam --
//
// Trust logic, save, merge and init sign only through `VaultSigningKey` and
// verify only through `verify`, with verifying keys as the base64 strings
// `VaultSigningKey::verifying_key` returns. A different scheme replaces this
// block, not the callers.

/// A key that can sign a vault: an age identity's derived Ed25519 key or an
/// ssh-ed25519 key.
pub struct VaultSigningKey(SigningKey);

impl VaultSigningKey {
    /// Sign `message`, returning the base64-encoded 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> String {
        sign(&self.0, message)
    }

    /// The base64 verifying key loaders check this key's signatures with.
    pub fn verifying_key(&self) -> String {
        verifying_key_b64(&self.0)
    }
}

/// The signing key of an age identity, from its raw X25519 secret bytes.
pub fn age_signing_key(age_key_bytes: &[u8]) -> VaultSigningKey {
    VaultSigningKey(signing_key_from_age_bytes(age_key_bytes))
}

/// The signing key of an unencrypted ssh-ed25519 private key (OpenSSH PEM).
pub fn ssh_signing_key(pem: &str) -> Option<VaultSigningKey> {
    ed25519_signing_key_from_openssh(pem).map(VaultSigningKey)
}

/// A short, comparable form of a verifying key for people to check out of
/// band: `SHA256:` and the unpadded base64 SHA-256 of the key bytes, the
/// format `ssh-keygen -l` uses. `None` for a string that is not a key.
pub fn fingerprint(verifying_key_b64: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = BASE64.decode(verifying_key_b64).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let digest = Sha256::digest(&bytes);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

// -- ssh-ed25519 signing --
//
// Unlike age keys, an ssh-ed25519 key IS an Ed25519 signing key, so we sign with
// the key itself rather than a derived one. The tradeoff is deliberate: the
// verifying key is then recoverable from the `ssh-ed25519 …` recipient string
// (self-authenticating — no registry entry, no TOFU pin needed). age won't hand
// us the SSH scalar, so we parse it from the retained OpenSSH PEM.

/// Parse an Ed25519 signing key from an OpenSSH private-key PEM.
///
/// Returns `None` for non-ed25519 keys (e.g. ssh-rsa), encrypted keys, or any
/// parse failure — the caller then leaves the vault unsigned.
pub fn ed25519_signing_key_from_openssh(pem: &str) -> Option<SigningKey> {
    let key = ssh_key::PrivateKey::from_openssh(pem).ok()?;
    let keypair = key.key_data().ed25519()?;
    // The 32-byte Ed25519 seed. Zeroized after `SigningKey` copies it.
    let seed = Zeroizing::new(keypair.private.to_bytes());
    Some(SigningKey::from_bytes(&seed))
}

/// Extract the base64 Ed25519 verifying key from an `ssh-ed25519 <base64> [comment]`
/// recipient string. Tolerates a trailing comment. Errors for non-ed25519 or
/// unparseable input, and for a key [`checked_verifying_key`] refuses. The
/// encoding matches what [`verify`] expects.
pub fn ed25519_verifying_key_b64_from_ssh_recipient(
    recipient: &str,
) -> Result<String, &'static str> {
    let key = ssh_key::PublicKey::from_openssh(recipient).map_err(|_| "not an ssh public key")?;
    let pk = key.key_data().ed25519().ok_or("not an ssh-ed25519 key")?;
    checked_verifying_key(pk.as_ref())?;
    Ok(BASE64.encode(pk.as_ref()))
}

/// Whether `key` — a base64 verifying key, or an `ssh-ed25519 …` line — is a
/// well-formed 32-byte Ed25519 key that [`checked_verifying_key`] refuses.
/// A string that does not decode to one is `false`: it never verifies a
/// signature, so it is junk rather than a dangerous key.
pub fn is_refused_signing_key(key: &str) -> bool {
    let bytes = if key.starts_with("ssh-") {
        ssh_key::PublicKey::from_openssh(key)
            .ok()
            .and_then(|k| k.key_data().ed25519().map(|pk| pk.as_ref().to_vec()))
    } else {
        BASE64.decode(key).ok()
    };
    bytes.is_some_and(|b| b.len() == 32 && checked_verifying_key(&b).is_err())
}

/// `ssh-ed25519 <base64>` for a well-formed ssh-ed25519 public key line, with
/// any trailing comment dropped; `None` for another key type or a string that
/// is not a key. The one-line, comment-free form is safe to write into a
/// file ssh-keygen reads (an allowed-signers list).
pub fn ssh_ed25519_key_line(recipient: &str) -> Option<String> {
    let mut key = ssh_key::PublicKey::from_openssh(recipient).ok()?;
    key.key_data().ed25519()?;
    key.set_comment("");
    key.to_openssh().ok()
}

/// The `ssh-keygen -l` fingerprint of an ssh-ed25519 public key line:
/// `SHA256:` and the unpadded base64 SHA-256 of the key's wire blob. This is
/// the form git prints for an ssh commit signature (`%GK`), which is what
/// lets a commit's signer be matched with a recipient. Not the same value as
/// [`fingerprint`], which hashes the bare 32-byte verifying key. `None` for
/// another key type or a string that is not a key.
pub fn ssh_ed25519_fingerprint(recipient: &str) -> Option<String> {
    let key = ssh_key::PublicKey::from_openssh(recipient).ok()?;
    key.key_data().ed25519()?;
    Some(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = signing_key_from_age_bytes(&bytes(7));
        let b = signing_key_from_age_bytes(&bytes(7));
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn different_age_keys_yield_different_signing_keys() {
        let a = signing_key_from_age_bytes(&bytes(1));
        let b = signing_key_from_age_bytes(&bytes(2));
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn signing_seed_is_not_the_raw_age_key() {
        // The KDF must not pass the age key through unchanged — reusing the
        // encryption scalar as a signing scalar is the cross-protocol footgun
        // the domain-separated derivation exists to avoid.
        let raw = bytes(9);
        let sk = signing_key_from_age_bytes(&raw);
        assert_ne!(sk.to_bytes(), raw);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = signing_key_from_age_bytes(&bytes(3));
        let vk = verifying_key_b64(&sk);
        let sig = sign(&sk, b"the vault bytes");
        assert!(verify(&vk, &sig, b"the vault bytes"));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = signing_key_from_age_bytes(&bytes(3));
        let vk = verifying_key_b64(&sk);
        let sig = sign(&sk, b"the vault bytes");
        assert!(!verify(&vk, &sig, b"the vault bytes (tampered)"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = signing_key_from_age_bytes(&bytes(3));
        let other = verifying_key_b64(&signing_key_from_age_bytes(&bytes(4)));
        let sig = sign(&sk, b"msg");
        assert!(!verify(&other, &sig, b"msg"));
    }

    #[test]
    fn verify_rejects_garbage_inputs() {
        let sk = signing_key_from_age_bytes(&bytes(3));
        let vk = verifying_key_b64(&sk);
        let sig = sign(&sk, b"msg");
        assert!(!verify("not base64!!!", &sig, b"msg"));
        assert!(!verify(&vk, "not base64!!!", b"msg"));
        assert!(!verify(&vk, &BASE64.encode([0u8; 10]), b"msg"));
    }

    // A real unencrypted ssh-ed25519 keypair (also used in crypto.rs tests).
    const SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
    const SSH_ED25519_PK: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

    #[test]
    fn ssh_signing_key_vk_matches_recipient() {
        // The vk the SSH signing key produces must equal the vk embedded in the
        // recipient string — that equality is what makes SSH signatures
        // self-authenticating (no registry).
        let sk = ed25519_signing_key_from_openssh(SSH_ED25519_SK).unwrap();
        let from_sk = verifying_key_b64(&sk);
        let from_pk = ed25519_verifying_key_b64_from_ssh_recipient(SSH_ED25519_PK).unwrap();
        assert_eq!(from_sk, from_pk);
    }

    #[test]
    fn ssh_sign_verify_roundtrip_against_recipient() {
        let sk = ed25519_signing_key_from_openssh(SSH_ED25519_SK).unwrap();
        let vk = ed25519_verifying_key_b64_from_ssh_recipient(SSH_ED25519_PK).unwrap();
        let sig = sign(&sk, b"vault bytes");
        assert!(verify(&vk, &sig, b"vault bytes"));
        assert!(!verify(&vk, &sig, b"tampered"));
    }

    #[test]
    fn ssh_recipient_vk_tolerates_trailing_comment() {
        let with_comment = format!("{SSH_ED25519_PK} someone@host");
        assert_eq!(
            ed25519_verifying_key_b64_from_ssh_recipient(SSH_ED25519_PK),
            ed25519_verifying_key_b64_from_ssh_recipient(&with_comment),
        );
    }

    #[test]
    fn ssh_helpers_reject_non_ed25519_and_garbage() {
        assert!(ed25519_signing_key_from_openssh("not a key").is_none());
        assert!(ed25519_verifying_key_b64_from_ssh_recipient("ssh-rsa AAAAB3xyz").is_err());
        assert!(ed25519_verifying_key_b64_from_ssh_recipient("garbage").is_err());
    }

    /// A signature forged without a secret under a weak key: dalek's `verify`
    /// accepts it, murk's never does.
    #[test]
    fn verify_refuses_signatures_forged_under_a_weak_key() {
        use ed25519_dalek::Verifier;
        for (name, point) in crate::testutil::WEAK_ED25519_KEYS {
            let sig = crate::testutil::forged_small_order_signature(&point, b"any vault");
            let vk = VerifyingKey::from_bytes(&point).unwrap();
            assert!(
                vk.verify(b"any vault", &Signature::from_bytes(&sig))
                    .is_ok(),
                "{name}: the forgery passes the lax check"
            );
            assert!(
                !verify(&BASE64.encode(point), &BASE64.encode(sig), b"any vault"),
                "{name}"
            );
        }
    }

    /// A key with a torsion component is neither weak nor non-canonical, and
    /// its holder can make a signature whose `R` is a small-order point:
    /// `R = T` and `s = k·a`, where `[s]B − [k]A = −[k]T₈` equals `T` for
    /// the right message. dalek's `verify` accepts it; `verify_strict`, and so
    /// murk, refuses it.
    #[test]
    fn verify_refuses_a_small_order_signature_point() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        use curve25519_dalek::edwards::EdwardsPoint;
        use curve25519_dalek::scalar::Scalar;
        use ed25519_dalek::Verifier;
        use sha2::{Digest, Sha512};

        let a = Scalar::from_bytes_mod_order([7u8; 32]);
        let key = (EdwardsPoint::mul_base(&a) + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        let vk = VerifyingKey::from_bytes(&key).unwrap();
        assert!(!vk.is_weak(), "a key with a torsion component is not weak");
        let (msg, sig) = (0u32..)
            .flat_map(|n| EIGHT_TORSION.map(move |t| (format!("vault {n}").into_bytes(), t)))
            .find_map(|(msg, t)| {
                let r = t.compress();
                let digest = Sha512::new()
                    .chain_update(r.as_bytes())
                    .chain_update(key)
                    .chain_update(&msg)
                    .finalize();
                let mut wide = [0u8; 64];
                wide.copy_from_slice(&digest);
                let k = Scalar::from_bytes_mod_order_wide(&wide);
                (-(k * EIGHT_TORSION[1]) == t).then(|| {
                    let mut sig = [0u8; 64];
                    sig[..32].copy_from_slice(r.as_bytes());
                    sig[32..].copy_from_slice((k * a).as_bytes());
                    (msg, sig)
                })
            })
            .unwrap();
        assert!(
            vk.verify(&msg, &Signature::from_bytes(&sig)).is_ok(),
            "the lax check accepts it"
        );
        assert!(!verify(&BASE64.encode(key), &BASE64.encode(sig), &msg));
    }

    #[test]
    fn ssh_fingerprint_matches_ssh_keygen() {
        // `ssh-keygen -lf` on this key prints this fingerprint; a comment on
        // the key line does not change it.
        let expected = "SHA256:PYX4o9UfGwCwG76hFcLAEkmMS0PtIBtV9MNmVgW16Oc";
        assert_eq!(ssh_ed25519_fingerprint(SSH_ED25519_PK).unwrap(), expected);
        let with_comment = format!("{SSH_ED25519_PK} str4d@carbon");
        assert_eq!(ssh_ed25519_fingerprint(&with_comment).unwrap(), expected);
    }

    #[test]
    fn ssh_fingerprint_and_key_line_reject_non_ed25519_and_garbage() {
        for bad in ["not a key", "ssh-rsa AAAAB3xyz", "age1abc", ""] {
            assert!(ssh_ed25519_fingerprint(bad).is_none(), "{bad}");
            assert!(ssh_ed25519_key_line(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ssh_key_line_drops_comment() {
        let with_comment = format!("{SSH_ED25519_PK} someone@host");
        assert_eq!(ssh_ed25519_key_line(&with_comment).unwrap(), SSH_ED25519_PK);
    }
}
