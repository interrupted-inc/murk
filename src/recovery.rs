// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use bech32::{Bech32, Hrp};
use zeroize::Zeroizing;

/// Errors that can occur during recovery phrase operations.
#[derive(Debug)]
pub enum RecoveryError {
    Bip39(String),
    InvalidKey(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::Bip39(msg) => write!(f, "BIP39 error: {msg}"),
            RecoveryError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

/// The Bech32 human-readable prefix for age secret keys.
/// age uses lowercase internally, then uppercases the full string for display.
const AGE_SECRET_KEY_HRP: Hrp = Hrp::parse_unchecked("age-secret-key-");

/// Generate a new age keypair and return the BIP39 24-word mnemonic,
/// secret key string, and public key string.
///
/// 24 BIP39 words encode 256 bits (32 bytes) — exactly the size of an
/// age x25519 secret key. The mnemonic is a direct encoding of the key
/// bytes with no derivation step. Same words, same key, always.
///
/// The mnemonic and secret key are returned in `Zeroizing` wrappers so the
/// plaintext is cleared from memory when dropped.
pub fn generate() -> Result<(Zeroizing<String>, Zeroizing<String>, String), RecoveryError> {
    let entropy = Zeroizing::new([0u8; 32].map(|_| rand::random::<u8>()));
    let mnemonic = bip39::Mnemonic::from_entropy(&*entropy)
        .map_err(|e| RecoveryError::Bip39(e.to_string()))?;

    let secret_key = bytes_to_age_key(&*entropy)?;

    let identity = crate::crypto::parse_identity(&secret_key)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;

    Ok((Zeroizing::new(mnemonic.to_string()), secret_key, pubkey))
}

/// Re-derive the BIP39 24-word mnemonic from an existing MURK_KEY.
/// Decodes the Bech32 key back to raw bytes, then encodes as a mnemonic.
///
/// Plugin identities (`AGE-PLUGIN-*`) have no recovery phrase because BIP39
/// words encode the raw 32 key bytes and hardware-backed keys never leave
/// the device. Back up a second hardware device as a vault recipient instead.
pub fn phrase_from_key(secret_key: &str) -> Result<Zeroizing<String>, RecoveryError> {
    let trimmed = secret_key.trim();
    if trimmed.to_ascii_uppercase().contains("AGE-PLUGIN-") {
        return Err(RecoveryError::InvalidKey(
            "plugin identities (YubiKey, Secure Enclave, FIDO2) do not have recovery phrases. \
             BIP39 words encode the raw 32 key bytes, but hardware-backed keys never leave the \
             device — there are no bytes to encode. Recovery means enrolling a backup hardware \
             device at setup and adding its pubkey as a recipient with `murk authorize`"
                .into(),
        ));
    }

    // age keys are uppercase; bech32 decoding requires lowercase.
    let lowercase = Zeroizing::new(trimmed.to_lowercase());
    let (_, key_bytes) =
        bech32::decode(&lowercase).map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;
    let key_bytes = Zeroizing::new(key_bytes);
    let mnemonic = bip39::Mnemonic::from_entropy(&key_bytes)
        .map_err(|e| RecoveryError::Bip39(e.to_string()))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Recover an age secret key from a BIP39 24-word mnemonic phrase.
/// Returns the same MURK_KEY that was originally generated.
pub fn recover(phrase: &str) -> Result<Zeroizing<String>, RecoveryError> {
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(|e| RecoveryError::Bip39(e.to_string()))?;

    let entropy = Zeroizing::new(mnemonic.to_entropy());
    bytes_to_age_key(&entropy)
}

/// Bech32-encode raw key bytes as an AGE-SECRET-KEY-1... string.
/// This matches exactly how the age crate encodes keys internally.
fn bytes_to_age_key(key_bytes: &[u8]) -> Result<Zeroizing<String>, RecoveryError> {
    let encoded = bech32::encode::<Bech32>(AGE_SECRET_KEY_HRP, key_bytes)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;

    let key_str = Zeroizing::new(encoded.to_uppercase());

    // Validate by round-tripping through the age crate.
    crate::crypto::parse_identity(&key_str)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;

    Ok(key_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_mnemonic_and_key() {
        let (phrase, secret_key, pubkey) = generate().unwrap();

        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(secret_key.starts_with("AGE-SECRET-KEY-1"));
        assert!(pubkey.starts_with("age1"));
    }

    #[test]
    fn recover_roundtrip() {
        let (phrase, original_key, _) = generate().unwrap();
        let recovered_key = recover(&phrase).unwrap();
        assert_eq!(original_key, recovered_key);
    }

    #[test]
    fn same_phrase_same_key() {
        let (phrase, key1, _) = generate().unwrap();
        let key2 = recover(&phrase).unwrap();
        let key3 = recover(&phrase).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
    }

    #[test]
    fn different_phrases_different_keys() {
        let (_, key1, _) = generate().unwrap();
        let (_, key2, _) = generate().unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn phrase_from_key_roundtrip() {
        let (original_phrase, secret_key, _) = generate().unwrap();
        let recovered_phrase = phrase_from_key(&secret_key).unwrap();
        assert_eq!(original_phrase, recovered_phrase);
    }

    #[test]
    fn invalid_phrase_fails() {
        assert!(recover("amet sed ut sit dolor et magna vita ipsum quasi nemo enim ad ex in id est non vel rem sint cum").is_err());
    }

    // ── New edge-case tests ──

    #[test]
    fn recover_wrong_word_count() {
        // 12 valid BIP39 words instead of 24 — should fail.
        assert!(recover("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());
    }

    #[test]
    fn recover_gibberish_words() {
        // 24 nonsense words — should fail.
        let words = "zzz yyy xxx www vvv uuu ttt sss rrr qqq ppp ooo nnn mmm lll kkk jjj iii hhh ggg fff eee ddd ccc";
        assert!(recover(words).is_err());
    }

    #[test]
    fn recover_empty_string() {
        assert!(recover("").is_err());
    }

    #[test]
    fn phrase_from_key_invalid_key() {
        assert!(phrase_from_key("not-a-valid-key").is_err());
    }

    #[test]
    fn phrase_from_key_empty() {
        assert!(phrase_from_key("").is_err());
    }

    #[test]
    fn generate_key_is_deterministic_from_entropy() {
        // Same entropy → same key, verified via phrase roundtrip.
        let (phrase, key, _) = generate().unwrap();
        let recovered = recover(&phrase).unwrap();
        assert_eq!(key, recovered);
        // And the phrase from that key matches.
        let phrase_back = phrase_from_key(&key).unwrap();
        assert_eq!(phrase, phrase_back);
    }

    #[test]
    fn recovery_error_display() {
        let e = RecoveryError::Bip39("bad mnemonic".into());
        assert!(e.to_string().contains("bad mnemonic"));

        let e = RecoveryError::InvalidKey("not a key".into());
        assert!(e.to_string().contains("not a key"));
    }
}
