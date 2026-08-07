use std::collections::HashMap;
use std::io::{Read, Write};

use age::cli_common::UiCallbacks;
use age::plugin::{
    Identity as PluginIdentity, IdentityPluginV1, Recipient as PluginRecipient, RecipientPluginV1,
};
use zeroize::Zeroizing;

/// Errors that can occur during crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    Encrypt(String),
    Decrypt(String),
    InvalidKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Encrypt(msg) => write!(f, "encryption failed: {msg}"),
            CryptoError::Decrypt(msg) => write!(f, "decryption failed: {msg}"),
            CryptoError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

/// A recipient that can receive age-encrypted data.
///
/// Wraps an age x25519 recipient, an SSH public key recipient, or a plugin
/// recipient like `age1yubikey1...`. Plugin recipients dispatch to an external
/// `age-plugin-<name>` binary during encryption.
#[derive(Clone)]
pub enum MurkRecipient {
    Age(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
    Plugin(PluginRecipient),
}

impl std::fmt::Debug for MurkRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MurkRecipient::Age(r) => write!(f, "Age({r})"),
            MurkRecipient::Ssh(r) => write!(f, "Ssh({r})"),
            MurkRecipient::Plugin(r) => write!(f, "Plugin({r})"),
        }
    }
}

/// An identity that can decrypt age-encrypted data.
///
/// Plugin identities (`AGE-PLUGIN-<NAME>-1...`) carry the recipient pubkey
/// alongside the pointer so `pubkey_string` does not require spawning the
/// plugin binary. Decryption spawns `age-plugin-<name>` via
/// [`IdentityPluginV1`] to access the hardware-backed key.
#[derive(Clone)]
pub enum MurkIdentity {
    Age(age::x25519::Identity),
    Ssh {
        identity: age::ssh::Identity,
        /// The original OpenSSH private-key text. age does not expose the SSH
        /// signing scalar, so we retain the PEM to derive an Ed25519 signing key
        /// for vault signing (ssh-ed25519 only). Zeroized on drop.
        pem: Zeroizing<String>,
    },
    Plugin {
        identity: PluginIdentity,
        pubkey: String,
    },
}

/// Debug prints only the identity *kind*, never key material, to keep
/// accidental logs from leaking secrets.
impl std::fmt::Debug for MurkIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MurkIdentity::Age(_) => write!(f, "Age(<redacted>)"),
            MurkIdentity::Ssh { .. } => write!(f, "Ssh(<redacted>)"),
            MurkIdentity::Plugin { pubkey, identity } => {
                write!(f, "Plugin({} → {pubkey})", identity.plugin())
            }
        }
    }
}

impl MurkIdentity {
    /// Return the public key string for this identity.
    ///
    /// For age keys: `age1...`. For SSH keys: `ssh-ed25519 AAAA...` or
    /// `ssh-rsa AAAA...`. For plugin keys: the `age1<plugin>1...` recipient
    /// that was parsed from the identity file's recipient header
    /// (`# Recipient:` or `# public key:`).
    pub fn pubkey_string(&self) -> Result<String, CryptoError> {
        match self {
            MurkIdentity::Age(id) => Ok(id.to_public().to_string()),
            MurkIdentity::Ssh { identity, .. } => {
                let recipient = age::ssh::Recipient::try_from(identity.clone()).map_err(|e| {
                    CryptoError::InvalidKey(format!("cannot derive SSH public key: {e:?}"))
                })?;
                Ok(recipient.to_string())
            }
            MurkIdentity::Plugin { pubkey, .. } => Ok(pubkey.clone()),
        }
    }

    /// Plugin name (e.g. `"yubikey"`, `"se"`) if this is a plugin identity.
    pub fn plugin_name(&self) -> Option<&str> {
        match self {
            MurkIdentity::Plugin { identity, .. } => Some(identity.plugin()),
            _ => None,
        }
    }

    /// Whether this identity can produce vault signatures: native age keys, and
    /// `ssh-ed25519` keys (which sign natively). `ssh-rsa` and hardware/plugin
    /// identities cannot. Cheap check for deciding whether to nudge on an unsigned
    /// vault; the actual key comes from [`Self::signing_key`].
    pub fn is_signing_capable(&self) -> bool {
        match self {
            MurkIdentity::Age(_) => true,
            MurkIdentity::Ssh { .. } => self
                .pubkey_string()
                .is_ok_and(|s| s.starts_with("ssh-ed25519 ")),
            MurkIdentity::Plugin { .. } => false,
        }
    }

    /// Whether this identity's verifying key must be recorded in the signer
    /// registry (`Meta::signers`) for its signature to be verifiable.
    ///
    /// Only age keys: their Ed25519 verifying key is derived from the secret and
    /// cannot be recovered from the public age recipient, so it must be published.
    /// `ssh-ed25519` verifying keys are embedded in the recipient string itself,
    /// so they are self-authenticating and are NOT registered.
    pub fn registers_verifying_key(&self) -> bool {
        matches!(self, MurkIdentity::Age(_))
    }

    /// This identity's Ed25519 signing key, if it can sign.
    ///
    /// - Age keys: derived from the raw x25519 key bytes via a domain-separated
    ///   KDF (see [`crate::signing`]), so it recovers from the BIP39 phrase.
    /// - `ssh-ed25519` keys: the SSH key *is* an Ed25519 signing key; we parse it
    ///   from the retained OpenSSH PEM (age does not expose the scalar). The
    ///   resulting verifying key matches the `ssh-ed25519 …` recipient string.
    /// - `ssh-rsa` and plugin/hardware identities return `None` (unsigned).
    pub fn signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        match self {
            MurkIdentity::Age(id) => {
                use age::secrecy::ExposeSecret;
                // age keys display uppercase; bech32 decoding requires lowercase.
                let secret = id.to_string();
                let lower = Zeroizing::new(secret.expose_secret().to_lowercase());
                let (_, bytes) = bech32::decode(&lower).ok()?;
                let bytes = Zeroizing::new(bytes);
                Some(crate::signing::signing_key_from_age_bytes(&bytes))
            }
            MurkIdentity::Ssh { pem, .. } => crate::signing::ed25519_signing_key_from_openssh(pem),
            MurkIdentity::Plugin { .. } => None,
        }
    }
}

/// Parse a public key string into a `MurkRecipient`.
///
/// Tries x25519 (`age1...`), then SSH (`ssh-ed25519 ...` / `ssh-rsa ...`),
/// then age plugin recipients (`age1<plugin>1...`).
pub fn parse_recipient(pubkey: &str) -> Result<MurkRecipient, CryptoError> {
    if let Ok(r) = pubkey.parse::<age::x25519::Recipient>() {
        return Ok(MurkRecipient::Age(r));
    }
    if let Ok(r) = pubkey.parse::<age::ssh::Recipient>() {
        return Ok(MurkRecipient::Ssh(r));
    }
    if let Ok(r) = pubkey.parse::<PluginRecipient>() {
        return Ok(MurkRecipient::Plugin(r));
    }
    Err(CryptoError::InvalidKey(format!(
        "not a valid age, SSH, or plugin public key: {pubkey}"
    )))
}

/// Parse a secret key or identity-file contents into a `MurkIdentity`.
///
/// Accepts three shapes:
/// - A bare age secret key (`AGE-SECRET-KEY-1...`)
/// - An SSH PEM-encoded private key (unencrypted only; encrypted keys are rejected)
/// - A plugin identity file — multi-line text with a recipient header
///   (`# Recipient: age1...` or `# public key: age1...`) followed by an
///   `AGE-PLUGIN-<NAME>-1...` pointer, as produced by tools like
///   `age-plugin-yubikey --identity`
///
/// Comments and blank lines are permitted anywhere.
pub fn parse_identity(input: &str) -> Result<MurkIdentity, CryptoError> {
    let trimmed = input.trim();
    if let Ok(id) = trimmed.parse::<age::x25519::Identity>() {
        return Ok(MurkIdentity::Age(id));
    }

    // SSH PEM has its own framing; feed the full input.
    let reader = std::io::BufReader::new(input.as_bytes());
    if let Ok(id) = age::ssh::Identity::from_buffer(reader, None) {
        match id {
            age::ssh::Identity::Unencrypted(_) => {
                // Retain the PEM: age won't expose the SSH signing scalar, so we
                // re-parse it (ssh-ed25519 only) when signing the vault.
                return Ok(MurkIdentity::Ssh {
                    identity: id,
                    pem: Zeroizing::new(input.to_string()),
                });
            }
            age::ssh::Identity::Encrypted(_) => {
                return Err(CryptoError::InvalidKey(
                    "encrypted SSH keys are not yet supported — use an unencrypted key or an age key"
                        .into(),
                ));
            }
            age::ssh::Identity::Unsupported(k) => {
                return Err(CryptoError::InvalidKey(format!(
                    "unsupported SSH key type: {k:?}"
                )));
            }
        }
    }

    // Identity-file form: walk lines, capture the recipient-pubkey header, then
    // accept a following plugin pointer. age x25519/ssh files use
    // `# public key:`; age-plugin-yubikey emits `# Recipient:`. Accept either,
    // case-insensitively, so real plugin output parses without rewriting.
    let mut pubkey: Option<String> = None;
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#').map(str::trim).and_then(|s| {
            let lower = s.to_ascii_lowercase();
            ["public key:", "recipient:"].iter().find_map(|p| {
                lower
                    .starts_with(p)
                    .then(|| s[p.len()..].trim().to_string())
            })
        }) {
            pubkey = Some(rest);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Ok(identity) = line.parse::<PluginIdentity>() {
            let pk = pubkey.ok_or_else(|| {
                CryptoError::InvalidKey(
                    "plugin identity is missing its recipient header (`# public key: age1...` \
                     or `# Recipient: age1...`). Save the plugin output (the header line PLUS \
                     the AGE-PLUGIN-... line) to a file and set MURK_KEY_FILE to its path — \
                     setting MURK_KEY to just the identity string is not enough, because murk \
                     needs the recipient pubkey"
                        .into(),
                )
            })?;
            parse_recipient(&pk).map_err(|e| {
                CryptoError::InvalidKey(format!(
                    "`# public key:` header in identity file is not a valid recipient: {e}"
                ))
            })?;
            return Ok(MurkIdentity::Plugin {
                identity,
                pubkey: pk,
            });
        }
        // Unrecognised non-comment line — retry as an age key for trailing-whitespace tolerance.
        if let Ok(id) = line.parse::<age::x25519::Identity>() {
            return Ok(MurkIdentity::Age(id));
        }
        break;
    }

    Err(CryptoError::InvalidKey(
        "not a valid age secret key, SSH private key, or plugin identity file".into(),
    ))
}

/// Encrypt plaintext bytes to one or more recipients.
///
/// Plugin recipients are grouped by plugin name and dispatched via
/// [`RecipientPluginV1`]. Native (age/ssh) recipients pass through directly.
pub fn encrypt(plaintext: &[u8], recipients: &[MurkRecipient]) -> Result<Vec<u8>, CryptoError> {
    let mut native: Vec<&dyn age::Recipient> = vec![];
    let mut grouped: HashMap<String, Vec<PluginRecipient>> = HashMap::new();

    for r in recipients {
        match r {
            MurkRecipient::Age(r) => native.push(r),
            MurkRecipient::Ssh(r) => native.push(r),
            MurkRecipient::Plugin(r) => grouped
                .entry(r.plugin().to_string())
                .or_default()
                .push(r.clone()),
        }
    }

    let mut plugins: Vec<RecipientPluginV1<UiCallbacks>> = vec![];
    for (name, plugin_recipients) in grouped {
        let plugin = RecipientPluginV1::new(&name, &plugin_recipients, &[], UiCallbacks)
            .map_err(|e| CryptoError::Encrypt(format!("age-plugin-{name} unavailable: {e}")))?;
        plugins.push(plugin);
    }

    let mut all_refs: Vec<&dyn age::Recipient> = native;
    for plugin in &plugins {
        all_refs.push(plugin);
    }

    let encryptor = age::Encryptor::with_recipients(all_refs.into_iter())
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    let mut ciphertext = vec![];
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    writer
        .write_all(plaintext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    // finish() is critical — without it, the output is silently
    // truncated and undecryptable. No error, just broken data.
    writer
        .finish()
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    Ok(ciphertext)
}

/// Decrypt ciphertext using an identity (age, SSH, or plugin).
///
/// Returns the plaintext wrapped in `Zeroizing<Vec<u8>>` so the buffer is
/// cleared when dropped. Defense-in-depth against plaintext lingering in
/// freed heap memory.
///
/// For plugin identities this spawns `age-plugin-<name>` and may prompt
/// the user (YubiKey touch, Touch ID, PIN entry) via [`UiCallbacks`].
pub fn decrypt(
    ciphertext: &[u8],
    identity: &MurkIdentity,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    let mut plaintext = Zeroizing::new(vec![]);

    // Hold the plugin object outside the match so the &dyn borrow stays valid.
    let plugin_holder: Option<IdentityPluginV1<UiCallbacks>> = match identity {
        MurkIdentity::Plugin { identity, .. } => Some(
            IdentityPluginV1::new(
                identity.plugin(),
                std::slice::from_ref(identity),
                UiCallbacks,
            )
            .map_err(|e| {
                CryptoError::Decrypt(format!("age-plugin-{} unavailable: {e}", identity.plugin()))
            })?,
        ),
        _ => None,
    };

    let id_ref: &dyn age::Identity = match identity {
        MurkIdentity::Age(id) => id,
        MurkIdentity::Ssh { identity, .. } => identity,
        MurkIdentity::Plugin { .. } => plugin_holder.as_ref().expect("constructed above"),
    };

    let mut reader = decryptor
        .decrypt(std::iter::once(id_ref))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn generate_keypair() -> (String, String) {
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string();
        let pubkey = identity.to_public().to_string();
        (secret.expose_secret().to_string(), pubkey)
    }

    #[test]
    fn roundtrip_single_recipient() {
        let (secret, pubkey) = generate_keypair();
        let recipient = parse_recipient(&pubkey).unwrap();
        let identity = parse_identity(&secret).unwrap();

        let plaintext = b"hello darkness";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn roundtrip_multiple_recipients() {
        let (secret_a, pubkey_a) = generate_keypair();
        let (secret_b, pubkey_b) = generate_keypair();

        let recipients = vec![
            parse_recipient(&pubkey_a).unwrap(),
            parse_recipient(&pubkey_b).unwrap(),
        ];

        let plaintext = b"sharing is caring";
        let ciphertext = encrypt(plaintext, &recipients).unwrap();

        // Both recipients can decrypt
        let id_a = parse_identity(&secret_a).unwrap();
        let id_b = parse_identity(&secret_b).unwrap();
        assert_eq!(&decrypt(&ciphertext, &id_a).unwrap()[..], plaintext);
        assert_eq!(&decrypt(&ciphertext, &id_b).unwrap()[..], plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let (_secret, pubkey) = generate_keypair();
        let (wrong_secret, _) = generate_keypair();

        let recipient = parse_recipient(&pubkey).unwrap();
        let wrong_identity = parse_identity(&wrong_secret).unwrap();

        let ciphertext = encrypt(b"none of your business", &[recipient]).unwrap();
        assert!(decrypt(&ciphertext, &wrong_identity).is_err());
    }

    #[test]
    fn invalid_key_strings() {
        assert!(parse_recipient("sine-loco").is_err());
        assert!(parse_identity("nihil-et-nemo").is_err());
    }

    // ── Plugin identity tests ──

    /// Build a syntactically-valid plugin identity + recipient pair for a
    /// given plugin name. Uses bech32 with dummy entropy — these tests verify
    /// parsing and dispatch, not plugin interop.
    fn make_plugin_pair(plugin: &str) -> (String, String) {
        use bech32::{Bech32, Hrp};
        let entropy = [0u8; 20];
        let identity_hrp = Hrp::parse(&format!("age-plugin-{plugin}-")).unwrap();
        let identity = bech32::encode::<Bech32>(identity_hrp, &entropy)
            .unwrap()
            .to_uppercase();
        let recipient_hrp = Hrp::parse(&format!("age1{plugin}")).unwrap();
        let recipient = bech32::encode::<Bech32>(recipient_hrp, &entropy).unwrap();
        (identity, recipient)
    }

    #[test]
    fn parse_identity_plugin_file() {
        let (identity_str, pubkey_str) = make_plugin_pair("yubikey");
        let file = format!(
            "# created: 2024-01-01T00:00:00-00:00\n# public key: {pubkey_str}\n{identity_str}\n"
        );
        let id = parse_identity(&file).expect("parses plugin identity file");
        match &id {
            MurkIdentity::Plugin { identity, pubkey } => {
                assert_eq!(identity.plugin(), "yubikey");
                assert_eq!(pubkey, &pubkey_str);
            }
            _ => panic!("expected Plugin variant, got {id:?}"),
        }
        assert_eq!(id.pubkey_string().unwrap(), pubkey_str);
    }

    #[test]
    fn parse_identity_plugin_file_recipient_header() {
        // age-plugin-yubikey 0.5.1 emits `# Recipient:`, not `# public key:`.
        // murk must accept it so the native identity file parses unmodified.
        let (identity_str, pubkey_str) = make_plugin_pair("yubikey");
        let file = format!(
            "#       Serial: 17600929, Slot: 1\n#         Name: murk-test\n\
             #    Recipient: {pubkey_str}\n{identity_str}\n"
        );
        let id = parse_identity(&file).expect("parses `# Recipient:` plugin file");
        match &id {
            MurkIdentity::Plugin { identity, pubkey } => {
                assert_eq!(identity.plugin(), "yubikey");
                assert_eq!(pubkey, &pubkey_str);
            }
            _ => panic!("expected Plugin variant, got {id:?}"),
        }
    }

    #[test]
    fn is_signing_capable_by_identity_kind() {
        // Native age keys are signing-capable.
        let (secret, _) = generate_keypair();
        assert!(parse_identity(&secret).unwrap().is_signing_capable());

        // Plugin/hardware identities cannot sign — no exposed signing scalar.
        let (identity_str, pubkey_str) = make_plugin_pair("yubikey");
        let file = format!("# public key: {pubkey_str}\n{identity_str}\n");
        assert!(!parse_identity(&file).unwrap().is_signing_capable());
    }

    #[test]
    fn parse_identity_plugin_file_missing_pubkey_header() {
        let (identity_str, _) = make_plugin_pair("yubikey");
        let err = parse_identity(&format!("{identity_str}\n"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("public key") && err.contains("MURK_KEY_FILE"),
            "expected pubkey + MURK_KEY_FILE guidance, got: {err}"
        );
    }

    #[test]
    fn parse_recipient_plugin_yubikey() {
        let (_, pubkey_str) = make_plugin_pair("yubikey");
        let r = parse_recipient(&pubkey_str).unwrap();
        assert!(matches!(r, MurkRecipient::Plugin(_)));
    }

    #[test]
    fn plugin_identity_trailing_whitespace_tolerated() {
        let (identity_str, pubkey_str) = make_plugin_pair("yubikey");
        let file = format!("\n\n# public key: {pubkey_str}\n{identity_str}\n\n");
        let id = parse_identity(&file).expect("parses with extra whitespace");
        assert_eq!(id.plugin_name(), Some("yubikey"));
    }

    // ── New edge-case tests ──

    #[test]
    fn encrypt_empty_plaintext() {
        let (secret, pubkey) = generate_keypair();
        let recipient = parse_recipient(&pubkey).unwrap();
        let identity = parse_identity(&secret).unwrap();

        let ciphertext = encrypt(b"", &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn decrypt_corrupted_ciphertext() {
        let (secret, _) = generate_keypair();
        let identity = parse_identity(&secret).unwrap();
        assert!(decrypt(b"this is not valid ciphertext", &identity).is_err());
    }

    #[test]
    fn decrypt_plugin_identity_without_binary_errs_and_never_panics() {
        // A plugin identity whose `age-plugin-<name>` binary is not installed.
        // The name is deliberately obscure so an installed plugin cannot make
        // this pass for the wrong reason.
        let (identity_str, _) = make_plugin_pair("murknosuchpluginxyz");
        let plugin_identity: PluginIdentity = identity_str.parse().unwrap();
        let identity = MurkIdentity::Plugin {
            identity: plugin_identity,
            pubkey: "age1-recipient-unused-by-decrypt".into(),
        };

        // Valid age ciphertext (to a native recipient) so the age header parses
        // and `decrypt` reaches the plugin-dispatch arm.
        let (_, pubkey) = generate_keypair();
        let recipient = parse_recipient(&pubkey).unwrap();
        let ciphertext = encrypt(b"unreadable without the plugin", &[recipient]).unwrap();

        // The binary is absent, so `IdentityPluginV1::new` fails and `decrypt`
        // surfaces a graceful "age-plugin-… unavailable" error. The mutant that
        // drops the `MurkIdentity::Plugin` arm here would leave `plugin_holder`
        // = None and panic at the `.expect()` below it — so reaching the arm and
        // getting an Err (not a panic) is exactly what kills that mutant.
        let err = decrypt(&ciphertext, &identity).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("age-plugin-murknosuchpluginxyz"),
            "expected a plugin-unavailable error naming the plugin, got: {msg}"
        );
    }

    #[test]
    fn parse_recipient_ssh_ed25519() {
        // A valid ssh-ed25519 public key (without comment)
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";
        let r = parse_recipient(key);
        assert!(r.is_ok());
        assert!(matches!(r.unwrap(), MurkRecipient::Ssh(_)));
    }

    #[test]
    fn parse_recipient_age_key() {
        let (_, pubkey) = generate_keypair();
        let r = parse_recipient(&pubkey);
        assert!(r.is_ok());
        assert!(matches!(r.unwrap(), MurkRecipient::Age(_)));
    }

    #[test]
    fn pubkey_string_age() {
        let (secret, pubkey) = generate_keypair();
        let id = parse_identity(&secret).unwrap();
        assert_eq!(id.pubkey_string().unwrap(), pubkey);
    }

    #[test]
    fn parse_identity_ssh_unencrypted() {
        // Unencrypted ed25519 SSH key from age's test suite.
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk);
        assert!(id.is_ok());
        assert!(matches!(id.unwrap(), MurkIdentity::Ssh { .. }));
    }

    #[test]
    fn ssh_identity_pubkey_roundtrip() {
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk).unwrap();
        let pubkey = id.pubkey_string().unwrap();
        assert!(pubkey.starts_with("ssh-ed25519 "));

        // The derived pubkey should be parseable as a recipient.
        let recipient = parse_recipient(&pubkey);
        assert!(recipient.is_ok());
    }

    #[test]
    fn ssh_encrypt_decrypt_roundtrip() {
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk).unwrap();
        let pubkey = id.pubkey_string().unwrap();
        let recipient = parse_recipient(&pubkey).unwrap();

        let plaintext = b"ssh secrets";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &id).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn mixed_age_and_ssh_recipients() {
        // Age keypair.
        let (age_secret, age_pubkey) = generate_keypair();

        // SSH keypair.
        let ssh_sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let ssh_id = parse_identity(ssh_sk).unwrap();
        let ssh_pubkey = ssh_id.pubkey_string().unwrap();

        // Encrypt to both.
        let recipients = vec![
            parse_recipient(&age_pubkey).unwrap(),
            parse_recipient(&ssh_pubkey).unwrap(),
        ];
        let plaintext = b"shared between age and ssh";
        let ciphertext = encrypt(plaintext, &recipients).unwrap();

        // Both can decrypt.
        let age_id = parse_identity(&age_secret).unwrap();
        assert_eq!(&decrypt(&ciphertext, &age_id).unwrap()[..], plaintext);
        assert_eq!(&decrypt(&ciphertext, &ssh_id).unwrap()[..], plaintext);
    }

    #[test]
    fn parse_identity_encrypted_ssh_rejected() {
        // A passphrase-encrypted OpenSSH key parses as `Encrypted` — murk cannot
        // prompt for the passphrase, so it must reject with actionable guidance
        // rather than silently treating the file as an unknown key type.
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCppyaxrR\nt7gjjxElEDYyPQAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIH4f8P5poEqKAj68\nDDdSXG/ynZroSlDI9aJW4Hwr7K2xAAAAkH1LpA6OVeypf2AyaW6uAAA2pzTDzin8xpbdFQ\nMNVWyLZP7JgiR8T21evnyek/7LUhHKDdPMG4H8rO8HC1uosT8lD2GIKHsRZ2ZRwcQeDH53\ntWpQ0MaprgaMjXb39SJn8Zy7ihDU4W6+qfKxZHem9X0IbXckE8vsBvzkZRlL+DRqADbee1\nDqF2zCI5NYNGbSJA==\n-----END OPENSSH PRIVATE KEY-----";
        let err = parse_identity(sk).unwrap_err().to_string();
        assert!(
            err.contains("encrypted SSH keys are not yet supported"),
            "expected encrypted-key rejection, got: {err}"
        );
    }

    #[test]
    fn parse_identity_unsupported_ssh_type_rejected() {
        // age supports ed25519 and rsa SSH keys; an ecdsa key parses as
        // `Unsupported` and must be rejected, not misfiled as an age key.
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR64I41Vo0JYyWv5JS/3Tmrj8o8PTaF\ndHLm1k95c1C/lltxquyQ0RhPtsp/g1VwOQkuPAySXQoEtGVt5uaY6vohAAAAmGYLyZNmC8\nmTAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHrgjjVWjQljJa/k\nlL/dOauPyjw9NoV0cubWT3lzUL+WW3Gq7JDRGE+2yn+DVXA5CS48DJJdCgS0ZW3m5pjq+i\nEAAAAgdQT/P3W0OB23mvEFBZnbZdwcCSEsVfXK5AHLpklry/0AAAAA\n-----END OPENSSH PRIVATE KEY-----";
        let err = parse_identity(sk).unwrap_err().to_string();
        assert!(
            err.contains("unsupported SSH key type"),
            "expected unsupported-type rejection, got: {err}"
        );
    }

    #[test]
    fn is_signing_capable_ssh_ed25519() {
        // ssh-ed25519 identities sign natively, so they are signing-capable —
        // the SSH arm that `is_signing_capable_by_identity_kind` never exercised.
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk).unwrap();
        assert!(id.is_signing_capable());
    }
}
