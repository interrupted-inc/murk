use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Current vault format version.
pub const VAULT_VERSION: &str = "2.0";

/// Default vault filename.
pub const DEFAULT_VAULT_NAME: &str = ".murk";

// -- Vault (on-disk format, v2) --
// The entire .murk file is a single JSON document with per-value encryption.
// Key names and schema are plaintext. Values are individually age-encrypted.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: String,
    pub created: String,
    pub vault_name: String,
    /// Repository URL, auto-detected from git remote during init.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo: String,
    /// Public keys only — no names. Name mappings live in the encrypted meta blob.
    pub recipients: Vec<String>,
    /// Key metadata — public, readable without decryption.
    pub schema: BTreeMap<String, SchemaEntry>,
    /// Optional agent access policy. Lives in the plaintext header (like schema)
    /// so it is readable on no-key paths and at the same trust level as the
    /// recipient list. Covered by the keyed MAC (`blake3v6:`) so it is
    /// tamper-evident. Absent when no policy is set, keeping policy-free vaults
    /// byte-identical to pre-policy murk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// Per-value encrypted secrets. Each value is a separate age ciphertext.
    pub secrets: BTreeMap<String, SecretEntry>,
    /// Encrypted metadata blob: recipient names and integrity MAC.
    pub meta: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// When the key was first added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// When the value was last updated. Doubles as "last rotated": any value
    /// change (`add`/`edit`/`rotate`) bumps it, so it anchors the rotation clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Soft rotation policy: rotate at least every N days. `doctor` flags the
    /// key as overdue when `updated + rotation_interval_days` is in the past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<u32>,
    /// Hard expiry (ISO-8601 UTC) for credentials with a known end-of-life,
    /// e.g. a token. `doctor` flags it as expired or expiring soon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Set to the revoke time (ISO-8601 UTC) when a recipient who could read
    /// this key is revoked and rotation is deferred. Its *presence* is the
    /// obligation: the revoked recipient can still decrypt the live value from
    /// git history until it changes. Any value write (`add`/`edit`/`rotate`/
    /// `import`) clears it, so a set `revoked_at` always means "still owed a
    /// rotation since this revoke". `doctor` flags it until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Shared value encrypted to all recipients (the implicit `everyone` group).
    /// Empty when the secret's base group is a named group instead.
    pub shared: String,
    /// Private per-recipient values: pubkey → encrypted value (encrypted to that
    /// pubkey only). This is the `me` tier — a singleton group of one recipient.
    /// Serialized as `scoped` for on-disk compatibility with vaults written
    /// before the tier was renamed; the wire format is unchanged.
    #[serde(rename = "scoped", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub private: BTreeMap<String, String>,
    /// Named-group values: group name → encrypted value (encrypted to that
    /// group's current members). A secret has at most one base group, so this
    /// map holds at most one entry, but it is keyed by name so the integrity MAC
    /// and merge driver can treat it uniformly with `scoped`. Group *names* are
    /// plaintext (like key names); group *membership* lives in the encrypted meta.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grouped: BTreeMap<String, String>,
}

/// A short-lived agent grant: an ephemeral identity with read access to a
/// narrow set of keys. The grant's `pubkey` is also a `Vault::recipients`
/// entry, and each granted key carries a `scoped` ciphertext under that pubkey —
/// so the agent's *access* is governed (and MAC-covered) by the scoped entries.
/// This record is the audit/TTL layer: it lives in the encrypted meta (so an
/// agent's existence and scope don't leak) and is covered by the keyed MAC
/// (`blake3v5:`) so TTL, scope, and issuer cannot be tampered with undetected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantEntry {
    /// The agent's ephemeral age public key (also in `Vault::recipients`).
    pub pubkey: String,
    /// Keys this grant can read (the `--only` set). Display/audit only — actual
    /// access is the set of `scoped` ciphertexts encrypted to `pubkey`.
    pub scope: Vec<String>,
    /// When the grant was issued (ISO-8601 UTC).
    pub issued_at: String,
    /// Expiry (ISO-8601 UTC), enforced at read time: an expired grant fails
    /// closed at every murk entry point (CLI, MCP, bindings). age keys cannot
    /// self-destruct, though, so the key still decrypts old `.murk` revisions
    /// with raw age — the real close is `agent revoke` + rotate.
    pub expires_at: String,
    /// Pubkey of the recipient who issued the grant (minimal accountability).
    pub issuer: String,
}

/// Agent access policy: machine-enforceable guardrails that travel with the
/// vault. This is NOT access control — every recipient can read every shared
/// secret by design, and an insider can use age directly or an old murk binary.
/// Its value is constraining what the murk binary will expose to *agents* (CI,
/// AI coding agents), enforced at the agent entry points (`agent exec`,
/// `agent grant`). Lives in the plaintext header and is MAC-covered so it can't
/// be silently weakened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Agent allow-list: in agent mode, a secret may be injected or granted only
    /// if it carries at least one of these tags. Default-deny once a policy is
    /// set — an untagged or wrong-tagged key is refused with a clear error. An
    /// empty list means no key is agent-injectable (agents fully locked out).
    #[serde(default)]
    pub agent_allow_tags: Vec<String>,
}

// -- Meta (encrypted, stored in vault.meta) --
// Contains metadata only visible to recipients.

/// An Ed25519 signature over the vault's canonical content.
///
/// The shared-key MAC binds ciphertexts together but authenticates no *author*:
/// its key lives in the meta blob, which anyone can re-encrypt using the public
/// recipient keys. A signature closes that — an attacker without a recipient's
/// signing key cannot forge one. Stored in the meta alongside the MAC. See
/// [`crate::signing`] and `THREAT_MODEL.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSignature {
    /// The recipient pubkey (`age1...`) whose signing key produced `sig`. Must be
    /// a current recipient, with a verifying key in `Meta::signers`, at verify time.
    pub signer: String,
    /// Signed-view version — bumped if the canonical signing message changes, so
    /// an old binary rejects a newer signed view rather than misverifying it.
    pub v: u32,
    /// Base64-encoded 64-byte Ed25519 signature.
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Maps pubkey → display name. The only place names are stored.
    pub recipients: HashMap<String, String>,
    /// Integrity MAC over secrets + schema.
    pub mac: String,
    /// Registered Ed25519 verifying keys: recipient pubkey → base64 verifying key.
    /// A signer's key must be listed here for its signature to verify. Populated
    /// when a signing-capable identity saves. Empty for vaults only ever written
    /// by SSH/hardware identities. Integrity of this map is anchored by the local
    /// TOFU pin and signed git history (see [`crate::signing`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signers: BTreeMap<String, String>,
    /// Ed25519 signature over the vault's canonical content. Absent when the last
    /// writer had no signing-capable identity; a *present* signature must verify
    /// or `load` fails as tampering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<VaultSignature>,
    /// BLAKE3 keyed MAC key (hex-encoded, 32 bytes). Generated at init, stored encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "hmac_key")]
    pub mac_key: Option<String>,
    /// Pinned GitHub key fingerprints: username → [SHA256:...].
    /// Used for TOFU (Trust On First Use) verification on `authorize github:user`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub github_pins: HashMap<String, Vec<String>>,
    /// Named recipient groups: group name → member pubkeys. Stored here (not in
    /// the plaintext header) so org structure — who is in which group — does not
    /// leak. Members are a subset of `Vault::recipients`. Covered by the keyed
    /// MAC (`blake3v4:`) so membership cannot be tampered with undetected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Short-lived agent grants: grant name → metadata. Stored here (encrypted)
    /// so an agent's existence and scope do not leak. Covered by the keyed MAC
    /// (`blake3v5:`) so TTL/scope/issuer are tamper-evident.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grants: BTreeMap<String, GrantEntry>,
}

/// Outcome of verifying the vault's Ed25519 signature at load time.
///
/// An *invalid* signature never reaches here — it fails the load as tampering.
/// So the working state distinguishes "signed" from "unsigned" (integrity then
/// rests on git). The binary warns on `Unsigned`, and on a `Signed` that is not
/// yet `anchored`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SignatureState {
    /// A valid signature produced by `signer` (a current recipient).
    ///
    /// `anchored` is whether the signer's verifying key is trusted independently
    /// of the (attacker-mutable) meta registry: always true for ssh-ed25519
    /// signers (the key is in the recipient string), and true for age signers
    /// whose key matched a prior local pin. When false — an age signer's key seen
    /// for the first time on this machine — the signature is trust-on-first-use,
    /// not yet authenticated authorship; git commit signing is the anchor.
    Signed { signer: String, anchored: bool },
    /// No signature present — the last writer had no signing-capable identity.
    #[default]
    Unsigned,
}

// -- Murk (decrypted in-memory state) --
// The working representation after decryption. Commands read/modify this,
// then save_vault compares against the original to minimize re-encryption.

#[derive(Debug, Clone, Default)]
pub struct Murk {
    /// Decrypted shared values. Wrapped in `Zeroizing` so plaintext is cleared
    /// from memory when the `Murk` is dropped.
    pub values: HashMap<String, Zeroizing<String>>,
    /// Pubkey → display name (from meta).
    pub recipients: HashMap<String, String>,
    /// Private per-recipient values (the `me` tier): key → { pubkey → decrypted
    /// value }. Only contains entries decryptable by the current identity.
    pub private: HashMap<String, HashMap<String, Zeroizing<String>>>,
    /// Named-group values: key → { group name → decrypted value }.
    /// Only contains groups the current identity is a member of (and can decrypt).
    pub grouped: HashMap<String, HashMap<String, Zeroizing<String>>>,
    /// Group membership: group name → member pubkeys (carried from meta).
    pub groups: BTreeMap<String, Vec<String>>,
    /// Agent grants (carried from meta): grant name → metadata.
    pub grants: BTreeMap<String, GrantEntry>,
    /// True if the vault uses a legacy unkeyed MAC (sha256/sha256v2).
    pub legacy_mac: bool,
    /// Pinned GitHub key fingerprints (carried from meta).
    pub github_pins: HashMap<String, Vec<String>>,
    /// Registered Ed25519 verifying keys (carried from meta): recipient pubkey →
    /// base64 verifying key. `save_vault` carries these forward so every signer's
    /// key persists, then adds/refreshes the current signer's entry.
    pub signers: BTreeMap<String, String>,
    /// Whether the loaded vault carried a valid signature. `Unsigned` means
    /// integrity rests on git; the binary surfaces a warning.
    pub signature: SignatureState,
    /// True when this vault loaded signed on this machine before but is now
    /// unsigned — a stripped signature, or a merge result not yet re-signed. Set
    /// from the signer-pin continuity check; the CLI warns distinctly, `verify`
    /// fails, and `MURK_STRICT` refuses the load.
    pub signature_downgraded: bool,
}
