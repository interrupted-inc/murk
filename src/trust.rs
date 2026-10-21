// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether this machine trusts a loaded vault.
//!
//! A valid signature only proves that *some* recipient listed in the file
//! signed it, and the file chooses its own recipients and, for age keys, the
//! verifying key each recipient signs with (the signer registry). So
//! acceptance is anchored in state the repo cannot touch: the local trust pin
//! ([`crate::pins`]) or the `MURK_TRUSTED_SIGNERS` environment variable. The
//! rules, applied on every keyed load before any secret is handed out or
//! re-encrypted:
//!
//! 1. An unsigned vault is refused when the loading key could sign it. Only a
//!    key that cannot sign (ssh-rsa, hardware/plugin) loads it, with a warning.
//! 2. A vault this machine accepted signed that is now unsigned is refused.
//! 3. The signer must be a trusted signer: in `MURK_TRUSTED_SIGNERS` when set,
//!    otherwise in the pin's set (the non-grant recipients of the last vault
//!    accepted here). With neither, the vault is refused until `murk trust`.
//! 4. An age signer's verifying key (from the registry) must be the one pinned
//!    for it, or the one `MURK_TRUSTED_SIGNERS` gives. A trusted signer with no
//!    pinned key yet (a teammate's first write) is refused until `murk trust`
//!    confirms the key: trust on first use. A different key for a pinned
//!    signer is refused outright — an age key's verifying key is derived from
//!    its secret, so it cannot legitimately change. ssh-ed25519 signers carry
//!    their verifying key in the recipient string.
//! 5. An agent-grant key never counts as a signer, and a key seen as a grant
//!    that now sits in the recipients without its grant is refused.
//! 6. The vault id must match the pinned one, and the save counter must not be
//!    below the highest accepted ("rolled back"). A murk ≤ 0.13 signature on a
//!    vault this machine has seen in 0.14 form is a rollback.
//! 7. A group membership change must be signed by a member of that group as
//!    pinned (removing a member who left the vault entirely is exempt).
//! 8. A key an accepted vault removed stays removed: a vault signed by it, or
//!    listing it at the generation it was removed at or below, is refused. A
//!    newer vault from a trusted signer that lists it again, or `murk trust
//!    --re-add`, brings it back.
//! 9. The generation may rise at most [`MAX_GENERATION_STEP`] above the mark
//!    and never past [`MAX_GENERATION`]; a different vault with the counter
//!    this machine accepted on the branch is a fork.
//!
//! An accepted vault that is the newest this machine has seen, on a checked-
//! out branch, replaces the pin's trusted set, grants and groups with its
//! own, and raises the counter; any other accepted load is history and only
//! narrows the pin (see [`Acceptance`]). Its registry entries for trusted
//! recipients are pinned where no key was pinned before — believed because the
//! vault carrying them was signed by an already-trusted signer (or confirmed by
//! `murk trust`), and only while that signer stays trusted. A pinned key is
//! never replaced. `murk trust` accepts a refused vault on the user's say-so
//! after showing what changed.

use std::collections::{BTreeMap, BTreeSet};

pub use crate::git::HeadState;
use crate::pins::{self, TrustPin};
use crate::recipients::canonical_recipient;
use crate::types;

/// Environment variable naming the keys trusted to sign, comma or newline
/// separated. When set it replaces the pin's trusted set (for CI runners and
/// other machines without a pin). Grant keys listed here still never count.
/// See [`parse_trusted_signer`] for the entry format.
pub const TRUSTED_SIGNERS_VAR: &str = "MURK_TRUSTED_SIGNERS";

/// The largest generation accepted: 2^53 − 1, the largest integer every JSON
/// reader holds exactly. A vault above it is refused as tampering, so no
/// signer can push the counter to where it stops increasing.
pub const MAX_GENERATION: u64 = (1 << 53) - 1;

/// How far above this machine's mark a loaded vault's generation may be.
/// Every save adds one and a merge one past its sides, so a team needs a
/// million saves between two loads here to reach it; a vault that jumps
/// further is refused until `murk trust`.
pub const MAX_GENERATION_STEP: u64 = 1_000_000;

/// Trusted signers supplied from outside the vault and the pin: canonical
/// recipient → the verifying key its signatures must verify under (`None` for
/// ssh-ed25519, whose recipient string is its verifying key).
pub type TrustedSigners = BTreeMap<String, Option<String>>;

/// Group name → member pubkeys, as stored in the meta.
pub type Groups = BTreeMap<String, Vec<String>>;

/// The parts of a decrypted vault the trust rules look at.
pub struct Loaded<'a> {
    pub vault: &'a types::Vault,
    pub signature: &'a types::SignatureState,
    /// For an age signature, the registry verifying key it verified against.
    /// `None` for ssh-ed25519 signers and unsigned vaults.
    pub signer_vk: Option<&'a str>,
    /// The signer registry (age pubkey → verifying key) carried in the meta.
    /// Written by the vault's author: its entries are pinned only once the
    /// vault is accepted, and never replace a pinned key.
    pub registry: &'a BTreeMap<String, String>,
    /// Pubkey → display name (attacker-chosen: always shown next to the key).
    pub names: &'a std::collections::HashMap<String, String>,
    pub groups: &'a BTreeMap<String, Vec<String>>,
    pub grants: &'a BTreeMap<String, types::GrantEntry>,
    /// Whether the loading identity can sign (age or ssh-ed25519).
    pub loader_can_sign: bool,
    /// The loading key, when it is known to be an operator and so can never be
    /// an agent grant: an ssh or plugin identity (grants are minted age keys).
    pub operator_key: Option<String>,
}

/// Why a vault was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Signed, but this machine has no trust decision for the vault yet.
    NotYetTrusted { signer: String },
    /// Signed by a key outside the trusted set.
    UntrustedSigner { signer: String },
    /// Signed by a key this machine has seen as an agent grant.
    GrantSigner { signer: String },
    /// A key seen as an agent grant is a recipient again without its grant.
    GrantWithoutRecord { key: String },
    /// No signature, and the loading key could have signed it.
    Unsigned,
    /// No signature, but a signed version was accepted here before.
    Downgraded,
    /// The save counter is below the highest accepted here.
    RolledBack { pinned: u64, found: u64 },
    /// The vault id differs from the pinned one.
    OtherVault { pinned: String, found: String },
    /// A group's membership was changed by someone who was not a member.
    GroupChange { group: String, signer: String },
    /// An age signature by a trusted signer whose verifying key this machine
    /// has not confirmed yet.
    UnconfirmedSignerKey { signer: String, vk: String },
    /// An age signature whose verifying key differs from the one pinned (or
    /// given in `MURK_TRUSTED_SIGNERS`) for its signer.
    SignerKeyChanged { signer: String },
    /// An agent grant record names a key that is an operator: a signer this
    /// machine trusts (or trusted), or a key with a signing-key registry
    /// entry. Grants get freshly minted keys, so this is tampering — and
    /// recording it would mark the operator as a grant here.
    GrantBindsOperator { grant: String, key: String },
    /// The vault is signed by, or lists, a key an accepted vault removed
    /// (`removed_at`), and is not a newer revision re-adding it: `found` is at
    /// or below `removed_at`, or the removed key signed it. `murk trust`
    /// accepts it only with `--re-add` naming the key.
    RemovedKey {
        key: String,
        removed_at: u64,
        found: u64,
        signer: bool,
    },
    /// A different vault with the generation this machine accepted on the
    /// branch (or outside git): the branch was rewritten, or another save
    /// with the same counter replaced the accepted one.
    Forked { generation: u64 },
    /// The generation is more than [`MAX_GENERATION_STEP`] above the mark.
    GenerationJump { pinned: u64, found: u64 },
    /// The generation is above [`MAX_GENERATION`].
    GenerationOutOfRange { found: u64 },
}

impl Refusal {
    /// Whether `murk trust` may accept this refusal. Grant-signed vaults never
    /// are: an agent grant is read-only by design. Nor is a changed verifying
    /// key: an age key's verifying key is derived from its secret, so a
    /// different one for the same recipient is a forgery. Nor a grant bound
    /// to an operator key, which is tampering, nor a generation past
    /// [`MAX_GENERATION`]. A removed key is accepted only when named (see
    /// [`Refusal::RemovedKey`]).
    pub fn acceptable(&self) -> bool {
        !matches!(
            self,
            Refusal::GrantSigner { .. }
                | Refusal::GrantWithoutRecord { .. }
                | Refusal::SignerKeyChanged { .. }
                | Refusal::GrantBindsOperator { .. }
                | Refusal::GenerationOutOfRange { .. }
        )
    }
}

/// The outcome of checking a loaded vault against this machine's trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Signed by a trusted signer and consistent with the pin.
    Trusted,
    /// Unsigned, loaded by a key that cannot sign: allowed with a warning.
    UnsignedAllowed,
    Refused(Refusal),
}

/// A verdict plus what it was computed against.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub verdict: Verdict,
    /// The pin as read (`None` when absent or pinning is unavailable).
    pub pin: Option<TrustPin>,
    /// Trusted signers from the environment, when set.
    pub env_signers: Option<TrustedSigners>,
    /// The signer set the verdict used in place of the pin's (environment
    /// and anchor together), when either was given.
    pub external: Option<TrustedSigners>,
}

impl Assessment {
    /// The ssh-ed25519 keys (canonical `ssh-ed25519 <blob>` form) this
    /// assessment treats as trusted signers of the vault: the environment and
    /// anchor set when there is one, otherwise the pin's trusted set, minus
    /// every agent-grant key (`grants` are the vault's own; the pin knows the
    /// ones seen before). Empty when nothing is trusted yet. Only these keys
    /// can sign a git commit, so this is the set a commit's signer is judged
    /// against.
    pub fn trusted_ssh_signers(&self, grants: &BTreeMap<String, types::GrantEntry>) -> Vec<String> {
        let keys: Vec<&String> = match (&self.external, self.pin.as_ref().filter(|p| p.has_trust()))
        {
            (Some(external), _) => external.keys().collect(),
            (None, Some(pin)) => pin.trusted.iter().collect(),
            (None, None) => return Vec::new(),
        };
        let mut grant = grant_keys(grants);
        if let Some(pin) = &self.pin {
            grant.extend(pin.grants.iter().cloned());
        }
        keys.into_iter()
            .map(|k| canonical_recipient(k).into_owned())
            .filter(|k| k.starts_with("ssh-ed25519 ") && !grant.contains(k))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Parse one trusted-signer entry, the format `MURK_TRUSTED_SIGNERS` and a
/// grant key file's anchor use:
///
/// - an age signer is `age1…:<verifying key>`: the recipient, a colon, and the
///   base64 Ed25519 verifying key (`murk trust --print-key` prints this line);
/// - an ssh-ed25519 signer is its public key line (`ssh-ed25519 AAAA… [comment]`),
///   which is its own verifying key.
pub fn parse_trusted_signer(entry: &str) -> Result<(String, Option<String>), String> {
    let entry = entry.trim();
    let (key, vk) = match entry.rsplit_once(':') {
        Some((key, vk)) if !key.starts_with("ssh-") => (key.trim(), Some(vk.trim())),
        _ => (entry, None),
    };
    if crate::crypto::parse_recipient(key).is_err() {
        return Err(format!("not a public key: {}", crate::truncate_pubkey(key)));
    }
    let is_ssh = key.starts_with("ssh-");
    if is_ssh && !key.starts_with("ssh-ed25519 ") {
        return Err(format!(
            "{} cannot sign, so it cannot be a trusted signer",
            crate::truncate_pubkey(key)
        ));
    }
    match vk {
        Some(vk) if crate::signing::is_verifying_key(vk) => {
            Ok((canonical_recipient(key).into_owned(), Some(vk.to_string())))
        }
        Some(_) => Err(format!(
            "not a verifying key after {}:",
            crate::truncate_pubkey(key)
        )),
        None if is_ssh => Ok((canonical_recipient(key).into_owned(), None)),
        None => Err(format!(
            "{} needs its verifying key: write it as `age1…:<verifying key>` (`murk trust --print-key` prints it)",
            crate::truncate_pubkey(key)
        )),
    }
}

/// Parse `MURK_TRUSTED_SIGNERS`. `Ok(None)` when unset or empty; an invalid
/// entry is an error (fail closed rather than trust less than the operator
/// meant and confuse them, or more than they meant).
pub fn env_trusted_signers() -> Result<Option<TrustedSigners>, String> {
    let Ok(raw) = std::env::var(TRUSTED_SIGNERS_VAR) else {
        return Ok(None);
    };
    let mut out = TrustedSigners::new();
    for entry in raw
        .split([',', '\n'])
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (key, vk) =
            parse_trusted_signer(entry).map_err(|e| format!("{TRUSTED_SIGNERS_VAR}: {e}"))?;
        out.insert(key, vk);
    }
    Ok((!out.is_empty()).then_some(out))
}

/// Canonical keys of the grants in `grants`.
fn grant_keys(grants: &BTreeMap<String, types::GrantEntry>) -> BTreeSet<String> {
    grants
        .values()
        .map(|g| canonical_recipient(&g.pubkey).into_owned())
        .collect()
}

/// One trusted-signer entry in the [`parse_trusted_signer`] format: the
/// ssh-ed25519 key line, or `age1…:<verifying key>`.
pub fn format_trusted_signer(recipient: &str, vk: Option<&str>) -> String {
    match vk {
        Some(vk) if !recipient.starts_with("ssh-") => format!("{recipient}:{vk}"),
        _ => recipient.to_string(),
    }
}

/// The signers this machine's pin trusts for `vault_path`, with their pinned
/// verifying keys — what an anchor written on this machine (a grant key file)
/// should carry. An age signer with no confirmed key yet is left out: nothing
/// here could check its signatures.
pub fn pinned_trusted_signers(vault_path: &str) -> Result<TrustedSigners, String> {
    let Some(pin) = pins::read(vault_path)?.filter(TrustPin::has_trust) else {
        return Ok(TrustedSigners::new());
    };
    Ok(pin
        .trusted
        .iter()
        .filter(|k| !pin.grants.contains(*k))
        .filter_map(|k| {
            if k.starts_with("ssh-ed25519 ") {
                Some((k.clone(), None))
            } else {
                pin.pinned_key(k).map(|vk| (k.clone(), Some(vk.clone())))
            }
        })
        .collect())
}

/// A short fingerprint of a signed vault — the SHA-256 of its signature, as
/// hex — that tells two vaults with the same generation apart. Empty for an
/// unsigned vault or one with a murk ≤ 0.13 signature in its meta.
pub fn vault_fingerprint(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};
    let Some(sig) = &vault.sig else {
        return String::new();
    };
    Sha256::digest(sig.sig.as_bytes())
        .iter()
        .take(16)
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The removed keys (canonical, with the generation each was removed at)
/// that `loaded` is signed by or lists, whatever its generation. `murk
/// trust` re-trusts a vault carrying any of them only when the user names
/// each one.
pub fn removed_keys_in(loaded: &Loaded<'_>, pin: Option<&TrustPin>) -> BTreeMap<String, u64> {
    let Some(pin) = pin.filter(|p| p.v >= pins::PIN_VERSION) else {
        return BTreeMap::new();
    };
    let signer = match loaded.signature {
        types::SignatureState::Signed { signer, .. } => Some(signer.as_str()),
        types::SignatureState::Unsigned => None,
    };
    loaded
        .vault
        .recipients
        .iter()
        .map(String::as_str)
        .chain(signer)
        .filter_map(|k| {
            let k = canonical_recipient(k).into_owned();
            pin.removed.get(&k).map(|&at| (k, at))
        })
        .collect()
}

/// Rule 8 for a load: the vault is signed by a removed key, or lists one at
/// or below the generation it was removed at. A newer vault listing it again
/// is how a trusted signer re-adds someone, so it passes (its signer is
/// checked like any other).
fn removal_refusal(loaded: &Loaded<'_>, pin: Option<&TrustPin>) -> Option<Refusal> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = loaded.vault.generation;
    if let types::SignatureState::Signed { signer, .. } = loaded.signature
        && let Some(&removed_at) = pin.removed.get(canonical_recipient(signer).as_ref())
    {
        return Some(Refusal::RemovedKey {
            key: signer.clone(),
            removed_at,
            found,
            signer: true,
        });
    }
    loaded.vault.recipients.iter().find_map(|r| {
        let removed_at = *pin.removed.get(canonical_recipient(r).as_ref())?;
        (found <= removed_at).then(|| Refusal::RemovedKey {
            key: r.clone(),
            removed_at,
            found,
            signer: false,
        })
    })
}

/// Rule 9 for a load: a generation more than [`MAX_GENERATION_STEP`] above
/// the mark, or a different vault with the generation accepted on this
/// branch (outside git: overall). A detached HEAD has no mark to fork from.
fn counter_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    head: &HeadState,
) -> Option<Refusal> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = loaded.vault.generation;
    if pin.generation > 0 && found > pin.generation.saturating_add(MAX_GENERATION_STEP) {
        return Some(Refusal::GenerationJump {
            pinned: pin.generation,
            found,
        });
    }
    let fingerprint = vault_fingerprint(loaded.vault);
    let (mark, seen) = match head {
        HeadState::Branch(b) => (pin.branches.get(b).copied(), pin.branch_heads.get(b)),
        HeadState::NotARepo => (Some(pin.generation), Some(&pin.head)),
        HeadState::Detached => (None, None),
    };
    let forked = mark == Some(found)
        && !fingerprint.is_empty()
        && seen.is_some_and(|s| !s.is_empty() && *s != fingerprint);
    forked.then_some(Refusal::Forked { generation: found })
}

/// The verdict for a load of the working vault: the core rules, then the
/// removal and counter rules. A refusal `murk trust` can never accept comes
/// first; a removed key next, so a vault that is also refused for another
/// reason still needs the key named.
fn load_verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    head: &HeadState,
) -> Verdict {
    let core = verdict(loaded, pin, external_signers, head);
    if let Verdict::Refused(r) = &core
        && !r.acceptable()
    {
        return core;
    }
    if let Some(refusal) = removal_refusal(loaded, pin) {
        return Verdict::Refused(refusal);
    }
    if matches!(core, Verdict::Refused(_)) {
        return core;
    }
    match counter_refusal(loaded, pin, head) {
        Some(refusal) => Verdict::Refused(refusal),
        None => core,
    }
}

/// Verify `vault`'s signature against `anchor` alone, for a loader that
/// cannot read the meta (an agent grant): the top-level (view 2) signature
/// must be by a signer in `anchor` and verify under the anchor's key for it.
/// Nothing inside the vault — the signer registry in particular — is read.
/// Returns the signer.
pub fn verify_anchored(vault: &types::Vault, anchor: &TrustedSigners) -> Result<String, Refusal> {
    let Some(sig) = &vault.sig else {
        return Err(Refusal::Unsigned);
    };
    let signer = canonical_recipient(&sig.signer).into_owned();
    let Some(expected) = anchor.get(&signer) else {
        return Err(Refusal::UntrustedSigner {
            signer: sig.signer.clone(),
        });
    };
    let registry = expected
        .as_ref()
        .map(|vk| BTreeMap::from([(signer.clone(), vk.clone())]))
        .unwrap_or_default();
    let verified = sig.v == crate::signature::SIGNED_VIEW_VERSION
        && crate::signature::verify_vault_signature(
            vault,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &std::collections::HashMap::new(),
            &registry,
            sig,
        )
        .is_some();
    if verified {
        Ok(signer)
    } else {
        Err(Refusal::SignerKeyChanged {
            signer: sig.signer.clone(),
        })
    }
}

/// Canonical non-grant recipients of a vault: who may sign its next version.
pub fn signers_of(
    vault: &types::Vault,
    grants: &BTreeMap<String, types::GrantEntry>,
) -> BTreeSet<String> {
    let grants = grant_keys(grants);
    vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .filter(|r| !grants.contains(r))
        .collect()
}

/// `groups` with every member key in canonical spelling.
pub fn canonical_groups(groups: &Groups) -> BTreeMap<String, BTreeSet<String>> {
    groups
        .iter()
        .map(|(g, members)| {
            (
                g.clone(),
                members
                    .iter()
                    .map(|m| canonical_recipient(m).into_owned())
                    .collect(),
            )
        })
        .collect()
}

/// Check `loaded` against the pin for `vault_path` and the environment.
///
/// `anchor` is a trusted-signer set supplied from outside the vault and the
/// pin (an agent grant's key file). When it or `MURK_TRUSTED_SIGNERS` is
/// given, their union is the trusted set and the pin's set is ignored; the
/// pin still supplies the rollback, vault-id and downgrade checks.
///
/// `readmit` names removed keys (canonical) the user is re-adding with
/// `murk trust --re-add`: they are judged as if never removed.
pub fn assess(
    vault_path: &str,
    loaded: &Loaded<'_>,
    anchor: Option<&TrustedSigners>,
    readmit: &BTreeSet<String>,
) -> Result<Assessment, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let external: Option<TrustedSigners> = match (anchor, &env_signers) {
        (None, None) => None,
        (a, e) => Some(
            a.into_iter()
                .chain(e.iter())
                .flatten()
                .map(|(k, vk)| (canonical_recipient(k).into_owned(), vk.clone()))
                .collect(),
        ),
    };
    let head = head_of(vault_path);
    let judged = pin.clone().map(|mut p| {
        p.removed.retain(|k, _| !readmit.contains(k));
        p
    });
    let verdict = load_verdict(loaded, judged.as_ref(), external.as_ref(), &head);
    Ok(Assessment {
        verdict,
        pin,
        env_signers,
        external,
    })
}

/// The verdict for `loaded` against `pin` as it is now (re-read under the
/// pin lock), with the external signers `assessment` was computed with. Used
/// to confirm an acceptance just before it is recorded: another process may
/// have raised the rollback mark or learned keys since the first read.
pub fn reassess(
    vault_path: &str,
    loaded: &Loaded<'_>,
    assessment: &Assessment,
    pin: Option<&TrustPin>,
) -> Verdict {
    load_verdict(
        loaded,
        pin,
        assessment.external.as_ref(),
        &head_of(vault_path),
    )
}

/// The git HEAD state of the checkout holding `vault_path`.
pub fn head_of(vault_path: &str) -> HeadState {
    let p = std::path::Path::new(vault_path);
    match std::env::current_dir() {
        Ok(cwd) if !p.is_absolute() => crate::git::head_state(&cwd.join(p)),
        _ => crate::git::head_state(p),
    }
}

/// Rule 4: an age signer's registry key must be the one pinned for it (or
/// given in the environment). `None` when it is, or the signer is ssh.
fn signer_key_refusal(
    loaded: &Loaded<'_>,
    signer: &str,
    external_signers: Option<&TrustedSigners>,
    trusted_pin: Option<&TrustPin>,
) -> Option<Refusal> {
    let vk = loaded.signer_vk?;
    let signer_c = canonical_recipient(signer).into_owned();
    let expected = match external_signers {
        Some(external) => external.get(&signer_c).cloned().flatten(),
        None => trusted_pin.and_then(|p| p.pinned_key(&signer_c).cloned()),
    };
    match expected {
        Some(expected) if expected == vk => None,
        Some(_) => Some(Refusal::SignerKeyChanged {
            signer: signer.to_string(),
        }),
        None => Some(Refusal::UnconfirmedSignerKey {
            signer: signer.to_string(),
            vk: vk.to_string(),
        }),
    }
}

/// Whether a grant record in `loaded` names an operator key: a signer this
/// machine trusts or ever trusted (on an operator's own machine, that includes
/// their own key), a signer named in `MURK_TRUSTED_SIGNERS` or an anchor, a
/// key with a signing-key registry entry (grants never sign), or the loading
/// key when it is known to be an operator. The first such grant is tampering.
fn grant_binding_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
) -> Option<Refusal> {
    let operator = loaded
        .operator_key
        .as_deref()
        .map(|k| canonical_recipient(k).into_owned());
    let registry: BTreeSet<String> = loaded
        .registry
        .keys()
        .map(|k| canonical_recipient(k).into_owned())
        .collect();
    loaded.grants.iter().find_map(|(name, grant)| {
        let key = canonical_recipient(&grant.pubkey).into_owned();
        let operator = operator.as_ref() == Some(&key)
            || registry.contains(&key)
            || external_signers.is_some_and(|e| e.contains_key(&key))
            || pin.is_some_and(|p| {
                !p.grants.contains(&key)
                    && (p.trusted.contains(&key) || p.ever_trusted.contains(&key))
            });
        operator.then(|| Refusal::GrantBindsOperator {
            grant: name.clone(),
            key,
        })
    })
}

/// Rule 5 for a signed vault: the signer is not a grant here or in the pin,
/// and no key the pin knows as a grant is back as a plain recipient. A pinned
/// grant entry never overrides signer trust this machine recorded.
fn grant_signer_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    signer: &str,
) -> Option<Refusal> {
    let signer_c = canonical_recipient(signer).into_owned();
    let current_grants = grant_keys(loaded.grants);
    let pinned_grants: BTreeSet<&String> = pin
        .map(|p| {
            p.grants
                .iter()
                .filter(|k| !p.trusted.contains(*k))
                .collect()
        })
        .unwrap_or_default();
    if current_grants.contains(&signer_c) || pinned_grants.contains(&signer_c) {
        return Some(Refusal::GrantSigner {
            signer: signer.to_string(),
        });
    }
    let recipients: BTreeSet<String> = loaded
        .vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    pinned_grants
        .into_iter()
        .find(|k| recipients.contains(*k) && !current_grants.contains(*k))
        .map(|key| Refusal::GrantWithoutRecord { key: key.clone() })
}

fn verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    head: &HeadState,
) -> Verdict {
    if loaded.vault.generation > MAX_GENERATION {
        return Verdict::Refused(Refusal::GenerationOutOfRange {
            found: loaded.vault.generation,
        });
    }
    if let Some(refusal) = grant_binding_refusal(loaded, pin, external_signers) {
        return Verdict::Refused(refusal);
    }
    let types::SignatureState::Signed { signer, v } = loaded.signature else {
        if pin.is_some_and(|p| p.was_signed) {
            return Verdict::Refused(Refusal::Downgraded);
        }
        // A key that cannot sign loads an unsigned vault with a warning —
        // unless the operator named the signers they require.
        if loaded.loader_can_sign || external_signers.is_some() {
            return Verdict::Refused(Refusal::Unsigned);
        }
        return Verdict::UnsignedAllowed;
    };
    let signer_c = canonical_recipient(signer).into_owned();
    let refuse = Verdict::Refused;

    if let Some(refusal) = grant_signer_refusal(loaded, pin, signer) {
        return refuse(refusal);
    }

    let trusted_pin = pin.filter(|p| p.has_trust());
    let is_trusted = match (external_signers, trusted_pin) {
        (Some(external), _) => external.contains_key(&signer_c),
        (None, Some(p)) => p.trusted.contains(&signer_c),
        (None, None) => {
            return refuse(Refusal::NotYetTrusted {
                signer: signer.clone(),
            });
        }
    };
    if !is_trusted {
        return refuse(Refusal::UntrustedSigner {
            signer: signer.clone(),
        });
    }

    if let Some(refusal) = signer_key_refusal(loaded, signer, external_signers, trusted_pin) {
        return refuse(refusal);
    }

    if let Some(p) = pin.filter(|p| p.v >= pins::PIN_VERSION) {
        // Once this machine has seen the vault written by murk 0.14 (an id or
        // a counter), a v1 signature can only be an older revision: v1 covers
        // neither field.
        if *v == crate::signature::LEGACY_SIGNED_VIEW_VERSION
            && (p.generation > 0 || !p.vault_id.is_empty())
        {
            return refuse(Refusal::RolledBack {
                pinned: p.generation,
                found: loaded.vault.generation,
            });
        }
        if !p.vault_id.is_empty() && loaded.vault.vault_id != p.vault_id {
            return refuse(Refusal::OtherVault {
                pinned: p.vault_id.clone(),
                found: loaded.vault.vault_id.clone(),
            });
        }
        // Rollback is judged per branch: checking out an older branch is
        // normal, a branch going backwards is not. A detached HEAD (rebase,
        // bisect, CI checkout of a commit) and a branch never seen here have
        // no high-water mark to compare with.
        let high = match head {
            HeadState::NotARepo => Some(p.generation),
            HeadState::Branch(b) => p.branches.get(b).copied(),
            HeadState::Detached => None,
        };
        if let Some(high) = high
            && loaded.vault.generation < high
        {
            return refuse(Refusal::RolledBack {
                pinned: high,
                found: loaded.vault.generation,
            });
        }
        if p.has_trust()
            && let Some(group) = unauthorised_group_change(loaded, p, &signer_c)
        {
            return refuse(Refusal::GroupChange {
                group,
                signer: signer.clone(),
            });
        }
    }
    Verdict::Trusted
}

/// Check one side of a merge (ours or theirs) before its content is merged
/// and re-signed. The same rules as a load, except that the counter is
/// compared with the common ancestor rather than the pin (merging an older
/// branch is normal), and group changes are judged against the ancestor's
/// membership. `changed` says whether the side differs from the ancestor.
/// `upgraded` says whether the merge has a side written by murk 0.14 (one
/// with a vault id or a counter).
///
/// A side written by murk 0.13 carries no authenticated identity or order,
/// so its content cannot be checked for rollback or for being another vault.
/// Once this vault has 0.14 state — in the pin, or on the other side — such
/// a side may only stand for history it shares with the ancestor: if it
/// changed anything it is refused, rather than letting an old signed
/// revision (or another 0.13 vault of the team) override newer content.
/// Returns the reason a side is refused.
pub fn check_merge_side(
    vault_path: &str,
    side: &Loaded<'_>,
    base: Option<(&types::Vault, Option<&Groups>)>,
    changed: bool,
    upgraded: bool,
) -> Result<(), String> {
    let pin = pins::read(vault_path)?;
    let legacy = side.vault.vault_id.is_empty() || side.vault.generation == 0;
    let pinned_id = pin
        .as_ref()
        .filter(|p| p.v >= pins::PIN_VERSION && !p.vault_id.is_empty())
        .map(|p| p.vault_id.as_str());
    let pin_upgraded = pinned_id.is_some()
        || pin
            .as_ref()
            .is_some_and(|p| p.v >= pins::PIN_VERSION && p.generation > 0);
    // With a pinned vault id, only the ancestor may be pre-0.14 history: a
    // side without an id or counter is never merged. Without one, a 0.13 side
    // that changed the vault is refused once the other side is 0.14.
    if legacy && (pin_upgraded || (changed && upgraded)) {
        return Err(
            "rolled back: it is a murk 0.13 revision (no vault id or counter), and this vault has since been saved by murk 0.14, so it cannot be checked for rollback or for being another vault — apply its intended change with murk after merging"
                .into(),
        );
    }
    if let Some(id) = pinned_id
        && side.vault.vault_id != id
    {
        return Err(format!(
            "it is a different vault (id {}, this machine pinned {id})",
            crate::validate::show(&side.vault.vault_id)
        ));
    }
    if let Some(refusal) = merge_side_counter_or_removal(side, base.map(|(b, _)| b), pin.as_ref()) {
        return Err(refusal);
    }
    let env_signers = env_trusted_signers()?;
    let side_pin = pin.map(|mut p| {
        p.generation = 0;
        p.branches.clear();
        if let Some((base, groups)) = base {
            if let Some(groups) = groups {
                p.groups = canonical_groups(groups);
            }
            // A side that forked before the vault got its id (murk 0.13) and
            // changed nothing is the ancestor's state, not another vault.
            if side.vault.vault_id.is_empty() && base.vault_id.is_empty() {
                p.vault_id.clear();
            }
        }
        p
    });
    match verdict(
        side,
        side_pin.as_ref(),
        env_signers.as_ref(),
        &HeadState::Detached,
    ) {
        Verdict::Trusted | Verdict::UnsignedAllowed => {}
        Verdict::Refused(r) => {
            let msg = refusal_message(vault_path, &r, side, side_pin.as_ref());
            return Err(msg.lines().next().unwrap_or_default().to_string());
        }
    }
    if let Some((base, _)) = base
        && changed
        && base.generation > 0
        && side.vault.generation <= base.generation
    {
        return Err(format!(
            "rolled back: it changed the vault but its generation {} is not above the common ancestor's {}",
            side.vault.generation, base.generation
        ));
    }
    Ok(())
}

/// Rules 8 and 9 for a merge side. A side signed by a removed key is refused.
/// The counter may be at most [`MAX_GENERATION_STEP`] above both the mark and
/// the ancestor; unlike a load it may be below the mark, since a merged branch
/// is legitimately older.
fn merge_side_counter_or_removal(
    side: &Loaded<'_>,
    base: Option<&types::Vault>,
    pin: Option<&TrustPin>,
) -> Option<String> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = side.vault.generation;
    if let types::SignatureState::Signed { signer, .. } = side.signature
        && let Some(at) = pin.removed.get(canonical_recipient(signer).as_ref())
    {
        return Some(format!(
            "rolled back: it is signed by {}, who was removed from this vault at generation {at} on this machine",
            label(side.names, signer)
        ));
    }
    let mark = pin.generation.max(base.map_or(0, |b| b.generation));
    (mark > 0 && found > mark.saturating_add(MAX_GENERATION_STEP)).then(|| {
        format!(
            "its generation {found} jumps more than {MAX_GENERATION_STEP} past {mark}, the highest this machine accepted or the common ancestor's"
        )
    })
}

/// The first group whose membership changed relative to the pin without the
/// signer being entitled to change it, if any.
fn unauthorised_group_change(loaded: &Loaded<'_>, pin: &TrustPin, signer: &str) -> Option<String> {
    group_change_violation(&loaded.vault.recipients, loaded.groups, &pin.groups, signer)
}

/// The first group in `after` (membership with `recipients` as the vault's
/// recipients) that differs from `before` in a way `signer` may not make:
/// adding or removing a member of a group they are not in, creating a group
/// they are not in, or deleting a group with members left that they are not
/// in. Removing a member who left the vault entirely is allowed, because
/// `circle revoke` does that and any recipient may revoke.
pub fn group_change_violation(
    recipients: &[String],
    after: &Groups,
    before: &BTreeMap<String, BTreeSet<String>>,
    signer: &str,
) -> Option<String> {
    let signer = canonical_recipient(signer).into_owned();
    let recipients: BTreeSet<String> = recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    let current = canonical_groups(after);
    for (group, members) in &current {
        let Some(was) = before.get(group) else {
            // A new group: its creator must be in it (the CLI requires that).
            if !members.contains(&signer) {
                return Some(group.clone());
            }
            continue;
        };
        let added = members.difference(was).next().is_some();
        let removed = was.difference(members).any(|m| recipients.contains(m));
        if (added || removed) && !was.contains(&signer) {
            return Some(group.clone());
        }
    }
    for (group, was) in before {
        if !current.contains_key(group) {
            let remaining = was.intersection(&recipients).next().is_some();
            if remaining && !was.contains(&signer) {
                return Some(group.clone());
            }
        }
    }
    None
}

/// How an accepted vault came to be accepted, which decides what it may
/// change in the pin.
#[derive(Debug, Clone, Copy)]
pub enum Acceptance<'a> {
    /// A load the trust rules accepted. It is the vault's current state, and
    /// replaces the trusted set, groups and registry, only when it is newer
    /// than everything this machine accepted and checked out on a branch (or
    /// outside git). Any other accepted load — a detached HEAD, a branch
    /// behind the mark, the vault already accepted, or a different vault with
    /// that counter — is history: it only narrows the pin (marks, grants seen,
    /// the signed bit), so reading history never adds trust.
    Load,
    /// The user's decision: `murk trust`, or `murk init` creating the vault.
    /// `reset_counter` lowers this branch's mark to the vault's counter (a
    /// rollback or fork accepted on purpose). `readmit` names the removed
    /// keys (canonical) the user re-adds with `--re-add`; any other removed
    /// key stays removed.
    Trust {
        reset_counter: bool,
        readmit: &'a BTreeSet<String>,
    },
    /// This machine's own signed save of a vault that listed `before`
    /// (canonical recipients; `None` for a new file). It changes the trusted
    /// set only by what the save itself added or removed, so saving over a
    /// vault read as history does not trust the keys it carried.
    OwnSave {
        before: Option<&'a BTreeSet<String>>,
    },
}

/// The pin to store once `loaded` is accepted (see [`Acceptance`]) while
/// `head` is checked out. Keeps the higher counters unless `reset_counter`.
///
/// A key the trusted set loses is recorded in `removed` with the vault's
/// generation — when the vault is this branch's next accepted state (a
/// branch seen here before, or outside git), the user's decision, or this
/// machine's own save — and leaves it only when a newer accepted vault lists
/// it again, or the user re-adds it. A registry entry for a recipient with
/// no pinned key is pinned on the signer's word and recorded in `added_by`;
/// when that signer leaves the trusted set the entry is dropped (see SPEC,
/// Trust: "independently confirmed").
pub fn accepted_pin(
    loaded: &Loaded<'_>,
    prior: Option<&TrustPin>,
    how: Acceptance<'_>,
    head: &HeadState,
) -> TrustPin {
    let prior_v2 = prior.filter(|p| p.v >= pins::PIN_VERSION);
    let had_trust = prior_v2.is_some_and(TrustPin::has_trust);
    let reset_counter = matches!(
        how,
        Acceptance::Trust {
            reset_counter: true,
            ..
        }
    );
    let found = loaded.vault.generation;
    // Generation 0 is murk ≤ 0.13: no order, so every such load is current.
    let current = match how {
        Acceptance::Load => prior_v2.filter(|p| p.has_trust()).is_none_or(|p| {
            *head != HeadState::Detached
                && (found > p.generation || (found == 0 && p.generation == 0))
        }),
        Acceptance::Trust { .. } | Acceptance::OwnSave { .. } => true,
    };
    let branch_seen = match head {
        HeadState::Branch(b) => prior_v2.is_some_and(|p| p.branches.contains_key(b)),
        _ => false,
    };

    let mut pin = prior_v2.cloned().unwrap_or_default();
    pin.v = pins::PIN_VERSION;
    // A key this machine trusts (or trusted) as a signer is never recorded as
    // a grant: that would lock its owner out here for good.
    let new_grants: Vec<String> = grant_keys(loaded.grants)
        .into_iter()
        .filter(|k| !pin.trusted.contains(k) && !pin.ever_trusted.contains(k))
        .collect();
    pin.grants.extend(new_grants);
    advance_marks(&mut pin, loaded.vault, current, reset_counter, head);

    let prior_id = std::mem::take(&mut pin.vault_id);
    pin.vault_id = if loaded.vault.vault_id.is_empty() {
        prior_id.clone()
    } else {
        loaded.vault.vault_id.clone()
    };
    // Removals belong to one vault: another vault's counters do not compare.
    let other_vault = !prior_id.is_empty() && prior_id != pin.vault_id;
    if other_vault {
        pin.removed.clear();
    }

    let dropped = replace_trusted(&mut pin, loaded.vault, how, had_trust, current);
    // A load on a branch never seen here may be a stale branch numbered past
    // the mark: what it lacks is not recorded as removed.
    let record_removals = !other_vault
        && match how {
            Acceptance::Load => current && (*head == HeadState::NotARepo || branch_seen),
            Acceptance::Trust { .. } | Acceptance::OwnSave { .. } => true,
        };
    if record_removals {
        for k in dropped {
            let at = pin.removed.entry(k).or_insert(found);
            *at = (*at).max(found);
        }
    }
    // Who comes back: a newer accepted vault listing the key (its signer was
    // trusted, or this load is history and changes nothing), the user naming
    // it, or this machine's own save adding it.
    let trusted = std::mem::take(&mut pin.trusted);
    match how {
        Acceptance::Load if current => pin
            .removed
            .retain(|k, at| !(trusted.contains(k) && found > *at)),
        Acceptance::Load => {}
        Acceptance::Trust { readmit, .. } => pin.removed.retain(|k, _| !readmit.contains(k)),
        Acceptance::OwnSave { before } => pin
            .removed
            .retain(|k, _| !(trusted.contains(k) && before.is_none_or(|b| !b.contains(k)))),
    }
    pin.trusted = trusted;
    let removed = pin.removed.clone();
    pin.trusted.retain(|k| !removed.contains_key(k));

    pin_signing_keys(&mut pin, loaded, current);
    if current {
        pin.groups = canonical_groups(loaded.groups);
    }
    let trusted = pin.trusted.clone();
    pin.ever_trusted.extend(trusted);
    pin.was_signed = matches!(loaded.signature, types::SignatureState::Signed { .. })
        || prior.is_some_and(|p| p.was_signed);
    pin
}

/// Raise the counters for an accepted `vault`: the overall mark (and the
/// fingerprint of the vault at it) only for a current acceptance, the
/// branch's mark for any. `reset_counter` lowers them to the vault's.
fn advance_marks(
    pin: &mut TrustPin,
    vault: &types::Vault,
    current: bool,
    reset_counter: bool,
    head: &HeadState,
) {
    let found = vault.generation;
    let fingerprint = vault_fingerprint(vault);
    if current
        && (found > pin.generation
            || (reset_counter && (*head == HeadState::NotARepo || found == pin.generation)))
    {
        pin.generation = found;
        pin.head.clone_from(&fingerprint);
    }
    if let HeadState::Branch(b) = head {
        let old = pin.branches.get(b).copied();
        let mark = match old {
            Some(m) if !reset_counter => m.max(found),
            _ => found,
        };
        pin.branches.insert(b.clone(), mark);
        if reset_counter || old.is_none_or(|m| found > m) {
            pin.branch_heads.insert(b.clone(), fingerprint);
        }
    }
}

/// Set the pin's trusted set for an accepted `vault` and return the keys it
/// lost. A first decision, or a current acceptance, takes the vault's non-
/// grant recipients; history leaves the set alone; an own save applies only
/// what it added and removed relative to the file it replaced. Where a grant
/// record names a key this machine trusts as a signer, that key stays a
/// signer.
fn replace_trusted(
    pin: &mut TrustPin,
    vault: &types::Vault,
    how: Acceptance<'_>,
    had_trust: bool,
    current: bool,
) -> BTreeSet<String> {
    let recipients: BTreeSet<String> = vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    let vault_signers: BTreeSet<String> = recipients
        .iter()
        .filter(|r| !pin.grants.contains(*r))
        .cloned()
        .collect();
    if !had_trust {
        pin.trusted = vault_signers;
        return BTreeSet::new();
    }
    match how {
        Acceptance::Load if !current => BTreeSet::new(),
        Acceptance::OwnSave {
            before: Some(before),
        } => {
            let dropped: BTreeSet<String> = pin
                .trusted
                .iter()
                .filter(|k| before.contains(*k) && !recipients.contains(*k))
                .cloned()
                .collect();
            let grants = &pin.grants;
            pin.trusted
                .retain(|k| !dropped.contains(k) && !grants.contains(k));
            pin.trusted
                .extend(vault_signers.into_iter().filter(|k| !before.contains(k)));
            dropped
        }
        _ => {
            let dropped = pin.trusted.difference(&vault_signers).cloned().collect();
            pin.trusted = vault_signers;
            dropped
        }
    }
}

/// Update the verifying keys for an accepted vault. An entry pinned on a
/// signer's word (`added_by`) goes when that signer is no longer trusted, so
/// a key they bound to a teammate's name stops counting. A current acceptance
/// then pins the signer's own key and the registry entries of the vault's
/// trusted recipients where none is pinned — believed because the vault
/// carrying them is accepted, and recorded as added by the signer. A pinned
/// key is never replaced, and is kept after its owner is revoked so their old
/// revisions still verify.
fn pin_signing_keys(pin: &mut TrustPin, loaded: &Loaded<'_>, current: bool) {
    let TrustPin {
        trusted,
        signers,
        added_by,
        groups: pinned_groups,
        ..
    } = pin;
    // Dropped here for good: the vault that removes the adder may still carry
    // the entry (its writer vouched for it while the adder was trusted), and
    // that must not pin it again under a new name.
    let mut dropped = BTreeSet::new();
    added_by.retain(|pk, adder| {
        let stands = trusted.contains(adder);
        if !stands {
            signers.remove(pk);
            dropped.insert(pk.clone());
        }
        stands
    });
    let types::SignatureState::Signed { signer, .. } = loaded.signature else {
        return;
    };
    if !current {
        return;
    }
    let signer = canonical_recipient(signer).into_owned();
    if let Some(vk) = loaded.signer_vk
        && !dropped.contains(&signer)
    {
        signers
            .entry(signer.clone())
            .or_insert_with(|| vk.to_string());
    }
    // Binding another recipient's key lets the signer speak as them, so it
    // must not reach further than the signer could itself: an entry for a
    // member of a group (as pinned, or in this vault) is believed only from a
    // member of that group. Otherwise a trusted non-member could bind a
    // member's name to their own key, then sign as that member to change the
    // group.
    let groups = canonical_groups(loaded.groups);
    let may_bind = |pk: &str| {
        groups
            .values()
            .chain(pinned_groups.values())
            .all(|members| !members.contains(pk) || members.contains(&signer))
    };
    for (pk, vk) in loaded.registry {
        let pk = canonical_recipient(pk).into_owned();
        if !trusted.contains(&pk) || signers.contains_key(&pk) || dropped.contains(&pk) {
            continue;
        }
        if pk == signer {
            signers.insert(pk, vk.clone());
        } else if may_bind(&pk) {
            signers.insert(pk.clone(), vk.clone());
            added_by.insert(pk, signer.clone());
        }
    }
}

/// Check a historical revision of the vault (`murk diff` against a git ref,
/// the merge driver's common ancestor) without writing anything. Unlike a
/// load there is no rollback or group-change check — an older revision is
/// expected — and the signer must be one this machine *ever* trusted, so a
/// teammate revoked since still verifies for the revisions they signed. The
/// signer's key must still be the pinned one, and a grant key or a signer
/// never trusted is refused. The vault id must match, except that a revision
/// with none is pre-0.14 history: it predates the id (and the counter), so
/// neither its missing id nor its 0.13 signature makes it another vault or a
/// rollback.
pub fn assess_revision(vault_path: &str, revision: &Loaded<'_>) -> Result<Verdict, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let historical = pin.map(|mut p| {
        p.trusted = p.ever_trusted.clone();
        p.generation = 0;
        p.branches.clear();
        p.groups.clear();
        if revision.vault.vault_id.is_empty() {
            p.vault_id.clear();
        }
        // History predating the pin may be unsigned without that being a
        // downgrade of the revision itself.
        p.was_signed = false;
        p
    });
    let mut verdict = verdict(
        revision,
        historical.as_ref(),
        env_signers.as_ref(),
        &HeadState::Detached,
    );
    // Groups were cleared above, so a pinned group would read as "new" for
    // every revision; group authority is a property of the working vault.
    if let Verdict::Refused(Refusal::GroupChange { .. }) = verdict {
        verdict = Verdict::Trusted;
    }
    Ok(verdict)
}

/// Recipient-set changes of `loaded` against the pinned trusted set, as
/// `(added, removed)` canonical keys. With no pin, every recipient is "added".
pub fn recipient_changes(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
) -> (Vec<String>, Vec<String>) {
    let now = signers_of(loaded.vault, loaded.grants);
    let before = pin
        .filter(|p| p.has_trust())
        .map(|p| p.trusted.clone())
        .unwrap_or_default();
    (
        now.difference(&before).cloned().collect(),
        before.difference(&now).cloned().collect(),
    )
}

/// `name (age1abc…wxyz)` for a key, or just the truncated key. The name is
/// chosen by whoever wrote the vault, so the key is always shown with it, and
/// the name is escaped with [`crate::validate::terminal_text`] (a `\r` that
/// would overwrite the line, a `\n` that would cut the message, a bidi
/// override).
pub fn label(names: &std::collections::HashMap<String, String>, key: &str) -> String {
    let name = names
        .iter()
        .find(|(pk, _)| crate::recipients::same_recipient(pk, key))
        .map(|(_, n)| n.as_str())
        .filter(|n| !n.is_empty());
    let short = crate::truncate_pubkey(key);
    match name {
        Some(n) => format!("{} ({short})", crate::validate::terminal_text(n, false)),
        None => short,
    }
}

/// The error a secret-handling load reports for `refusal`: what happened, what
/// to review, and how to accept it if it is legitimate.
pub fn refusal_message(
    vault_path: &str,
    refusal: &Refusal,
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
) -> String {
    let review = format!(
        "review `git log -p -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` if you accept it"
    );
    let changes = || {
        use std::fmt::Write;
        let has_pin = pin.is_some_and(TrustPin::has_trust);
        let (added, removed) = recipient_changes(loaded, pin);
        let mut lines = String::new();
        for k in added {
            let what = if has_pin {
                "recipient added"
            } else {
                "recipient"
            };
            let _ = write!(lines, "\n{what}: {}", label(loaded.names, &k));
        }
        for k in removed {
            let _ = write!(lines, "\nrecipient removed: {}", label(loaded.names, &k));
        }
        lines
    };
    match refusal {
        Refusal::NotYetTrusted { signer } => format!(
            "vault {vault_path} is not trusted on this machine yet — signed by {}{}\n{review}\nfor CI, set {TRUSTED_SIGNERS_VAR} to the expected signer keys",
            label(loaded.names, signer),
            changes()
        ),
        Refusal::UntrustedSigner { signer } => format!(
            "vault {vault_path} is signed by {}, which is not a trusted signer on this machine{}\n{review}",
            label(loaded.names, signer),
            changes()
        ),
        Refusal::GrantSigner { signer } => format!(
            "vault {vault_path} is signed by agent grant key {}, and agent grants are read-only — it may have been tampered with\nrestore {vault_path} from git",
            crate::truncate_pubkey(signer)
        ),
        Refusal::GrantWithoutRecord { key } => format!(
            "vault {vault_path} lists former agent grant key {} as a recipient without its grant — it may have been tampered with\nrestore {vault_path} from git",
            crate::truncate_pubkey(key)
        ),
        Refusal::Unsigned => format!(
            "vault {vault_path} is unsigned, so nothing shows who wrote it\nreview `git diff -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` to sign it"
        ),
        Refusal::Downgraded => format!(
            "vault {vault_path} was signed when this machine last accepted it and is now unsigned — the signature was stripped, or a merge or a hardware-key write left it unsigned\nreview `git diff -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` to accept and re-sign it"
        ),
        Refusal::RolledBack { pinned, found } => format!(
            "vault {vault_path} rolled back: generation {found}, but this machine accepted generation {pinned} — an older revision may have been replayed\nif you switched to an older branch, switch back; for a deliberate revert, {review}"
        ),
        Refusal::OtherVault { pinned, found } => format!(
            "vault {vault_path} is a different vault (id {}, expected {pinned}) — another vault's file may have been copied over it\n{review}",
            if found.is_empty() { "none" } else { found }
        ),
        Refusal::GroupChange { group, signer } => format!(
            "vault {vault_path} changes the membership of group {group}, but the signer {} was not a member of it\n{review}",
            label(loaded.names, signer)
        ),
        Refusal::UnconfirmedSignerKey { signer, vk } => format!(
            "vault {vault_path} is signed by {}, a trusted recipient whose signing key this machine has not confirmed yet (their first signed write seen here)\nsigning key fingerprint: {}\nask them to confirm it (they run `murk trust --print-key`), then run `murk trust --vault {vault_path}`",
            label(loaded.names, signer),
            crate::signing::fingerprint(vk).unwrap_or_else(|| "(invalid)".into())
        ),
        Refusal::SignerKeyChanged { signer } => format!(
            "vault {vault_path} is signed by {} with a signing key that is not theirs — an age key's signing key cannot change, so this is a forgery\nrestore {vault_path} from git",
            label(loaded.names, signer)
        ),
        Refusal::GrantBindsOperator { grant, key } => format!(
            "vault {vault_path} binds agent grant {} to {}, which signs this vault as a teammate — agent grants get freshly minted keys, so it has been tampered with\nnothing from it was recorded; restore {vault_path} from git",
            crate::validate::show(grant),
            label(loaded.names, key)
        ),
        Refusal::RemovedKey {
            key,
            removed_at,
            found,
            signer,
        } => removed_key_message(vault_path, loaded, key, *removed_at, *found, *signer),
        Refusal::Forked { generation } => format!(
            "vault {vault_path} forked: generation {generation} is not the vault this machine accepted at that generation here — the branch was rewritten, or another save with the same counter replaced it\nmerge the two saves with the murk merge driver, or {review}"
        ),
        Refusal::GenerationJump { pinned, found } => format!(
            "vault {vault_path} jumps from generation {pinned} to {found}, more than {MAX_GENERATION_STEP} saves at once — a signer may be running the counter up\n{review}"
        ),
        Refusal::GenerationOutOfRange { found } => format!(
            "vault {vault_path} has generation {found}, above the largest murk accepts ({MAX_GENERATION}) — it may have been tampered with to exhaust the counter\nrestore {vault_path} from git"
        ),
    }
}

/// The message for [`Refusal::RemovedKey`].
fn removed_key_message(
    vault_path: &str,
    loaded: &Loaded<'_>,
    key: &str,
    removed_at: u64,
    found: u64,
    signer: bool,
) -> String {
    let who = label(loaded.names, key);
    let what = if signer {
        format!(
            "it is signed by {who}, who was removed from this vault at generation {removed_at} on this machine\nrestore {vault_path} from git"
        )
    } else {
        format!(
            "it lists {who}, who was removed from this vault at generation {removed_at} on this machine, and its generation {found} is not newer — an older revision may have been replayed\nupdate to the vault that removed them (pull, or merge the removal into this branch)"
        )
    };
    format!(
        "vault {vault_path} rolled back: {what}; to re-add them on purpose, have a trusted teammate authorize them again, or review it and run `murk trust --vault {vault_path} --re-add {}`",
        canonical_recipient(key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The rules outside a git checkout (one counter for the vault).
    fn verdict(
        loaded: &Loaded<'_>,
        pin: Option<&TrustPin>,
        env: Option<&TrustedSigners>,
    ) -> Verdict {
        super::verdict(loaded, pin, env, &HeadState::NotARepo)
    }

    /// A trusted load, or (`reset`) an explicit `murk trust` of a rollback.
    fn accepted_pin(loaded: &Loaded<'_>, prior: Option<&TrustPin>, reset: bool) -> TrustPin {
        static NONE: BTreeSet<String> = BTreeSet::new();
        let how = if reset {
            Acceptance::Trust {
                reset_counter: true,
                readmit: &NONE,
            }
        } else {
            Acceptance::Load
        };
        super::accepted_pin(loaded, prior, how, &HeadState::NotARepo)
    }

    #[test]
    fn rollback_is_judged_per_branch() {
        let main = HeadState::Branch("main".into());
        let feature = HeadState::Branch("feature".into());
        let at = |g| Case::new(&[A], g, A);
        // main accepted at 5, then feature moved to 6.
        let pin = super::accepted_pin(&at(5).loaded(), None, Acceptance::Load, &main);
        let pin = super::accepted_pin(&at(6).loaded(), Some(&pin), Acceptance::Load, &feature);
        // Switching back to main (still 5) is fine; main going back to 4 is not.
        assert_eq!(
            super::verdict(&at(5).loaded(), Some(&pin), None, &main),
            Verdict::Trusted
        );
        assert!(matches!(
            super::verdict(&at(4).loaded(), Some(&pin), None, &main),
            Verdict::Refused(Refusal::RolledBack {
                pinned: 5,
                found: 4
            })
        ));
        // The next save is numbered past everything seen on any branch.
        assert_eq!(pin.generation, 6);
        // A detached HEAD has no branch to compare with.
        assert_eq!(
            super::verdict(&at(1).loaded(), Some(&pin), None, &HeadState::Detached),
            Verdict::Trusted
        );
    }

    fn vault(recipients: &[&str], generation: u64) -> types::Vault {
        let mut v = crate::testutil::empty_vault();
        v.recipients = recipients.iter().map(|r| (*r).to_string()).collect();
        v.generation = generation;
        v.vault_id = "00112233445566778899aabbccddeeff".into();
        v
    }

    fn signed(by: &str) -> types::SignatureState {
        types::SignatureState::Signed {
            signer: by.into(),
            v: crate::signature::SIGNED_VIEW_VERSION,
        }
    }

    struct Case {
        vault: types::Vault,
        sig: types::SignatureState,
        groups: BTreeMap<String, Vec<String>>,
        grants: BTreeMap<String, types::GrantEntry>,
        names: HashMap<String, String>,
        registry: BTreeMap<String, String>,
        /// The registry key the signature verified against (age signers).
        vk: Option<String>,
    }

    /// Trusted signers without verifying keys (as for ssh-ed25519 keys).
    fn env(keys: &[&str]) -> TrustedSigners {
        keys.iter().map(|k| ((*k).to_string(), None)).collect()
    }

    impl Case {
        fn new(recipients: &[&str], generation: u64, by: &str) -> Self {
            Self {
                vault: vault(recipients, generation),
                sig: signed(by),
                groups: BTreeMap::new(),
                grants: BTreeMap::new(),
                names: HashMap::new(),
                registry: BTreeMap::new(),
                vk: None,
            }
        }
        /// An age-style signature: `vk` is the signer's registry key.
        fn with_vk(mut self, vk: &str) -> Self {
            self.vk = Some(vk.into());
            self
        }
        fn loaded(&self) -> Loaded<'_> {
            Loaded {
                vault: &self.vault,
                signature: &self.sig,
                registry: &self.registry,
                signer_vk: self.vk.as_deref(),
                names: &self.names,
                groups: &self.groups,
                grants: &self.grants,
                loader_can_sign: true,
                operator_key: None,
            }
        }
    }

    const A: &str = "age1alice";
    const B: &str = "age1bob";
    const M: &str = "age1mallory";

    fn pin_for(c: &Case) -> TrustPin {
        accepted_pin(&c.loaded(), None, false)
    }

    #[test]
    fn self_enrolled_signer_is_refused_against_the_pin() {
        let pin = pin_for(&Case::new(&[A], 3, A));
        let forged = Case::new(&[A, M], 4, M);
        assert_eq!(
            verdict(&forged.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UntrustedSigner { signer: M.into() })
        );
    }

    #[test]
    fn a_trusted_signer_adding_a_recipient_extends_the_pin() {
        let pin = pin_for(&Case::new(&[A], 3, A));
        let next = Case::new(&[A, B], 4, A);
        assert_eq!(verdict(&next.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&next.loaded(), Some(&pin), false);
        let by_bob = Case::new(&[A, B], 5, B);
        assert_eq!(
            verdict(&by_bob.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    #[test]
    fn a_revoked_recipient_loses_signing_trust() {
        let pin = pin_for(&Case::new(&[A, B], 3, A));
        let revoked = Case::new(&[A], 4, A);
        let pin = accepted_pin(&revoked.loaded(), Some(&pin), false);
        let back = Case::new(&[A, B], 5, B);
        assert!(matches!(
            verdict(&back.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UntrustedSigner { .. })
        ));
    }

    #[test]
    fn rollback_below_the_high_water_mark_is_refused_equal_is_not() {
        let pin = pin_for(&Case::new(&[A], 7, A));
        assert_eq!(
            verdict(&Case::new(&[A], 6, A).loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::RolledBack {
                pinned: 7,
                found: 6
            })
        );
        assert_eq!(
            verdict(&Case::new(&[A], 7, A).loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    #[test]
    fn another_vaults_file_is_refused() {
        let pin = pin_for(&Case::new(&[A], 1, A));
        let mut other = Case::new(&[A], 9, A);
        other.vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
        assert!(matches!(
            verdict(&other.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::OtherVault { .. })
        ));
    }

    #[test]
    fn env_signers_replace_the_pin_and_no_trust_at_all_refuses() {
        let c = Case::new(&[A, B], 1, B);
        assert_eq!(
            verdict(&c.loaded(), None, None),
            Verdict::Refused(Refusal::NotYetTrusted { signer: B.into() })
        );
        let env = super::tests::env(&[B]);
        assert_eq!(verdict(&c.loaded(), None, Some(&env)), Verdict::Trusted);
        let env = super::tests::env(&[A]);
        assert!(matches!(
            verdict(&c.loaded(), None, Some(&env)),
            Verdict::Refused(Refusal::UntrustedSigner { .. })
        ));
    }

    #[test]
    fn unsigned_is_refused_for_a_signing_loader_and_after_a_signed_load() {
        let mut c = Case::new(&[A], 1, A);
        c.sig = types::SignatureState::Unsigned;
        assert_eq!(
            verdict(&c.loaded(), None, None),
            Verdict::Refused(Refusal::Unsigned)
        );
        let mut hw = c.loaded();
        hw.loader_can_sign = false;
        assert_eq!(verdict(&hw, None, None), Verdict::UnsignedAllowed);
        let pin = pin_for(&Case::new(&[A], 1, A));
        assert_eq!(
            verdict(&hw, Some(&pin), None),
            Verdict::Refused(Refusal::Downgraded)
        );
    }

    #[test]
    fn a_grant_bound_to_a_trusted_signer_is_tampering_and_never_pinned() {
        let pin = pin_for(&Case::new(&[A, B], 1, A));
        let mut ghost = Case::new(&[A, B], 2, B);
        ghost.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: A.into(),
                ..Default::default()
            },
        );
        let v = verdict(&ghost.loaded(), Some(&pin), None);
        assert_eq!(
            v,
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: A.into()
            })
        );
        let Verdict::Refused(r) = v else {
            unreachable!()
        };
        assert!(!r.acceptable());
        // Even if such a vault were recorded (an own save, a re-sign), the
        // pin keeps A a signer and never a grant.
        let recorded = accepted_pin(&ghost.loaded(), Some(&pin), false);
        assert!(!recorded.grants.contains(A));
        assert!(recorded.trusted.contains(A), "A stays a trusted signer");
        // A pinned grant entry for a trusted signer does not override trust.
        let mut stale = pin.clone();
        stale.grants.insert(A.into());
        assert_eq!(
            verdict(&Case::new(&[A, B], 2, A).loaded(), Some(&stale), None),
            Verdict::Trusted
        );

        // A fresh machine (no pin) whose loading key is an operator for sure
        // (ssh or plugin, never a grant) refuses a grant bound to that key.
        let ssh = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb";
        let mut to_loader = Case::new(&[A, ssh], 3, A);
        to_loader.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: ssh.into(),
                ..Default::default()
            },
        );
        let mut as_operator = to_loader.loaded();
        as_operator.operator_key = Some(ssh.into());
        assert_eq!(
            verdict(&as_operator, None, None),
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: ssh.into()
            })
        );
        // An age loader may be the grant itself: only the pin can tell.
        assert!(matches!(
            verdict(&to_loader.loaded(), None, None),
            Verdict::Refused(Refusal::NotYetTrusted { .. })
        ));

        // A runner with no pin that trusts both through MURK_TRUSTED_SIGNERS:
        // B binds a grant to A and leaves A out of the registry. A is a named
        // signer there, so this is still tampering.
        let mut ghost_ci = Case::new(&[A, B], 2, B);
        ghost_ci.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: A.into(),
                ..Default::default()
            },
        );
        assert_eq!(
            verdict(&ghost_ci.loaded(), None, Some(&env(&[A, B]))),
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: A.into()
            })
        );
    }

    #[test]
    fn a_grant_key_never_signs_even_after_dropping_its_record() {
        let mut with_grant = Case::new(&[A, "age1agent"], 1, A);
        with_grant.grants.insert(
            "bot".into(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                ..Default::default()
            },
        );
        let pin = pin_for(&with_grant);
        assert!(!pin.trusted.contains("age1agent"));
        // The grant deletes its own record and signs.
        let forged = Case::new(&[A, "age1agent"], 2, "age1agent");
        assert!(matches!(
            verdict(&forged.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::GrantSigner { .. })
        ));
        // Or keeps a trusted signature but re-lists itself as a plain recipient.
        let demoted = Case::new(&[A, "age1agent"], 2, A);
        assert!(matches!(
            verdict(&demoted.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::GrantWithoutRecord { .. })
        ));
    }

    #[test]
    fn a_v1_vault_is_refused_once_the_vault_was_seen_in_v2_form() {
        // Upgrade: a v1 vault (no id, no counter) is pinned once...
        let mut v1 = Case::new(&[A], 0, A);
        v1.vault.vault_id.clear();
        v1.sig = types::SignatureState::Signed {
            signer: A.into(),
            v: crate::signature::LEGACY_SIGNED_VIEW_VERSION,
        };
        let pin = pin_for(&v1);
        assert_eq!(verdict(&v1.loaded(), Some(&pin), None), Verdict::Trusted);
        // ...then the first 0.14 save lands (id + counter)...
        let pin = accepted_pin(&Case::new(&[A], 1, A).loaded(), Some(&pin), false);
        // ...and the old v1 revision is now a rollback.
        assert!(matches!(
            verdict(&v1.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::RolledBack { .. })
        ));
    }

    #[test]
    fn named_signers_refuse_an_unsigned_vault_even_for_a_key_that_cannot_sign() {
        let mut c = Case::new(&[A], 1, A);
        c.sig = types::SignatureState::Unsigned;
        let mut hw = c.loaded();
        hw.loader_can_sign = false;
        let env = super::tests::env(&[A]);
        assert_eq!(
            verdict(&hw, None, Some(&env)),
            Verdict::Refused(Refusal::Unsigned)
        );
    }

    #[test]
    fn a_merging_key_outside_a_group_may_not_carry_its_membership_change() {
        let before = canonical_groups(&BTreeMap::from([("ops".to_string(), vec![A.to_string()])]));
        let after = BTreeMap::from([("ops".to_string(), vec![A.to_string(), M.to_string()])]);
        let recipients = [A.to_string(), B.to_string(), M.to_string()];
        assert_eq!(
            group_change_violation(&recipients, &after, &before, B),
            Some("ops".into())
        );
        assert_eq!(
            group_change_violation(&recipients, &after, &before, A),
            None
        );
    }

    #[test]
    fn group_self_add_by_a_non_member_is_refused() {
        let mut base = Case::new(&[A, B, M], 1, A);
        base.groups.insert("prod".into(), vec![A.into(), B.into()]);
        let pin = pin_for(&base);
        let mut forged = Case::new(&[A, B, M], 2, M);
        forged
            .groups
            .insert("prod".into(), vec![A.into(), B.into(), M.into()]);
        let env = super::tests::env(&[A, B, M]);
        // Even with M trusted to sign, it may not change a group it is not in.
        assert_eq!(
            verdict(&forged.loaded(), Some(&pin), Some(&env)),
            Verdict::Refused(Refusal::GroupChange {
                group: "prod".into(),
                signer: M.into()
            })
        );
        // A member may.
        let mut by_member = Case::new(&[A, B, M], 2, A);
        by_member
            .groups
            .insert("prod".into(), vec![A.into(), B.into(), M.into()]);
        assert_eq!(
            verdict(&by_member.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
        // A non-member revoking B from the vault strips B from the group.
        let mut revoke = Case::new(&[A, M], 2, M);
        revoke.groups.insert("prod".into(), vec![A.into()]);
        assert_eq!(
            verdict(&revoke.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    // Two distinct, well-formed verifying keys for the key-pinning tests.
    fn vks() -> (String, String) {
        let a = crate::signing::age_signing_key(&[1u8; 32]).verifying_key();
        let b = crate::signing::age_signing_key(&[2u8; 32]).verifying_key();
        (a, b)
    }

    /// Run `f` with a sandboxed HOME holding `pin` for `vault_path`.
    fn with_pin<T>(vault_path: &str, pin: &TrustPin, f: impl FnOnce() -> T) -> T {
        let _lock = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("MURK_NO_SIGNER_PIN");
            std::env::remove_var("MURK_TRUSTED_SIGNERS");
        }
        pins::write(vault_path, pin).unwrap();
        let out = f();
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        out
    }

    #[test]
    fn a_pinned_vault_refuses_an_id_less_merge_side_even_unchanged() {
        // The pin has seen the vault in 0.14 form. A side without a vault id
        // (a 0.13 revision) is refused even when it equals the ancestor:
        // only the ancestor may be pre-0.14 history.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let pin = pin_for(&Case::new(&[A], 3, A));
        let mut legacy = Case::new(&[A], 0, A);
        legacy.vault.vault_id.clear();
        let base = legacy.vault.clone();
        let refused = with_pin(path, &pin, || {
            check_merge_side(path, &legacy.loaded(), Some((&base, None)), false, false)
        });
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("murk 0.13 revision")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_pinned_vault_refuses_a_merge_side_from_another_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let pin = pin_for(&Case::new(&[A], 3, A));
        let mut other = Case::new(&[A], 5, A);
        other.vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
        let base = Case::new(&[A], 3, A).vault;
        let refused = with_pin(path, &pin, || {
            check_merge_side(path, &other.loaded(), Some((&base, None)), true, true)
        });
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("different vault")),
            "{refused:?}"
        );
        // The pinned vault's own side is accepted.
        let own = Case::new(&[A], 5, A);
        let accepted = with_pin(path, &pin, || {
            check_merge_side(path, &own.loaded(), Some((&base, None)), true, true)
        });
        assert_eq!(accepted, Ok(()));
    }

    #[test]
    fn a_trusted_signers_first_key_waits_for_confirmation_then_is_pinned() {
        let (vk_a, vk_b) = vks();
        // Alice's vault (her key pinned) adds Bob, who has not signed yet.
        let pin = pin_for(&Case::new(&[A], 3, A).with_vk(&vk_a));
        let next = Case::new(&[A, B], 4, A).with_vk(&vk_a);
        assert_eq!(verdict(&next.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&next.loaded(), Some(&pin), false);
        // Bob's first write registers his key himself: not believed.
        let by_bob = Case::new(&[A, B], 5, B).with_vk(&vk_b);
        let refusal = verdict(&by_bob.loaded(), Some(&pin), None);
        assert_eq!(
            refusal,
            Verdict::Refused(Refusal::UnconfirmedSignerKey {
                signer: B.into(),
                vk: vk_b.clone()
            })
        );
        let Verdict::Refused(r) = refusal else {
            unreachable!()
        };
        assert!(r.acceptable());
        // `murk trust` confirms it; from then on Bob's writes load.
        let pin = accepted_pin(&by_bob.loaded(), Some(&pin), true);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
        let again = Case::new(&[A, B], 6, B).with_vk(&vk_b);
        assert_eq!(verdict(&again.loaded(), Some(&pin), None), Verdict::Trusted);
    }

    #[test]
    fn a_registry_entry_is_believed_from_a_trusted_signers_vault_and_never_replaced() {
        let (vk_a, vk_b) = vks();
        let mut by_alice = Case::new(&[A, B], 3, A).with_vk(&vk_a);
        by_alice.registry = BTreeMap::from([(A.into(), vk_a.clone()), (B.into(), vk_b.clone())]);
        let pin = pin_for(&by_alice);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
        // Bob's key arrived through Alice's signed vault: his write loads.
        let by_bob = Case::new(&[A, B], 4, B).with_vk(&vk_b);
        assert_eq!(
            verdict(&by_bob.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
        // A vault claiming another key for Bob (a forger poisoning the
        // registry under Bob's name) is refused, and `murk trust` cannot
        // accept it.
        let forged = Case::new(&[A, B], 5, B).with_vk(&vk_a);
        let v = verdict(&forged.loaded(), Some(&pin), None);
        assert_eq!(
            v,
            Verdict::Refused(Refusal::SignerKeyChanged { signer: B.into() })
        );
        let Verdict::Refused(r) = v else {
            unreachable!()
        };
        assert!(!r.acceptable());
        // Nor does a later accepted vault's registry overwrite a pinned key.
        let mut rewrite = Case::new(&[A, B], 5, A).with_vk(&vk_a);
        rewrite.registry = BTreeMap::from([(B.into(), vk_a.clone())]);
        let pin = accepted_pin(&rewrite.loaded(), Some(&pin), false);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
    }

    #[test]
    fn a_non_member_cannot_bind_a_group_members_key_then_sign_as_them() {
        // Pinned: ops = [bob], Alice and Mallory trusted with confirmed keys,
        // Bob has never signed. Revision 1 by Mallory changes no group but
        // registers her own key under Bob's name; revision 2 is "signed by
        // Bob" with that key and adds Mallory to ops.
        let (vk_a, vk_m) = vks();
        let ops = |members: &[&str]| {
            BTreeMap::from([(
                "ops".to_string(),
                members.iter().map(|m| (*m).to_string()).collect::<Vec<_>>(),
            )])
        };
        let mut start = Case::new(&[A, B, M], 1, A).with_vk(&vk_a);
        start.groups = ops(&[B]);
        start.registry = BTreeMap::from([(A.into(), vk_a.clone()), (M.into(), vk_m.clone())]);
        let pin = pin_for(&start);

        let mut bind = Case::new(&[A, B, M], 2, M).with_vk(&vk_m);
        bind.groups = ops(&[B]);
        bind.registry = BTreeMap::from([(M.into(), vk_m.clone()), (B.into(), vk_m.clone())]);
        assert_eq!(verdict(&bind.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&bind.loaded(), Some(&pin), false);
        assert_eq!(pin.signers.get(B), None, "Mallory may not bind Bob's key");

        // The self-add is refused, so nothing of it reaches the pin: the
        // pinned membership stays ops = [bob].
        let mut self_add = Case::new(&[A, B, M], 3, B).with_vk(&vk_m);
        self_add.groups = ops(&[B, M]);
        assert_eq!(
            verdict(&self_add.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UnconfirmedSignerKey {
                signer: B.into(),
                vk: vk_m.clone()
            })
        );
        assert_eq!(pin.groups, canonical_groups(&ops(&[B])));

        // A member of ops may vouch for Bob's key.
        let vk_b = crate::signing::age_signing_key(&[3u8; 32]).verifying_key();
        let mut by_member = Case::new(&[A, B, M], 2, A).with_vk(&vk_a);
        by_member.groups = ops(&[A, B]);
        by_member.registry = BTreeMap::from([(B.into(), vk_b.clone())]);
        let mut member_pin = pin_for(&start);
        member_pin.groups = canonical_groups(&ops(&[A, B]));
        let member_pin = accepted_pin(&by_member.loaded(), Some(&member_pin), false);
        assert_eq!(member_pin.signers.get(B), Some(&vk_b));
    }

    #[test]
    fn env_signers_pin_the_verifying_key_of_age_signers() {
        let (vk_a, vk_b) = vks();
        let c = Case::new(&[A], 1, A).with_vk(&vk_a);
        let good = TrustedSigners::from([(A.to_string(), Some(vk_a.clone()))]);
        assert_eq!(verdict(&c.loaded(), None, Some(&good)), Verdict::Trusted);
        let wrong = TrustedSigners::from([(A.to_string(), Some(vk_b))]);
        assert_eq!(
            verdict(&c.loaded(), None, Some(&wrong)),
            Verdict::Refused(Refusal::SignerKeyChanged { signer: A.into() })
        );
    }

    #[test]
    fn trusted_signer_entries_need_a_verifying_key_for_age_keys() {
        let (secret, age) = crate::testutil::generate_keypair();
        let _ = secret;
        let (vk, _) = vks();
        assert_eq!(
            parse_trusted_signer(&format!("{age}:{vk}")),
            Ok((age.clone(), Some(vk.clone())))
        );
        assert!(
            parse_trusted_signer(&age)
                .unwrap_err()
                .contains("needs its verifying key")
        );
        assert!(parse_trusted_signer(&format!("{age}:nope")).is_err());
        let ssh = crate::testutil::SSH_ED25519_PK;
        assert_eq!(
            parse_trusted_signer(&format!("{ssh} me@host")),
            Ok((ssh.to_string(), None))
        );
        assert!(parse_trusted_signer("not-a-key").is_err());
    }

    fn assessment(pin: Option<TrustPin>, external: Option<TrustedSigners>) -> Assessment {
        Assessment {
            verdict: Verdict::Trusted,
            pin,
            env_signers: None,
            external,
        }
    }

    #[test]
    fn trusted_ssh_signers_are_the_pins_ssh_keys_without_grants() {
        let ssh = crate::testutil::SSH_ED25519_PK;
        let other =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI7KsDGxx+I8XZQwtbgoEYDfuNd9fQ4MzcHHUmtIau9";
        let pin = TrustPin {
            v: pins::PIN_VERSION,
            trusted: [A, ssh, other, "ssh-rsa AAAAB3xyz"]
                .iter()
                .map(|k| (*k).to_string())
                .collect(),
            grants: [other.to_string()].into(),
            ..TrustPin::default()
        };
        // Only ssh-ed25519 keys, and a grant key never counts.
        let got = assessment(Some(pin.clone()), None).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![ssh.to_string()]);

        // A grant the vault carries now excludes its key too, even where the
        // pin has not seen the grant yet.
        let mut grants = BTreeMap::new();
        grants.insert(
            "bot".to_string(),
            types::GrantEntry {
                pubkey: format!("{ssh} bot@host"),
                ..Default::default()
            },
        );
        assert_eq!(
            assessment(Some(pin), None).trusted_ssh_signers(&grants),
            Vec::<String>::new()
        );
    }

    #[test]
    fn trusted_ssh_signers_prefer_the_external_set_over_the_pin() {
        let ssh = crate::testutil::SSH_ED25519_PK;
        let other =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI7KsDGxx+I8XZQwtbgoEYDfuNd9fQ4MzcHHUmtIau9";
        let pin = TrustPin {
            v: pins::PIN_VERSION,
            trusted: [ssh.to_string()].into(),
            ..TrustPin::default()
        };
        let external = env(&[&format!("{other} ci@runner")]);
        let got =
            assessment(Some(pin), Some(external.clone())).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![other.to_string()]);
        // With no pin at all the external set still applies.
        let got = assessment(None, Some(external)).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![other.to_string()]);
    }

    #[test]
    fn trusted_ssh_signers_are_empty_without_a_trust_decision() {
        // No pin, or a legacy pin that records no decision.
        assert_eq!(
            assessment(None, None).trusted_ssh_signers(&BTreeMap::new()),
            Vec::<String>::new()
        );
        let legacy = TrustPin {
            trusted: [crate::testutil::SSH_ED25519_PK.to_string()].into(),
            ..TrustPin::default()
        };
        assert_eq!(
            assessment(Some(legacy), None).trusted_ssh_signers(&BTreeMap::new()),
            Vec::<String>::new()
        );
    }
}
