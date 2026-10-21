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
//!
//! An accepted vault replaces the pin's trusted set, grants and groups with its
//! own, and raises the counter. Its registry entries for trusted recipients are
//! pinned where no key was pinned before — believed because the vault carrying
//! them was signed by an already-trusted signer (or confirmed by `murk trust`).
//! A pinned key is never replaced. `murk trust` accepts a refused vault on the
//! user's say-so after showing what changed.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::canonical_recipient;
pub use crate::git::HeadState;
use crate::pins::{self, TrustPin};
use crate::types;

/// Environment variable naming the keys trusted to sign, comma or newline
/// separated. When set it replaces the pin's trusted set (for CI runners and
/// other machines without a pin). Grant keys listed here still never count.
/// See [`parse_trusted_signer`] for the entry format.
pub const TRUSTED_SIGNERS_VAR: &str = "MURK_TRUSTED_SIGNERS";

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
}

impl Refusal {
    /// Whether `murk trust` may accept this refusal. Grant-signed vaults never
    /// are: an agent grant is read-only by design. Nor is a changed verifying
    /// key: an age key's verifying key is derived from its secret, so a
    /// different one for the same recipient is a forgery. Nor a grant bound
    /// to an operator key, which is tampering.
    pub fn acceptable(&self) -> bool {
        !matches!(
            self,
            Refusal::GrantSigner { .. }
                | Refusal::GrantWithoutRecord { .. }
                | Refusal::SignerKeyChanged { .. }
                | Refusal::GrantBindsOperator { .. }
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
            Ok((canonical_recipient(key), Some(vk.to_string())))
        }
        Some(_) => Err(format!(
            "not a verifying key after {}:",
            crate::truncate_pubkey(key)
        )),
        None if is_ssh => Ok((canonical_recipient(key), None)),
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
        .map(|g| canonical_recipient(&g.pubkey))
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
                pin.signers.get(k).map(|vk| (k.clone(), Some(vk.clone())))
            }
        })
        .collect())
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
    let signer = canonical_recipient(&sig.signer);
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
        .map(|r| canonical_recipient(r))
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
                members.iter().map(|m| canonical_recipient(m)).collect(),
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
pub fn assess(
    vault_path: &str,
    loaded: &Loaded<'_>,
    anchor: Option<&TrustedSigners>,
) -> Result<Assessment, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let external: Option<TrustedSigners> = match (anchor, &env_signers) {
        (None, None) => None,
        (a, e) => Some(
            a.into_iter()
                .chain(e.iter())
                .flatten()
                .map(|(k, vk)| (canonical_recipient(k), vk.clone()))
                .collect(),
        ),
    };
    let head = head_of(vault_path);
    let verdict = verdict(loaded, pin.as_ref(), external.as_ref(), &head);
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
    verdict(
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
    let signer_c = canonical_recipient(signer);
    let expected = match external_signers {
        Some(external) => external.get(&signer_c).cloned().flatten(),
        None => trusted_pin.and_then(|p| p.signers.get(&signer_c).cloned()),
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
/// their own key), a key with a signing-key registry entry (grants never
/// sign), or the loading key when it is known to be an operator. The first
/// such grant is tampering.
fn grant_binding_refusal(loaded: &Loaded<'_>, pin: Option<&TrustPin>) -> Option<Refusal> {
    let operator = loaded.operator_key.as_deref().map(canonical_recipient);
    let registry: BTreeSet<String> = loaded
        .registry
        .keys()
        .map(|k| canonical_recipient(k))
        .collect();
    loaded.grants.iter().find_map(|(name, grant)| {
        let key = canonical_recipient(&grant.pubkey);
        let operator = operator.as_ref() == Some(&key)
            || registry.contains(&key)
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
    let signer_c = canonical_recipient(signer);
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
        .map(|r| canonical_recipient(r))
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
    if let Some(refusal) = grant_binding_refusal(loaded, pin) {
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
    let signer_c = canonical_recipient(signer);
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
/// Returns the reason a side is refused.
pub fn check_merge_side(
    vault_path: &str,
    side: &Loaded<'_>,
    base: Option<(&types::Vault, Option<&Groups>)>,
    changed: bool,
) -> Result<(), String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let side_pin = pin.map(|mut p| {
        p.generation = 0;
        p.branches.clear();
        if let Some((base, groups)) = base {
            if let Some(groups) = groups {
                p.groups = canonical_groups(groups);
            }
            // A branch that forked before the vault got its id (murk 0.13)
            // carries none; that is the ancestor's state, not another vault.
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
    let signer = canonical_recipient(signer);
    let recipients: BTreeSet<String> = recipients.iter().map(|r| canonical_recipient(r)).collect();
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

/// The pin to store once `loaded` is accepted (by a trusted load, `murk
/// trust`, or this machine's own signed save) while `head` is checked out.
/// Keeps the higher counters unless `reset_counter` (an explicit `murk trust`
/// of a rollback), which lowers the mark for this branch.
pub fn accepted_pin(
    loaded: &Loaded<'_>,
    prior: Option<&TrustPin>,
    reset_counter: bool,
    head: &HeadState,
) -> TrustPin {
    let prior_v2 = prior.filter(|p| p.v >= pins::PIN_VERSION);
    let mut grants: BTreeSet<String> = prior_v2.map(|p| p.grants.clone()).unwrap_or_default();
    // A key this machine trusts (or trusted) as a signer is never recorded as
    // a grant: that would lock its owner out here for good.
    grants.extend(grant_keys(loaded.grants).into_iter().filter(|k| {
        !prior_v2.is_some_and(|p| p.trusted.contains(k) || p.ever_trusted.contains(k))
    }));
    let found = loaded.vault.generation;
    let prior_high = prior_v2.map_or(0, |p| p.generation);
    let generation = if reset_counter && *head == HeadState::NotARepo {
        found
    } else {
        found.max(prior_high)
    };
    let mut branches = prior_v2.map(|p| p.branches.clone()).unwrap_or_default();
    if let HeadState::Branch(b) = head {
        let entry = branches.entry(b.clone()).or_insert(found);
        *entry = if reset_counter {
            found
        } else {
            (*entry).max(found)
        };
    }
    let vault_id = if loaded.vault.vault_id.is_empty() {
        prior_v2.map(|p| p.vault_id.clone()).unwrap_or_default()
    } else {
        loaded.vault.vault_id.clone()
    };
    let signed = matches!(loaded.signature, types::SignatureState::Signed { .. });
    // The vault's non-grant recipients — where a grant record names a key this
    // machine trusts as a signer, that key stays a signer.
    let trusted: BTreeSet<String> = loaded
        .vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r))
        .filter(|r| !grants.contains(r))
        .collect();
    // Verifying keys: the ones pinned before, plus the signer's own and the
    // registry entries of the vault's trusted signers — believed because the
    // vault carrying them is accepted. A pinned key is never replaced, and is
    // kept after its owner is revoked so their old revisions still verify.
    let mut signers = prior_v2.map(|p| p.signers.clone()).unwrap_or_default();
    if let types::SignatureState::Signed { signer, .. } = loaded.signature {
        let signer = canonical_recipient(signer);
        if let Some(vk) = loaded.signer_vk {
            signers
                .entry(signer.clone())
                .or_insert_with(|| vk.to_string());
        }
        // Binding another recipient's key lets the signer speak as them, so
        // it must not reach further than the signer could itself: an entry
        // for a member of a group (as pinned, or in this vault) is believed
        // only from a member of that group. Otherwise a trusted non-member
        // could bind a member's name to their own key, then sign as that
        // member to change the group.
        let groups = canonical_groups(loaded.groups);
        let pinned_groups = prior_v2.map(|p| &p.groups);
        let may_bind = |pk: &str| {
            groups
                .values()
                .chain(pinned_groups.into_iter().flat_map(BTreeMap::values))
                .all(|members| !members.contains(pk) || members.contains(&signer))
        };
        for (pk, vk) in loaded.registry {
            let pk = canonical_recipient(pk);
            if trusted.contains(&pk) && (pk == signer || may_bind(&pk)) {
                signers.entry(pk).or_insert_with(|| vk.clone());
            }
        }
    }
    let mut ever_trusted = prior_v2.map(|p| p.ever_trusted.clone()).unwrap_or_default();
    ever_trusted.extend(trusted.iter().cloned());
    TrustPin {
        v: pins::PIN_VERSION,
        vault_id,
        generation,
        branches,
        ever_trusted,
        trusted,
        grants,
        groups: canonical_groups(loaded.groups),
        signers,
        was_signed: signed || prior.is_some_and(|p| p.was_signed),
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
/// control characters in it (a `\r` that would overwrite the line, a `\n`
/// that would cut the message) are replaced.
pub fn label(names: &std::collections::HashMap<String, String>, key: &str) -> String {
    let canon = canonical_recipient(key);
    let name = names
        .iter()
        .find(|(pk, _)| canonical_recipient(pk) == canon)
        .map(|(_, n)| n.as_str())
        .filter(|n| !n.is_empty());
    let short = crate::truncate_pubkey(key);
    match name {
        Some(n) => {
            let n: String = n
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect();
            format!("{n} ({short})")
        }
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
    }
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

    fn accepted_pin(loaded: &Loaded<'_>, prior: Option<&TrustPin>, reset: bool) -> TrustPin {
        super::accepted_pin(loaded, prior, reset, &HeadState::NotARepo)
    }

    #[test]
    fn rollback_is_judged_per_branch() {
        let main = HeadState::Branch("main".into());
        let feature = HeadState::Branch("feature".into());
        let at = |g| Case::new(&[A], g, A);
        // main accepted at 5, then feature moved to 6.
        let pin = super::accepted_pin(&at(5).loaded(), None, false, &main);
        let pin = super::accepted_pin(&at(6).loaded(), Some(&pin), false, &feature);
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
}
