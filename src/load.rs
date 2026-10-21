// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault load path: decrypt the meta blob, verify its MAC and signature under
//! the version-gating rules, and materialize the caller's view of the secrets.

use crate::{
    MurkError, compute_mac, crypto, decode_mac_key, decrypt_value, env,
    plaintext_bytes_to_zeroizing_string, policy, read_vault, trust, types, verify_mac,
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
    signer_vk: Option<String>,
}

/// Determine the signature state of a vault and its decrypted meta, treating a
/// present-but-invalid signature as tampering (hard error). An absent signature
/// is `Unsigned`; whether that is acceptable is the trust check's call. Also
/// returns the registry verifying key a v1 age signature verified against.
///
/// Where a signature lives fixes its view: the top-level `Vault::sig` is always
/// view 2, a signature inside the meta always view 1 (vaults from before 3.0).
/// A vault carrying both, or either in the other's view, is refused.
///
/// A signature by an agent grant is tampering too, however well it verifies:
/// grants are read-only, and a 2.x vault let a grant key decrypt the meta, so
/// it could re-MAC and re-sign a hand-edited vault. Only a non-grant recipient
/// is a valid author.
fn check_signature(
    vault: &types::Vault,
    meta: &types::Meta,
) -> Result<(types::SignatureState, Option<String>), MurkError> {
    let invalid = || {
        MurkError::Integrity(
            "vault signature is invalid — it may have been tampered with. Run `murk verify` for details"
                .into(),
        )
    };
    let sig = match (&vault.sig, &meta.sig) {
        (None, None) => return Ok((types::SignatureState::Unsigned, None)),
        (Some(sig), None) if sig.v > crate::signature::SIGNED_VIEW_VERSION => {
            return Err(newer_murk(&format!(
                "its signature format (signed view v{})",
                sig.v
            )));
        }
        (Some(sig), None) if sig.v == crate::signature::SIGNED_VIEW_VERSION => sig,
        (None, Some(sig)) if sig.v == crate::signature::LEGACY_SIGNED_VIEW_VERSION => sig,
        _ => return Err(invalid()),
    };
    if let Some((name, _)) = meta.grants.iter().find(|(_, g)| g.pubkey == sig.signer) {
        return Err(MurkError::Integrity(format!(
            "vault is signed by agent grant {name}, and agent grants are read-only — it may have been tampered with. Restore it from git, then run `murk agent revoke {name}`"
        )));
    }
    let verified = verify_vault_signature(
        vault,
        &meta.groups,
        &meta.grants,
        &meta.github_pins,
        &meta.signers,
        sig,
    )
    .ok_or_else(invalid)?;
    Ok((
        types::SignatureState::Signed {
            signer: sig.signer.clone(),
            v: sig.v,
        },
        verified.vk,
    ))
}

/// The state of a vault with no meta blob: only a skeleton with no secrets,
/// and only for a key its header lists.
fn empty_meta_state(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<MetaState, MurkError> {
    if !vault.secrets.is_empty() {
        return Err(MurkError::Integrity(
            "vault has secrets but no meta — vault may have been tampered with".into(),
        ));
    }
    // An empty-meta vault proves nothing about who may write to it: anyone
    // with repo write can publish one listing only their own key. Unless
    // the header lists our key, treat it like any vault we can't open, so
    // a write can't encrypt our secrets to recipients someone else chose.
    if !identity
        .pubkey_string()
        .is_ok_and(|pk| is_listed_recipient(vault, &pk))
    {
        return Err(not_a_recipient());
    }
    Ok(MetaState {
        recipients: HashMap::new(),
        groups: BTreeMap::new(),
        grants: BTreeMap::new(),
        legacy_mac: false,
        github_pins: HashMap::new(),
        signers: BTreeMap::new(),
        signature: types::SignatureState::Unsigned,
        signer_vk: None,
    })
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
        return empty_meta_state(vault, identity);
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
            return Err(not_a_recipient());
        }
    };
    let meta: types::Meta = serde_json::from_slice(&plaintext).map_err(|_| {
        MurkError::Integrity("vault meta is corrupt — vault may have been tampered with".into())
    })?;
    crate::validate::meta(&meta).map_err(|e| {
        MurkError::Integrity(format!(
            "vault meta is invalid ({e}) — vault may have been tampered with"
        ))
    })?;

    if meta.mac.is_empty() {
        if !vault.secrets.is_empty() {
            return Err(MurkError::Integrity(
                "vault has secrets but MAC is empty — vault may have been tampered with".into(),
            ));
        }
        let (signature, signer_vk) = check_signature(vault, &meta)?;
        return Ok(MetaState {
            recipients: meta.recipients,
            groups: meta.groups,
            grants: meta.grants,
            legacy_mac: false,
            github_pins: meta.github_pins,
            signers: meta.signers,
            signature,
            signer_vk,
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
        if crate::mac::is_newer_mac_scheme(&meta.mac) {
            return Err(newer_murk(&format!(
                "its MAC scheme ({})",
                crate::validate::show(meta.mac.split(':').next().unwrap_or_default())
            )));
        }
        let expected = compute_mac(vault, &meta.groups, &meta.grants, mac_key.as_ref());
        return Err(MurkError::Integrity(format!(
            "vault may have been tampered with (expected {expected}, got {})",
            meta.mac
        )));
    }
    let legacy_mac = meta.mac.starts_with("sha256:") || meta.mac.starts_with("sha256v2:");
    let (signature, signer_vk) = check_signature(vault, &meta)?;
    Ok(MetaState {
        recipients: meta.recipients,
        groups: meta.groups,
        grants: meta.grants,
        legacy_mac,
        github_pins: meta.github_pins,
        signers: meta.signers,
        signature,
        signer_vk,
    })
}

/// Drop grant records bound to `pubkey`, the key that just opened a 3.x meta.
/// Grants get their own `agents` blob and are never meta recipients, so this
/// key is no grant: such a record was written by a meta writer, and left in
/// place it would expire the operator or, on their next save, revoke them.
/// Runs after the trust check, which sees the records as written (and may
/// refuse the vault for them); the next save drops them. A 2.x vault still
/// encrypted its meta to grants, so there a matching record is the loader's
/// real grant (refused in `decrypt_vault_with_signature`).
fn drop_ghost_grants(vault: &types::Vault, murk: &mut types::Murk, pubkey: &str) {
    if vault.version.starts_with("2.") {
        return;
    }
    let me = crate::recipients::canonical_recipient(pubkey);
    murk.grants
        .retain(|_, g| crate::recipients::canonical_recipient(&g.pubkey) != me);
}

fn not_a_recipient() -> MurkError {
    MurkError::Crypto(crypto::CryptoError::Decrypt(
        "you are not a recipient of this vault. Run `murk circle` to check, or ask a recipient to authorize you".into(),
    ))
}

/// A vault format element this build doesn't understand: report it as a newer
/// murk's output, not as tampering, so the fix (upgrading) is obvious.
fn newer_murk(what: &str) -> MurkError {
    MurkError::Integrity(format!(
        "this vault was written by a newer murk: this build does not understand {what}. Upgrade murk to read it"
    ))
}

/// Whether `pubkey` names one of the vault's public header recipients. SSH
/// entries may be stored with a trailing comment while `pubkey_string()` drops
/// it, so this compares canonical forms.
pub(crate) fn is_listed_recipient(vault: &types::Vault, pubkey: &str) -> bool {
    crate::recipients::find_recipient(vault, pubkey).is_some()
}

/// What the merge driver needs from one side of a merge after its MAC and
/// signature verified: the signature, and the meta the trust rules look at.
pub(crate) struct VerifiedSide {
    pub signature: types::SignatureState,
    pub signer_vk: Option<String>,
    pub registry: BTreeMap<String, String>,
    pub names: HashMap<String, String>,
    pub groups: BTreeMap<String, Vec<String>>,
    pub grants: BTreeMap<String, types::GrantEntry>,
}

/// Verify one side of a merge the way a load does (meta, MAC, signature)
/// without decrypting any secret.
pub(crate) fn verify_side(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<VerifiedSide, MurkError> {
    let state = resolve_meta_state(vault, identity)?;
    Ok(VerifiedSide {
        signature: state.signature,
        signer_vk: state.signer_vk,
        registry: state.signers,
        names: state.recipients,
        groups: state.groups,
        grants: state.grants,
    })
}

/// Decrypt a vault using the given identity. Verifies integrity, decrypts all
/// shared and scoped values, and returns the working state.
///
/// This checks the MAC and that any signature is valid, but NOT whether the
/// signer is trusted on this machine — that needs the vault path's trust pin.
/// Callers handing out secrets from a file on disk should use `load_vault`.
pub fn decrypt_vault(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<types::Murk, MurkError> {
    decrypt_vault_with_signature(vault, identity).map(|(mut murk, _)| {
        let pubkey = murk.loaded_by.clone().unwrap_or_default();
        drop_ghost_grants(vault, &mut murk, &pubkey);
        murk
    })
}

/// [`decrypt_vault`], also returning the registry verifying key a v1 age
/// signature verified against (for the trust check).
fn decrypt_vault_with_signature(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<(types::Murk, Option<String>), MurkError> {
    let pubkey = identity.pubkey_string()?;
    if crate::agents::loader_blob(vault, identity).is_some() {
        return Err(MurkError::Grant(
            "an agent grant key reads a vault only through `load_vault`, which checks the \
             signature against the trusted signers in the grant's key file"
                .into(),
        ));
    }

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
        signer_vk,
    } = resolve_meta_state(vault, identity)?;

    // This key opened the meta, so it is not an agent grant (a 3.x record
    // bound to it is a ghost, dropped after the trust check). A 2.x vault
    // still encrypted its meta to grants; a grant key reading one has no trust
    // anchor, so it is refused until the operator re-saves.
    if vault.version.starts_with("2.")
        && grants
            .values()
            .any(|g| crate::recipients::same_recipient(&g.pubkey, &pubkey))
    {
        return Err(MurkError::Grant(
            "this vault predates murk 0.14's agent records, so an agent grant can't read \
             it: ask the operator to save it with murk 0.14 or later and re-mint the grant"
                .into(),
        ));
    }

    // Decrypt shared values (skip scoped-only entries with empty shared ciphertext).
    let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        if entry.shared.is_empty() {
            continue;
        }
        let Ok(plaintext) = decrypt_value(&entry.shared, identity) else {
            return Err(not_a_recipient());
        };
        let value = plaintext_bytes_to_zeroizing_string(&plaintext)
            .map_err(|e| MurkError::Secret(format!("invalid UTF-8 in secret {key}: {e}")))?;
        values.insert(key.clone(), value);
    }

    let private = own_private(vault, identity, &pubkey);

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

    Ok((
        types::Murk {
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
            loaded_by: Some(pubkey),
            loaded_as_grant: false,
        },
        signer_vk,
    ))
}

/// Decrypt `pubkey`'s private (per-recipient) values — the `me` tier, and an
/// agent grant's scoped copies.
fn own_private(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
    pubkey: &str,
) -> HashMap<String, HashMap<String, Zeroizing<String>>> {
    let mut private: HashMap<String, HashMap<String, Zeroizing<String>>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        // An older murk may have keyed ours by another spelling of our key (an
        // SSH comment, an uppercase age key), so match by canonical key; the
        // value is filed under our canonical pubkey either way.
        if let Some(encoded) = crate::recipients::scoped_entry_for(entry, pubkey)
            && let Ok(value) = decrypt_value(encoded, identity).and_then(|pt| {
                plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| MurkError::Secret(e.to_string()))
            })
        {
            private
                .entry(key.clone())
                .or_default()
                .insert(pubkey.to_string(), value);
        }
    }
    private
}

/// Load `vault` as the agent grant `identity`, whose `agents` blob is `blob`.
///
/// The grant can't read the meta, so nothing inside the vault is trusted
/// first: the signature must verify under a trusted signer named in the
/// grant's key file (`key_text`) or `MURK_TRUSTED_SIGNERS`. Only then is the
/// grant's own record decrypted and its TTL checked, and only then its scoped
/// values. No pin is read or written.
fn inspect_as_grant(
    vault: types::Vault,
    identity: crypto::MurkIdentity,
    key_text: &str,
    blob: &str,
) -> Result<InspectedVault, MurkError> {
    let pubkey = identity.pubkey_string()?;
    let mut anchor = crate::agents::anchor_from_key_text(key_text).map_err(MurkError::Key)?;
    if let Some(env) = trust::env_trusted_signers().map_err(MurkError::Key)? {
        anchor.extend(env);
    }
    if anchor.is_empty() {
        return Err(MurkError::Grant(
            "this grant key names no trusted signers, so murk can't check the vault it reads: \
             ask the operator to re-mint the grant (`murk agent grant --renew`), or set \
             MURK_TRUSTED_SIGNERS"
                .into(),
        ));
    }
    let signer = trust::verify_anchored(&vault, &anchor).map_err(|r| {
        MurkError::Trust(match r {
            trust::Refusal::Unsigned => {
                "refusing to read: the vault is unsigned, and an agent grant trusts only a vault \
                 signed by one of the signers in its key file"
                    .into()
            }
            trust::Refusal::UntrustedSigner { signer } => format!(
                "refusing to read: the vault is signed by {}, which is not a trusted signer in this \
                 grant's key file. If the operator's signer changed, ask them to re-mint the grant",
                crate::truncate_pubkey(&signer)
            ),
            other => format!(
                "refusing to read: the vault signature does not verify under the trusted signer \
                 in this grant's key file ({other:?}) — it may have been tampered with"
            ),
        })
    })?;
    let record = crate::agents::open_blob(blob, &identity, &pubkey)?;
    policy::check_grant_expiry(&record.name, &record.grant, chrono::Utc::now())?;
    let v = vault.sig.as_ref().map_or(0, |s| s.v);
    let murk = types::Murk {
        private: own_private(&vault, &identity, &pubkey),
        grants: BTreeMap::from([(record.name, record.grant)]),
        signature: types::SignatureState::Signed { signer, v },
        loaded_by: Some(pubkey),
        loaded_as_grant: true,
        ..Default::default()
    };
    Ok(InspectedVault {
        vault,
        murk,
        identity,
        assessment: trust::Assessment {
            verdict: trust::Verdict::Trusted,
            pin: None,
            env_signers: None,
        },
        signer_vk: None,
        grant: true,
    })
}

/// A decrypted vault and this machine's trust verdict on it, before anything
/// is handed out. `load_vault` refuses unless the verdict accepts it; `murk
/// trust`, `murk verify` and `murk diff` inspect it instead.
pub struct InspectedVault {
    pub vault: types::Vault,
    pub murk: types::Murk,
    pub identity: crypto::MurkIdentity,
    pub assessment: trust::Assessment,
    signer_vk: Option<String>,
    /// Loaded as an agent grant ([`inspect_as_grant`]): trusted by its key
    /// file's anchor, never by this machine's pin.
    grant: bool,
}

impl InspectedVault {
    /// The view of this vault the trust rules use.
    pub fn loaded(&self) -> trust::Loaded<'_> {
        trust::Loaded {
            vault: &self.vault,
            signature: &self.murk.signature,
            signer_vk: self.signer_vk.as_deref(),
            registry: &self.murk.signers,
            names: &self.murk.recipients,
            groups: &self.murk.groups,
            grants: &self.murk.grants,
            loader_can_sign: self.identity.is_signing_capable(),
            operator_key: crypto::operator_key(&self.identity),
        }
    }

    /// The refusal, if the verdict refuses.
    pub fn refusal(&self) -> Option<&trust::Refusal> {
        match &self.assessment.verdict {
            trust::Verdict::Refused(r) => Some(r),
            _ => None,
        }
    }

    /// The user-facing message for a refusal.
    pub fn refusal_message(&self, vault_path: &str) -> Option<String> {
        self.refusal().map(|r| {
            trust::refusal_message(vault_path, r, &self.loaded(), self.assessment.pin.as_ref())
        })
    }

    /// Record this vault as accepted in the trust pin — the explicit `murk
    /// trust` decision. `reset_counter` lowers the rollback high-water mark to
    /// this vault's counter (an older revision accepted on purpose). A v1
    /// signer's verifying key is replaced by the one this vault carries.
    pub fn record_trust(&self, vault_path: &str, reset_counter: bool) -> Result<(), String> {
        if self.grant {
            return Err(
                "an agent grant can't record trust: its key file names the signers it trusts"
                    .into(),
            );
        }
        let mut pin = trust::accepted_pin(
            &self.loaded(),
            self.assessment.pin.as_ref(),
            reset_counter,
            &trust::head_of(vault_path),
        );
        if let (types::SignatureState::Signed { signer, .. }, Some(vk)) =
            (&self.murk.signature, &self.signer_vk)
        {
            pin.signers.insert(
                crate::recipients::canonical_recipient(signer).into_owned(),
                vk.clone(),
            );
        }
        crate::pins::write(vault_path, &pin)
    }

    /// Refuse unless the verdict accepts the vault; on acceptance, update the
    /// pin. The update is best-effort: the vault is trusted either way, so a
    /// pin that cannot be written (read-only home) only warns. When the trust
    /// came from `MURK_TRUSTED_SIGNERS`, the pin's trusted set is left as it
    /// was, so the environment variable never widens trust that outlives it.
    pub fn into_trusted(
        self,
        vault_path: &str,
    ) -> Result<(types::Vault, types::Murk, crypto::MurkIdentity), MurkError> {
        match &self.assessment.verdict {
            trust::Verdict::Refused(_) => {
                let msg = self.refusal_message(vault_path).unwrap_or_default();
                return Err(MurkError::Trust(msg));
            }
            trust::Verdict::Trusted if self.grant => {}
            trust::Verdict::Trusted => {
                let prior = self.assessment.pin.as_ref();
                let mut pin =
                    trust::accepted_pin(&self.loaded(), prior, false, &trust::head_of(vault_path));
                if self.assessment.env_signers.is_some() {
                    let prior = prior.cloned().unwrap_or_default();
                    pin.trusted = prior.trusted;
                    pin.ever_trusted = prior.ever_trusted;
                    pin.signers = prior.signers;
                    pin.groups = prior.groups;
                }
                if prior != Some(&pin)
                    && crate::pins::signer_pin_available()
                    && let Err(e) = crate::pins::write(vault_path, &pin)
                {
                    eprintln!("warn {e}");
                }
            }
            trust::Verdict::UnsignedAllowed => {}
        }
        Ok((self.vault, self.murk, self.identity))
    }
}

/// Resolve the key from the environment, read and decrypt the vault, and
/// assess it against this machine's trust state without enforcing the verdict.
pub fn inspect_vault(vault_path: &str) -> Result<InspectedVault, MurkError> {
    let secret_key = env::resolve_key_for_vault(vault_path).map_err(MurkError::Key)?;

    let identity = crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
        // Same shape as the not-set error: summary first, one action per line.
        MurkError::Key(format!(
            "{e}\nfor an age key, set MURK_KEY\nfor an SSH key, set MURK_KEY_FILE=~/.ssh/id_ed25519"
        ))
    })?;

    let vault = read_vault(vault_path)?;
    if let Some(blob) = crate::agents::loader_blob(&vault, &identity) {
        return inspect_as_grant(vault, identity, secret_key.expose_secret(), &blob);
    }
    let (murk, signer_vk) = decrypt_vault_with_signature(&vault, &identity)?;
    let mut inspected = InspectedVault {
        vault,
        murk,
        identity,
        assessment: trust::Assessment {
            verdict: trust::Verdict::UnsignedAllowed,
            pin: None,
            env_signers: None,
        },
        signer_vk,
        grant: false,
    };
    inspected.assessment =
        trust::assess(vault_path, &inspected.loaded(), None).map_err(MurkError::Trust)?;
    let pubkey = inspected.identity.pubkey_string()?;
    drop_ghost_grants(&inspected.vault, &mut inspected.murk, &pubkey);
    Ok(inspected)
}

/// Resolve the key from the environment, read the vault, decrypt it, and
/// refuse it unless this machine trusts it (see [`crate::trust`]).
///
/// Every path that hands out or re-encrypts secrets goes through here — the
/// CLI, the MCP server and the Python/Node bindings — so the same rules apply
/// everywhere.
pub fn load_vault(
    vault_path: &str,
) -> Result<(types::Vault, types::Murk, crypto::MurkIdentity), MurkError> {
    inspect_vault(vault_path)?.into_trusted(vault_path)
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
        let stale_meta = decrypt_meta(&tampered, &identity).unwrap().unwrap();
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
    fn forged_header_field_with_recomputed_mac_fails_load() {
        // An outsider rewrites a header identity field, re-MACs with a fresh key
        // and re-encrypts the meta to the public recipient key, keeping the
        // stale signature. The signature must cover the header, so load fails.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", home.path()) };
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };

        let forge: [(&str, VaultRewrite); 3] = [
            ("vault_name", |v| v.vault_name = "payments-prod".into()),
            ("repo", |v| v.repo = "https://github.com/evil/fork".into()),
            ("created", |v| v.created = "2020-01-01T00:00:00Z".into()),
        ];
        let mut failures = Vec::new();
        for (field, rewrite) in forge {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.murk");
            let ps = path.to_str().unwrap();
            let mut vault = signed_test_vault(&pubkey, &recipient);
            let original = types::Murk {
                values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
                recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
                ..Default::default()
            };
            save_vault(ps, &mut vault, &original, &original).unwrap();

            let mut tampered: types::Vault =
                serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            let stale_meta = decrypt_meta(&tampered, &identity).unwrap().unwrap();
            rewrite(&mut tampered);
            let mac_key_hex = generate_mac_key();
            let mac_key = decode_mac_key(&mac_key_hex).unwrap();
            let forged_meta = types::Meta {
                mac: compute_mac(
                    &tampered,
                    &stale_meta.groups,
                    &stale_meta.grants,
                    Some(&mac_key),
                ),
                mac_key: Some(mac_key_hex),
                ..stale_meta
            };
            tampered.meta = encrypt_value(
                &serde_json::to_vec(&forged_meta).unwrap(),
                std::slice::from_ref(&recipient),
            )
            .unwrap();
            fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

            match load_vault(ps) {
                Err(e) if e.to_string().contains("signature is invalid") => {}
                other => failures.push(format!("{field}: {:?}", other.map(|_| ()))),
            }
        }
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(
            failures.is_empty(),
            "forged header fields loaded: {failures:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one case per untrusted meta field
    fn load_rejects_invalid_meta_fields_naming_them() {
        // The meta blob is re-encryptable by anyone holding the public
        // recipient keys, so its fields are untrusted and checked on load.
        type Mutate<'a> = Box<dyn Fn(&mut types::Meta) + 'a>;
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.murk");

        let mut vault = signed_test_vault(&pubkey, &recipient);
        let original = types::Murk {
            values: HashMap::from([("API_KEY".into(), crate::testutil::secret("REAL"))]),
            recipients: HashMap::from([(pubkey.clone(), "alice".to_string())]),
            ..Default::default()
        };
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        let grant = |expires_at: &str| types::GrantEntry {
            pubkey: pubkey.clone(),
            scope: vec!["API_KEY".into()],
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: expires_at.into(),
            issuer: pubkey.clone(),
        };
        let cases: Vec<(&str, Mutate)> = vec![
            (
                "meta.grants[codex].expires_at: not an RFC 3339",
                Box::new(|m| {
                    m.grants.insert("codex".into(), grant("tomorrow"));
                }),
            ),
            (
                "meta.grants key: invalid grant name",
                Box::new(|m| {
                    m.grants
                        .insert("../x".into(), grant("2026-01-02T00:00:00Z"));
                }),
            ),
            (
                "meta.groups key: invalid group name",
                Box::new(|m| {
                    m.groups.insert("a b".into(), vec![pubkey.clone()]);
                }),
            ),
            (
                "meta.groups[prod] member: not a valid",
                Box::new(|m| {
                    m.groups.insert("prod".into(), vec!["age1nope".into()]);
                }),
            ),
            (
                "contains control characters",
                Box::new(|m| {
                    m.recipients.insert(pubkey.clone(), "\u{1b}[2Jalice".into());
                }),
            ),
            (
                "meta.github_pins key: invalid GitHub username",
                Box::new(|m| {
                    m.github_pins
                        .insert("../../evil".into(), vec!["SHA256:abc".into()]);
                }),
            ),
            (
                "meta.mac_key: not a 64-character hex key",
                Box::new(|m| m.mac_key = Some("zz".into())),
            ),
            (
                "meta.groups key: invalid group name \\u{1b}[31mprod",
                Box::new(|m| {
                    m.groups
                        .insert("\u{1b}[31mprod".into(), vec![pubkey.clone()]);
                }),
            ),
            (
                "meta.grants key: invalid grant name \\u{1b}]0;pwned\\u{7}",
                Box::new(|m| {
                    m.grants
                        .insert("\u{1b}]0;pwned\u{7}".into(), grant("2026-01-02T00:00:00Z"));
                }),
            ),
        ];
        for (expected, mutate) in cases {
            let mut tampered: types::Vault = serde_json::from_str(&saved).unwrap();
            let mut meta = decrypt_meta(&tampered, &identity).unwrap().unwrap();
            mutate(&mut meta);
            tampered.meta = encrypt_value(
                &serde_json::to_vec(&meta).unwrap(),
                std::slice::from_ref(&recipient),
            )
            .unwrap();
            fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

            let err = load_vault(path.to_str().unwrap())
                .expect_err(&format!("expected rejection: {expected}"))
                .to_string();
            assert!(
                err.contains("vault meta is invalid") && err.contains(expected),
                "want {expected:?}, got {err:?}"
            );
            assert!(
                !err.chars().any(char::is_control),
                "raw control char in {err:?}"
            );

            // The best-effort reader (info, circle, merge) fails closed too.
            let other = decrypt_meta(&tampered, &identity)
                .expect_err(&format!("decrypt_meta must reject: {expected}"));
            assert!(other.contains(expected), "want {expected:?}, got {other:?}");
            assert!(
                !other.chars().any(char::is_control),
                "raw control char in {other:?}"
            );
        }
        unsafe { std::env::remove_var("MURK_KEY") };
    }

    #[test]
    fn legacy_registry_vk_swap_is_refused_on_load() {
        // A murk ≤ 0.13 (v1) signature verifies against the signer registry in
        // the re-encryptable meta. An attacker can register their OWN verifying
        // key under a trusted recipient's pubkey and forge a v1 signature the
        // signature layer accepts. The trust check must refuse it: the pin holds
        // no verifying key for that signer that this machine accepted.
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
        let stale = decrypt_meta(&tampered, &identity).unwrap().unwrap();
        tampered.secrets.get_mut("API_KEY").unwrap().shared =
            encrypt_value(b"POISON", std::slice::from_ref(&recipient)).unwrap();
        // A v1 signature only verifies on a pre-3.0 vault without the v2
        // header fields, and lives inside the meta.
        tampered.version = "2.0".into();
        tampered.vault_id.clear();
        tampered.generation = 0;
        tampered.sig = None;
        let mut signers = stale.signers.clone();
        signers.insert(pubkey.clone(), att_vk);
        let msg = crate::signature::signing_message(
            &tampered,
            &stale.groups,
            &stale.grants,
            &stale.github_pins,
            &signers,
        );
        let forged_sig = types::VaultSignature {
            signer: pubkey.clone(),
            v: crate::signature::LEGACY_SIGNED_VIEW_VERSION,
            sig: signing::sign(&att_sk, &msg),
        };
        // The signature layer alone IS fooled — it verifies against the swapped key.
        assert!(
            verify_vault_signature(
                &tampered,
                &stale.groups,
                &stale.grants,
                &stale.github_pins,
                &signers,
                &forged_sig
            )
            .is_some()
        );
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

        // The trust check refuses it even though the signature verifies.
        let err = load_vault(ps).unwrap_err();
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        // Refused for the swapped key (and, the pin having seen the vault in
        // 0.14 form, it would be refused as a rollback next).
        assert!(
            err.to_string().contains("signing key that is not theirs"),
            "expected a changed-key refusal, got: {err}"
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
    fn load_vault_refuses_a_stripped_signature() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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

        // Strip the signature: it lives outside the meta and the MAC does not
        // cover it, so dropping it leaves a clean unsigned downgrade.
        let mut on_disk = read_vault(path_str).unwrap();
        on_disk.sig = None;
        vault::write(std::path::Path::new(path_str), &on_disk).unwrap();

        // Second load: refused, with or without MURK_STRICT.
        let err = load_vault(path_str).expect_err("a stripped signature must be refused");
        assert!(
            err.to_string()
                .contains("was signed when this machine last accepted it"),
            "{err}"
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
        // Damaged meta must never read as "not a recipient"; non-base64 meta
        // is refused at parse time, naming the field.
        let mut garbled: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        garbled.meta = "not-base64!!".into();
        fs::write(&path, serde_json::to_string_pretty(&garbled).unwrap()).unwrap();

        let result = load_vault(path.to_str().unwrap());

        let err = result
            .expect_err("expected corrupt meta to fail")
            .to_string();
        assert!(
            err.contains("meta: not valid base64") && !err.contains("not a recipient"),
            "expected meta to be rejected as invalid, got: {err}"
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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

    /// One person's machine: their HOME (and so their trust pin) and key.
    struct Machine {
        home: tempfile::TempDir,
        secret: String,
        pubkey: String,
    }

    impl Machine {
        fn new() -> Self {
            let (secret, pubkey) = generate_keypair();
            Self {
                home: tempfile::tempdir().unwrap(),
                secret,
                pubkey,
            }
        }

        /// Run `f` as this person. Caller holds ENV_LOCK.
        fn run<T>(&self, f: impl FnOnce() -> T) -> T {
            unsafe {
                std::env::set_var("HOME", self.home.path());
                std::env::set_var("MURK_KEY", &self.secret);
                std::env::remove_var("MURK_KEY_FILE");
                std::env::remove_var("MURK_NO_SIGNER_PIN");
                std::env::remove_var("MURK_TRUSTED_SIGNERS");
            }
            f()
        }

        /// Load, apply `change`, save.
        fn write(&self, path: &str, change: impl FnOnce(&mut types::Vault, &mut types::Murk)) {
            self.run(|| {
                let (mut vault, original, _) = load_vault(path).unwrap();
                let mut current = original.clone();
                change(&mut vault, &mut current);
                save_vault(path, &mut vault, &original, &current).unwrap();
            });
        }

        /// Accept whatever the vault is now, as `murk trust` does.
        fn trust(&self, path: &str) {
            self.run(|| {
                inspect_vault(path)
                    .unwrap()
                    .record_trust(path, false)
                    .unwrap();
            });
        }

        fn pin_bytes(&self, path: &str) -> Vec<u8> {
            self.run(|| fs::read(crate::pins::pin_path(path).unwrap()).unwrap())
        }
    }

    fn grant_to(pubkey: &str, issuer: &str) -> types::GrantEntry {
        types::GrantEntry {
            pubkey: pubkey.into(),
            scope: vec!["DB_URL".into()],
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            issuer: issuer.into(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one scenario across three machines
    fn a_grant_record_bound_to_a_trusted_signer_is_refused_without_touching_the_pin() {
        // Bob, a trusted signer, writes a grant record bound to Alice's
        // operator key and signs it. Carol's machine must refuse that vault
        // as tampering and leave her pin as it was, so Alice's later signed
        // vaults still load there. A genuine grant still pins as a grant.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_home = std::env::var_os("HOME");
        let (alice, bob, carol) = (Machine::new(), Machine::new(), Machine::new());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.murk");
        let path = path.to_str().unwrap();

        alice.run(|| {
            let id = crypto::parse_identity(&alice.secret).unwrap();
            let v = crate::create_vault("team.murk", &id, "alice").unwrap();
            vault::write(std::path::Path::new(path), &v).unwrap();
            crate::pin_created_vault(path, &v, &id).unwrap();
        });
        alice.write(path, |vault, murk| {
            for (pk, name) in [(&bob.pubkey, "bob"), (&carol.pubkey, "carol")] {
                vault.recipients.push(pk.clone());
                murk.recipients.insert(pk.clone(), name.into());
            }
            murk.values
                .insert("DB_URL".into(), crate::testutil::secret("prod-db"));
        });
        for m in [&bob, &carol] {
            m.trust(path);
        }
        // Bob's first write; Carol and Alice confirm his key.
        bob.write(path, |_, murk| {
            murk.values.insert("B".into(), crate::testutil::secret("1"));
        });
        for m in [&carol, &alice] {
            m.trust(path);
        }
        carol.run(|| load_vault(path).unwrap());
        let good = fs::read(path).unwrap();

        // The ghost grant: Bob binds a grant record to Alice's key.
        bob.write(path, |_, murk| {
            murk.grants
                .insert("ghost".into(), grant_to(&alice.pubkey, &bob.pubkey));
        });
        let pin_before = carol.pin_bytes(path);
        let err = carol.run(|| load_vault(path).map(|_| ()).unwrap_err());
        assert!(
            err.to_string().contains("ghost") && err.to_string().contains("alice"),
            "{err}"
        );
        assert_eq!(
            carol.pin_bytes(path),
            pin_before,
            "nothing recorded from it"
        );
        // murk trust will not accept it either.
        let refusal = carol.run(|| inspect_vault(path).unwrap().refusal().cloned());
        assert!(refusal.is_some_and(|r| !r.acceptable()));

        // The vault is restored; Alice's next signed write loads at Carol's.
        fs::write(path, &good).unwrap();
        alice.write(path, |_, murk| {
            murk.values.insert("A".into(), crate::testutil::secret("2"));
        });
        let (_, murk, _) = carol.run(|| load_vault(path).unwrap());
        assert_eq!(murk.values["A"].as_str(), "2");

        // A genuine grant (a fresh agent key) still pins as a grant.
        let (_, agent) = generate_keypair();
        alice.write(path, |vault, murk| {
            vault.recipients.push(agent.clone());
            murk.recipients.insert(agent.clone(), "agent:ci".into());
            murk.grants
                .insert("ci".into(), grant_to(&agent, &alice.pubkey));
        });
        carol.run(|| load_vault(path).unwrap());
        let pin = carol.run(|| crate::pins::read(path).unwrap().unwrap());
        assert!(pin.grants.contains(&agent));
        assert!(!pin.grants.contains(&alice.pubkey));
        assert!(pin.trusted.contains(&alice.pubkey));

        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }
}
