// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an agent grant gets instead of the vault meta.
//!
//! The meta holds the MAC key, recipient names, groups, signers and every
//! grant, so whoever can read it can re-MAC a hand-edited vault and sees the
//! team's structure. Grants are not meta recipients. Each grant instead gets
//! an `agents` blob encrypted to its key alone, holding only its own record
//! ([`AgentMeta`]), plus its scoped values as before.
//!
//! A grant can't check the MAC, so it trusts a vault only by its signature,
//! and only against signers named outside the vault: the anchor lines the
//! operator writes into the grant's key file when minting it (plus
//! `MURK_TRUSTED_SIGNERS`). Nothing inside the vault is consulted for that.

use std::collections::BTreeMap;

use crate::error::MurkError;
use crate::trust::TrustedSigners;
use crate::types::{self, AgentMeta};
use crate::{crypto, decrypt_value, encrypt_value};

/// The key-file line that names one trusted signer, in the
/// [`crate::trust::parse_trusted_signer`] format.
pub const ANCHOR_PREFIX: &str = "# murk-trusted-signer:";

/// The trusted signers named in a grant key file's anchor lines. Lines that
/// aren't anchor lines (the key itself, age's own comments) are skipped; a
/// malformed anchor line is an error rather than a silently smaller anchor.
pub fn anchor_from_key_text(text: &str) -> Result<TrustedSigners, String> {
    let mut out = TrustedSigners::new();
    for line in text.lines() {
        let Some(entry) = line.trim().strip_prefix(ANCHOR_PREFIX) else {
            continue;
        };
        let (key, vk) = crate::trust::parse_trusted_signer(entry)
            .map_err(|e| format!("grant key file: {e}"))?;
        out.insert(key, vk);
    }
    Ok(out)
}

/// The anchor lines to write above a new grant key: this machine's pinned
/// trusted signers for `vault_path`, plus `minter` (who just signed the vault
/// the grant first reads). Empty when nobody here can sign.
pub fn anchor_lines(vault_path: &str, minter: &crypto::MurkIdentity) -> Result<String, String> {
    let mut signers = crate::trust::pinned_trusted_signers(vault_path)?;
    if let (Ok(pk), Some(sk)) = (minter.pubkey_string(), minter.signing_key()) {
        let canonical = crypto::canonical_recipient(&pk);
        let vk = (!canonical.starts_with("ssh-")).then(|| sk.verifying_key());
        signers.insert(canonical, vk);
    }
    let mut out = String::new();
    for (key, vk) in &signers {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "{ANCHOR_PREFIX} {}",
            crate::trust::format_trusted_signer(key, vk.as_deref())
        );
    }
    Ok(out)
}

/// The `agents` entry for `pubkey`, matched canonically.
pub(crate) fn blob_for<'a>(vault: &'a types::Vault, pubkey: &str) -> Option<&'a String> {
    let want = crypto::canonical_recipient(pubkey);
    vault
        .agents
        .iter()
        .find(|(k, _)| crypto::canonical_recipient(k) == want)
        .map(|(_, blob)| blob)
}

/// Decrypt and check the grant record in `blob` for `pubkey`.
pub(crate) fn open_blob(
    blob: &str,
    identity: &crypto::MurkIdentity,
    pubkey: &str,
) -> Result<AgentMeta, MurkError> {
    let corrupt = || {
        MurkError::Integrity(
            "your agent grant record is corrupt — the vault may have been tampered with".into(),
        )
    };
    let plaintext = decrypt_value(blob, identity).map_err(|_| corrupt())?;
    let meta: AgentMeta = serde_json::from_slice(&plaintext).map_err(|_| corrupt())?;
    if crypto::canonical_recipient(&meta.grant.pubkey) != crypto::canonical_recipient(pubkey)
        || crate::grants::validate_grant_name(&meta.name).is_err()
    {
        return Err(corrupt());
    }
    Ok(meta)
}

/// Rebuild `vault.agents` for the grants in `current`: one blob per grant,
/// encrypted to that grant's key alone. A grant whose record is unchanged
/// since load keeps its blob (no churn in the diff); blobs for grants that are
/// gone are dropped.
pub(crate) fn rebuild(
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    let agents = blobs_for(&current.grants, &[(vault, &original.grants)])?;
    vault.agents = agents;
    Ok(())
}

/// One `agents` blob per grant in `grants`. A grant whose record equals the
/// one in a `previous` vault's grants reuses that vault's blob; any other is
/// encrypted afresh to the grant's key alone.
pub(crate) fn blobs_for(
    grants: &BTreeMap<String, types::GrantEntry>,
    previous: &[(&types::Vault, &BTreeMap<String, types::GrantEntry>)],
) -> Result<BTreeMap<String, String>, MurkError> {
    let mut agents = BTreeMap::new();
    for (name, grant) in grants {
        let kept = previous
            .iter()
            .filter(|(_, prev)| prev.get(name) == Some(grant))
            .find_map(|(vault, _)| blob_for(vault, &grant.pubkey))
            .cloned();
        let blob = if let Some(blob) = kept {
            blob
        } else {
            let record = AgentMeta {
                name: name.clone(),
                grant: grant.clone(),
            };
            let json = serde_json::to_vec(&record)
                .map_err(|e| MurkError::Secret(format!("agent record serialize: {e}")))?;
            encrypt_value(&json, &[crypto::parse_recipient(&grant.pubkey)?])?
        };
        agents.insert(grant.pubkey.clone(), blob);
    }
    Ok(agents)
}

/// `recipients` without the keys of `grants`: who the meta is encrypted to.
pub(crate) fn meta_recipients(
    recipients: &[String],
    grants: &BTreeMap<String, types::GrantEntry>,
) -> Vec<String> {
    let grant_keys: std::collections::BTreeSet<String> = grants
        .values()
        .map(|g| crypto::canonical_recipient(&g.pubkey))
        .collect();
    recipients
        .iter()
        .filter(|pk| !grant_keys.contains(&crypto::canonical_recipient(pk)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_lines_round_trip_and_other_lines_are_ignored() {
        let (sk, pk) = crate::testutil::generate_keypair();
        let id = crate::testutil::make_identity(&sk);
        let vk = id.signing_key().unwrap().verifying_key();
        let text = format!("# created: today\n{ANCHOR_PREFIX} {pk}:{vk}\nAGE-SECRET-KEY-1ABC\n");
        let anchor = anchor_from_key_text(&text).unwrap();
        assert_eq!(anchor.get(&pk), Some(&Some(vk)));
        assert_eq!(anchor.len(), 1);
        assert!(anchor_from_key_text(&format!("{ANCHOR_PREFIX} {pk}\n")).is_err());
    }
}
