//! Three-way merge driver for `.murk` vault files.
//!
//! Operates at the Vault struct level: recipients as a set, schema and secrets
//! as key-level maps. Ciphertext equality against the base determines whether
//! a side modified a value (murk preserves ciphertext for unchanged values).

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{Policy, SecretEntry, Vault};

/// A single conflict discovered during merge.
#[derive(Debug)]
pub struct MergeConflict {
    pub field: String,
    pub reason: String,
}

/// Result of a three-way vault merge.
#[derive(Debug)]
pub struct MergeResult {
    pub vault: Vault,
    pub conflicts: Vec<MergeConflict>,
}

/// Three-way merge of vault files at the struct level.
///
/// `base` is the common ancestor, `ours` is the current branch,
/// `theirs` is the incoming branch. Returns the merged vault and any conflicts.
/// On conflict, the conflicting field keeps the "ours" value.
pub fn merge_vaults(base: &Vault, ours: &Vault, theirs: &Vault) -> MergeResult {
    let mut conflicts = Vec::new();

    // -- Static fields: take ours --
    let version = ours.version.clone();
    let created = ours.created.clone();
    let vault_name = ours.vault_name.clone();
    let repo = ours.repo.clone();

    // -- Recipients: set union/removal --
    let recipients = merge_recipients(base, ours, theirs, &mut conflicts);

    // Detect recipient-change sides (triggers full re-encryption).
    let base_recip: BTreeSet<&str> = base.recipients.iter().map(String::as_str).collect();
    let ours_recip: BTreeSet<&str> = ours.recipients.iter().map(String::as_str).collect();
    let theirs_recip: BTreeSet<&str> = theirs.recipients.iter().map(String::as_str).collect();
    let ours_changed_recipients = ours_recip != base_recip;
    let theirs_changed_recipients = theirs_recip != base_recip;

    // -- Schema: key-level merge --
    let schema = merge_btree(
        &base.schema,
        &ours.schema,
        &theirs.schema,
        "schema",
        &mut conflicts,
    );

    // -- Secrets: key-level merge with ciphertext comparison --
    let secrets = merge_secrets(
        base,
        ours,
        theirs,
        ours_changed_recipients,
        theirs_changed_recipients,
        &mut conflicts,
    );

    // -- Meta: take ours for now; the CLI command handles regeneration --
    let meta = ours.meta.clone();

    let vault = Vault {
        version,
        created,
        vault_name,
        repo,
        recipients,
        schema,
        policy: merge_policy(
            base.policy.as_ref(),
            ours.policy.as_ref(),
            theirs.policy.as_ref(),
            &mut conflicts,
        ),
        secrets,
        meta,
    };

    MergeResult { vault, conflicts }
}

/// Merge the header policy three-way. The policy is a security guardrail, so a
/// change on either side must not be silently dropped (taking "ours" blindly
/// would discard a tightening from the other branch and re-MAC it as valid).
/// Take the side that changed from base; if both changed differently, keep ours
/// and flag a conflict for a human to resolve.
fn merge_policy(
    base: Option<&Policy>,
    ours: Option<&Policy>,
    theirs: Option<&Policy>,
    conflicts: &mut Vec<MergeConflict>,
) -> Option<Policy> {
    if ours == theirs {
        return ours.cloned();
    }
    if ours == base {
        return theirs.cloned(); // only theirs changed — take it
    }
    if theirs == base {
        return ours.cloned(); // only ours changed — take it
    }
    conflicts.push(MergeConflict {
        field: "policy".into(),
        reason: "agent policy changed on both sides".into(),
    });
    ours.cloned()
}

/// The first 12 *characters* of a recipient string, for a conflict label.
/// Recipients on the `theirs` side are unvalidated, attacker-controlled data,
/// so byte slicing (`&pk[..12]`) can panic mid-codepoint on multibyte input;
/// take chars to stay panic-free.
fn recipient_label(pk: &str) -> String {
    pk.chars().take(12).collect()
}

/// Merge recipient lists as sets: union additions, honor removals.
fn merge_recipients(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> Vec<String> {
    let base_set: BTreeSet<&str> = base.recipients.iter().map(String::as_str).collect();
    let ours_set: BTreeSet<&str> = ours.recipients.iter().map(String::as_str).collect();
    let theirs_set: BTreeSet<&str> = theirs.recipients.iter().map(String::as_str).collect();

    let ours_added: BTreeSet<&str> = ours_set.difference(&base_set).copied().collect();
    let theirs_added: BTreeSet<&str> = theirs_set.difference(&base_set).copied().collect();
    let ours_removed: BTreeSet<&str> = base_set.difference(&ours_set).copied().collect();
    let theirs_removed: BTreeSet<&str> = base_set.difference(&theirs_set).copied().collect();

    let mut result: BTreeSet<&str> = base_set;

    // Recipient addition requires both sides to agree, or it's a conflict.
    // Blind set-union would let a malicious branch silently grant access.
    for pk in &ours_added {
        if theirs_added.contains(pk) {
            // Both sides added the same recipient — safe.
            result.insert(pk);
        } else {
            // Only ours added — conflict. Include the recipient but flag it.
            result.insert(pk);
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", recipient_label(pk)),
                reason: "added on one side but not the other".into(),
            });
        }
    }
    for pk in &theirs_added {
        if !ours_added.contains(pk) {
            // Only theirs added — conflict.
            result.insert(pk);
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", recipient_label(pk)),
                reason: "added on one side but not the other".into(),
            });
        }
    }

    // Recipient removal requires both sides to agree, or it's a conflict.
    for pk in &ours_removed {
        if theirs_removed.contains(pk) {
            // Both sides removed — safe.
            result.remove(pk);
        } else {
            // Only ours removed — conflict. Keep the recipient (safer default).
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", recipient_label(pk)),
                reason: "removed on one side but not the other".into(),
            });
        }
    }
    for pk in &theirs_removed {
        if !ours_removed.contains(pk) {
            // Only theirs removed — conflict. Keep the recipient.
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", recipient_label(pk)),
                reason: "removed on one side but not the other".into(),
            });
        }
    }

    result.into_iter().map(String::from).collect()
}

/// Generic three-way merge for BTreeMap where values implement PartialEq + Clone.
fn merge_btree<V: PartialEq + Clone>(
    base: &BTreeMap<String, V>,
    ours: &BTreeMap<String, V>,
    theirs: &BTreeMap<String, V>,
    field_name: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, V> {
    let all_keys: BTreeSet<&str> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.get(key);
        let in_ours = ours.get(key);
        let in_theirs = theirs.get(key);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o == t {
                    result.insert(key.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "added on both sides with different values".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
            }

            // Both sides removed — safe to omit.
            (Some(_) | None, None, None) => {}
            // One side removed, other kept unchanged — conflict.
            (Some(b), Some(o), None) => {
                if o == b {
                    // Ours didn't touch it, theirs removed — conflict.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, unchanged on the other".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                } else {
                    // Ours modified AND theirs removed — keep the modified value
                    // (it must not be silently dropped) but flag it for review.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, modified on the other".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
            }
            (Some(b), None, Some(t)) => {
                if t == b {
                    // Theirs didn't touch it, ours removed — conflict.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, unchanged on the other".into(),
                    });
                    result.insert(key.to_string(), t.clone());
                } else {
                    // Theirs modified AND ours removed — keep the modified value
                    // (it must not be silently dropped) but flag it for review.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, modified on the other".into(),
                    });
                    result.insert(key.to_string(), t.clone());
                }
            }

            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o != b;
                let theirs_changed = t != b;

                match (ours_changed, theirs_changed) {
                    (false, true) => {
                        result.insert(key.to_string(), t.clone());
                    }
                    (true, true) if o != t => {
                        conflicts.push(MergeConflict {
                            field: format!("{field_name}.{key}"),
                            reason: "modified on both sides with different values".into(),
                        });
                        result.insert(key.to_string(), o.clone());
                    }
                    _ => {
                        result.insert(key.to_string(), o.clone());
                    }
                }
            }
        }
    }

    result
}

/// Merge secrets with ciphertext-equality-against-base comparison.
///
/// When one side changed recipients (triggering full re-encryption), that side's
/// ciphertext all differs from base. We detect this and use the re-encrypted side
/// as the baseline, applying the other side's additions/removals.
fn merge_secrets(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    ours_changed_recipients: bool,
    theirs_changed_recipients: bool,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    // If a side changed recipients, all its ciphertext differs from base, so
    // ciphertext-equality cannot detect that side's edits. Route on which
    // side(s) re-encrypted: use the re-encrypted side as the new baseline and
    // apply the other side's key-level diffs; if both did, only additions and
    // removals can be merged without decryption.
    match (ours_changed_recipients, theirs_changed_recipients) {
        (true, false) => {
            merge_secrets_with_reencrypted_side(base, ours, theirs, "theirs", conflicts)
        }
        (false, true) => merge_secrets_with_reencrypted_side(base, theirs, ours, "ours", conflicts),
        (true, true) => merge_secrets_both_reencrypted(base, ours, theirs, conflicts),
        (false, false) => merge_secrets_normal(base, ours, theirs, conflicts),
    }
}

/// Normal secret merge: compare ciphertext against base to detect changes.
fn merge_secrets_normal(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(ours.secrets.keys())
        .chain(theirs.secrets.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_ours = ours.secrets.get(key);
        let in_theirs = theirs.secrets.get(key);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o.shared == t.shared {
                    result.insert(key.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: "added on both sides (values may differ)".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
            }

            // Both removed or impossible key.
            (Some(_) | None, None, None) => {}

            (Some(b), Some(o), None) => {
                // Theirs removed, ours kept — always conflict.
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: if o.shared == b.shared {
                        "removed on one side, unchanged on the other".into()
                    } else {
                        "modified on our side but removed on theirs".into()
                    },
                });
                result.insert(key.to_string(), o.clone());
            }
            (Some(b), None, Some(t)) => {
                // Ours removed, theirs kept — always conflict.
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: if t.shared == b.shared {
                        "removed on one side, unchanged on the other".into()
                    } else {
                        "removed on our side but modified on theirs".into()
                    },
                });
                result.insert(key.to_string(), t.clone());
            }

            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o.shared != b.shared;
                let theirs_changed = t.shared != b.shared;

                let shared = match (ours_changed, theirs_changed) {
                    (false, true) => t.shared.clone(),
                    (true, true) => {
                        conflicts.push(MergeConflict {
                            field: format!("secrets.{key}"),
                            reason: "shared value modified on both sides".into(),
                        });
                        o.shared.clone()
                    }
                    _ => o.shared.clone(),
                };

                let private = merge_scoped(
                    &b.private, &o.private, &t.private, key, "private", conflicts,
                );
                let grouped = merge_scoped(
                    &b.grouped, &o.grouped, &t.grouped, key, "grouped", conflicts,
                );
                result.insert(
                    key.to_string(),
                    SecretEntry {
                        shared,
                        private,
                        grouped,
                    },
                );
            }
        }
    }

    result
}

/// Merge scoped (mote) entries within a single secret key.
/// Three-way merge of a per-name ciphertext map. Used for both `scoped`
/// (keyed by pubkey) and `grouped` (keyed by group name) — `kind` is the field
/// name used in conflict messages.
fn merge_scoped(
    base: &BTreeMap<String, String>,
    ours: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
    secret_key: &str,
    kind: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, String> {
    let all_pks: BTreeSet<&str> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for pk in all_pks {
        let in_base = base.get(pk);
        let in_ours = ours.get(pk);
        let in_theirs = theirs.get(pk);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(pk.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(pk.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o == t {
                    result.insert(pk.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.{kind}.{pk}"),
                        reason: format!("{kind} entry added on both sides"),
                    });
                    result.insert(pk.to_string(), o.clone());
                }
            }
            (Some(_) | None, None, None) => {}
            (Some(b), Some(o), None) => {
                if o != b {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.{kind}.{pk}"),
                        reason: format!("{kind} entry modified on our side but removed on theirs"),
                    });
                    result.insert(pk.to_string(), o.clone());
                }
            }
            (Some(b), None, Some(t)) => {
                if t != b {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.{kind}.{pk}"),
                        reason: format!("{kind} entry removed on our side but modified on theirs"),
                    });
                    result.insert(pk.to_string(), t.clone());
                }
            }
            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o != b;
                let theirs_changed = t != b;

                match (ours_changed, theirs_changed) {
                    (false, true) => {
                        result.insert(pk.to_string(), t.clone());
                    }
                    (true, true) if o != t => {
                        conflicts.push(MergeConflict {
                            field: format!("secrets.{secret_key}.{kind}.{pk}"),
                            reason: format!("{kind} entry modified on both sides"),
                        });
                        result.insert(pk.to_string(), o.clone());
                    }
                    _ => {
                        result.insert(pk.to_string(), o.clone());
                    }
                }
            }
        }
    }

    result
}

/// When one side re-encrypted (changed recipients), use it as the new baseline
/// and apply the other side's key-level additions/removals.
///
/// `reencrypted` is the side that changed recipients (all ciphertext differs from base).
/// `other` is the side with stable ciphertext. `other_label` is "ours" or "theirs" for messages.
fn merge_secrets_with_reencrypted_side(
    base: &Vault,
    reencrypted: &Vault,
    other: &Vault,
    other_label: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    // Start with the re-encrypted side's secrets (they have the new recipient set).
    let mut result = reencrypted.secrets.clone();

    // Detect what the other side added/removed/modified relative to base.
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(other.secrets.keys())
        .map(String::as_str)
        .collect();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_other = other.secrets.get(key);

        match (in_base, in_other) {
            (None, Some(entry)) => {
                if result.contains_key(key) {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: format!(
                            "added on {other_label} side and on the side that changed recipients"
                        ),
                    });
                } else {
                    result.insert(key.to_string(), entry.clone());
                }
            }
            (Some(_), None) => {
                // Other side removed this key. Honor the removal.
                result.remove(key);
            }
            (Some(b), Some(entry)) => {
                if entry.shared != b.shared || entry.private != b.private || entry.grouped != b.grouped {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: format!(
                            "modified on {other_label} side while recipients changed on the other"
                        ),
                    });
                }
                // If other side didn't modify, keep re-encrypted version.
            }
            (None, None) => {}
        }
    }

    result
}

/// Both sides changed recipients — all ciphertext on both sides differs from base.
/// Without decryption we can only merge keys that were added/removed (not modified).
fn merge_secrets_both_reencrypted(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(ours.secrets.keys())
        .chain(theirs.secrets.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_ours = ours.secrets.get(key);
        let in_theirs = theirs.secrets.get(key);

        match (in_base, in_ours, in_theirs) {
            // Both have it and it was in base — take ours.
            (Some(_), Some(o), Some(_)) | (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            // Removals — honor them.
            (Some(_), Some(_) | None, None) | (Some(_), None, Some(_)) | (None, None, None) => {}
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), Some(_)) => {
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: "added on both sides while both changed recipients".into(),
                });
                result.insert(key.to_string(), o.clone());
            }
        }
    }

    result
}

/// Output of the merge driver: the merge result and whether meta was regenerated.
#[derive(Debug)]
pub struct MergeDriverOutput {
    pub result: MergeResult,
    pub meta_regenerated: bool,
}

/// Run the three-way merge driver on vault contents (as strings).
///
/// Parses all three versions, merges, and attempts meta regeneration.
/// Returns the merged vault and conflict list. The caller is responsible for
/// writing the result to disk.
pub fn run_merge_driver(base: &str, ours: &str, theirs: &str) -> Result<MergeDriverOutput, String> {
    use crate::vault;

    let base_vault = vault::parse(base).map_err(|e| format!("parsing base: {e}"))?;
    let ours_vault = vault::parse(ours).map_err(|e| format!("parsing ours: {e}"))?;
    let theirs_vault = vault::parse(theirs).map_err(|e| format!("parsing theirs: {e}"))?;

    let mut result = merge_vaults(&base_vault, &ours_vault, &theirs_vault);
    let meta_regenerated = regenerate_meta(&mut result.vault, &ours_vault, &theirs_vault).is_some();

    Ok(MergeDriverOutput {
        result,
        meta_regenerated,
    })
}

/// Attempt to regenerate the meta blob for a merged vault.
///
/// Decrypts meta from `ours` and `theirs` to merge recipient name maps,
/// recomputes the MAC, and re-encrypts. Falls back to `ours.meta` if
/// MURK_KEY is unavailable.
pub fn regenerate_meta(merged: &mut Vault, ours: &Vault, theirs: &Vault) -> Option<String> {
    use crate::{compute_mac, crypto, decrypt_meta, encrypt_value, parse_recipients, resolve_key};
    use age::secrecy::ExposeSecret;
    use std::collections::HashMap;

    let secret_key = resolve_key().ok()?;
    let identity = crypto::parse_identity(secret_key.expose_secret()).ok()?;

    let default_meta = || crate::types::Meta {
        recipients: HashMap::new(),
        mac: String::new(),
        mac_key: None,
        github_pins: HashMap::new(),
        groups: BTreeMap::new(),
        grants: BTreeMap::new(),
        signers: BTreeMap::new(),
        sig: None,
    };

    let ours_meta = decrypt_meta(ours, &identity).unwrap_or_else(default_meta);
    let theirs_meta = decrypt_meta(theirs, &identity).unwrap_or_else(default_meta);

    // Merge name maps: union, ours wins on conflict.
    let mut names = theirs_meta.recipients;
    for (pk, name) in ours_meta.recipients {
        names.insert(pk, name);
    }

    // Only keep names for recipients still in the merged vault.
    names.retain(|pk, _| merged.recipients.contains(pk));

    // Merge group membership: union, ours wins on conflict. Drop members no
    // longer in the merged recipient set, and drop now-empty groups.
    let mut groups = theirs_meta.groups;
    for (name, members) in ours_meta.groups {
        groups.insert(name, members);
    }
    for members in groups.values_mut() {
        members.retain(|pk| merged.recipients.contains(pk));
    }
    groups.retain(|_, members| !members.is_empty());

    // Merge agent grants: union, ours wins on conflict. Drop grants whose
    // ephemeral pubkey is no longer in the merged recipient set.
    let mut grants = theirs_meta.grants;
    for (name, grant) in ours_meta.grants {
        grants.insert(name, grant);
    }
    grants.retain(|_, grant| merged.recipients.contains(&grant.pubkey));

    let mac_key_hex = crate::generate_mac_key();
    let mac_key = crate::decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(merged, &groups, &grants, Some(&mac_key));
    // Merge github pins: union, ours wins on conflict.
    let mut github_pins = theirs_meta.github_pins;
    for (user, pins) in ours_meta.github_pins {
        github_pins.insert(user, pins);
    }

    // Merge the signer registry (union, ours wins), retained to current
    // recipients. The merged vault is deliberately left UNSIGNED: the driver runs
    // non-interactively and must not vouch for content a human hasn't reviewed —
    // auto-signing here would re-bless one-sided value injection just as
    // auto-MACing did. `sig: None` makes the next load warn "unsigned"; any
    // keyholder write (after reviewing `murk diff`) re-signs it.
    let mut signers = theirs_meta.signers;
    for (pk, vk) in ours_meta.signers {
        signers.insert(pk, vk);
    }
    signers.retain(|pk, _| merged.recipients.contains(pk));

    let meta = crate::types::Meta {
        recipients: names,
        mac,
        mac_key: Some(mac_key_hex),
        github_pins,
        groups,
        grants,
        signers,
        sig: None,
    };

    let recipients = parse_recipients(&merged.recipients).ok()?;

    if recipients.is_empty() {
        return None;
    }

    let meta_json = serde_json::to_vec(&meta).ok()?;
    let encrypted = encrypt_value(&meta_json, &recipients).ok()?;
    merged.meta = encrypted;
    Some("meta regenerated".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SchemaEntry, SecretEntry, VAULT_VERSION, Vault};
    use std::collections::BTreeMap;

    fn base_vault() -> Vault {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            SchemaEntry {
                description: "database url".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "DB_URL".into(),
            SecretEntry {
                shared: "base-cipher-db".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        Vault {
            version: VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1alice".into(), "age1bob".into()],
            schema,
            policy: None,
            secrets,
            meta: "base-meta".into(),
        }
    }

    // -- No-change merge --

    #[test]
    fn merge_no_changes() {
        let base = base_vault();
        let r = merge_vaults(&base, &base, &base);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets.len(), 1);
        assert_eq!(r.vault.recipients.len(), 2);
    }

    // -- Ours-only changes --

    #[test]
    fn merge_ours_adds_secret() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "API_KEY".into(),
            SecretEntry {
                shared: "ours-cipher-api".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        ours.schema.insert(
            "API_KEY".into(),
            SchemaEntry {
                description: "api key".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let r = merge_vaults(&base, &ours, &base);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("API_KEY"));
        assert!(r.vault.schema.contains_key("API_KEY"));
        assert_eq!(r.vault.secrets.len(), 2);
    }

    // -- Theirs-only changes --

    #[test]
    fn merge_theirs_adds_secret() {
        let base = base_vault();
        let mut theirs = base.clone();
        theirs.secrets.insert(
            "STRIPE_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher-stripe".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("STRIPE_KEY"));
    }

    // -- Both add different keys --

    #[test]
    fn merge_both_add_different_keys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "API_KEY".into(),
            SecretEntry {
                shared: "ours-cipher-api".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut theirs = base.clone();
        theirs.secrets.insert(
            "STRIPE_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher-stripe".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("API_KEY"));
        assert!(r.vault.secrets.contains_key("STRIPE_KEY"));
        assert!(r.vault.secrets.contains_key("DB_URL"));
        assert_eq!(r.vault.secrets.len(), 3);
    }

    // -- Both remove same key --

    #[test]
    fn merge_both_remove_same_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        let mut theirs = base.clone();
        theirs.secrets.remove("DB_URL");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(!r.vault.secrets.contains_key("DB_URL"));
    }

    // -- Ours modifies, theirs unchanged --

    #[test]
    fn merge_ours_modifies_theirs_unchanged() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-new-cipher-db".into();

        let r = merge_vaults(&base, &ours, &base);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-new-cipher-db");
    }

    // -- Theirs modifies, ours unchanged --

    #[test]
    fn merge_theirs_modifies_ours_unchanged() {
        let base = base_vault();
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-new-cipher-db".into();

        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets["DB_URL"].shared, "theirs-new-cipher-db");
    }

    // -- Conflicts --

    #[test]
    fn merge_both_modify_same_secret() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-new".into();
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-new".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("DB_URL"));
        // Takes ours on conflict.
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-new");
    }

    #[test]
    fn merge_both_add_same_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "ours-cipher".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut theirs = base.clone();
        theirs.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("NEW_KEY"));
    }

    #[test]
    fn merge_remove_vs_modify() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-modified".into();
        let mut theirs = base.clone();
        theirs.secrets.remove("DB_URL");

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(
            r.conflicts[0]
                .reason
                .contains("modified on our side but removed on theirs")
        );
    }

    // -- Recipients --

    #[test]
    fn merge_recipient_added_one_side_conflicts() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());

        let r = merge_vaults(&base, &ours, &base);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].reason.contains("added on one side"));
        // Recipient is still included (safer to keep than drop).
        assert!(r.vault.recipients.contains(&"age1charlie".to_string()));
    }

    #[test]
    fn merge_recipient_label_handles_multibyte() {
        // A recipient whose 12th byte lands mid-codepoint must not panic the
        // conflict-label formatter. `theirs` recipients are unvalidated, so this
        // is adversarial input reachable through the merge driver.
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1aaaaaaañ".into());

        let r = merge_vaults(&base, &ours, &base);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.starts_with("recipients."));
    }

    #[test]
    fn merge_recipient_added_both_same() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());
        let mut theirs = base.clone();
        theirs.recipients.push("age1charlie".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert_eq!(
            r.vault
                .recipients
                .iter()
                .filter(|r| *r == "age1charlie")
                .count(),
            1
        );
    }

    #[test]
    fn merge_recipient_removed_one_side_conflicts() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.retain(|r| r != "age1bob");

        let r = merge_vaults(&base, &ours, &base);
        // One-sided removal should conflict — recipient kept for safety.
        assert!(!r.conflicts.is_empty());
        assert!(r.vault.recipients.contains(&"age1bob".to_string()));
    }

    #[test]
    fn merge_recipient_removed_both_sides_ok() {
        let base = base_vault();
        let mut ours = base.clone();
        let mut theirs = base.clone();
        ours.recipients.retain(|r| r != "age1bob");
        theirs.recipients.retain(|r| r != "age1bob");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(!r.vault.recipients.contains(&"age1bob".to_string()));
    }

    // -- Schema --

    #[test]
    fn merge_schema_different_keys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.insert(
            "API_KEY".into(),
            SchemaEntry {
                description: "api".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        let mut theirs = base.clone();
        theirs.schema.insert(
            "STRIPE".into(),
            SchemaEntry {
                description: "stripe".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.schema.contains_key("API_KEY"));
        assert!(r.vault.schema.contains_key("STRIPE"));
    }

    #[test]
    fn merge_schema_same_key_conflict() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.get_mut("DB_URL").unwrap().description = "ours desc".into();
        let mut theirs = base.clone();
        theirs.schema.get_mut("DB_URL").unwrap().description = "theirs desc".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("schema.DB_URL"));
    }

    // -- Scoped --

    #[test]
    fn merge_scoped_different_pubkeys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "alice-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1bob".into(), "bob-scope".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        let entry = &r.vault.secrets["DB_URL"];
        assert_eq!(entry.private["age1alice"], "alice-scope");
        assert_eq!(entry.private["age1bob"], "bob-scope");
    }

    #[test]
    fn merge_scoped_both_modify_same() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "base-scope".into());

        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "ours-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "theirs-scope".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("private"));
        assert!(r.conflicts[0].reason.contains("private entry"));
    }

    #[test]
    fn merge_scoped_add_vs_base_key_removal() {
        let base = base_vault();

        // Ours: remove the base key entirely.
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        ours.schema.remove("DB_URL");

        // Theirs: add a scoped entry on the same key (shared unchanged).
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "alice-scoped".into());

        let r = merge_vaults(&base, &ours, &theirs);
        // Ours removed the key, theirs kept it — conflict.
        // Schema removal conflicts, secret kept because theirs modified (added scoped).
        assert!(!r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("DB_URL"));
    }

    #[test]
    fn merge_scoped_add_vs_base_key_modification() {
        let base = base_vault();

        // Ours: remove the base key entirely.
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        ours.schema.remove("DB_URL");

        // Theirs: modify the shared value AND add scoped.
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-modified".into();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "alice-scoped".into());

        let r = merge_vaults(&base, &ours, &theirs);
        // Theirs modified shared, ours removed — conflicts for both secrets and schema.
        assert!(!r.conflicts.is_empty());
        assert!(r.conflicts.iter().any(|c| c.reason.contains("removed")));
    }

    // -- Recipient change + secret addition --

    #[test]
    fn merge_ours_changes_recipients_theirs_adds_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-reencrypted-db".into();

        let mut theirs = base.clone();
        theirs.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "theirs-new".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        // One-sided recipient addition now conflicts.
        assert!(
            r.conflicts
                .iter()
                .any(|c| c.reason.contains("added on one side"))
        );
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-reencrypted-db");
        assert!(r.vault.secrets.contains_key("NEW_KEY"));
        assert!(r.vault.recipients.contains(&"age1charlie".to_string()));
    }

    // -- Meta handling --

    #[test]
    fn merge_takes_ours_meta() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.meta = "ours-meta".into();
        let mut theirs = base.clone();
        theirs.meta = "theirs-meta".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.vault.meta, "ours-meta");
    }

    // -- run_merge_driver parses and delegates --

    #[test]
    fn run_merge_driver_invalid_base() {
        let result = run_merge_driver("not json", "{}", "{}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing base"));
    }

    #[test]
    fn run_merge_driver_invalid_ours() {
        let base = serde_json::to_string(&base_vault()).unwrap();
        let result = run_merge_driver(&base, "not json", &base);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing ours"));
    }

    #[test]
    fn run_merge_driver_invalid_theirs() {
        let base = serde_json::to_string(&base_vault()).unwrap();
        let result = run_merge_driver(&base, &base, "not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing theirs"));
    }

    #[test]
    fn run_merge_driver_clean_no_changes() {
        let base = serde_json::to_string(&base_vault()).unwrap();
        let output = run_merge_driver(&base, &base, &base).unwrap();
        assert!(output.result.conflicts.is_empty());
        // meta_regenerated depends on MURK_KEY availability — don't assert it.
    }

    // -- Static field preservation --

    #[test]
    fn merge_preserves_ours_static_fields() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.vault_name = "custom.murk".into();
        ours.repo = "https://github.com/test/repo".into();

        let r = merge_vaults(&base, &ours, &base);
        assert_eq!(r.vault.vault_name, "custom.murk");
        assert_eq!(r.vault.repo, "https://github.com/test/repo");
        assert_eq!(r.vault.version, VAULT_VERSION);
    }

    // -- Both sides remove same recipient --

    #[test]
    fn merge_both_remove_same_recipient() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.retain(|r| r != "age1bob");
        let mut theirs = base.clone();
        theirs.recipients.retain(|r| r != "age1bob");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(!r.vault.recipients.contains(&"age1bob".to_string()));
        // Both removed same recipient — should not conflict.
        assert!(
            !r.conflicts.iter().any(|c| c.reason.contains("recipient")),
            "removing same recipient from both sides should not conflict"
        );
    }

    // -- Empty vault merge --

    #[test]
    fn merge_empty_vaults() {
        let empty = Vault {
            version: VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1alice".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let r = merge_vaults(&empty, &empty, &empty);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.is_empty());
    }

    // -- Schema merge: description changes --

    #[test]
    fn merge_schema_ours_changes_description() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.get_mut("DB_URL").unwrap().description = "updated desc".into();

        let r = merge_vaults(&base, &ours, &base);
        assert_eq!(r.vault.schema["DB_URL"].description, "updated desc");
        assert!(r.conflicts.is_empty());
    }

    #[test]
    fn merge_schema_both_change_description_takes_ours() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.get_mut("DB_URL").unwrap().description = "ours desc".into();
        let mut theirs = base.clone();
        theirs.schema.get_mut("DB_URL").unwrap().description = "theirs desc".into();

        let r = merge_vaults(&base, &ours, &theirs);
        // Both changed the same schema entry — ours wins (schema conflicts are
        // reported but the merge still produces a result).
        assert_eq!(r.vault.schema["DB_URL"].description, "ours desc");
    }

    // -- Policy merge --

    fn policy(tags: &[&str]) -> Policy {
        Policy {
            agent_allow_tags: tags.iter().map(|t| (*t).to_string()).collect(),
        }
    }

    #[test]
    fn merge_policy_takes_the_side_that_changed() {
        // Only theirs set a policy — it must be kept, not silently dropped.
        let base = base_vault();
        let mut theirs = base_vault();
        theirs.policy = Some(policy(&["agents"]));
        let r = merge_vaults(&base, &base, &theirs);
        assert_eq!(r.vault.policy, Some(policy(&["agents"])));
        assert!(!r.conflicts.iter().any(|c| c.field == "policy"));
    }

    #[test]
    fn merge_policy_conflict_when_both_change() {
        let base = base_vault();
        let mut ours = base_vault();
        ours.policy = Some(policy(&["agents"]));
        let mut theirs = base_vault();
        theirs.policy = Some(policy(&["dev"]));
        let r = merge_vaults(&base, &ours, &theirs);
        // Divergent change is flagged, not silently resolved; ours is kept.
        assert!(r.conflicts.iter().any(|c| c.field == "policy"));
        assert_eq!(r.vault.policy, Some(policy(&["agents"])));
    }

    // -- merge_btree (schema) key-level resolution --

    #[test]
    fn merge_schema_both_add_same_key_no_conflict() {
        let base = base_vault();
        let entry = SchemaEntry {
            description: "new".into(),
            example: None,
            tags: vec![],
            ..Default::default()
        };
        let mut ours = base.clone();
        ours.schema.insert("NEW".into(), entry.clone());
        let mut theirs = base.clone();
        theirs.schema.insert("NEW".into(), entry.clone());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.is_empty(),
            "identical add must not conflict: {:?}",
            r.conflicts
        );
        assert!(r.vault.schema.contains_key("NEW"));
    }

    #[test]
    fn merge_schema_both_change_to_same_value_no_conflict() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.get_mut("DB_URL").unwrap().description = "converged".into();
        let mut theirs = base.clone();
        theirs.schema.get_mut("DB_URL").unwrap().description = "converged".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            !r.conflicts.iter().any(|c| c.field.contains("schema")),
            "identical change must not conflict: {:?}",
            r.conflicts
        );
        assert_eq!(r.vault.schema["DB_URL"].description, "converged");
    }

    #[test]
    fn merge_schema_theirs_changes_ours_unchanged_takes_theirs() {
        let base = base_vault();
        let mut theirs = base.clone();
        theirs.schema.get_mut("DB_URL").unwrap().description = "theirs desc".into();

        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty());
        // Ours untouched, theirs changed — theirs value wins.
        assert_eq!(r.vault.schema["DB_URL"].description, "theirs desc");
    }

    #[test]
    fn merge_schema_removed_one_side_unchanged_other_conflicts() {
        // A schema-only key isolates the merge_btree removal path (no secret).
        let mut base = base_vault();
        base.schema.insert(
            "TAGGED".into(),
            SchemaEntry {
                description: "d".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        // Theirs removes it; ours leaves it unchanged → conflict, key kept.
        let ours = base.clone();
        let mut theirs = base.clone();
        theirs.schema.remove("TAGGED");
        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c.field == "schema.TAGGED"),
            "removal-vs-unchanged must conflict: {:?}",
            r.conflicts
        );
        assert!(r.vault.schema.contains_key("TAGGED"));

        // Symmetric: ours removes, theirs unchanged.
        let mut ours2 = base.clone();
        ours2.schema.remove("TAGGED");
        let theirs2 = base.clone();
        let r2 = merge_vaults(&base, &ours2, &theirs2);
        assert!(r2.conflicts.iter().any(|c| c.field == "schema.TAGGED"));
        assert!(r2.vault.schema.contains_key("TAGGED"));
    }

    #[test]
    fn merge_schema_removed_one_side_modified_other_keeps_modified() {
        // A schema-only key isolates the merge_btree modify-vs-delete path
        // (no secret entry involved).
        let mut base = base_vault();
        base.schema.insert(
            "TAGGED".into(),
            SchemaEntry {
                description: "d".into(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );

        // Ours modifies the key; theirs deletes it — the modification must
        // survive, not be silently dropped, and must be flagged.
        let mut ours = base.clone();
        ours.schema.get_mut("TAGGED").unwrap().description = "ours-modified".into();
        let mut theirs = base.clone();
        theirs.schema.remove("TAGGED");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c.field == "schema.TAGGED"
                && c.reason.contains("removed on one side, modified on the other")),
            "modify-vs-delete must conflict, not silently drop: {:?}",
            r.conflicts
        );
        assert_eq!(
            r.vault.schema.get("TAGGED").map(|s| s.description.as_str()),
            Some("ours-modified"),
            "the modified value must survive"
        );

        // Symmetric: theirs modifies, ours deletes.
        let mut ours2 = base.clone();
        ours2.schema.remove("TAGGED");
        let mut theirs2 = base.clone();
        theirs2.schema.get_mut("TAGGED").unwrap().description = "theirs-modified".into();

        let r2 = merge_vaults(&base, &ours2, &theirs2);
        assert!(
            r2.conflicts.iter().any(|c| c.field == "schema.TAGGED"
                && c.reason.contains("removed on one side, modified on the other")),
            "conflicts: {:?}",
            r2.conflicts
        );
        assert_eq!(
            r2.vault.schema.get("TAGGED").map(|s| s.description.as_str()),
            Some("theirs-modified"),
            "the modified value must survive"
        );
    }

    // -- merge_scoped (private) entry resolution --

    #[test]
    fn merge_scoped_both_add_same_entry_no_conflict() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "same-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "same-scope".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.is_empty(),
            "identical scoped add must not conflict: {:?}",
            r.conflicts
        );
        assert_eq!(r.vault.secrets["DB_URL"].private["age1alice"], "same-scope");
    }

    #[test]
    fn merge_scoped_modified_vs_removed_conflicts() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "base-scope".into());

        // Ours modifies the scoped entry; theirs removes it → conflict, ours kept.
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "ours-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .remove("age1alice");
        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c
                .reason
                .contains("modified on our side but removed on theirs")),
            "conflicts: {:?}",
            r.conflicts
        );
        assert_eq!(
            r.vault.secrets["DB_URL"]
                .private
                .get("age1alice")
                .map(String::as_str),
            Some("ours-scope")
        );

        // Symmetric: ours removes, theirs modifies → conflict, theirs kept.
        let mut ours2 = base.clone();
        ours2
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .remove("age1alice");
        let mut theirs2 = base.clone();
        theirs2
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "theirs-scope".into());
        let r2 = merge_vaults(&base, &ours2, &theirs2);
        assert!(
            r2.conflicts.iter().any(|c| c
                .reason
                .contains("removed on our side but modified on theirs")),
            "conflicts: {:?}",
            r2.conflicts
        );
        assert_eq!(
            r2.vault.secrets["DB_URL"]
                .private
                .get("age1alice")
                .map(String::as_str),
            Some("theirs-scope")
        );
    }

    #[test]
    fn merge_scoped_theirs_change_and_identical_change() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "base-scope".into());

        // Theirs changes the scoped entry, ours unchanged → theirs wins.
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "theirs-scope".into());
        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty(), "conflicts: {:?}", r.conflicts);
        assert_eq!(
            r.vault.secrets["DB_URL"].private["age1alice"],
            "theirs-scope"
        );

        // Both change the scoped entry to the SAME value → no conflict.
        let mut ours2 = base.clone();
        ours2
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "converged".into());
        let mut theirs2 = base.clone();
        theirs2
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "converged".into());
        let r2 = merge_vaults(&base, &ours2, &theirs2);
        assert!(
            r2.conflicts.is_empty(),
            "identical scoped change must not conflict: {:?}",
            r2.conflicts
        );
        assert_eq!(r2.vault.secrets["DB_URL"].private["age1alice"], "converged");
    }

    // -- merge_secrets_normal: removed-vs-unchanged reason --

    #[test]
    fn merge_secret_removed_ours_unchanged_theirs_reports_unchanged() {
        let base = base_vault();
        // Ours removes DB_URL; theirs leaves it exactly as base.
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        ours.schema.remove("DB_URL");
        let theirs = base.clone();

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c.field == "secrets.DB_URL"
                && c.reason
                    .contains("removed on one side, unchanged on the other")),
            "conflicts: {:?}",
            r.conflicts
        );
        assert!(r.vault.secrets.contains_key("DB_URL"));
    }

    // -- merge_secrets_with_reencrypted_side: stable-side private/grouped edits --

    #[test]
    fn merge_reencrypted_side_private_edit_not_silently_dropped() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "base-scope".into());

        // Ours (the stable side) edits the private ciphertext.
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .private
            .insert("age1alice".into(), "ours-edited-scope".into());

        // Theirs re-encrypts: recipient set changes, so its ciphertext is the
        // new baseline and can't be compared against base for edits.
        let mut theirs = base.clone();
        theirs.recipients.push("age1charlie".into());
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-reencrypted-db".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c.field == "secrets.DB_URL"
                && c.reason
                    .contains("modified on ours side while recipients changed on the other")),
            "a private-tier edit on the stable side must not be silently dropped: {:?}",
            r.conflicts
        );
    }

    #[test]
    fn merge_reencrypted_side_grouped_edit_not_silently_dropped() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .grouped
            .insert("team".into(), "base-group-scope".into());

        // Ours (the stable side) edits the grouped ciphertext.
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .grouped
            .insert("team".into(), "ours-edited-group-scope".into());

        // Theirs re-encrypts: recipient set changes.
        let mut theirs = base.clone();
        theirs.recipients.push("age1charlie".into());
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-reencrypted-db".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(
            r.conflicts.iter().any(|c| c.field == "secrets.DB_URL"
                && c.reason
                    .contains("modified on ours side while recipients changed on the other")),
            "a grouped-tier edit on the stable side must not be silently dropped: {:?}",
            r.conflicts
        );
    }

    // -- merge_secrets_both_reencrypted: key-level union when both re-encrypt --

    #[test]
    fn merge_both_change_recipients_merges_secret_keys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-reenc-db".into();
        ours.secrets.insert(
            "OURS_KEY".into(),
            SecretEntry {
                shared: "ours-only".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        let mut theirs = base.clone();
        theirs.recipients.push("age1dave".into());
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-reenc-db".into();
        theirs.secrets.insert(
            "THEIRS_KEY".into(),
            SecretEntry {
                shared: "theirs-only".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        // Both re-encrypted: a base key takes ours; each side's added key survives.
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-reenc-db");
        assert!(r.vault.secrets.contains_key("OURS_KEY"));
        assert!(r.vault.secrets.contains_key("THEIRS_KEY"));
    }

    // -- recipient_label: conflict field names the truncated pubkey --

    #[test]
    fn merge_recipient_conflict_label_is_truncated_pubkey() {
        let base = base_vault();
        let mut ours = base.clone();
        // Longer than the 12-char label window.
        ours.recipients.push("age1charlie9999".into());
        let r = merge_vaults(&base, &ours, &base);
        assert!(
            r.conflicts
                .iter()
                .any(|c| c.field == "recipients.age1charlie9"),
            "conflict field must be the 12-char-truncated pubkey: {:?}",
            r.conflicts
        );
    }

    // -- regenerate_meta: rebuilds names, prunes stale groups --

    #[test]
    fn regenerate_meta_rebuilds_names_and_prunes_stale_groups() {
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity, make_recipient};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        // Meta with a name for pubkey, a live group, and a stale group whose
        // only member is no longer a recipient of the merged vault.
        let source_meta = crate::types::Meta {
            recipients: std::collections::HashMap::from([(pubkey.clone(), "alice".to_string())]),
            groups: BTreeMap::from([
                ("team".to_string(), vec![pubkey.clone()]),
                ("ghost".to_string(), vec!["age1stranger".to_string()]),
            ]),
            ..Default::default()
        };
        let meta_ct = crate::encrypt_value(
            &serde_json::to_vec(&source_meta).unwrap(),
            std::slice::from_ref(&recipient),
        )
        .unwrap();

        let mut ours = base_vault();
        ours.recipients = vec![pubkey.clone()];
        ours.meta = meta_ct;
        let theirs = ours.clone();
        let mut merged = ours.clone();
        // The merged vault recognizes only `pubkey`; age1stranger is gone.
        merged.recipients = vec![pubkey.clone()];

        // ENV_LOCK is held, so set + clear is safe; no need to read the prior
        // value (reading MURK_KEY outside env.rs trips the read-path invariant).
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        let out = regenerate_meta(&mut merged, &ours, &theirs);
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(
            out.is_some(),
            "regenerate_meta must succeed with MURK_KEY set"
        );
        let meta = crate::decrypt_meta(&merged, &identity).expect("merged meta must decrypt");
        assert_eq!(
            meta.recipients.get(&pubkey).map(String::as_str),
            Some("alice")
        );
        // Live group survives; the stale group is pruned to empty and dropped.
        assert!(meta.groups.contains_key("team"), "live group must survive");
        assert!(
            !meta.groups.contains_key("ghost"),
            "stale now-empty group must be pruned"
        );
    }
}
