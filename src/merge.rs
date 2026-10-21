// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Three-way merge driver for `.murk` vault files.
//!
//! Operates at the Vault struct level: recipients as a set, schema and secrets
//! as key-level maps. Ciphertext equality against the base determines whether
//! a side modified a value (murk preserves ciphertext for unchanged values).

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{Meta, Policy, SecretEntry, Vault};

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
    let vault_id = ours.vault_id.clone();
    let generation = ours.generation.max(theirs.generation);

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
        // A keyed merge re-signs and moves the counter past both sides and this
        // machine's mark (see `regenerate_meta`).
        vault_id,
        generation,
        recipients,
        schema,
        policy: merge_policy(
            base.policy.as_ref(),
            ours.policy.as_ref(),
            theirs.policy.as_ref(),
            &mut conflicts,
        ),
        // Per-grant blobs: taken from ours, like the meta blob they accompany.
        agents: ours.agents.clone(),
        secrets,
        meta,
        // The driver never vouches for merged content: a keyholder re-signs on
        // the next write after reviewing `murk diff`.
        sig: None,
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
                if entry.shared != b.shared
                    || entry.private != b.private
                    || entry.grouped != b.grouped
                {
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
    /// Why the merge cannot be reported clean while meta was not regenerated:
    /// the merged secrets, recipients, schema or policy differ from ours (so
    /// ours' MAC and signature, kept in the merged meta, may no longer verify),
    /// or theirs changed its encrypted meta (which would be silently dropped).
    pub needs_key: Option<&'static str>,
}

/// Whether two vaults agree on every plaintext field that the MAC and the
/// signature cover and a merge can change: recipients (as a set), schema,
/// secrets and policy. When they agree, ours' MAC and signature (kept in the
/// merged meta) still verify. When they differ, they may not. Compared as
/// structures, not as MAC bytes, because the signature covers the serialized
/// fields (an absent `example` and an empty one hash alike in the MAC but not
/// in the signed view). A merge takes every other field from ours, and groups
/// and grants live in the encrypted meta.
fn same_covered_content(a: &Vault, b: &Vault) -> bool {
    fn sorted(v: &Vault) -> Vec<&str> {
        let mut recipients: Vec<&str> = v.recipients.iter().map(String::as_str).collect();
        recipients.sort_unstable();
        recipients
    }
    sorted(a) == sorted(b) && a.schema == b.schema && a.secrets == b.secrets && a.policy == b.policy
}

/// Run the three-way merge driver on vault contents (as strings).
///
/// Parses all three versions, merges, and attempts meta regeneration.
/// Returns the merged vault and conflict list. The caller is responsible for
/// writing the result to disk. `vault_path` is the vault's path in the work
/// tree (git's `%P`), whose trust pin the sides are checked against.
///
/// Refuses an agent grant key before merging: grants are read-only (see
/// [`crate::ensure_writable`]), and the caller would otherwise write the merged
/// vault over `ours`.
pub fn run_merge_driver(
    base: &str,
    ours: &str,
    theirs: &str,
    vault_path: &str,
) -> Result<MergeDriverOutput, String> {
    use crate::vault;

    let base_vault = vault::parse(base).map_err(|e| format!("parsing base: {e}"))?;
    let ours_vault = vault::parse(ours).map_err(|e| format!("parsing ours: {e}"))?;
    let theirs_vault = vault::parse(theirs).map_err(|e| format!("parsing theirs: {e}"))?;

    if merge_key_is_grant(&[&base_vault, &ours_vault, &theirs_vault]) {
        return Err("agent grants are read-only; ask the operator to make this change".into());
    }

    let mut result = merge_vaults(&base_vault, &ours_vault, &theirs_vault);
    let meta_regenerated = regenerate_meta(
        &mut result.vault,
        &base_vault,
        &ours_vault,
        &theirs_vault,
        vault_path,
        &mut result.conflicts,
    )?
    .is_some();
    let needs_key = if meta_regenerated {
        None
    } else if !same_covered_content(&result.vault, &ours_vault) {
        Some("the merged secrets, recipients, schema or policy differ from ours")
    } else if theirs_vault.meta != base_vault.meta && theirs_vault.meta != ours_vault.meta {
        // Any write re-encrypts the meta, so this can't tell a real group,
        // grant, pin or signer change from a rewrite. Refuse rather than drop
        // what may be a member removal.
        Some(
            "theirs changed the encrypted meta (groups, grants, GitHub pins or signers), which only a key can merge",
        )
    } else {
        None
    };

    Ok(MergeDriverOutput {
        result,
        meta_regenerated,
        needs_key,
    })
}

/// Group membership in the meta: group name → member pubkeys.
type Groups = BTreeMap<String, Vec<String>>;
/// Whether the key in the environment is an agent grant on any of `sides`, per
/// that side's decrypted meta. No key, or a key that can't read a side's meta,
/// is not a grant there.
fn merge_key_is_grant(sides: &[&Vault]) -> bool {
    use age::secrecy::ExposeSecret;

    let Ok(secret_key) = crate::resolve_key() else {
        return false;
    };
    let Ok(identity) = crate::crypto::parse_identity(secret_key.expose_secret()) else {
        return false;
    };
    let Ok(pubkey) = identity.pubkey_string() else {
        return false;
    };
    // A grant loads through its `agents` record and can't open the meta. Only
    // a 2.x vault listed grants among the meta's readers; on 3.x a meta record
    // bound to a key that opens the meta is a ghost, not a grant.
    sides.iter().any(|side| {
        crate::agents::loader_blob(side, &identity).is_some()
            || (side.version.starts_with("2.")
                && matches!(
                    crate::decrypt_meta(side, &identity),
                    Ok(Some(meta)) if meta.grants.values().any(|g| g.pubkey == pubkey)
                ))
    })
}

/// Attempt to regenerate the meta blob for a merged vault.
///
/// First, ours and theirs must each pass the checks a load applies — MAC,
/// signature, and a signer this machine trusts (see
/// [`crate::trust::check_merge_side`]). A side that fails is a conflict naming
/// it, and nothing of it is merged, re-MACed or signed: the driver must never
/// bless content nobody trusted vouched for.
///
/// Then it decrypts the meta of all three versions, merges it, recomputes the
/// MAC, signs the result with the merging key, and re-encrypts. Group
/// membership, agent grants and GitHub pins merge three-way, like recipients:
/// a change on one side (including a removal) is taken, and different changes
/// on both sides are a conflict, so a member removed on one branch never
/// regains access. If the common ancestor's meta is unreadable, any difference
/// between the sides is a conflict. Conflicts are appended to `conflicts`.
///
/// Returns `Ok(None)` (leaving `ours.meta` in place) if MURK_KEY is
/// unavailable, cannot read both sides' meta (a conflict), a side fails its
/// authenticity check, the merge has any conflict (so a conflicted result
/// never gets fresh integrity metadata), or the merged recipients cannot be
/// encrypted to. A side whose meta decrypts but is invalid is an error:
/// merging it as empty would silently drop its groups, grants, and pins.
pub fn regenerate_meta(
    merged: &mut Vault,
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    vault_path: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> Result<Option<String>, String> {
    use crate::{compute_mac, crypto, decrypt_meta, encrypt_value, parse_recipients, resolve_key};
    use age::secrecy::ExposeSecret;

    let Ok(secret_key) = resolve_key() else {
        return Ok(None);
    };
    let Ok(identity) = crypto::parse_identity(secret_key.expose_secret()) else {
        return Ok(None);
    };

    let base_authentic = match authenticate_inputs(vault_path, base, ours, theirs, &identity) {
        Ok(authentic) => authentic,
        Err(conflict) => {
            conflicts.push(conflict);
            return Ok(None);
        }
    };
    // An ancestor nobody trusted signed (pre-0.14 history, or one this key
    // cannot read) is not an authority on what changed: merge as if it were
    // unreadable, so any meta difference between the sides is a conflict.
    let base_meta = if base_authentic {
        decrypt_meta(base, &identity).map_err(|e| format!("base: {e}"))?
    } else {
        None
    };

    let ours_meta = decrypt_meta(ours, &identity).map_err(|e| format!("ours: {e}"))?;
    let theirs_meta = decrypt_meta(theirs, &identity).map_err(|e| format!("theirs: {e}"))?;
    let (Some(ours_meta), Some(theirs_meta)) = (ours_meta, theirs_meta) else {
        conflicts.push(MergeConflict {
            field: "meta".into(),
            reason: "this key cannot decrypt both sides' meta, so groups, grants and pins cannot be merged".into(),
        });
        return Ok(None);
    };

    let mut meta = merge_meta(
        merged,
        (base, base_meta.as_ref()),
        (ours, &ours_meta),
        (theirs, &theirs_meta),
        conflicts,
    );
    if !conflicts.is_empty() {
        return Ok(None);
    }

    // The merged vault is signed by the merging key, so the group rule a load
    // applies (a membership change needs a member's signature) must hold for
    // that key against ours: otherwise every machine would refuse the result.
    if let Ok(me) = identity.pubkey_string()
        && let Some(group) = crate::trust::group_change_violation(
            &merged.recipients,
            &meta.groups,
            &crate::trust::canonical_groups(&ours_meta.groups),
            &me,
        )
    {
        conflicts.push(MergeConflict {
            field: format!("groups.{group}"),
            reason: format!(
                "theirs changes the membership of group {group}, and you are not a member of it; a member of {group} must do this merge"
            ),
        });
        return Ok(None);
    }

    // The merged vault is a new version of both sides: identity from ours
    // (equal to theirs, or theirs predates vault ids), and a counter past both
    // sides and past anything this machine accepted.
    if merged.vault_id.is_empty() {
        merged.vault_id = if theirs.vault_id.is_empty() {
            crate::save::derived_vault_id(merged)
        } else {
            theirs.vault_id.clone()
        };
    }
    let pin = crate::pins::read(vault_path)?;
    merged.generation = ours
        .generation
        .max(theirs.generation)
        .max(pin.as_ref().map_or(0, |p| p.generation))
        .saturating_add(1);
    meta.signers = crate::save::vouched_registry(merged, &meta.signers, pin.as_ref(), &identity);

    // Each grant gets its own record again; one unchanged on a side keeps
    // that side's blob.
    merged.agents = crate::agents::blobs_for(
        &meta.grants,
        &[(ours, &ours_meta.grants), (theirs, &theirs_meta.grants)],
    )
    .map_err(|e| e.to_string())?;

    let mac_key_hex = crate::generate_mac_key();
    let mac_key = crate::decode_mac_key(&mac_key_hex).unwrap();
    meta.mac = compute_mac(merged, &meta.groups, &meta.grants, Some(&mac_key));
    meta.mac_key = Some(mac_key_hex);
    meta.sig = None;

    // The meta goes to every recipient except agent grants (see
    // [`crate::agents`]).
    let Ok(recipients) = parse_recipients(&crate::agents::meta_recipients(
        &merged.recipients,
        &meta.grants,
    )) else {
        return Ok(None);
    };

    if recipients.is_empty() {
        return Ok(None);
    }

    crate::validate::meta(&meta).map_err(|e| format!("merged meta is invalid: {e}"))?;
    let meta_json = serde_json::to_vec(&meta).map_err(|e| format!("meta serialize: {e}"))?;
    let Ok(encrypted) = encrypt_value(&meta_json, &recipients) else {
        return Ok(None);
    };
    merged.meta = encrypted;
    // The merged meta is MACed by this build (blake3v8 covers no version, so
    // stamping after the MAC is safe), so the merged vault carries this build's
    // format version, not either side's.
    merged.version = crate::types::VAULT_VERSION.to_string();
    // Both sides were signed by trusted signers (checked above), so the merge
    // of their content is signed by the merging key — unless it cannot sign
    // (ssh-rsa/hardware), which leaves it unsigned for a teammate to review
    // and `murk trust`. The signature covers the finished file, so it comes last.
    merged.sig = crate::sign_vault(merged, &identity);
    Ok(Some("meta regenerated".into()))
}

/// The authenticity gate before any merging: the ancestor, then ours and
/// theirs, must pass (see [`check_base`] and [`check_side`]), and both sides
/// must be the same vault. The ancestor decides what counts as a change and
/// supplies the membership group changes are judged against, so only an
/// authenticated ancestor is used for either: an attacker-chosen parent
/// (cherry-pick, `git apply --3way`, or a stripped legacy file) could
/// otherwise shape the delta. Returns whether the ancestor is authenticated,
/// or the conflict to record.
fn authenticate_inputs(
    vault_path: &str,
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    identity: &crate::crypto::MurkIdentity,
) -> Result<bool, MergeConflict> {
    let base_groups = check_base(vault_path, base, identity).map_err(|reason| MergeConflict {
        field: "base".into(),
        reason: format!(
            "the common ancestor failed its authenticity check, so nothing was merged or signed: {reason}"
        ),
    })?;
    // Whether either side was written by murk 0.14: a 0.13 side that changed
    // the vault may then not override it (see `trust::check_merge_side`).
    let upgraded = [ours, theirs]
        .iter()
        .any(|v| !v.vault_id.is_empty() || v.generation > 0);
    for (side, vault) in [("ours", ours), ("theirs", theirs)] {
        check_side(
            vault_path,
            vault,
            base,
            base_groups.as_ref(),
            identity,
            upgraded,
        )
        .map_err(|reason| MergeConflict {
            field: side.into(),
            reason: format!(
                "{side} failed its authenticity check, so nothing was merged or signed: {reason}"
            ),
        })?;
    }
    if !ours.vault_id.is_empty() && !theirs.vault_id.is_empty() && ours.vault_id != theirs.vault_id
    {
        return Err(MergeConflict {
            field: "vault_id".into(),
            reason: "ours and theirs are different vaults".into(),
        });
    }
    Ok(base_groups.is_some())
}

/// Verify one side of a merge (MAC, signature) and check it against this
/// machine's trust state, returning the reason it fails.
fn check_side(
    vault_path: &str,
    side: &Vault,
    base: &Vault,
    base_groups: Option<&Groups>,
    identity: &crate::crypto::MurkIdentity,
    upgraded: bool,
) -> Result<(), String> {
    let verified = crate::load::verify_side(side, identity).map_err(|e| e.to_string())?;
    let loaded = crate::trust::Loaded {
        vault: side,
        signature: &verified.signature,
        signer_vk: verified.signer_vk.as_deref(),
        registry: &verified.registry,
        names: &verified.names,
        groups: &verified.groups,
        grants: &verified.grants,
        loader_can_sign: identity.is_signing_capable(),
        operator_key: crate::crypto::operator_key(identity),
    };
    let changed = !same_covered_content(side, base) || side.meta != base.meta;
    crate::trust::check_merge_side(
        vault_path,
        &loaded,
        Some((base, base_groups)),
        changed,
        upgraded,
    )
}

/// Authenticate the merge base: MAC and signature as a load does, and a
/// signer this machine ever trusted (see [`crate::trust::assess_revision`]).
/// Returns its group membership when it is authenticated. `None` when this
/// key cannot read it, or when it is unsigned: an unsigned ancestor with no
/// vault id is accepted as pre-0.14 history, but anyone can strip a signature
/// and re-MAC, so its contents are never used as authority — group changes
/// are then judged against the pinned membership.
fn check_base(
    vault_path: &str,
    base: &Vault,
    identity: &crate::crypto::MurkIdentity,
) -> Result<Option<BTreeMap<String, Vec<String>>>, String> {
    let verified = match crate::load::verify_side(base, identity) {
        Ok(v) => v,
        // Not a recipient at the ancestor: nothing of it is used.
        Err(crate::MurkError::Crypto(_)) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let loaded = crate::trust::Loaded {
        vault: base,
        signature: &verified.signature,
        signer_vk: verified.signer_vk.as_deref(),
        registry: &verified.registry,
        names: &verified.names,
        groups: &verified.groups,
        grants: &verified.grants,
        loader_can_sign: identity.is_signing_capable(),
        operator_key: crate::crypto::operator_key(identity),
    };
    match crate::trust::assess_revision(vault_path, &loaded)? {
        crate::trust::Verdict::Trusted => Ok(Some(verified.groups)),
        crate::trust::Verdict::UnsignedAllowed => Ok(None),
        crate::trust::Verdict::Refused(crate::trust::Refusal::Unsigned)
            if base.vault_id.is_empty() =>
        {
            Ok(None)
        }
        crate::trust::Verdict::Refused(r) => {
            let msg = crate::trust::refusal_message(vault_path, &r, &loaded, None);
            Err(msg.lines().next().unwrap_or_default().to_string())
        }
    }
}

/// Merge the three decrypted metas for `merged`, appending conflicts. Returns
/// a meta without MAC, MAC key or signature: the caller fills those in, and
/// adds its own signer-registry entry.
fn merge_meta(
    merged: &mut Vault,
    (base, base_meta): (&Vault, Option<&Meta>),
    (ours, ours_meta): (&Vault, &Meta),
    (theirs, theirs_meta): (&Vault, &Meta),
    conflicts: &mut Vec<MergeConflict>,
) -> Meta {
    // Agent grants first, three-way per grant, so an agent key that lost its
    // grant leaves the recipient set before anything else is retained to it.
    // A conflicting grant is dropped, never kept with the wider side's terms.
    let mut grants = merge_meta_entries(
        "grants",
        base_meta.map(|m| &m.grants),
        &ours_meta.grants,
        &theirs_meta.grants,
        (str::to_string, OnConflict::Drop),
        conflicts,
    );
    grants.retain(|_, grant| merged.recipients.contains(&grant.pubkey));
    remove_ungranted_agent_keys(
        merged,
        [base_meta, Some(ours_meta), Some(theirs_meta)],
        &grants,
        conflicts,
    );

    // Merge name maps: union, ours wins on conflict. Names are labels only.
    let mut names = theirs_meta.recipients.clone();
    names.extend(ours_meta.recipients.clone());
    // Only keep names for recipients still in the merged vault.
    names.retain(|pk, _| merged.recipients.contains(pk));

    // Group membership, three-way per member. Drop members no longer in the
    // merged recipient set, and drop now-empty groups.
    let mut groups = merge_groups(
        base_meta.map(|m| &m.groups),
        &ours_meta.groups,
        &theirs_meta.groups,
        conflicts,
    );
    for members in groups.values_mut() {
        members.retain(|pk| merged.recipients.contains(pk));
    }
    groups.retain(|_, members| !members.is_empty());
    check_grouped_ciphertexts(
        merged,
        base,
        [
            ("ours", ours, &ours_meta.groups),
            ("theirs", theirs, &theirs_meta.groups),
        ],
        &groups,
        conflicts,
    );

    // GitHub pins, three-way per user.
    let sorted_pins = |m: &Meta| -> BTreeMap<String, Vec<String>> {
        m.github_pins
            .iter()
            .map(|(user, pins)| (user.clone(), pins.clone()))
            .collect()
    };
    let github_pins = merge_meta_entries(
        "github_pins",
        base_meta.map(sorted_pins).as_ref(),
        &sorted_pins(ours_meta),
        &sorted_pins(theirs_meta),
        (str::to_string, OnConflict::KeepOurs),
        conflicts,
    )
    .into_iter()
    .collect();

    // Signer registry: the union of both sides' entries for the merged
    // recipients. Both sides were signed by trusted signers, so both vouch for
    // their entries; an age key has one verifying key, so two different
    // entries for the same key mean one side lies, and that is a conflict.
    let recipients: BTreeSet<String> = merged
        .recipients
        .iter()
        .map(|r| crate::recipients::canonical_recipient(r).into_owned())
        .collect();
    let mut signers = BTreeMap::new();
    for (pk, vk) in ours_meta.signers.iter().chain(&theirs_meta.signers) {
        let pk = crate::recipients::canonical_recipient(pk).into_owned();
        if !recipients.contains(&pk) {
            continue;
        }
        match signers.get(&pk) {
            Some(existing) if existing != vk => conflicts.push(MergeConflict {
                field: format!("signers.{}", crate::truncate_pubkey(&pk)),
                reason: "ours and theirs register different verifying keys for this key".into(),
            }),
            Some(_) => {}
            None => {
                signers.insert(pk, vk.clone());
            }
        }
    }

    Meta {
        recipients: names,
        github_pins,
        groups,
        grants,
        signers,
        ..Meta::default()
    }
}

/// Merge group membership three-way, one (group, member) pair at a time: a
/// member added or removed on one side follows that side. With an unreadable
/// `base`, a member present on only one side is a conflict and is left out, so
/// a conflict never grants access.
fn merge_groups(
    base: Option<&Groups>,
    ours: &Groups,
    theirs: &Groups,
    conflicts: &mut Vec<MergeConflict>,
) -> Groups {
    fn pairs(groups: &Groups) -> BTreeSet<(&str, &str)> {
        groups
            .iter()
            .flat_map(|(name, members)| members.iter().map(|m| (name.as_str(), m.as_str())))
            .collect()
    }
    let (base, ours, theirs) = (base.map(pairs), pairs(ours), pairs(theirs));

    let mut merged = Groups::new();
    for &pair in ours.union(&theirs) {
        let (in_ours, in_theirs) = (ours.contains(&pair), theirs.contains(&pair));
        let keep = if in_ours == in_theirs {
            in_ours
        } else if let Some(base) = &base {
            // Exactly one side differs from base; take that side.
            if in_ours == base.contains(&pair) {
                in_theirs
            } else {
                in_ours
            }
        } else {
            conflicts.push(MergeConflict {
                field: format!("groups.{}", pair.0),
                reason: format!(
                    "member {} differs between the sides and the common ancestor's meta is unreadable",
                    recipient_label(pair.1)
                ),
            });
            false
        };
        if keep {
            merged
                .entry(pair.0.to_string())
                .or_default()
                .push(pair.1.to_string());
        }
    }
    merged
}

/// What [`merge_meta_entries`] keeps for an entry in conflict.
#[derive(Clone, Copy)]
enum OnConflict {
    /// Leave the entry out, so a conflict never grants or restores access.
    Drop,
    /// Keep ours' entry (or its absence), so a conflict never discards a
    /// check ours relies on, such as a GitHub key pin or a signer mapping.
    KeepOurs,
}

/// Merge one meta map three-way per entry: an entry added, changed or removed
/// on one side follows that side. Different changes on both sides (or any
/// difference when `base` is unreadable) are a conflict, resolved by
/// `on_conflict`. `label` renders a key for the conflict field.
fn merge_meta_entries<V: PartialEq + Clone>(
    field: &str,
    base: Option<&BTreeMap<String, V>>,
    ours: &BTreeMap<String, V>,
    theirs: &BTreeMap<String, V>,
    (label, on_conflict): (fn(&str) -> String, OnConflict),
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, V> {
    let keys: BTreeSet<&String> = ours.keys().chain(theirs.keys()).collect();
    let mut merged = BTreeMap::new();
    for key in keys {
        let (o, t) = (ours.get(key), theirs.get(key));
        let picked = if o == t {
            o
        } else {
            match base.map(|b| b.get(key)) {
                Some(b) if o == b => t,
                Some(b) if t == b => o,
                known => {
                    let reason = if known.is_some() {
                        "changed differently on both sides"
                    } else {
                        "differs between the sides and the common ancestor's meta is unreadable"
                    };
                    conflicts.push(MergeConflict {
                        field: format!("{field}.{}", label(key)),
                        reason: reason.into(),
                    });
                    match on_conflict {
                        OnConflict::Drop => None,
                        OnConflict::KeepOurs => o,
                    }
                }
            }
        };
        if let Some(value) = picked {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// An agent key whose grant did not survive the merge must not stay a plain
/// recipient: shared values are withheld from a key only while it has a grant
/// (`src/save.rs`), so the next write would encrypt every shared secret to it.
/// Remove such keys from the recipients and their scoped values, and flag it.
fn remove_ungranted_agent_keys(
    merged: &mut Vault,
    metas: [Option<&Meta>; 3],
    grants: &BTreeMap<String, crate::types::GrantEntry>,
    conflicts: &mut Vec<MergeConflict>,
) {
    let granted: BTreeSet<&str> = grants.values().map(|g| g.pubkey.as_str()).collect();
    let ungranted: BTreeSet<String> = metas
        .into_iter()
        .flatten()
        .flat_map(|m| m.grants.values().map(|g| g.pubkey.clone()))
        .filter(|pk| !granted.contains(pk.as_str()) && merged.recipients.contains(pk))
        .collect();
    for pk in &ungranted {
        conflicts.push(MergeConflict {
            field: format!("recipients.{}", recipient_label(pk)),
            reason:
                "agent key lost its grant in the merge; removed it (grant again if still needed)"
                    .into(),
        });
    }
    merged.recipients.retain(|pk| !ungranted.contains(pk));
    for entry in merged.secrets.values_mut() {
        entry.private.retain(|pk, _| !ungranted.contains(pk));
    }
}

/// Check every merged grouped ciphertext against the merged membership.
///
/// A ciphertext for a group that no longer exists is a conflict (the vault
/// would not verify). A ciphertext that a side added or changed is encrypted
/// to that side's members of the group; if the merged membership dropped any
/// of them, the value would stay readable by a removed member, so it is a
/// conflict and the ciphertext is dropped from the written file, making the
/// conflicted result safe to accept as-is.
fn check_grouped_ciphertexts(
    merged: &mut Vault,
    base: &Vault,
    sides: [(&str, &Vault, &Groups); 2],
    groups: &Groups,
    conflicts: &mut Vec<MergeConflict>,
) {
    let grouped = |vault: &Vault, key: &str, group: &str| -> Option<String> {
        vault.secrets.get(key)?.grouped.get(group).cloned()
    };
    let mut stale = Vec::new();
    for (key, entry) in &merged.secrets {
        for (group, ciphertext) in &entry.grouped {
            let members = groups.get(group);
            if members.is_none() {
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: format!("group {group} no longer exists after the merge"),
                });
            }
            if grouped(base, key, group).as_ref() == Some(ciphertext) {
                continue;
            }
            let stale_side = sides.iter().find(|(_, vault, side_groups)| {
                grouped(vault, key, group).as_ref() == Some(ciphertext)
                    && side_groups
                        .get(group)
                        .into_iter()
                        .flatten()
                        .any(|m| !members.is_some_and(|ms| ms.contains(m)))
            });
            if let Some((side, _, _)) = stale_side {
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: format!(
                        "{side} encrypted it to members of group {group} that the merge removed; dropped it, add it again after resolving"
                    ),
                });
                stale.push((key.clone(), group.clone()));
            }
        }
    }
    for (key, group) in stale {
        if let Some(entry) = merged.secrets.get_mut(&key) {
            entry.grouped.remove(&group);
            if entry.shared.is_empty() && entry.private.is_empty() && entry.grouped.is_empty() {
                merged.secrets.remove(&key);
            }
        }
    }
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1alice".into(), "age1bob".into()],
            schema,
            policy: None,
            secrets,
            meta: "base-meta".into(),
        }
    }

    /// `base_vault()` serialized with recipient and ciphertext values that pass
    /// load-time validation, for tests that go through `run_merge_driver`.
    fn base_vault_json() -> String {
        let mut v = base_vault();
        v.recipients = vec![
            crate::testutil::AGE_PK.into(),
            crate::testutil::SSH_ED25519_PK.into(),
        ];
        for entry in v.secrets.values_mut() {
            entry.shared = "Y2lwaGVy".into();
        }
        v.meta = "bWV0YQ==".into();
        serde_json::to_string(&v).unwrap()
    }

    // -- Keyless comparison --

    #[test]
    fn same_covered_content_detects_each_field_and_ignores_recipient_order() {
        let ours = base_vault();

        let mut reordered = ours.clone();
        reordered.recipients.reverse();
        assert!(same_covered_content(&ours, &reordered));

        let mut recipients = ours.clone();
        recipients.recipients.push("age1carol".into());
        let mut schema = ours.clone();
        schema.schema.get_mut("DB_URL").unwrap().description = "changed".into();
        let mut secrets = ours.clone();
        secrets.secrets.get_mut("DB_URL").unwrap().shared = "other-cipher".into();
        let mut policy = ours.clone();
        policy.policy = Some(Policy::default());
        // The MAC hashes these alike, but the signed view does not.
        let mut empty_example = ours.clone();
        empty_example.schema.get_mut("DB_URL").unwrap().example = Some(String::new());

        for (what, other) in [
            ("recipients", &recipients),
            ("schema", &schema),
            ("secrets", &secrets),
            ("policy", &policy),
            ("empty example", &empty_example),
        ] {
            assert!(
                !same_covered_content(&ours, other),
                "{what} difference missed"
            );
        }
    }

    // -- Meta three-way merge --

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn meta_entries_take_a_one_sided_change_and_conflict_on_two() {
        let base = map(&[("kept", "1"), ("gone", "1"), ("both", "1")]);
        let ours = map(&[("kept", "1"), ("both", "ours"), ("new", "1")]);
        let theirs = map(&[("kept", "2"), ("gone", "1"), ("both", "theirs")]);

        let mut conflicts = Vec::new();
        let merged = merge_meta_entries(
            "grants",
            Some(&base),
            &ours,
            &theirs,
            (str::to_string, OnConflict::Drop),
            &mut conflicts,
        );
        // `gone` removed on ours stays removed; `both` conflicts and is left out.
        assert_eq!(merged, map(&[("kept", "2"), ("new", "1")]));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].field, "grants.both");

        // KeepOurs resolves the same conflict to ours' entry.
        let merged = merge_meta_entries(
            "signers",
            Some(&base),
            &ours,
            &theirs,
            (str::to_string, OnConflict::KeepOurs),
            &mut Vec::new(),
        );
        assert_eq!(
            merged,
            map(&[("kept", "2"), ("both", "ours"), ("new", "1")])
        );
    }

    #[test]
    fn meta_entries_without_a_readable_base_conflict_on_any_difference() {
        let ours = map(&[("same", "1"), ("only_ours", "1")]);
        let theirs = map(&[("same", "1")]);
        let mut conflicts = Vec::new();

        let merged = merge_meta_entries(
            "grants",
            None,
            &ours,
            &theirs,
            (str::to_string, OnConflict::Drop),
            &mut conflicts,
        );

        assert_eq!(merged, map(&[("same", "1")]));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].field, "grants.only_ours");
    }

    #[test]
    fn groups_merge_each_member_three_way() {
        let groups = |members: &[&str]| -> Groups {
            BTreeMap::from([(
                "ops".to_string(),
                members.iter().map(|m| (*m).to_string()).collect(),
            )])
        };
        let base = groups(&["alice", "bob"]);
        let mut conflicts = Vec::new();

        // Theirs removes bob, ours adds carol: both changes land.
        let merged = merge_groups(
            Some(&base),
            &groups(&["alice", "bob", "carol"]),
            &groups(&["alice"]),
            &mut conflicts,
        );
        assert_eq!(merged, groups(&["alice", "carol"]));
        assert!(conflicts.is_empty());

        // Without a base, a one-sided member is a conflict and gets no access.
        let merged = merge_groups(
            None,
            &groups(&["alice", "bob"]),
            &groups(&["alice"]),
            &mut conflicts,
        );
        assert_eq!(merged, groups(&["alice"]));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].field, "groups.ops");
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
        let result = run_merge_driver("not json", "{}", "{}", ".murk");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing base"));
    }

    #[test]
    fn run_merge_driver_invalid_ours() {
        let base = base_vault_json();
        let result = run_merge_driver(&base, "not json", &base, ".murk");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing ours"));
    }

    #[test]
    fn run_merge_driver_invalid_theirs() {
        let base = base_vault_json();
        let result = run_merge_driver(&base, &base, "not json", ".murk");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parsing theirs"));
    }

    #[test]
    fn run_merge_driver_clean_no_changes() {
        // Hold ENV_LOCK: a key set by a concurrent test would make the driver
        // try (and fail) to decrypt these placeholder metas, a conflict.
        let _env = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = base_vault_json();
        let output = run_merge_driver(&base, &base, &base, ".murk").unwrap();
        assert!(output.result.conflicts.is_empty());
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
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
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
                && c.reason
                    .contains("removed on one side, modified on the other")),
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
                && c.reason
                    .contains("removed on one side, modified on the other")),
            "conflicts: {:?}",
            r2.conflicts
        );
        assert_eq!(
            r2.vault
                .schema
                .get("TAGGED")
                .map(|s| s.description.as_str()),
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

    /// Give `vault` a valid meta for `meta`: fresh MAC, signed by `identity`,
    /// encrypted to the vault's recipients — a side the authenticity gate
    /// accepts once its signer is trusted (see [`trusting`]).
    fn seal(vault: &mut Vault, meta: &crate::types::Meta, identity: &crate::crypto::MurkIdentity) {
        let mut meta = meta.clone();
        let key_hex = crate::generate_mac_key();
        let key = crate::decode_mac_key(&key_hex).unwrap();
        meta.mac = crate::compute_mac(vault, &meta.groups, &meta.grants, Some(&key));
        meta.mac_key = Some(key_hex);
        meta.sig = None;
        crate::register_signer(vault, &mut meta.signers, identity);
        let recipients = crate::parse_recipients(&vault.recipients).unwrap();
        vault.meta =
            crate::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
        vault.version = crate::types::VAULT_VERSION.into();
        vault.sig = None;
        vault.sig = crate::sign_vault(vault, identity);
    }

    /// Run `f` with `key` as MURK_KEY and `pubkey` as the only trusted signer,
    /// with no trust pin read or written. Caller holds ENV_LOCK.
    fn trusting<T>(key: &str, pubkey: &str, f: impl FnOnce() -> T) -> T {
        let vk = crate::crypto::parse_identity(key)
            .unwrap()
            .signing_key()
            .unwrap()
            .verifying_key();
        unsafe {
            std::env::set_var("MURK_KEY", key);
            std::env::set_var("MURK_TRUSTED_SIGNERS", format!("{pubkey}:{vk}"));
            std::env::set_var("MURK_NO_SIGNER_PIN", "1");
        }
        let out = f();
        unsafe {
            std::env::remove_var("MURK_KEY");
            std::env::remove_var("MURK_TRUSTED_SIGNERS");
            std::env::remove_var("MURK_NO_SIGNER_PIN");
        }
        out
    }

    // -- regenerate_meta: rebuilds names, prunes stale groups --

    #[test]
    fn regenerate_meta_rebuilds_names_and_prunes_stale_groups() {
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);

        // Meta with a name for pubkey, a live group, and a stale group whose
        // only member is no longer a recipient of the merged vault.
        let source_meta = crate::types::Meta {
            recipients: std::collections::HashMap::from([(pubkey.clone(), "alice".to_string())]),
            groups: BTreeMap::from([
                ("team".to_string(), vec![pubkey.clone()]),
                (
                    "ghost".to_string(),
                    vec![crate::testutil::AGE_PK.to_string()],
                ),
            ]),
            ..Default::default()
        };

        let mut ours = base_vault();
        ours.recipients = vec![pubkey.clone()];
        seal(&mut ours, &source_meta, &identity);
        let theirs = ours.clone();
        let mut merged = ours.clone();
        // The merged vault recognizes only `pubkey`; the ghost member is gone.
        merged.recipients = vec![pubkey.clone()];

        let mut conflicts = Vec::new();
        let out = trusting(&secret, &pubkey, || {
            regenerate_meta(&mut merged, &ours, &ours, &theirs, ".murk", &mut conflicts).unwrap()
        });

        assert!(
            out.is_some(),
            "regenerate_meta must succeed with MURK_KEY set"
        );
        let meta = crate::decrypt_meta(&merged, &identity)
            .unwrap()
            .expect("merged meta must decrypt");
        assert!(
            merged.sig.is_some(),
            "a keyed merge of trusted sides is signed"
        );
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

    #[test]
    fn merge_refuses_a_theirs_that_drops_a_group_still_in_use() {
        // Base has group ops; ours adds S to it; theirs deletes the group.
        // Every side is genuine, and the merge still must not keep S's
        // ciphertext for a group that no longer exists.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let with_ops = crate::types::Meta {
            groups: BTreeMap::from([("ops".to_string(), vec![pubkey.clone()])]),
            ..Default::default()
        };

        let mut base = base_vault();
        base.recipients = vec![pubkey.clone()];
        base.generation = 1;
        let mut ours = base.clone();
        let mut theirs = base.clone();
        seal(&mut base, &with_ops, &identity);
        ours.generation = 2;
        ours.secrets.insert(
            "S".to_string(),
            SecretEntry {
                grouped: BTreeMap::from([("ops".to_string(), "Y2lwaGVy".to_string())]),
                ..Default::default()
            },
        );
        seal(&mut ours, &with_ops, &identity);
        theirs.generation = 2;
        seal(&mut theirs, &crate::types::Meta::default(), &identity);
        let mut result = merge_vaults(&base, &ours, &theirs);
        let regenerated = trusting(&secret, &pubkey, || {
            regenerate_meta(
                &mut result.vault,
                &base,
                &ours,
                &theirs,
                ".murk",
                &mut result.conflicts,
            )
        })
        .unwrap();

        assert!(
            result.conflicts.iter().any(|c| c.field == "secrets.S"),
            "{:?}",
            result.conflicts
        );
        assert!(
            regenerated.is_none(),
            "a conflicted merge must not get a fresh MAC"
        );
        assert_eq!(result.vault.meta, ours.meta);
    }

    #[test]
    fn merge_refuses_two_verifying_keys_for_one_signer() {
        // Both sides are genuine and signed by trusted alice, yet they register
        // different verifying keys for bob: one of them lies, so the merge must
        // stop rather than pick a key.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (alice_secret, alice) = generate_keypair();
        let alice_identity = make_identity(&alice_secret);
        let (_, bob) = generate_keypair();
        let vk = || {
            make_identity(&generate_keypair().0)
                .signing_key()
                .unwrap()
                .verifying_key()
        };
        let registry = |vk: String| crate::types::Meta {
            signers: BTreeMap::from([(bob.clone(), vk)]),
            ..Default::default()
        };

        let mut base = base_vault();
        base.recipients = vec![alice.clone(), bob.clone()];
        base.generation = 1;
        let mut ours = base.clone();
        let mut theirs = base.clone();
        seal(&mut base, &crate::types::Meta::default(), &alice_identity);
        ours.generation = 2;
        seal(&mut ours, &registry(vk()), &alice_identity);
        theirs.generation = 2;
        seal(&mut theirs, &registry(vk()), &alice_identity);

        let mut result = merge_vaults(&base, &ours, &theirs);
        let regenerated = trusting(&alice_secret, &alice, || {
            regenerate_meta(
                &mut result.vault,
                &base,
                &ours,
                &theirs,
                ".murk",
                &mut result.conflicts,
            )
        })
        .unwrap();

        assert!(
            result
                .conflicts
                .iter()
                .any(|c| c.field.starts_with("signers.")
                    && c.reason.contains("different verifying keys")),
            "{:?}",
            result.conflicts
        );
        assert!(
            regenerated.is_none(),
            "a conflicted merge must not get a fresh MAC"
        );
        assert_eq!(result.vault.meta, ours.meta);
    }

    #[test]
    fn a_ghost_grant_on_the_operators_key_does_not_block_their_merge() {
        // A 3.x meta record (and `agents` blob) bound to the merging key is a
        // ghost: the key opens the meta, so it is an operator and may merge.
        // The real grant (no meta access, its own blob) is still refused.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_recipient};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (op_sk, op_pk) = generate_keypair();
        let (agent_sk, agent_pk) = generate_keypair();
        let grant = |pubkey: &str| crate::types::GrantEntry {
            pubkey: pubkey.to_string(),
            scope: vec!["DB_URL".into()],
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            issuer: op_pk.clone(),
            anchors: Vec::new(),
        };
        let meta = crate::types::Meta {
            grants: BTreeMap::from([
                ("ghost".to_string(), grant(&op_pk)),
                ("bot".to_string(), grant(&agent_pk)),
            ]),
            ..Default::default()
        };
        let mut side = base_vault();
        side.version = crate::types::VAULT_VERSION.into();
        side.recipients = vec![op_pk.clone(), agent_pk.clone()];
        side.meta = crate::encrypt_value(
            &serde_json::to_vec(&meta).unwrap(),
            std::slice::from_ref(&make_recipient(&op_pk)),
        )
        .unwrap();
        side.agents = crate::agents::blobs_for(&meta.grants, &[]).unwrap();

        unsafe { std::env::set_var("MURK_KEY", &op_sk) };
        let operator_refused = merge_key_is_grant(&[&side]);
        unsafe { std::env::set_var("MURK_KEY", &agent_sk) };
        let grant_refused = merge_key_is_grant(&[&side]);
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(
            !operator_refused,
            "the operator's merge must not be refused"
        );
        assert!(grant_refused, "the real grant's merge must be refused");
    }

    #[test]
    fn regenerate_meta_refuses_invalid_meta_instead_of_dropping_it() {
        use crate::testutil::{ENV_LOCK, generate_keypair, make_recipient};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        // A hostile meta: a group whose name carries a terminal escape.
        let hostile = crate::types::Meta {
            groups: BTreeMap::from([("\u{1b}[31mprod".to_string(), vec![pubkey.clone()])]),
            ..Default::default()
        };
        let mut ours = base_vault();
        ours.recipients = vec![pubkey.clone()];
        ours.meta = crate::encrypt_value(
            &serde_json::to_vec(&hostile).unwrap(),
            std::slice::from_ref(&recipient),
        )
        .unwrap();
        let theirs = ours.clone();
        let mut merged = ours.clone();

        let mut conflicts = Vec::new();
        let out = trusting(&secret, &pubkey, || {
            regenerate_meta(&mut merged, &ours, &ours, &theirs, ".murk", &mut conflicts)
        });

        assert_eq!(
            out,
            Ok(None),
            "invalid meta must fail the merge, not be emptied"
        );
        // Base and ours carry the same hostile meta; the ancestor is checked
        // first and named.
        let reason = &conflicts
            .iter()
            .find(|c| c.field == "base" || c.field == "ours")
            .expect("the hostile meta must be flagged")
            .reason;
        assert!(
            reason.contains("vault meta is invalid (meta.groups key: invalid group name"),
            "{reason:?}"
        );
        assert!(
            !reason.chars().any(char::is_control),
            "raw control char in {reason:?}"
        );
        assert_eq!(merged.meta, ours.meta, "meta must not be rewritten");
    }

    #[test]
    fn merge_never_merges_or_signs_a_forged_theirs() {
        // Theirs is signed by a key the merging machine does not trust (an
        // outsider who listed themselves). It must be a conflict naming theirs,
        // with ours' meta left in place — no fresh MAC, no signature.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (secret, pubkey) = generate_keypair();
        let (mallory_secret, mallory) = generate_keypair();
        let mut ours = base_vault();
        ours.recipients = vec![pubkey.clone()];
        seal(
            &mut ours,
            &crate::types::Meta::default(),
            &make_identity(&secret),
        );
        let mut theirs = ours.clone();
        theirs.recipients.push(mallory.clone());
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "attacker-ciphertext".into();
        seal(
            &mut theirs,
            &crate::types::Meta::default(),
            &make_identity(&mallory_secret),
        );

        let mut result = merge_vaults(&ours, &ours, &theirs);
        let regenerated = trusting(&secret, &pubkey, || {
            regenerate_meta(
                &mut result.vault,
                &ours,
                &ours,
                &theirs,
                ".murk",
                &mut result.conflicts,
            )
        })
        .unwrap();

        assert!(
            result
                .conflicts
                .iter()
                .any(|c| c.field == "theirs" && c.reason.contains("not a trusted signer")),
            "{:?}",
            result.conflicts
        );
        assert!(regenerated.is_none());
        assert_eq!(result.vault.meta, ours.meta, "nothing re-MACed or signed");
    }

    #[test]
    fn an_unsigned_ancestor_grants_no_group_authority() {
        // Pinned: group ops = [alice]. Mallory, a trusted signer outside ops,
        // adds herself on theirs and supplies an unsigned, id-less ancestor
        // that already lists her in ops, so her change looks like no change.
        // The ancestor is not authenticated, so pinned membership decides.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(".murk");
        let vault_path = vault_path.to_str().unwrap();
        let (alice_secret, alice) = generate_keypair();
        let (mallory_secret, mallory) = generate_keypair();

        let mut ours = base_vault();
        ours.recipients = vec![alice.clone(), mallory.clone()];
        ours.vault_id = "00112233445566778899aabbccddeeff".into();
        let alice_only = crate::types::Meta {
            groups: BTreeMap::from([("ops".to_string(), vec![alice.clone()])]),
            ..Default::default()
        };
        let with_mallory = crate::types::Meta {
            groups: BTreeMap::from([("ops".to_string(), vec![alice.clone(), mallory.clone()])]),
            ..Default::default()
        };
        let mut base = ours.clone();
        base.vault_id.clear();
        let mut theirs = ours.clone();
        ours.generation = 2;
        theirs.generation = 2;
        seal(&mut ours, &alice_only, &make_identity(&alice_secret));
        seal(&mut theirs, &with_mallory, &make_identity(&mallory_secret));
        seal(&mut base, &with_mallory, &make_identity(&mallory_secret));
        // Strip the ancestor's signature: an unsigned pre-0.14-looking file.
        base.sig = None;

        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("MURK_NO_SIGNER_PIN");
            std::env::remove_var("MURK_TRUSTED_SIGNERS");
            std::env::set_var("MURK_KEY", &alice_secret);
        }
        let pin = crate::pins::TrustPin {
            v: crate::pins::PIN_VERSION,
            vault_id: ours.vault_id.clone(),
            generation: 1,
            trusted: [alice.clone(), mallory.clone()].into(),
            ever_trusted: [alice.clone(), mallory.clone()].into(),
            groups: BTreeMap::from([("ops".to_string(), [alice.clone()].into())]),
            signers: [&alice_secret, &mallory_secret]
                .iter()
                .zip([&alice, &mallory])
                .map(|(secret, pk)| {
                    let vk = make_identity(secret).signing_key().unwrap().verifying_key();
                    (pk.clone(), vk)
                })
                .collect(),
            was_signed: true,
            ..Default::default()
        };
        crate::pins::write(vault_path, &pin).unwrap();

        let mut result = merge_vaults(&base, &ours, &theirs);
        let regenerated = regenerate_meta(
            &mut result.vault,
            &base,
            &ours,
            &theirs,
            vault_path,
            &mut result.conflicts,
        )
        .unwrap();
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(regenerated.is_none(), "{:?}", result.conflicts);
        assert!(
            result
                .conflicts
                .iter()
                .any(|c| c.field == "theirs" && c.reason.contains("group ops")),
            "{:?}",
            result.conflicts
        );
    }

    /// Give `vault` a murk 0.13 meta: fresh MAC, the signer registry naming
    /// `signer` with `sk`'s verifying key, and a view-1 signature by `sk`
    /// inside the meta.
    fn seal_v1(vault: &mut Vault, signer: &str, sk: &crate::signing::VaultSigningKey) {
        let mut meta = crate::types::Meta {
            signers: BTreeMap::from([(signer.to_string(), sk.verifying_key())]),
            ..Default::default()
        };
        let key_hex = crate::generate_mac_key();
        let key = crate::decode_mac_key(&key_hex).unwrap();
        meta.mac = crate::compute_mac(vault, &meta.groups, &meta.grants, Some(&key));
        meta.mac_key = Some(key_hex);
        let msg = crate::signature::signing_message(
            vault,
            &meta.groups,
            &meta.grants,
            &meta.github_pins,
            &meta.signers,
        );
        meta.sig = Some(crate::types::VaultSignature {
            signer: signer.to_string(),
            v: crate::signature::LEGACY_SIGNED_VIEW_VERSION,
            sig: sk.sign(&msg),
        });
        let recipients = crate::parse_recipients(&vault.recipients).unwrap();
        vault.meta =
            crate::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
    }

    #[test]
    fn a_genuine_0_13_ancestor_of_two_upgraded_sides_merges() {
        // Two branches forked before the 0.14 upgrade and were each saved by
        // 0.14 since: their common ancestor is a 0.13 vault (format 2.0, no id,
        // a view-1 signature in the meta by a trusted signer whose key this
        // machine pinned on upgrade). That is history, not a rollback or
        // another vault, so the keyed merge goes ahead and is signed.
        use crate::testutil::{ENV_LOCK, generate_keypair, make_identity};

        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(".murk");
        let vault_path = vault_path.to_str().unwrap();
        let (alice_secret, alice) = generate_keypair();
        let alice_id = make_identity(&alice_secret);
        let alice_vk = alice_id.signing_key().unwrap().verifying_key();

        // The 0.13 ancestor: view 1 inside the meta, signed with the KDF key.
        let mut base = base_vault();
        base.recipients = vec![alice.clone()];
        base.version = "2.0".into();
        let alice_sk = alice_id.signing_key().unwrap();
        seal_v1(&mut base, &alice, &alice_sk);

        // Both sides upgraded: id derived from the shared header, counters set.
        let mut ours = base.clone();
        ours.vault_id = crate::save::derived_vault_id(&base);
        ours.generation = 1;
        let mut theirs = ours.clone();
        theirs.generation = 2;
        seal(&mut ours, &crate::types::Meta::default(), &alice_id);
        seal(&mut theirs, &crate::types::Meta::default(), &alice_id);

        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("MURK_NO_SIGNER_PIN");
            std::env::remove_var("MURK_TRUSTED_SIGNERS");
            std::env::set_var("MURK_KEY", &alice_secret);
        }
        // This machine trusted the 0.13 vault, then saw it upgraded.
        let pin = crate::pins::TrustPin {
            v: crate::pins::PIN_VERSION,
            vault_id: ours.vault_id.clone(),
            generation: 2,
            trusted: [alice.clone()].into(),
            ever_trusted: [alice.clone()].into(),
            signers: BTreeMap::from([(alice.clone(), alice_vk.clone())]),
            was_signed: true,
            ..Default::default()
        };
        crate::pins::write(vault_path, &pin).unwrap();

        let mut result = merge_vaults(&base, &ours, &theirs);
        let regenerated = regenerate_meta(
            &mut result.vault,
            &base,
            &ours,
            &theirs,
            vault_path,
            &mut result.conflicts,
        );
        // The same ancestor with a registry key this machine never pinned
        // (a forged 0.13 history) is still refused.
        let mut forged_base = base.clone();
        let mallory_sk = make_identity(&generate_keypair().0).signing_key().unwrap();
        seal_v1(&mut forged_base, &alice, &mallory_sk);
        let mut forged = merge_vaults(&forged_base, &ours, &theirs);
        let forged_out = regenerate_meta(
            &mut forged.vault,
            &forged_base,
            &ours,
            &theirs,
            vault_path,
            &mut forged.conflicts,
        );
        unsafe { std::env::remove_var("MURK_KEY") };
        match prev_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert!(
            matches!(regenerated, Ok(Some(_))),
            "{regenerated:?} {:?}",
            result.conflicts
        );
        assert!(result.conflicts.is_empty(), "{:?}", result.conflicts);
        assert!(result.vault.sig.is_some(), "the merge is signed");
        assert!(matches!(forged_out, Ok(None)), "{forged_out:?}");
        assert!(
            forged.conflicts.iter().any(|c| c.field == "base"),
            "{:?}",
            forged.conflicts
        );
    }
}
