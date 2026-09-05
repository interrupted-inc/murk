//! Named recipient groups: the access-segmentation primitive.
//!
//! A group is a named subset of the vault's recipients. Secrets assigned to a
//! group are encrypted only to its members, so a leaked member key can't read
//! secrets outside that member's groups. Membership lives in the encrypted meta
//! (see [`crate::types::Meta::groups`]) so org structure doesn't leak, and is
//! covered by the keyed MAC so it can't be tampered with undetected.
//!
//! Two group names are reserved as routing aliases for the existing tiers and
//! are never stored: `everyone` (the shared value, encrypted to all recipients)
//! and `me` (a personal scoped value, encrypted to the caller only).

use crate::error::MurkError;
use crate::types;

/// Reserved group names. These route to the shared/private tiers instead of a
/// stored group, so a real group can't take these names.
pub const RESERVED_GROUP_NAMES: &[&str] = &["everyone", "me", "all", "self", "mine", "shared"];

/// True if `name` is a reserved routing alias.
pub fn is_reserved(name: &str) -> bool {
    RESERVED_GROUP_NAMES.contains(&name)
}

/// Validate a group name: 1–64 chars of `[A-Za-z0-9_-]`, not reserved.
pub fn validate_group_name(name: &str) -> Result<(), MurkError> {
    crate::grants::validate_short_name(name, "group").map_err(MurkError::Group)?;
    if is_reserved(name) {
        return Err(MurkError::Group(format!(
            "\"{name}\" is a reserved name (it routes to the {name} tier, not a group)"
        )));
    }
    Ok(())
}

/// Create a new empty group, seeded with the creator as its first member so
/// they can always read and re-encrypt it. Errors if the name is invalid or the
/// group already exists.
pub fn create_group(
    murk: &mut types::Murk,
    name: &str,
    creator_pubkey: &str,
) -> Result<(), MurkError> {
    validate_group_name(name)?;
    if murk.groups.contains_key(name) {
        return Err(MurkError::Group(format!("group already exists: {name}")));
    }
    murk.groups
        .insert(name.into(), vec![creator_pubkey.to_string()]);
    Ok(())
}

/// Delete a group. Refuses if any secret is still assigned to it — the caller
/// should reassign or remove those secrets first, so no data is silently
/// orphaned (group ciphertext would become unreadable).
pub fn delete_group(
    vault: &types::Vault,
    murk: &mut types::Murk,
    name: &str,
) -> Result<(), MurkError> {
    if !murk.groups.contains_key(name) {
        return Err(MurkError::Group(format!("group not found: {name}")));
    }
    let assigned: Vec<&str> = vault
        .secrets
        .iter()
        .filter(|(_, e)| e.grouped.contains_key(name))
        .map(|(k, _)| k.as_str())
        .collect();
    if !assigned.is_empty() {
        return Err(MurkError::Group(format!(
            "group \"{name}\" still has {} secret(s) assigned ({}) — reassign or remove them first",
            assigned.len(),
            assigned.join(", ")
        )));
    }
    murk.groups.remove(name);
    Ok(())
}

/// Resolve a member spec (a pubkey or a display name) to a recipient pubkey.
/// The result must be an authorized recipient of the vault.
pub fn resolve_member(
    vault: &types::Vault,
    murk: &types::Murk,
    spec: &str,
) -> Result<String, MurkError> {
    if vault.recipients.iter().any(|pk| pk == spec) {
        return Ok(spec.to_string());
    }
    let matched: Vec<&String> = murk
        .recipients
        .iter()
        .filter(|(_, name)| name.as_str() == spec)
        .map(|(pk, _)| pk)
        .collect();
    match matched.as_slice() {
        [] => Err(MurkError::Group(format!(
            "no recipient matches \"{spec}\" — authorize them first with `murk circle authorize`"
        ))),
        [pk] => Ok((*pk).clone()),
        _ => Err(MurkError::Group(format!(
            "ambiguous name \"{spec}\" matches {} recipients — use a pubkey",
            matched.len()
        ))),
    }
}

/// Add a member to a group. The group must exist, the operator must already be
/// a member (so they can re-encrypt the group's secrets), and the new member
/// must be an authorized recipient. Returns true if the member was added (false
/// if already present).
pub fn add_member(
    murk: &mut types::Murk,
    name: &str,
    member_pubkey: &str,
    operator_pubkey: &str,
) -> Result<bool, MurkError> {
    let members = murk
        .groups
        .get_mut(name)
        .ok_or_else(|| MurkError::Group(format!("group not found: {name}")))?;
    if !members.iter().any(|pk| pk == operator_pubkey) {
        return Err(MurkError::Group(format!(
            "you must be a member of group \"{name}\" to modify it"
        )));
    }
    if members.iter().any(|pk| pk == member_pubkey) {
        return Ok(false);
    }
    members.push(member_pubkey.to_string());
    Ok(true)
}

/// Remove a member from a group. The operator must be a member. Refuses to
/// remove the last member (the group's secrets would become unreadable).
/// Returns true if the member was removed (false if not present).
pub fn remove_member(
    murk: &mut types::Murk,
    name: &str,
    member_pubkey: &str,
    operator_pubkey: &str,
) -> Result<bool, MurkError> {
    let members = murk
        .groups
        .get_mut(name)
        .ok_or_else(|| MurkError::Group(format!("group not found: {name}")))?;
    if !members.iter().any(|pk| pk == operator_pubkey) {
        return Err(MurkError::Group(format!(
            "you must be a member of group \"{name}\" to modify it"
        )));
    }
    if !members.iter().any(|pk| pk == member_pubkey) {
        return Ok(false);
    }
    if members.len() == 1 {
        return Err(MurkError::Group(format!(
            "cannot remove the last member of group \"{name}\" — delete the group instead"
        )));
    }
    members.retain(|pk| pk != member_pubkey);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::testutil::{empty_murk, empty_vault};

    #[test]
    fn validate_rejects_reserved_and_invalid() {
        assert!(validate_group_name("prod").is_ok());
        assert!(validate_group_name("dev-team_1").is_ok());
        assert!(validate_group_name("me").is_err());
        assert!(validate_group_name("everyone").is_err());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("has space").is_err());
        assert!(validate_group_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn create_seeds_creator_as_member() {
        let mut murk = empty_murk();
        create_group(&mut murk, "prod", "age1alice").unwrap();
        assert_eq!(murk.groups["prod"], vec!["age1alice".to_string()]);
        // Duplicate create fails.
        assert!(create_group(&mut murk, "prod", "age1alice").is_err());
    }

    #[test]
    fn add_member_requires_operator_membership() {
        let mut murk = empty_murk();
        create_group(&mut murk, "prod", "age1alice").unwrap();
        // A non-member operator can't modify the group.
        assert!(add_member(&mut murk, "prod", "age1bob", "age1carol").is_err());
        // A member can.
        assert!(add_member(&mut murk, "prod", "age1bob", "age1alice").unwrap());
        // Adding an existing member is a no-op.
        assert!(!add_member(&mut murk, "prod", "age1bob", "age1alice").unwrap());
        assert_eq!(murk.groups["prod"].len(), 2);
    }

    #[test]
    fn remove_member_refuses_last() {
        let mut murk = empty_murk();
        create_group(&mut murk, "prod", "age1alice").unwrap();
        add_member(&mut murk, "prod", "age1bob", "age1alice").unwrap();
        assert!(remove_member(&mut murk, "prod", "age1bob", "age1alice").unwrap());
        // Only alice left — removing her is refused.
        assert!(remove_member(&mut murk, "prod", "age1alice", "age1alice").is_err());
    }

    #[test]
    fn delete_refuses_when_secrets_assigned() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        create_group(&mut murk, "prod", "age1alice").unwrap();

        // No secrets yet — delete works.
        delete_group(&vault, &mut murk, "prod").unwrap();

        // Re-create and assign a secret; now delete is refused.
        create_group(&mut murk, "prod", "age1alice").unwrap();
        vault.secrets.insert(
            "K".into(),
            types::SecretEntry {
                grouped: BTreeMap::from([("prod".into(), "ct".into())]),
                ..Default::default()
            },
        );
        assert!(delete_group(&vault, &mut murk, "prod").is_err());
    }

    #[test]
    fn resolve_member_by_name_and_pubkey() {
        let vault = types::Vault {
            recipients: vec!["age1alice".into()],
            ..empty_vault()
        };
        let mut murk = empty_murk();
        murk.recipients.insert("age1alice".into(), "alice".into());

        assert_eq!(
            resolve_member(&vault, &murk, "age1alice").unwrap(),
            "age1alice"
        );
        assert_eq!(resolve_member(&vault, &murk, "alice").unwrap(), "age1alice");
        assert!(resolve_member(&vault, &murk, "nobody").is_err());
    }
}
