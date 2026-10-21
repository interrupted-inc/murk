// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault MAC engine: the versioned keyed/unkeyed integrity tags and the
//! version-gated verifier. Preserving these byte-for-byte is what keeps old
//! vaults verifiable and blocks silent downgrade of a newer scheme.

use crate::types;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Compute an integrity MAC over the vault's secrets, scoped entries, grouped
/// entries, recipients, schema, group membership, grants, policy, revoked-at
/// markers, and the header identity fields.
///
/// With a key, always uses v10 (`blake3v8:`), the only scheme that covers the
/// header identity fields (`vault_name`, `repo`, `created`, `vault_id`,
/// `generation`), so every save upgrades an older vault. Without a key, falls
/// back to unkeyed SHA-256 v2 for legacy compatibility.
pub(crate) fn compute_mac(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    mac_key: Option<&[u8; 32]>,
) -> String {
    match mac_key {
        Some(key) => compute_mac_v10(vault, groups, grants, key),
        None => compute_mac_v2(vault),
    }
}

/// Newest `blake3vN:` prefix this build writes and verifies.
const NEWEST_BLAKE3_VERSION: u32 = 8;

/// Whether `mac` carries a `blake3vN:` prefix newer than this build knows: the
/// output of a newer murk, which the caller reports as such instead of as
/// tampering. Any other unrecognized MAC is just invalid.
pub(crate) fn is_newer_mac_scheme(mac: &str) -> bool {
    mac.strip_prefix("blake3v")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(n, _)| n.parse::<u32>().ok())
        .is_some_and(|n| n > NEWEST_BLAKE3_VERSION)
}

/// Legacy MAC: covers key names, shared ciphertext, and recipients (no scoped).
fn compute_mac_v1(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V2 MAC: covers key names, shared ciphertext, scoped entries, and recipients.
fn compute_mac_v2(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Hash sorted key names.
    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    // Hash encrypted shared values (as stored).
    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");

        // Hash scoped entries (sorted by pubkey for determinism).
        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            hasher.update(pk.as_bytes());
            hasher.update(b"\x01");
            hasher.update(entry.private[pk].as_bytes());
            hasher.update(b"\x00");
        }
    }

    // Hash sorted recipient pubkeys.
    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256v2:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V3 MAC: BLAKE3 keyed hash over the same inputs as v2.
fn compute_mac_v3(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3:{hash}")
}

/// V4 MAC: BLAKE3 keyed hash over secrets, recipients, AND schema.
/// Prefix `blake3v2:` distinguishes from v3 which omitted schema.
fn compute_mac_v4(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    // Schema: include descriptions, examples, and tags for each key.
    // Uses 0x02 separator to distinguish from secrets/recipients data.
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v2:{hash}")
}

/// V5 MAC: extends v4 to also cover each schema entry's lifecycle metadata —
/// `created`, `updated`, `rotation_interval_days`, and `expires_at`. This makes
/// rotation policy tamper-evident, so strict mode can treat it as a trustworthy
/// machine-checkable signal rather than freely-editable plaintext. Prefix
/// `blake3v3:` distinguishes it from v4 which stopped at description/example/tags.
pub(crate) fn compute_mac_v5(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    // Schema: description, example, tags (as in v4) plus lifecycle metadata.
    // Optional fields are emitted as their bytes (empty when absent) followed by
    // a 0x00 terminator, so present/absent stays deterministic. `0x02` separates
    // each schema entry from the secrets/recipients stream above.
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
        // Lifecycle metadata (new in v5). Strings go in as UTF-8; the interval
        // goes in as its decimal text for consistency with the rest of the stream.
        if let Some(created) = &entry.created {
            data.extend_from_slice(created.as_bytes());
        }
        data.push(0x00);
        if let Some(updated) = &entry.updated {
            data.extend_from_slice(updated.as_bytes());
        }
        data.push(0x00);
        if let Some(days) = entry.rotation_interval_days {
            data.extend_from_slice(days.to_string().as_bytes());
        }
        data.push(0x00);
        if let Some(expires) = &entry.expires_at {
            data.extend_from_slice(expires.as_bytes());
        }
        data.push(0x00);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v3:{hash}")
}

/// Append the v5/v6 schema byte stream to `data`. Kept identical to the inline
/// loop in `compute_mac_v5` so v6 reuses the exact schema encoding without
/// risking a change to v5's bytes.
fn schema_mac_bytes(vault: &types::Vault, data: &mut Vec<u8>) {
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
        if let Some(created) = &entry.created {
            data.extend_from_slice(created.as_bytes());
        }
        data.push(0x00);
        if let Some(updated) = &entry.updated {
            data.extend_from_slice(updated.as_bytes());
        }
        data.push(0x00);
        if let Some(days) = entry.rotation_interval_days {
            data.extend_from_slice(days.to_string().as_bytes());
        }
        data.push(0x00);
        if let Some(expires) = &entry.expires_at {
            data.extend_from_slice(expires.as_bytes());
        }
        data.push(0x00);
    }
}

/// Append the v6 byte stream (secrets, scoped, grouped ciphertexts, recipients,
/// schema, and group definitions) to `data`. Factored out so v7 can extend the
/// exact same bytes without risking a change to v6's encoding.
fn v6_mac_bytes(vault: &types::Vault, groups: &BTreeMap<String, Vec<String>>, data: &mut Vec<u8>) {
    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }

        // Grouped ciphertexts, sorted by group name. `0x03` marks each entry so
        // the group stream can't be confused with the scoped (`0x01`) stream.
        let mut group_names: Vec<&String> = entry.grouped.keys().collect();
        group_names.sort();
        for g in group_names {
            data.push(0x03);
            data.extend_from_slice(g.as_bytes());
            data.push(0x00);
            data.extend_from_slice(entry.grouped[g].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    schema_mac_bytes(vault, data);

    // Group definitions (sorted by name; members sorted). `0x04` separates each
    // group, `0x05` each member, so membership can't be tampered with undetected.
    for (name, members) in groups {
        data.push(0x04);
        data.extend_from_slice(name.as_bytes());
        data.push(0x00);
        let mut sorted = members.clone();
        sorted.sort();
        for member in &sorted {
            data.push(0x05);
            data.extend_from_slice(member.as_bytes());
        }
    }
}

/// v6 MAC (`blake3v4:`). Extends v5 with the per-secret grouped ciphertexts and
/// the group membership map, so a named group's members and the values encrypted
/// to them cannot be tampered with undetected. Verified for vaults written
/// before v10; no longer emitted.
fn compute_mac_v6(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v6_mac_bytes(vault, groups, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v4:{hash}")
}

/// v7 MAC (`blake3v5:`). Extends v6 with agent grant metadata — each grant's
/// name, ephemeral pubkey, sorted scope, issued_at, expires_at, and issuer — so
/// a grant's TTL and scope cannot be tampered with undetected. Verified for
/// vaults written before v10; no longer emitted.
///
/// Append the v7 byte stream (v6 bytes plus agent grant metadata) to `data`.
/// Factored out so v8 can extend the exact same bytes without risking a change
/// to v7's encoding.
fn v7_mac_bytes(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    data: &mut Vec<u8>,
) {
    v6_mac_bytes(vault, groups, data);

    // Grants (BTreeMap → sorted by name). `0x06` separates each grant; fixed
    // fields are 0x00-terminated; each scope key is prefixed `0x07` (sorted), so
    // the grant stream can't be confused with the group (`0x04`/`0x05`) stream.
    for (name, grant) in grants {
        data.push(0x06);
        data.extend_from_slice(name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.pubkey.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.issued_at.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.expires_at.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.issuer.as_bytes());
        data.push(0x00);
        let mut scope = grant.scope.clone();
        scope.sort();
        for k in &scope {
            data.push(0x07);
            data.extend_from_slice(k.as_bytes());
        }
    }
}

fn compute_mac_v7(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v7_mac_bytes(vault, groups, grants, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v5:{hash}")
}

/// Append the v8 byte stream (v7 bytes plus the header policy block) to `data`.
/// Factored out so v9 can extend the exact same bytes without risking a change
/// to v8's encoding.
fn v8_mac_bytes(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    data: &mut Vec<u8>,
) {
    v7_mac_bytes(vault, groups, grants, data);

    // Policy (header). `0x08` opens the policy block (present only when a policy
    // exists, so Some-but-empty is distinct from None). Each agent allow-tag is
    // length-prefixed (8-byte big-endian) and sorted, so the byte stream is
    // unambiguous regardless of tag contents — a crafted tag can't forge a
    // boundary (e.g. `["a\tb"]` and `["a", "b"]` hash differently). New policy
    // fields extend this block.
    if let Some(policy) = &vault.policy {
        data.push(0x08);
        let mut tags = policy.agent_allow_tags.clone();
        tags.sort();
        for tag in &tags {
            let bytes = tag.as_bytes();
            // usize→u64 is lossless on supported targets; fixed-width length
            // prefix keeps the encoding unambiguous.
            data.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            data.extend_from_slice(bytes);
        }
    }
}

/// v8 MAC (`blake3v6:`). Extends v7 with the plaintext header policy object, so a
/// vault's agent access policy cannot be weakened or stripped undetected.
/// Verified for vaults written before v10; no longer emitted.
fn compute_mac_v8(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v8_mac_bytes(vault, groups, grants, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v6:{hash}")
}

/// v9 MAC (`blake3v7:`). Extends v8 with each schema entry's `revoked_at` marker,
/// so the "still owed a rotation since a revoke" flag is tamper-evident — an
/// attacker editing `.murk` can't silently clear it. Verified for vaults written
/// before v10; no longer emitted.
fn compute_mac_v9(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v9_mac_bytes(vault, groups, grants, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v7:{hash}")
}

/// Append the v9 byte stream (v8 bytes plus revoked-at markers) to `data`.
/// Factored out so v10 extends the exact same bytes without risking a change
/// to v9's encoding.
fn v9_mac_bytes(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    data: &mut Vec<u8>,
) {
    v8_mac_bytes(vault, groups, grants, data);

    // Revoked-at markers, in schema order (BTreeMap → sorted by key name). `0x09`
    // opens each marker so the stream can't be confused with the schema (`0x02`)
    // or policy (`0x08`) blocks; absent markers emit nothing, so a vault that
    // sets one then clears it hashes identically to one that never set it.
    for (key_name, entry) in &vault.schema {
        if let Some(revoked_at) = &entry.revoked_at {
            data.push(0x09);
            data.extend_from_slice(key_name.as_bytes());
            data.push(0x00);
            data.extend_from_slice(revoked_at.as_bytes());
            data.push(0x00);
        }
    }
}

/// v10 MAC (`blake3v8:`). Extends v9 with the plaintext header identity fields
/// and the per-grant `agents` blobs, so a vault's name, repo URL, creation
/// time, vault id, save generation, and grant ciphertexts cannot be edited
/// undetected. `0x0A` opens the header block; each string is length-prefixed
/// (8-byte big-endian) so no field value can forge a boundary, and the
/// generation is a fixed 8-byte big-endian integer. `0x0B` then opens each
/// `agents` entry (sorted by pubkey): length-prefixed pubkey, then ciphertext.
/// Always emitted when a key is present, because every vault has these fields.
fn compute_mac_v10(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    fn push_len_prefixed(data: &mut Vec<u8>, s: &str) {
        // usize→u64 is lossless on supported targets.
        data.extend_from_slice(&(s.len() as u64).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
    }

    let mut data = Vec::new();
    v9_mac_bytes(vault, groups, grants, &mut data);

    data.push(0x0A);
    for field in [
        &vault.vault_name,
        &vault.repo,
        &vault.created,
        &vault.vault_id,
    ] {
        push_len_prefixed(&mut data, field);
    }
    data.extend_from_slice(&vault.generation.to_be_bytes());

    for (pubkey, blob) in &vault.agents {
        data.push(0x0B);
        push_len_prefixed(&mut data, pubkey);
        push_len_prefixed(&mut data, blob);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v8:{hash}")
}

/// Verify a stored MAC against the vault, accepting v1, v2, blake3, and
/// blake3v2 through blake3v8 schemes.
pub(crate) fn verify_mac(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    stored_mac: &str,
    mac_key: Option<&[u8; 32]>,
) -> bool {
    use constant_time_eq::constant_time_eq;

    // `vault_id`, `generation`, and `agents` are only covered by v10
    // (`blake3v8:`), and a 3.x vault is only ever written with it. A vault
    // carrying any of them, or a 3.x version, under an older MAC is tampered or
    // inconsistent: reject it so an attacker can't roll the counter back, swap
    // the vault id, or inject a grant blob by downgrading.
    let needs_v10 = !vault.vault_id.is_empty()
        || vault.generation != 0
        || !vault.agents.is_empty()
        || crate::validate::is_v3_version(&vault.version);
    if needs_v10 && !stored_mac.starts_with("blake3v8:") {
        return false;
    }

    // `revoked_at` is only covered by v9 (`blake3v7:`) and up. A vault carrying
    // one but stamped with an older MAC is tampered or inconsistent — reject it
    // so an attacker can't clear a pending-rotation flag by downgrading the MAC.
    if vault.schema.values().any(|e| e.revoked_at.is_some())
        && !stored_mac.starts_with("blake3v7:")
        && !stored_mac.starts_with("blake3v8:")
    {
        return false;
    }

    // Policy is covered by v8 (`blake3v6:`) and v9 (`blake3v7:`). A vault carrying
    // a policy but stamped with an older MAC is tampered or inconsistent — reject
    // it so an attacker can't strip or weaken the policy by downgrading the MAC.
    if vault.policy.is_some()
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
        && !stored_mac.starts_with("blake3v8:")
    {
        return false;
    }

    // Grant metadata is covered by v7 (`blake3v5:`) and up. A vault carrying
    // grants but stamped with an older MAC is tampered or inconsistent.
    if !grants.is_empty()
        && !stored_mac.starts_with("blake3v5:")
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
        && !stored_mac.starts_with("blake3v8:")
    {
        return false;
    }

    // Group data is covered by v6 and up. A vault carrying any grouped ciphertext
    // or group membership but stamped with an older MAC is either tampered (an
    // attacker injected a `grouped` entry that the old MAC ignores, then relies on
    // group-before-shared resolution) or inconsistent. Reject it rather than
    // verify against a scheme that doesn't cover groups.
    let touches_groups =
        !groups.is_empty() || vault.secrets.values().any(|e| !e.grouped.is_empty());
    if touches_groups
        && !stored_mac.starts_with("blake3v4:")
        && !stored_mac.starts_with("blake3v5:")
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
        && !stored_mac.starts_with("blake3v8:")
    {
        return false;
    }

    let expected = if stored_mac.starts_with("blake3v8:") {
        match mac_key {
            Some(key) => compute_mac_v10(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v7:") {
        match mac_key {
            Some(key) => compute_mac_v9(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v6:") {
        match mac_key {
            Some(key) => compute_mac_v8(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v5:") {
        match mac_key {
            Some(key) => compute_mac_v7(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v4:") {
        match mac_key {
            Some(key) => compute_mac_v6(vault, groups, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v3:") {
        match mac_key {
            Some(key) => compute_mac_v5(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v2:") {
        match mac_key {
            Some(key) => compute_mac_v4(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3:") {
        match mac_key {
            Some(key) => compute_mac_v3(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("sha256v2:") {
        compute_mac_v2(vault)
    } else if stored_mac.starts_with("sha256:") {
        compute_mac_v1(vault)
    } else {
        return false;
    };
    constant_time_eq(stored_mac.as_bytes(), expected.as_bytes())
}

/// Generate a random 32-byte BLAKE3 MAC key, returned as hex. Both the raw
/// bytes and the hex are wiped on drop; the hex is sized up front so writing it
/// never reallocates.
pub(crate) fn generate_mac_key() -> Zeroizing<String> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(rand::random());
    let mut hex = Zeroizing::new(String::with_capacity(64));
    for b in key.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Decode a hex-encoded 32-byte key into a buffer wiped on drop.
pub(crate) fn decode_mac_key(hex: &str) -> Option<Zeroizing<[u8; 32]>> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    #[test]
    fn compute_mac_deterministic() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_eq!(mac1, mac2);
        assert!(mac1.starts_with("blake3v8:"));

        // Without key, falls back to sha256v2
        let mac_legacy = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            None,
        );
        assert!(mac_legacy.starts_with("sha256v2:"));
    }

    #[test]
    fn compute_mac_changes_with_different_secrets() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac_empty = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mac_with_secret = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_empty, mac_with_secret);
    }

    #[test]
    fn compute_mac_changes_with_different_recipients() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        vault.recipients.push("age1xyz".into());
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn compute_mac_changes_with_scoped_entries() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let key = [0u8; 32];
        let mac_no_scoped = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault
            .secrets
            .get_mut("KEY")
            .unwrap()
            .private
            .insert("age1bob".into(), "scoped-ct".into());

        let mac_with_scoped = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_no_scoped, mac_with_scoped);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustively enumerates every MAC scheme
    fn verify_mac_accepts_v1_prefix() {
        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let v1_mac = compute_mac_v1(&vault);
        let v2_mac = compute_mac_v2(&vault);
        let v3_mac = compute_mac_v3(&vault, &key);
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v1_mac,
            None
        ));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v2_mac,
            None
        ));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v3_mac,
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "sha256:bogus",
            None
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3v2:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3v3:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "unknown:prefix",
            None
        ));

        // v4 (blake3v2) — includes schema; still accepted as legacy
        let v4_mac = compute_mac_v4(&vault, &key);
        assert!(v4_mac.starts_with("blake3v2:"));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v4_mac,
            Some(&key)
        ));

        // v5 (blake3v3) — includes lifecycle metadata
        let v5_mac = compute_mac_v5(&vault, &key);
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));

        // v6 (blake3v4) — covers groups; verifies and round-trips
        let groups = BTreeMap::from([("prod".to_string(), vec!["age1abc".to_string()])]);
        let v6_mac = compute_mac_v6(&vault, &groups, &key);
        assert!(v6_mac.starts_with("blake3v4:"));
        assert!(verify_mac(
            &vault,
            &groups,
            &std::collections::BTreeMap::new(),
            &v6_mac,
            Some(&key)
        ));
        // Tampering with membership changes the MAC.
        let tampered = BTreeMap::from([(
            "prod".to_string(),
            vec!["age1abc".to_string(), "age1evil".to_string()],
        )]);
        assert!(!verify_mac(
            &vault,
            &tampered,
            &std::collections::BTreeMap::new(),
            &v6_mac,
            Some(&key)
        ));
    }

    #[test]
    fn verify_mac_rejects_grouped_under_legacy_prefix() {
        // A v5 (blake3v3) MAC doesn't cover grouped ciphertext. Injecting a
        // grouped entry must not verify against the old scheme — otherwise an
        // attacker without a key could add a group value that wins on read.
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [7u8; 32];
        let no_groups = BTreeMap::new();
        let v5_mac = compute_mac_v5(&vault, &key);
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(verify_mac(
            &vault,
            &no_groups,
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));

        // Attacker injects a grouped entry; the v5 MAC is now invalid for it.
        vault.secrets.insert(
            "STOLEN".into(),
            types::SecretEntry {
                grouped: BTreeMap::from([("prod".to_string(), "injected-ct".to_string())]),
                ..Default::default()
            },
        );
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v7_covers_grant_metadata() {
        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into(), "age1agent".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [9u8; 32];
        let no_groups = BTreeMap::new();

        // v7 (blake3v5) covers grant metadata.
        let grants = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
                anchors: Vec::new(),
            },
        )]);
        let v7_mac = compute_mac_v7(&vault, &no_groups, &grants, &key);
        assert!(v7_mac.starts_with("blake3v5:"));
        assert!(verify_mac(&vault, &no_groups, &grants, &v7_mac, Some(&key)));

        // Widening the scope (or extending the TTL) changes the MAC.
        let tampered = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into(), "PROD_DB".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
                anchors: Vec::new(),
            },
        )]);
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &tampered,
            &v7_mac,
            Some(&key)
        ));
    }

    #[test]
    fn verify_mac_rejects_grants_under_legacy_prefix() {
        // Grant metadata is only covered by v7. A vault carrying grants but
        // stamped with an older (group-era) MAC must not verify — otherwise an
        // attacker could fabricate or extend a grant the MAC ignores.
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [3u8; 32];
        let no_groups = BTreeMap::new();
        let grants = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
                anchors: Vec::new(),
            },
        )]);
        // A v6 MAC (no grants in the digest) must be rejected once grants exist.
        let v6_mac = compute_mac_v6(&vault, &no_groups, &key);
        assert!(v6_mac.starts_with("blake3v4:"));
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &grants,
            &v6_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v8_covers_policy() {
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: Some(types::Policy {
                agent_allow_tags: vec!["agents".into()],
            }),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [11u8; 32];
        let no_groups = BTreeMap::new();
        let no_grants = BTreeMap::new();

        // v8 (blake3v6) covers the policy.
        let v8_mac = compute_mac_v8(&vault, &no_groups, &no_grants, &key);
        assert!(v8_mac.starts_with("blake3v6:"));
        assert!(verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v8_mac,
            Some(&key)
        ));

        // Weakening the policy (adding an allowed tag) changes the MAC.
        vault.policy = Some(types::Policy {
            agent_allow_tags: vec!["agents".into(), "production".into()],
        });
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v8_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v8_policy_tags_are_unambiguous() {
        // A crafted tag must not collide with a different tag list: ["a\tb"] and
        // ["a", "b"] previously hashed identically under a separator-only scheme.
        let base = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [7u8; 32];
        let groups = BTreeMap::new();
        let grants = BTreeMap::new();

        let mut a = base.clone();
        a.policy = Some(types::Policy {
            agent_allow_tags: vec!["a\tb".into()],
        });
        let mut b = base.clone();
        b.policy = Some(types::Policy {
            agent_allow_tags: vec!["a".into(), "b".into()],
        });

        let mac_a = compute_mac(&a, &groups, &grants, Some(&key));
        let mac_b = compute_mac(&b, &groups, &grants, Some(&key));
        assert_ne!(mac_a, mac_b, "distinct tag lists must not share a MAC");
    }

    #[test]
    fn verify_mac_rejects_policy_under_legacy_prefix() {
        // Policy is only covered by v8. A vault carrying a policy but stamped
        // with an older MAC must not verify — otherwise an attacker could strip
        // or weaken the policy by downgrading the MAC.
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: Some(types::Policy {
                agent_allow_tags: vec!["agents".into()],
            }),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [5u8; 32];
        let no_groups = BTreeMap::new();
        let no_grants = BTreeMap::new();
        // A v5 MAC (no policy in the digest) must be rejected once a policy exists.
        let v5_mac = compute_mac_v5(&vault, &key);
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v5_mac,
            Some(&key)
        ));
    }

    #[test]
    fn compute_mac_v5_covers_rotation_metadata() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                updated: Some("2026-02-28T00:00:00Z".into()),
                ..Default::default()
            },
        );

        let key = [0u8; 32];
        let baseline = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        // Setting a rotation interval changes the MAC — tamper-evident.
        vault
            .schema
            .get_mut("API_KEY")
            .unwrap()
            .rotation_interval_days = Some(90);
        let with_interval = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(baseline, with_interval);

        // So does an expiry.
        vault.schema.get_mut("API_KEY").unwrap().expires_at = Some("2026-09-01T23:59:59Z".into());
        let with_expiry = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(with_interval, with_expiry);

        // v4 (which ignores these fields) is blind to the change — the reason
        // v5 exists. Confirms the new fields really are what moved the MAC.
        let mut cleared = vault.clone();
        cleared
            .schema
            .get_mut("API_KEY")
            .unwrap()
            .rotation_interval_days = None;
        cleared.schema.get_mut("API_KEY").unwrap().expires_at = None;
        assert_eq!(compute_mac_v4(&vault, &key), compute_mac_v4(&cleared, &key));
    }

    #[test]
    fn compute_mac_v9_covers_revoked_at() {
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                updated: Some("2026-02-28T00:00:00Z".into()),
                ..Default::default()
            },
        );
        let key = [0u8; 32];
        let groups = BTreeMap::new();
        let grants = BTreeMap::new();

        let baseline = compute_mac_v9(&vault, &groups, &grants, &key);

        // Setting `revoked_at` changes the v9 MAC.
        vault.schema.get_mut("API_KEY").unwrap().revoked_at = Some("2026-06-18T00:00:00Z".into());
        let with_marker = compute_mac_v9(&vault, &groups, &grants, &key);
        assert!(with_marker.starts_with("blake3v7:"));
        assert_ne!(baseline, with_marker);

        // The v9 MAC round-trips, and a downgraded (v8) MAC is rejected while the
        // marker is present — an attacker can't clear it by stamping an older scheme.
        assert!(verify_mac(
            &vault,
            &groups,
            &grants,
            &with_marker,
            Some(&key)
        ));
        let v8_mac = compute_mac_v8(&vault, &groups, &grants, &key);
        assert!(!verify_mac(&vault, &groups, &grants, &v8_mac, Some(&key)));

        // v8 (which ignores the marker) is blind to it — confirms `revoked_at` is
        // what moved the v9 digest, mirroring the v5 rotation-metadata test.
        let mut cleared = vault.clone();
        cleared.schema.get_mut("API_KEY").unwrap().revoked_at = None;
        assert_eq!(
            compute_mac_v8(&vault, &groups, &grants, &key),
            compute_mac_v8(&cleared, &groups, &grants, &key)
        );
    }

    #[test]
    fn compute_mac_changes_with_schema() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac_no_schema = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                tags: vec!["deploy".into()],
                ..Default::default()
            },
        );

        let mac_with_schema = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_no_schema, mac_with_schema);

        // Changing a tag changes the MAC
        let mac_before_retag = mac_with_schema;
        vault.schema.get_mut("API_KEY").unwrap().tags = vec!["ops".into()];
        let mac_after_retag = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_before_retag, mac_after_retag);
    }

    #[test]
    fn mac_key_roundtrip() {
        let hex = generate_mac_key();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let key = decode_mac_key(&hex).expect("valid hex should decode");
        // Re-encode and compare.
        let rehex = key.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex.as_str(), rehex);
    }

    #[test]
    fn decode_mac_key_rejects_bad_input() {
        assert!(decode_mac_key("").is_none());
        assert!(decode_mac_key("tooshort").is_none());
        assert!(decode_mac_key(&"zz".repeat(32)).is_none()); // invalid hex
        assert!(decode_mac_key(&"aa".repeat(31)).is_none()); // 31 bytes
        assert!(decode_mac_key(&"aa".repeat(33)).is_none()); // 33 bytes
    }

    #[test]
    fn blake3_mac_different_key_different_mac() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            vault_id: String::new(),
            generation: 0,
            agents: BTreeMap::new(),
            sig: None,
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key1),
        );
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key2),
        );
        assert_ne!(mac1, mac2);
    }

    /// Each header identity field, with a rewrite an attacker might make.
    fn header_rewrites() -> Vec<(&'static str, crate::testutil::VaultRewrite)> {
        vec![
            ("vault_name", |v| v.vault_name = "payments-prod".into()),
            ("repo", |v| v.repo = "https://github.com/evil/fork".into()),
            ("created", |v| v.created = "2020-01-01T00:00:00Z".into()),
            ("vault_id", |v| {
                v.vault_id = "0123456789abcdef0123456789abcdef".into();
            }),
            ("generation", |v| v.generation = 7),
            ("agents", |v| {
                v.agents
                    .insert("age1agent".into(), "Y2lwaGVydGV4dA==".into());
            }),
        ]
    }

    #[test]
    fn mac_v10_covers_header_fields() {
        let mut vault = crate::testutil::empty_vault();
        vault.repo = "https://github.com/org/repo".into();
        vault.vault_id = "ffffffffffffffffffffffffffffffff".into();
        vault.generation = 3;
        let key = [5u8; 32];
        let (groups, grants) = (BTreeMap::new(), BTreeMap::new());
        let mac = compute_mac(&vault, &groups, &grants, Some(&key));
        assert!(mac.starts_with("blake3v8:"));
        assert!(verify_mac(&vault, &groups, &grants, &mac, Some(&key)));

        for (field, rewrite) in header_rewrites() {
            let mut forged = vault.clone();
            rewrite(&mut forged);
            assert!(
                !verify_mac(&forged, &groups, &grants, &mac, Some(&key)),
                "rewriting `{field}` must break the v10 MAC"
            );
        }
    }

    #[test]
    fn mac_v10_length_prefix_blocks_field_boundary_shift() {
        // Moving bytes between adjacent header strings must change the MAC.
        let mut a = crate::testutil::empty_vault();
        a.vault_name = "ab".into();
        a.repo = "c".into();
        let mut b = a.clone();
        b.vault_name = "a".into();
        b.repo = "bc".into();
        let key = [5u8; 32];
        let (groups, grants) = (BTreeMap::new(), BTreeMap::new());
        assert_ne!(
            compute_mac(&a, &groups, &grants, Some(&key)),
            compute_mac(&b, &groups, &grants, Some(&key))
        );
    }

    #[test]
    fn verify_mac_rejects_pre_v10_scheme_where_v10_is_required() {
        // A 3.x vault, or one carrying a vault id, generation or agents blob, is
        // only written with v10. An older MAC on it is a downgrade.
        let key = [5u8; 32];
        let (groups, grants) = (BTreeMap::new(), BTreeMap::new());
        let mut old = crate::testutil::empty_vault();
        old.version = "2.0".into();
        let v9 = compute_mac_v9(&old, &groups, &grants, &key);
        assert!(verify_mac(&old, &groups, &grants, &v9, Some(&key)));

        let mut v3 = old.clone();
        v3.version = "3.0".into();
        assert!(!verify_mac(&v3, &groups, &grants, &v9, Some(&key)));
        for (field, rewrite) in header_rewrites()
            .into_iter()
            .filter(|(f, _)| matches!(*f, "vault_id" | "generation" | "agents"))
        {
            let mut carrying = old.clone();
            rewrite(&mut carrying);
            let v9 = compute_mac_v9(&carrying, &groups, &grants, &key);
            assert!(
                !verify_mac(&carrying, &groups, &grants, &v9, Some(&key)),
                "a vault carrying `{field}` must not verify under v9"
            );
        }
    }

    #[test]
    fn newer_mac_scheme_is_recognized() {
        assert!(is_newer_mac_scheme("blake3v9:00"));
        assert!(is_newer_mac_scheme("blake3v12:00"));
        assert!(!is_newer_mac_scheme("blake3v8:00"));
        assert!(!is_newer_mac_scheme("blake3:00"));
        assert!(!is_newer_mac_scheme("garbage"));
    }
}
