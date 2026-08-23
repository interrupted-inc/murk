//! Property-based invariant tests for murk's core security guarantees.
//!
//! The fuzz targets (`fuzz/`) assert only panic-freedom. These assert the
//! semantic invariants a secrets tool lives or dies by:
//!
//! * **roundtrip fidelity** — every recipient decrypts exactly what was
//!   encrypted, and a non-recipient cannot read the vault at all;
//! * **tamper-evidence** — any mutation of a MAC-covered field (or the meta
//!   blob) fails the trusted load rather than returning wrong plaintext;
//! * **scope isolation** — a recipient reads exactly the scoped (`me`-tier)
//!   values addressed to it, and none addressed only to another recipient.
//!
//! They drive the real library trust boundary (`decrypt_vault`) in-process with
//! no filesystem or environment, so proptest can run many cases quickly.

use std::collections::BTreeMap;

use proptest::prelude::*;

use crate::crypto::{MurkIdentity, MurkRecipient};
use crate::testutil::{empty_vault, generate_keypair, make_identity, make_recipient};
use crate::{compute_mac, decode_mac_key, decrypt_vault, encrypt_value, generate_mac_key, types};

/// A generated party: its pubkey and decrypting identity. The recipient is
/// rebuilt on demand (`recipient()`) so we needn't require `Clone` on the type.
struct Party {
    pubkey: String,
    identity: MurkIdentity,
}

impl Party {
    fn recipient(&self) -> MurkRecipient {
        make_recipient(&self.pubkey)
    }
}

fn make_party() -> Party {
    let (secret, pubkey) = generate_keypair();
    Party {
        identity: make_identity(&secret),
        pubkey,
    }
}

fn recipients_of(parties: &[Party]) -> Vec<MurkRecipient> {
    parties.iter().map(Party::recipient).collect()
}

/// Build a valid, unsigned vault whose meta carries a correct keyed MAC.
///
/// * `shared` — key → plaintext, encrypted to every party (the "everyone" tier).
/// * `scoped` — key → (party index, plaintext), encrypted only to that one party
///   (the per-recipient `me` tier).
///
/// Mirrors what `save_vault` writes, minus the optional signature, so
/// `decrypt_vault` treats it as a genuine intact vault. Shared and scoped keys
/// must be disjoint (callers use distinct name prefixes).
fn build_vault(
    parties: &[Party],
    shared: &BTreeMap<String, String>,
    scoped: &BTreeMap<String, (usize, String)>,
) -> types::Vault {
    let all = recipients_of(parties);

    let mut vault = empty_vault();
    vault.recipients = parties.iter().map(|p| p.pubkey.clone()).collect();

    for (key, val) in shared {
        vault.secrets.insert(
            key.clone(),
            types::SecretEntry {
                shared: encrypt_value(val.as_bytes(), &all).unwrap(),
                private: BTreeMap::new(),
                grouped: BTreeMap::new(),
            },
        );
    }
    for (key, (idx, val)) in scoped {
        let target = &parties[*idx];
        let mut private = BTreeMap::new();
        private.insert(
            target.pubkey.clone(),
            encrypt_value(val.as_bytes(), std::slice::from_ref(&target.recipient())).unwrap(),
        );
        vault.secrets.insert(
            key.clone(),
            types::SecretEntry {
                shared: String::new(),
                private,
                grouped: BTreeMap::new(),
            },
        );
    }

    seal_meta(&mut vault, parties, &all);
    vault
}

/// Compute the keyed MAC over `vault` and encrypt a matching meta blob to every
/// party — the step that makes the vault load-valid (integrity + recipients).
fn seal_meta(vault: &mut types::Vault, parties: &[Party], all: &[MurkRecipient]) {
    let groups = BTreeMap::new();
    let grants = BTreeMap::new();
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(vault, &groups, &grants, Some(&mac_key));
    let meta = types::Meta {
        recipients: parties
            .iter()
            .map(|p| (p.pubkey.clone(), "tester".to_string()))
            .collect(),
        mac,
        mac_key: Some(mac_key_hex),
        ..Default::default()
    };
    vault.meta = encrypt_value(&serde_json::to_vec(&meta).unwrap(), all).unwrap();
}

// Strategies. Key namespaces are prefix-disjoint (`H…` shared, `S…` scoped) so a
// scoped key can never shadow a shared one when both maps feed `build_vault`.
fn shared_key() -> &'static str {
    "H[A-Z0-9_]{0,8}"
}
fn scoped_key() -> &'static str {
    "S[A-Z0-9_]{0,8}"
}
fn value() -> &'static str {
    "[a-zA-Z0-9 _.:/=+-]{0,48}"
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Every recipient decrypts every shared value byte-for-byte, and an
    /// identity outside the recipient set cannot open the vault at all.
    #[test]
    fn roundtrip_every_recipient_reads_shared(
        shared in prop::collection::btree_map(shared_key(), value(), 0..6),
        n in 1usize..=4,
    ) {
        let parties: Vec<Party> = (0..n).map(|_| make_party()).collect();
        let vault = build_vault(&parties, &shared, &BTreeMap::new());

        for p in &parties {
            let murk = decrypt_vault(&vault, &p.identity)
                .expect("a listed recipient must decrypt an intact vault");
            prop_assert_eq!(murk.values.len(), shared.len());
            for (k, v) in &shared {
                let got = murk.values.get(k).map(|z| z.as_str());
                prop_assert_eq!(got, Some(v.as_str()));
            }
        }

        // A freshly generated key is not a recipient -> hard failure, never a
        // silent empty/partial success.
        let outsider = make_party();
        prop_assert!(decrypt_vault(&vault, &outsider.identity).is_err());
    }

    /// Any single mutation of a MAC-covered field (or the meta blob) makes the
    /// trusted load fail. The invariant is *fails*, never "succeeds with
    /// different data".
    #[test]
    fn any_tamper_fails_the_load(
        shared in prop::collection::btree_map(shared_key(), value(), 1..6),
        n in 1usize..=4,
        sel in 0u8..6,
    ) {
        let parties: Vec<Party> = (0..n).map(|_| make_party()).collect();
        let mut vault = build_vault(&parties, &shared, &BTreeMap::new());

        // Sanity: intact vault loads for the first recipient.
        prop_assert!(decrypt_vault(&vault, &parties[0].identity).is_ok());

        let first_key = vault.secrets.keys().next().unwrap().clone();
        match sel {
            // Swap a shared ciphertext for a different (valid) one.
            0 => {
                let all = recipients_of(&parties);
                vault.secrets.get_mut(&first_key).unwrap().shared =
                    encrypt_value(b"POISON-DIFFERENT-VALUE", &all).unwrap();
            }
            // Inject a bogus recipient into the public header.
            1 => vault.recipients.push(
                "age1injected000000000000000000000000000000000000000000000000000".into(),
            ),
            // Drop a recipient from the public header.
            2 => {
                vault.recipients.pop();
            }
            // Rename a secret key.
            3 => {
                let entry = vault.secrets.remove(&first_key).unwrap();
                vault.secrets.insert(format!("{first_key}_RENAMED"), entry);
            }
            // Corrupt the encrypted meta blob.
            4 => vault.meta.insert(0, 'Z'),
            // Add a schema entry (the keyed MAC covers schema).
            _ => {
                vault.schema.insert(
                    first_key.clone(),
                    types::SchemaEntry { description: "injected".into(), ..Default::default() },
                );
            }
        }

        prop_assert!(
            decrypt_vault(&vault, &parties[0].identity).is_err(),
            "tampered vault (mutation {sel}) must fail the load"
        );
    }

    /// A recipient sees exactly the scoped values addressed to it: its own, and
    /// never one addressed only to a different recipient. Scoped-only keys never
    /// appear in the shared tier.
    #[test]
    fn scoped_values_isolated_per_recipient(
        shared in prop::collection::btree_map(shared_key(), value(), 0..3),
        scoped_spec in prop::collection::btree_map(scoped_key(), (0usize..4, value()), 1..4),
        n in 2usize..=4,
    ) {
        let parties: Vec<Party> = (0..n).map(|_| make_party()).collect();

        // Fold each spec's out-of-range index into the actual party count.
        let scoped: BTreeMap<String, (usize, String)> = scoped_spec
            .iter()
            .map(|(k, (idx, v))| (k.clone(), (idx % n, v.clone())))
            .collect();

        let vault = build_vault(&parties, &shared, &scoped);

        for (r, p) in parties.iter().enumerate() {
            let murk = decrypt_vault(&vault, &p.identity).expect("recipient must decrypt");

            // Shared tier: fully readable, and scoped keys never leak into it.
            for k in shared.keys() {
                prop_assert!(murk.values.contains_key(k));
            }
            for k in scoped.keys() {
                prop_assert!(!murk.values.contains_key(k), "scoped key {k} leaked to shared");
            }

            // Scoped tier: exactly the entries addressed to this recipient.
            for (key, (target, val)) in &scoped {
                let visible = murk
                    .private
                    .get(key)
                    .and_then(|m| m.get(&p.pubkey))
                    .map(|z| z.as_str());
                if *target == r {
                    prop_assert_eq!(visible, Some(val.as_str()));
                } else {
                    prop_assert!(
                        !murk.private.contains_key(key),
                        "recipient {r} must not see scoped key {key} addressed to {target}"
                    );
                }
            }
        }
    }
}

// ── Agent-grant and partial-recipient boundaries (example-based) ──
//
// These pin the `is_agent` branch in `decrypt_vault`: an agent grant reads only
// its scoped keys and never the shared tier, while a *listed* recipient that
// cannot decrypt a shared value must fail the load rather than silently receive
// a partial view.

/// Seal `vault` with a keyed MAC + a meta blob encrypted to `all`, carrying
/// `grants` (so the MAC is the grant-aware scheme and `decrypt_vault` sees the
/// grant). `names` maps each recipient pubkey to its display name.
fn seal_with_grants(
    vault: &mut types::Vault,
    names: &[(String, String)],
    all: &[MurkRecipient],
    grants: &BTreeMap<String, types::GrantEntry>,
) {
    let groups = BTreeMap::new();
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(vault, &groups, grants, Some(&mac_key));
    let meta = types::Meta {
        recipients: names.iter().cloned().collect(),
        mac,
        mac_key: Some(mac_key_hex),
        grants: grants.clone(),
        ..Default::default()
    };
    vault.meta = encrypt_value(&serde_json::to_vec(&meta).unwrap(), all).unwrap();
}

fn secret_entry(shared: String, private: BTreeMap<String, String>) -> types::SecretEntry {
    types::SecretEntry {
        shared,
        private,
        grouped: BTreeMap::new(),
    }
}

#[test]
fn agent_grant_reads_only_scoped_never_shared() {
    let op = make_party(); // a normal recipient
    let agent = make_party(); // the ephemeral grant identity
    let op_rec = op.recipient();
    let agent_rec = agent.recipient();

    let mut vault = empty_vault();
    vault.recipients = vec![op.pubkey.clone(), agent.pubkey.clone()];

    // A shared secret only the operator can read — the agent is deliberately
    // NOT a recipient of the shared "everyone" ciphertext.
    vault.secrets.insert(
        "SHARED".into(),
        secret_entry(
            encrypt_value(b"op-only-shared", std::slice::from_ref(&op_rec)).unwrap(),
            BTreeMap::new(),
        ),
    );
    // The granted key: shared to the operator, and scoped (the `me` tier) to the
    // agent's ephemeral key — the actual grant access.
    let mut granted = BTreeMap::new();
    granted.insert(
        agent.pubkey.clone(),
        encrypt_value(b"granted-value", std::slice::from_ref(&agent_rec)).unwrap(),
    );
    vault.secrets.insert(
        "GRANTED".into(),
        secret_entry(
            encrypt_value(b"granted-value", std::slice::from_ref(&op_rec)).unwrap(),
            granted,
        ),
    );

    let mut grants = BTreeMap::new();
    grants.insert(
        "build-bot".to_string(),
        types::GrantEntry {
            pubkey: agent.pubkey.clone(),
            scope: vec!["GRANTED".into()],
            issued_at: "2026-02-28T00:00:00Z".into(),
            // Far future: this test is about scoping; expiry has its own tests.
            expires_at: "2200-01-01T00:00:00Z".into(),
            issuer: op.pubkey.clone(),
        },
    );

    let all = [op_rec, agent_rec];
    seal_with_grants(
        &mut vault,
        &[
            (op.pubkey.clone(), "op".into()),
            (agent.pubkey.clone(), "build-bot".into()),
        ],
        &all,
        &grants,
    );

    // Operator (not an agent) reads both shared values.
    let op_view = decrypt_vault(&vault, &op.identity).expect("operator decrypts");
    assert_eq!(
        op_view.values.get("SHARED").map(|z| z.as_str()),
        Some("op-only-shared")
    );
    assert_eq!(
        op_view.values.get("GRANTED").map(|z| z.as_str()),
        Some("granted-value")
    );

    // Agent reads NO shared secret, and exactly its granted key via the scoped tier.
    let agent_view = decrypt_vault(&vault, &agent.identity)
        .expect("agent is a meta recipient + grant, so it decrypts");
    assert!(
        agent_view.values.is_empty(),
        "agent must not read any shared secret"
    );
    assert_eq!(
        agent_view
            .private
            .get("GRANTED")
            .and_then(|m| m.get(&agent.pubkey))
            .map(|z| z.as_str()),
        Some("granted-value"),
        "agent must read exactly its granted, scoped key"
    );

    // Schema is covered by the grant-aware (v7) MAC too: a post-seal schema
    // insert must fail the load (exercises schema_mac_bytes on the v6+ path).
    let mut schema_tampered = vault.clone();
    schema_tampered.schema.insert(
        "GRANTED".into(),
        types::SchemaEntry {
            description: "injected".into(),
            ..Default::default()
        },
    );
    assert!(
        decrypt_vault(&schema_tampered, &op.identity).is_err(),
        "schema tamper on a v7 vault must fail the load"
    );
}

#[test]
fn listed_recipient_excluded_from_shared_fails_load() {
    // A recipient present in the meta (can open it) but NOT a recipient of a
    // shared ciphertext must fail loudly — only an agent grant may skip an
    // unreadable shared value; a normal recipient seeing a partial vault is a bug.
    let a = make_party();
    let b = make_party();
    let a_rec = a.recipient();
    let b_rec = b.recipient();

    let mut vault = empty_vault();
    vault.recipients = vec![a.pubkey.clone(), b.pubkey.clone()];
    // "S" is shared only to B, though A is a listed recipient of the vault.
    vault.secrets.insert(
        "S".into(),
        secret_entry(
            encrypt_value(b"b-only", std::slice::from_ref(&b_rec)).unwrap(),
            BTreeMap::new(),
        ),
    );
    let all = [a_rec, b_rec];
    seal_with_grants(
        &mut vault,
        &[
            (a.pubkey.clone(), "a".into()),
            (b.pubkey.clone(), "b".into()),
        ],
        &all,
        &BTreeMap::new(),
    );

    assert!(
        decrypt_vault(&vault, &b.identity).is_ok(),
        "B is a recipient of S"
    );
    assert!(
        decrypt_vault(&vault, &a.identity).is_err(),
        "a listed non-agent recipient that cannot read a shared value must fail the load"
    );
}

#[test]
fn legacy_unkeyed_mac_vault_sets_legacy_flag() {
    // An unkeyed sha256 (v2) MAC is legacy: the vault still loads, but the
    // working state must flag it so strict mode and the CLI can warn.
    let p = make_party();
    let rec = p.recipient();

    let mut vault = empty_vault();
    vault.recipients = vec![p.pubkey.clone()];
    vault.secrets.insert(
        "K".into(),
        secret_entry(
            encrypt_value(b"v", std::slice::from_ref(&rec)).unwrap(),
            BTreeMap::new(),
        ),
    );

    // No mac_key -> compute_mac emits the legacy unkeyed sha256v2 scheme.
    let mac = compute_mac(&vault, &BTreeMap::new(), &BTreeMap::new(), None);
    let meta = types::Meta {
        recipients: [(p.pubkey.clone(), "p".to_string())].into_iter().collect(),
        mac,
        mac_key: None,
        ..Default::default()
    };
    vault.meta = encrypt_value(
        &serde_json::to_vec(&meta).unwrap(),
        std::slice::from_ref(&rec),
    )
    .unwrap();

    let murk = decrypt_vault(&vault, &p.identity).expect("legacy-MAC vault still loads");
    assert!(
        murk.legacy_mac,
        "an unkeyed sha256 MAC must be flagged as legacy"
    );
}

#[test]
fn mac_downgrade_below_group_scheme_rejected() {
    // A grouped ciphertext is only covered by v6+ (`blake3v4:`). A vault carrying
    // one but stamped with an older (pre-group) MAC must be rejected — otherwise
    // an attacker could inject a `grouped` entry the old MAC never covered. The
    // stamped MAC is a *valid* pre-group MAC, so only the downgrade guard (not a
    // hash mismatch) can catch it.
    let p = make_party();
    let rec = p.recipient();

    let mut vault = empty_vault();
    vault.recipients = vec![p.pubkey.clone()];
    let mut grouped = BTreeMap::new();
    grouped.insert(
        "team".to_string(),
        encrypt_value(b"group-val", std::slice::from_ref(&rec)).unwrap(),
    );
    vault.secrets.insert(
        "K".into(),
        types::SecretEntry {
            shared: encrypt_value(b"v", std::slice::from_ref(&rec)).unwrap(),
            private: BTreeMap::new(),
            grouped,
        },
    );

    // Stamp a valid pre-group MAC (v5 = `blake3v3:`) that does not cover grouped
    // data. Group membership is left empty so the guard must treat a stray
    // grouped ciphertext alone as "touches groups".
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let downgraded = crate::compute_mac_v5(&vault, &mac_key);
    let meta = types::Meta {
        recipients: [(p.pubkey.clone(), "p".to_string())].into_iter().collect(),
        mac: downgraded,
        mac_key: Some(mac_key_hex),
        ..Default::default()
    };
    vault.meta = encrypt_value(
        &serde_json::to_vec(&meta).unwrap(),
        std::slice::from_ref(&rec),
    )
    .unwrap();

    assert!(
        decrypt_vault(&vault, &p.identity).is_err(),
        "a grouped vault stamped with a pre-group MAC must be rejected as a downgrade"
    );
}
