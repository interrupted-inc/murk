// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access invariants over random sequences of real `murk` commands.
//!
//! Each case copies a small fixture vault (three members, two groups, values in
//! the shared, group and personal tiers), runs a random sequence of commands
//! as random actors (members, an agent grant, an outsider), and after every
//! step decrypts every value in the vault with every identity in the cast,
//! straight through age. It then checks:
//!
//! 1. **No widening.** Nobody gains read access to a value unless the step is
//!    an explicit widening of exactly that value (a write to the tier it names,
//!    `circle authorize`, `group add`, a new grant), and then only someone the
//!    step itself admits to that tier. Recipients and group members change
//!    only as the step asks (the named recipient joins or leaves); the vault's
//!    own metadata is checked against that, never trusted as the oracle.
//! 2. **No drops.** Everyone allowed to read a value before the step still
//!    reads the same plaintext afterwards, unless the step deliberately
//!    changes it (a write or rotation of that key: the new plaintext must be
//!    the one supplied for that key), removes it (`rm`, a write that names a
//!    different tier), or removes that reader (revoke, `group rm --member`).
//! 3. **Refusals change nothing.** A command that exits non-zero leaves the
//!    vault file byte-for-byte unchanged.
//! 4. **Accepted steps verify.** After a command that succeeds, `murk verify`
//!    passes for a current member.
//!
//! The harness drives the CLI binary rather than the library: the bugs it
//! targets live in the command layer (which tier a command writes, which keys
//! a piped rotation consumes, which identities may save), which the library
//! API never sees.
//!
//! `MURK_INVARIANT_CASES` sets the number of cases (default 32, sized for CI).
//! `.github/workflows/invariants.yaml` runs a nightly soak with many more; set
//! it to e.g. 10000 for a local soak run.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::sync::LazyLock;

use common::cast::{self, Cast, Cell, Cells, Tier, Who};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

const KEYS: [&str; 4] = ["K1", "K2", "K3", "K4"];
const GROUPS: [&str; 2] = ["ops", "dev"];

/// Who runs a command.
#[derive(Clone, Copy, Debug)]
enum Actor {
    Alice,
    Bob,
    Carol,
    /// The most recently minted agent grant (live or revoked). A step with this
    /// actor is skipped while no grant has been minted.
    Grant,
    /// An age identity that was never a recipient.
    Outsider,
}

/// The `--group` argument of a write.
#[derive(Clone, Copy)]
enum To {
    /// No `--group`: an existing key keeps its tier.
    Kept,
    Everyone,
    Me,
    Group(usize),
}

impl fmt::Debug for To {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            To::Kept => write!(f, "(no --group)"),
            To::Everyone => write!(f, "--group everyone"),
            To::Me => write!(f, "--group me"),
            To::Group(g) => write!(f, "--group {}", GROUPS[*g]),
        }
    }
}

/// How a rotation gets its values.
#[derive(Clone, Copy, Debug)]
enum Feed {
    /// One line per value on piped stdin, matched by position.
    Piped,
    /// `--values-from -`: `KEY=value` lines, matched by name. Steps using it
    /// are skipped on a binary without the flag.
    Named,
}

#[derive(Clone, Copy)]
struct Key(usize);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(KEYS[self.0])
    }
}

#[derive(Clone, Copy)]
struct Member(usize);

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(["alice", "bob", "carol"][self.0])
    }
}

#[derive(Clone, Copy)]
struct Group(usize);

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(GROUPS[self.0])
    }
}

#[derive(Clone, Debug)]
enum Op {
    Add {
        by: Actor,
        key: Key,
        to: To,
    },
    Rm {
        by: Actor,
        key: Key,
    },
    Rotate {
        by: Actor,
        key: Key,
        feed: Feed,
    },
    /// `rotate --all`, one piped value per key in key order.
    RotateAll {
        by: Actor,
    },
    /// `rotate --all --values-from -`, naming only `keys`.
    RotateAllNamed {
        by: Actor,
        keys: Vec<Key>,
    },
    Import {
        by: Actor,
        keys: Vec<Key>,
        to: To,
    },
    Authorize {
        by: Actor,
        who: Member,
        group: Option<Group>,
    },
    Revoke {
        by: Actor,
        who: Member,
        rotate: Option<Feed>,
    },
    GroupAdd {
        by: Actor,
        group: Group,
        who: Member,
    },
    GroupRm {
        by: Actor,
        group: Group,
        who: Option<Member>,
    },
    GrantCreate {
        by: Actor,
        keys: Vec<Key>,
    },
    GrantRevoke {
        by: Actor,
        rotate: Option<Feed>,
    },
}

fn actor() -> impl Strategy<Value = Actor> {
    prop_oneof![
        4 => Just(Actor::Alice),
        3 => Just(Actor::Bob),
        3 => Just(Actor::Carol),
        1 => Just(Actor::Grant),
        1 => Just(Actor::Outsider),
    ]
}

fn to() -> impl Strategy<Value = To> {
    prop_oneof![
        3 => Just(To::Kept),
        1 => Just(To::Everyone),
        1 => Just(To::Me),
        1 => (0..GROUPS.len()).prop_map(To::Group),
    ]
}

fn feed() -> impl Strategy<Value = Feed> {
    prop_oneof![Just(Feed::Piped), Just(Feed::Named)]
}

fn key() -> impl Strategy<Value = Key> {
    (0..KEYS.len()).prop_map(Key)
}

fn keys() -> impl Strategy<Value = Vec<Key>> {
    proptest::sample::subsequence((0..KEYS.len()).collect::<Vec<_>>(), 1..=3)
        .prop_map(|ks| ks.into_iter().map(Key).collect())
}

fn member() -> impl Strategy<Value = Member> {
    (0..3usize).prop_map(Member)
}

fn group() -> impl Strategy<Value = Group> {
    (0..GROUPS.len()).prop_map(Group)
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (actor(), key(), to()).prop_map(|(by, key, to)| Op::Add { by, key, to }),
        1 => (actor(), key()).prop_map(|(by, key)| Op::Rm { by, key }),
        2 => (actor(), key(), feed()).prop_map(|(by, key, feed)| Op::Rotate { by, key, feed }),
        1 => actor().prop_map(|by| Op::RotateAll { by }),
        2 => (actor(), keys()).prop_map(|(by, keys)| Op::RotateAllNamed { by, keys }),
        2 => (actor(), keys(), to()).prop_map(|(by, keys, to)| Op::Import { by, keys, to }),
        1 => (actor(), member(), proptest::option::of(group()))
            .prop_map(|(by, who, group)| Op::Authorize { by, who, group }),
        2 => (actor(), member(), proptest::option::of(feed()))
            .prop_map(|(by, who, rotate)| Op::Revoke { by, who, rotate }),
        2 => (actor(), group(), member()).prop_map(|(by, group, who)| Op::GroupAdd { by, group, who }),
        1 => (actor(), group(), proptest::option::of(member()))
            .prop_map(|(by, group, who)| Op::GroupRm { by, group, who }),
        // Only a shared value can be granted, and K1 starts as the one shared
        // key, so most grants ask for just K1.
        2 => (actor(), prop_oneof![3 => Just(vec![Key(0)]), 1 => keys()])
            .prop_map(|(by, keys)| Op::GrantCreate { by, keys }),
        1 => (actor(), proptest::option::of(feed()))
            .prop_map(|(by, rotate)| Op::GrantRevoke { by, rotate }),
    ]
}

/// The fixture every case starts from, built once per test binary.
struct Fixture {
    /// Holds the identities; its directory is gone once the build returns.
    cast: Cast,
    vault: Vec<u8>,
    values_from: bool,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let cast = Cast::new(dir.path());
    let ok = |who: &Who, args: &[&str], stdin: &str| {
        cast.murk_as(who)
            .args(args)
            .write_stdin(stdin)
            .assert()
            .success();
    };
    let (alice, bob, carol) = (&cast.alice, &cast.bob, &cast.carol);
    ok(alice, &["group", "create", "ops"], "");
    ok(alice, &["group", "add", "ops", "--member", &bob.pubkey], "");
    ok(carol, &["group", "create", "dev"], "");
    // K1: shared, with a personal override of bob's on top.
    ok(alice, &["add", "K1"], "init-K1\n");
    ok(bob, &["add", "K1", "--group", "me"], "init-K1-bob\n");
    // K2: the ops group's. K3: alice's personal value only. K4: dev's.
    ok(alice, &["add", "K2", "--group", "ops"], "init-K2\n");
    ok(alice, &["add", "K3", "--group", "me"], "init-K3\n");
    ok(carol, &["add", "K4", "--group", "dev"], "init-K4\n");
    let vault = fs::read(cast.vault_path()).unwrap();

    let help = cast
        .murk_as(alice)
        .args(["rotate", "--help"])
        .output()
        .unwrap();
    let values_from = String::from_utf8_lossy(&help.stdout).contains("--values-from");
    Fixture {
        cast,
        vault,
        values_from,
    }
});

/// A minted agent grant.
struct GrantRec {
    name: String,
    who: Who,
    live: bool,
}

/// One case's vault and the identities seen so far.
struct World {
    _dir: tempfile::TempDir,
    cast: Cast,
    grants: Vec<GrantRec>,
    values_from: bool,
}

/// What a step may legitimately change, worked out before it runs.
#[derive(Default)]
struct Plan {
    /// Cells that may gain readers (only readers their tier allows). A `None`
    /// key matches every key.
    widen: Vec<(Option<String>, Tier)>,
    /// The membership changes the step asks for. Every other recipient and
    /// group must stay as it was.
    membership: Vec<Change>,
    /// Cells that may disappear or lose readers.
    vanish: Vec<(String, Option<Tier>)>,
    /// Identities whose access may drop.
    loses: BTreeSet<String>,
    /// (identity, tier) pairs whose access may drop, for every key.
    loses_tier: Vec<(String, Tier)>,
    /// New plaintexts this step may write, per key.
    values: BTreeMap<String, BTreeSet<String>>,
}

/// One membership change a step asks for, by identity label.
enum Change {
    /// Becomes a recipient (`circle authorize`).
    Authorize(String),
    /// Joins a group.
    Join(String, String),
    /// Stops being a recipient and leaves every group (`circle revoke`).
    Revoke(String),
    /// Leaves a group.
    Leave(String, String),
    /// The group is deleted.
    Delete(String),
}

impl Plan {
    fn value(&mut self, key: &str, value: String) {
        self.values
            .entry(key.to_string())
            .or_default()
            .insert(value);
    }
}

/// A step that ran: whether murk accepted it, and what it printed.
struct Ran {
    accepted: bool,
    stderr: String,
}

impl World {
    fn new() -> Self {
        let fx = &*FIXTURE;
        let dir = tempfile::tempdir().unwrap();
        let cast = Cast::from_vault(dir.path(), &fx.vault, &fx.cast);
        Self {
            _dir: dir,
            cast,
            grants: Vec::new(),
            values_from: fx.values_from,
        }
    }

    /// Every identity to decrypt with: the members, the outsider, every grant.
    fn identities(&self) -> Vec<Who> {
        let mut all: Vec<Who> = self.cast.members().into_iter().cloned().collect();
        all.push(self.cast.outsider.clone());
        all.extend(self.grants.iter().map(|g| g.who.clone()));
        all
    }

    fn member(&self, m: Member) -> &Who {
        self.cast.members()[m.0]
    }

    fn actor(&self, actor: Actor) -> Option<&Who> {
        match actor {
            Actor::Alice => Some(&self.cast.alice),
            Actor::Bob => Some(&self.cast.bob),
            Actor::Carol => Some(&self.cast.carol),
            Actor::Outsider => Some(&self.cast.outsider),
            Actor::Grant => self.grants.last().map(|g| &g.who),
        }
    }

    fn vault_json(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.cast.vault_path()).unwrap()).unwrap()
    }

    /// The vault's recipients and group membership, as identity labels.
    fn membership(&self) -> Membership {
        let by_pk: BTreeMap<String, String> = self
            .identities()
            .into_iter()
            .map(|w| (w.pubkey, w.label))
            .collect();
        let vault = self.vault_json();
        let recipients: BTreeSet<String> = vault["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pk| pk.as_str().unwrap().to_string())
            .collect();
        let meta = self
            .cast
            .members()
            .into_iter()
            .filter(|m| recipients.contains(&m.pubkey))
            .find_map(|m| cast::meta(self.cast.vault_path(), m))
            .expect("a current member can read the meta");
        let label = |pk: &str| by_pk.get(pk).cloned().unwrap_or_else(|| pk.to_string());
        let grant_pks: BTreeSet<String> = meta["grants"]
            .as_object()
            .map(|g| {
                g.values()
                    .map(|e| e["pubkey"].as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let shared = recipients
            .iter()
            .filter(|pk| !grant_pks.contains(*pk))
            .map(|pk| label(pk))
            .collect();
        let groups = meta["groups"]
            .as_object()
            .map(|groups| {
                groups
                    .iter()
                    .map(|(name, members)| {
                        let members = members
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|pk| label(pk.as_str().unwrap()))
                            .collect();
                        (name.clone(), members)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Membership {
            shared,
            groups,
            by_pk,
        }
    }

    /// A current member to run `verify` as.
    fn some_member(&self) -> &Who {
        let vault = self.vault_json();
        let recipients = vault["recipients"].as_array().unwrap();
        self.cast
            .members()
            .into_iter()
            .find(|m| recipients.iter().any(|pk| pk.as_str() == Some(&m.pubkey)))
            .expect("the vault keeps at least one member")
    }

    /// Run one step. `None` when the step doesn't apply (no grant yet, or a
    /// flag this binary lacks) and was not run.
    fn run(&mut self, step: usize, op: &Op, before: &Cells, plan: &mut Plan) -> Option<Ran> {
        let value = |key: &str| format!("s{step}-{key}");
        let by = match op {
            Op::Add { by, .. }
            | Op::Rm { by, .. }
            | Op::Rotate { by, .. }
            | Op::RotateAll { by }
            | Op::RotateAllNamed { by, .. }
            | Op::Import { by, .. }
            | Op::Authorize { by, .. }
            | Op::Revoke { by, .. }
            | Op::GroupAdd { by, .. }
            | Op::GroupRm { by, .. }
            | Op::GrantCreate { by, .. }
            | Op::GrantRevoke { by, .. } => *by,
        };
        let by = self.actor(by)?.clone();
        let mut args: Vec<String> = Vec::new();
        let mut stdin = String::new();
        let mut new_grant = None;

        // Values for `keys`, fed as `feed` says.
        let feed_values = |feed: Feed,
                           keys: &[String],
                           args: &mut Vec<String>,
                           stdin: &mut String,
                           plan: &mut Plan| {
            if matches!(feed, Feed::Named) {
                args.extend(["--values-from".into(), "-".into()]);
            }
            for key in keys {
                let v = value(key);
                match feed {
                    Feed::Piped => stdin.push_str(&format!("{v}\n")),
                    Feed::Named => stdin.push_str(&format!("{key}={v}\n")),
                }
                plan.value(key, v);
            }
        };
        let names_values = matches!(
            op,
            Op::Rotate {
                feed: Feed::Named,
                ..
            } | Op::RotateAllNamed { .. }
                | Op::Revoke {
                    rotate: Some(Feed::Named),
                    ..
                }
                | Op::GrantRevoke {
                    rotate: Some(Feed::Named),
                    ..
                }
        );
        if names_values && !self.values_from {
            return None;
        }
        let vault_keys: Vec<String> = {
            let keys: BTreeSet<String> = before.keys().map(|(k, _)| k.clone()).collect();
            keys.into_iter().collect()
        };

        match op {
            Op::Add { key, to, .. } => {
                let key = KEYS[key.0];
                args.extend(["add".into(), key.into()]);
                if let Some(flag) = group_flag(*to) {
                    args.extend(["--group".into(), flag]);
                }
                plan_write(key, *to, &by, before, plan);
                stdin = format!("{}\n", value(key));
                plan.value(key, value(key));
            }
            Op::Import { keys, to, .. } => {
                let mut file = String::new();
                for key in keys {
                    let key = KEYS[key.0];
                    plan_write(key, *to, &by, before, plan);
                    file.push_str(&format!("{key}={}\n", value(key)));
                    plan.value(key, value(key));
                }
                let path = self.cast.dir.join("import.env");
                fs::write(&path, file).unwrap();
                args.extend([
                    "import".into(),
                    path.display().to_string(),
                    "--force".into(),
                ]);
                if let Some(flag) = group_flag(*to) {
                    args.extend(["--group".into(), flag]);
                }
            }
            Op::Rm { key, .. } => {
                let key = KEYS[key.0];
                args.extend(["rm".into(), key.into()]);
                plan.vanish.push((key.into(), None));
            }
            Op::Rotate { key, feed, .. } => {
                let key = KEYS[key.0];
                args.extend(["rotate".into(), key.into()]);
                feed_values(*feed, &[key.to_string()], &mut args, &mut stdin, plan);
            }
            Op::RotateAll { .. } => {
                args.extend(["rotate".into(), "--all".into()]);
                feed_values(Feed::Piped, &vault_keys, &mut args, &mut stdin, plan);
            }
            Op::RotateAllNamed { keys, .. } => {
                args.extend(["rotate".into(), "--all".into()]);
                let keys: Vec<String> = keys.iter().map(|k| KEYS[k.0].to_string()).collect();
                feed_values(Feed::Named, &keys, &mut args, &mut stdin, plan);
            }
            Op::Authorize { who, group, .. } => {
                let who = self.member(*who);
                args.extend([
                    "circle".into(),
                    "authorize".into(),
                    who.pubkey.clone(),
                    "--name".into(),
                    who.label.clone(),
                ]);
                plan.widen.push((None, Tier::Shared));
                plan.membership.push(Change::Authorize(who.label.clone()));
                if let Some(g) = group {
                    let name = GROUPS[g.0];
                    args.extend(["--group".into(), name.into()]);
                    plan.widen.push((None, Tier::Group(name.into())));
                    plan.membership
                        .push(Change::Join(who.label.clone(), name.into()));
                }
            }
            Op::Revoke { who, rotate, .. } => {
                let who = self.member(*who).clone();
                args.extend(["circle".into(), "revoke".into(), who.pubkey.clone()]);
                plan.loses.insert(who.label.clone());
                plan.membership.push(Change::Revoke(who.label.clone()));
                if let Some(feed) = rotate {
                    args.push("--rotate".into());
                    // The base values they could read, in key order.
                    let exposed: Vec<String> = vault_keys
                        .iter()
                        .filter(|k| {
                            before.iter().any(|((key, tier), by)| {
                                key == *k
                                    && !matches!(tier, Tier::Private(_))
                                    && by.contains_key(&who.label)
                            })
                        })
                        .cloned()
                        .collect();
                    feed_values(*feed, &exposed, &mut args, &mut stdin, plan);
                }
            }
            Op::GroupAdd { group, who, .. } => {
                let name = GROUPS[group.0];
                let who = self.member(*who);
                args.extend([
                    "group".into(),
                    "add".into(),
                    name.into(),
                    "--member".into(),
                    who.pubkey.clone(),
                ]);
                plan.widen.push((None, Tier::Group(name.into())));
                plan.membership
                    .push(Change::Join(who.label.clone(), name.into()));
            }
            Op::GroupRm { group, who, .. } => {
                let name = GROUPS[group.0];
                args.extend(["group".into(), "rm".into(), name.into()]);
                if let Some(who) = who {
                    let who = self.member(*who);
                    args.extend(["--member".into(), who.pubkey.clone()]);
                    plan.loses_tier
                        .push((who.label.clone(), Tier::Group(name.into())));
                    plan.membership
                        .push(Change::Leave(who.label.clone(), name.into()));
                } else {
                    plan.membership.push(Change::Delete(name.into()));
                }
            }
            Op::GrantCreate { keys, .. } => {
                let name = format!("g{step}");
                args.extend([
                    "agent".into(),
                    "grant".into(),
                    "--name".into(),
                    name.clone(),
                ]);
                args.push("--out".into());
                args.push(self.cast.grant_key_path(&name).display().to_string());
                for key in keys {
                    let key = KEYS[key.0];
                    args.extend(["--only".into(), key.into()]);
                    // The grant's copy carries the key's current value.
                    for ((k, tier), by) in before {
                        if k == key && !matches!(tier, Tier::Private(_)) {
                            for v in by.values() {
                                plan.value(key, v.clone());
                            }
                        }
                    }
                }
                new_grant = Some((name, keys.clone()));
            }
            Op::GrantRevoke { rotate, .. } => {
                let grant = self.grants.iter().rev().find(|g| g.live)?;
                let (name, label) = (grant.name.clone(), grant.who.label.clone());
                let scope: Vec<String> = before
                    .keys()
                    .filter(|(_, tier)| *tier == Tier::Private(grant.who.pubkey.clone()))
                    .map(|(k, _)| k.clone())
                    .collect();
                args.extend(["agent".into(), "revoke".into(), name]);
                plan.loses.insert(label);
                if let Some(feed) = rotate {
                    args.push("--rotate".into());
                    // Scope keys that still have a shared value, in key order.
                    let shared: Vec<String> = scope
                        .into_iter()
                        .filter(|k| before.contains_key(&(k.clone(), Tier::Shared)))
                        .collect();
                    feed_values(*feed, &shared, &mut args, &mut stdin, plan);
                }
            }
        }

        let out = self
            .cast
            .murk_as(&by)
            .args(&args)
            .write_stdin(stdin)
            .output()
            .unwrap();
        let ran = Ran {
            accepted: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };

        if ran.accepted {
            if let Some((name, keys)) = new_grant {
                let who = self.cast.read_grant(&name);
                for key in keys {
                    plan.widen
                        .push((Some(KEYS[key.0].into()), Tier::Private(who.pubkey.clone())));
                }
                self.grants.push(GrantRec {
                    name,
                    who,
                    live: true,
                });
            }
            if let Op::GrantRevoke { .. } = op
                && let Some(g) = self.grants.iter_mut().rev().find(|g| g.live)
            {
                g.live = false;
            }
        }
        Some(ran)
    }
}

/// Plan a value write of `key` by `by` to `to`.
fn plan_write(key: &str, to: To, by: &Who, before: &Cells, plan: &mut Plan) {
    let base: Vec<Tier> = before
        .keys()
        .filter(|(k, tier)| k == key && !matches!(tier, Tier::Private(_)))
        .map(|(_, tier)| tier.clone())
        .collect();
    let dest = match to {
        To::Everyone => Tier::Shared,
        To::Me => Tier::Private(by.pubkey.clone()),
        To::Group(g) => Tier::Group(GROUPS[g].into()),
        // No --group: the key keeps its base tier; failing that, the writer's
        // own personal value; failing that (a new key), shared.
        To::Kept => base.first().cloned().unwrap_or_else(|| {
            let mine = Tier::Private(by.pubkey.clone());
            if before.contains_key(&(key.to_string(), mine.clone())) {
                mine
            } else {
                Tier::Shared
            }
        }),
    };
    // Naming a base tier moves the key there: its other base value goes.
    if matches!(to, To::Everyone | To::Group(_)) {
        for tier in base.into_iter().filter(|t| *t != dest) {
            plan.vanish.push((key.into(), Some(tier)));
        }
    }
    plan.widen.push((Some(key.into()), dest));
}

fn group_flag(to: To) -> Option<String> {
    match to {
        To::Kept => None,
        To::Everyone => Some("everyone".into()),
        To::Me => Some("me".into()),
        To::Group(g) => Some(GROUPS[g].into()),
    }
}

/// Who each tier is meant for, as identity labels.
#[derive(Clone, Debug)]
struct Membership {
    /// Recipients other than agent grants.
    shared: BTreeSet<String>,
    groups: BTreeMap<String, BTreeSet<String>>,
    by_pk: BTreeMap<String, String>,
}

impl Membership {
    fn allows(&self, tier: &Tier, label: &str) -> bool {
        match tier {
            Tier::Shared => self.shared.contains(label),
            Tier::Group(g) => self.groups.get(g).is_some_and(|m| m.contains(label)),
            Tier::Private(pk) => self.by_pk.get(pk).is_some_and(|l| l == label),
        }
    }

    /// This membership after `changes`, with identities resolved by `by_pk`
    /// (which may know a grant minted by the step).
    fn after(&self, changes: &[Change], by_pk: &BTreeMap<String, String>) -> Self {
        let mut next = self.clone();
        next.by_pk = by_pk.clone();
        for change in changes {
            match change {
                Change::Authorize(who) => {
                    next.shared.insert(who.clone());
                }
                Change::Join(who, group) => {
                    next.groups
                        .entry(group.clone())
                        .or_default()
                        .insert(who.clone());
                }
                Change::Revoke(who) => {
                    next.shared.remove(who);
                    for members in next.groups.values_mut() {
                        members.remove(who);
                    }
                }
                Change::Leave(who, group) => {
                    if let Some(members) = next.groups.get_mut(group) {
                        members.remove(who);
                    }
                }
                Change::Delete(group) => {
                    next.groups.remove(group);
                }
            }
        }
        next
    }
}

fn show(cell: &Cell) -> String {
    let tier = match &cell.1 {
        Tier::Shared => "shared".to_string(),
        Tier::Group(g) => format!("group {g}"),
        Tier::Private(pk) => format!("private {}…", &pk[..12]),
    };
    format!("{} ({tier})", cell.0)
}

/// Invariants 1 and 2 for an accepted step. `expected` is the membership the
/// step asked for (see [`Membership::after`]); `now` is what the vault holds.
fn check_access(
    plan: &Plan,
    before: &Cells,
    after: &Cells,
    was: &Membership,
    expected: &Membership,
    now: &Membership,
) -> Result<(), String> {
    let empty = BTreeMap::new();
    let mut errors = Vec::new();
    // 1. Recipients and groups change only as the step asked.
    if now.shared != expected.shared {
        errors.push(format!(
            "recipients are {:?}, expected {:?}",
            now.shared, expected.shared
        ));
    }
    if now.groups != expected.groups {
        errors.push(format!(
            "groups are {:?}, expected {:?}",
            now.groups, expected.groups
        ));
    }
    for (cell, by) in after {
        let had = before.get(cell).unwrap_or(&empty);
        for (label, plaintext) in by {
            // 1. No widening.
            if !had.contains_key(label) {
                let explicit = plan
                    .widen
                    .iter()
                    .any(|(k, tier)| k.as_ref().is_none_or(|k| *k == cell.0) && *tier == cell.1);
                if !explicit || !expected.allows(&cell.1, label) {
                    errors.push(format!("{label} can now read {}", show(cell)));
                }
            }
            // 2. Every plaintext is the cell's old value or one this step
            //    supplied for this key.
            let old = had.values().any(|v| v == plaintext);
            let supplied = plan
                .values
                .get(&cell.0)
                .is_some_and(|vs| vs.contains(plaintext));
            if !old && !supplied {
                errors.push(format!(
                    "{label} reads {plaintext:?} from {}, a value never written there",
                    show(cell)
                ));
            }
        }
    }
    // 2. No drops: everyone the tier allowed keeps reading it.
    for (cell, by) in before {
        if plan
            .vanish
            .iter()
            .any(|(k, tier)| *k == cell.0 && tier.as_ref().is_none_or(|t| *t == cell.1))
        {
            continue;
        }
        for (label, plaintext) in by {
            if plan.loses.contains(label)
                || plan
                    .loses_tier
                    .iter()
                    .any(|(l, t)| l == label && *t == cell.1)
                || !was.allows(&cell.1, label)
            {
                continue;
            }
            match after.get(cell).and_then(|by| by.get(label)) {
                None => errors.push(format!("{label} can no longer read {}", show(cell))),
                Some(now) if now != plaintext => {
                    let supplied = plan.values.get(&cell.0).is_some_and(|vs| vs.contains(now));
                    if !supplied {
                        errors.push(format!(
                            "{label}'s {} changed from {plaintext:?} to {now:?}",
                            show(cell)
                        ));
                    }
                }
                Some(_) => {}
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n  "))
    }
}

/// Run a sequence, checking all four invariants after every step.
fn run_sequence(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut world = World::new();
    for (step, op) in ops.iter().enumerate() {
        let vault_path = world.cast.vault_path();
        let before_bytes = fs::read(&vault_path).unwrap();
        let before = cast::cells(&vault_path, &world.identities());
        let was = world.membership();
        let mut plan = Plan::default();
        let Some(ran) = world.run(step, op, &before, &mut plan) else {
            continue;
        };
        let fail = |what: &str, detail: &str| {
            TestCaseError::fail(format!(
                "step {step} {op:?}: {what}\n  {detail}\n  murk stderr:\n{}",
                ran.stderr
            ))
        };

        if !ran.accepted {
            // 3. A refused step changes nothing.
            if fs::read(&vault_path).unwrap() != before_bytes {
                return Err(fail("refused, but the vault changed", "exit was non-zero"));
            }
            continue;
        }

        // 4. The vault verifies.
        let verify = world
            .cast
            .murk_as(world.some_member())
            .arg("verify")
            .output()
            .unwrap();
        if !verify.status.success() {
            return Err(fail(
                "accepted, but `murk verify` fails",
                &String::from_utf8_lossy(&verify.stderr),
            ));
        }

        let after = cast::cells(&vault_path, &world.identities());
        let now = world.membership();
        let expected = was.after(&plan.membership, &now.by_pk);
        check_access(&plan, &before, &after, &was, &expected, &now)
            .map_err(|e| fail("accepted, but access changed", &e))?;
    }
    Ok(())
}

fn cases() -> u32 {
    std::env::var("MURK_INVARIANT_CASES")
        .ok()
        .map(|n| n.parse().expect("MURK_INVARIANT_CASES must be a number"))
        .unwrap_or(32)
}

#[test]
fn access_invariants_hold_across_random_command_sequences() {
    let config = Config {
        cases: cases(),
        // Shrunk counterexamples are reported in the failure; don't write
        // regression files into the source tree.
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner = TestRunner::new(config);
    let result = runner.run(&proptest::collection::vec(op(), 1..=8), |ops| {
        run_sequence(&ops)
    });
    if let Err(e) = result {
        panic!("{e}");
    }
}

/// The widening oracle is held to the membership the step asked for, not the
/// membership the vault ends up with: a `group add` of bob that also slipped
/// carol into the group must be reported, though the vault's own metadata
/// lists her as a member.
#[test]
fn group_add_admits_only_the_named_member() {
    let label = |s: &str| s.to_string();
    let ops = Tier::Group(label("ops"));
    let cell: Cell = (label("K2"), ops.clone());
    let readers = |who: &[&str]| -> BTreeMap<String, String> {
        who.iter().map(|w| (label(w), label("v"))).collect()
    };
    let before: Cells = [(cell.clone(), readers(&["alice"]))].into();
    let after: Cells = [(cell, readers(&["alice", "bob", "carol"]))].into();
    let membership = |ops: &[&str]| Membership {
        shared: ["alice", "bob", "carol"].map(label).into(),
        groups: [(label("ops"), ops.iter().map(|w| label(w)).collect())].into(),
        by_pk: BTreeMap::new(),
    };
    let was = membership(&["alice"]);
    let plan = Plan {
        widen: vec![(None, ops)],
        membership: vec![Change::Join(label("bob"), label("ops"))],
        ..Plan::default()
    };
    let expected = was.after(&plan.membership, &was.by_pk);
    let now = membership(&["alice", "bob", "carol"]);

    let err = check_access(&plan, &before, &after, &was, &expected, &now).unwrap_err();
    assert!(err.contains("carol can now read K2 (group ops)"), "{err}");
    assert!(!err.contains("bob can now read"), "{err}");
}
