// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault trust invariants over random multi-machine histories.
//!
//! Four people share a git remote: alice (two machines), bob, carol, and dave,
//! who starts outside the vault. Each machine is its own clone with its own
//! `HOME`, so its own trust pin. A CI runner loads with a fresh `HOME` and
//! `MURK_TRUSTED_SIGNERS`, and an agent grant loads with its key-file anchor.
//! Each case runs a random sequence of: saves, `circle authorize` / `revoke`,
//! vouching (a member registers a signing key they control for another
//! recipient), `git merge` through the murk driver, `murk trust`, pushes of a
//! branch, loads of the branch tip, an older revision, a new branch, a pushed
//! branch or a detached HEAD, `murk diff` against an older revision, an agent
//! grant, forgeries (a vault rebuilt from any revision the attacker could
//! open, with a chosen generation, signed by their own key or as a recipient
//! whose registry entry holds a key they control), and replays of old
//! revisions.
//!
//! Every vault in the run is traced to who produced it and when. After every
//! step the harness checks:
//!
//! - **Revoked signers stay out.** Once an observer (a machine, CI, the agent,
//!   which follows the machine that minted it) has accepted a vault that
//!   removes X, it never accepts (by a load, `murk trust`, `murk diff` or the
//!   merge driver) a vault X produced after that revoke, whichever key signed
//!   it, nor a vault produced after the revoke that lists X again without a
//!   `circle authorize` of X since.
//! - **No reads after removal.** X never decrypts a value first written in a
//!   vault that did not list X, unless X was authorized again afterwards.
//! - The access invariants for the commands a member runs: a refused command
//!   leaves the vault byte-for-byte unchanged; a saved value is readable by
//!   exactly the vault's recipients (no widening, no drop); and after an
//!   accepted write the writer's machine loads the vault again.
//! - **A revoke takes its grants with it.** The vault a revoke of X writes
//!   keeps no agent grant whose anchor trusts X.
//!
//! Stored sequences run first. Each is scripted: every step must run, a load
//! of an honest vault must be accepted before the decisive step, and the
//! decisive step must be accepted or refused as the scenario requires, so a
//! sequence cannot pass without making its attack.
//!
//! `MURK_TRUST_CASES` sets the number of cases (default 8, sized for CI);
//! `.github/workflows/invariants.yaml` runs a nightly soak with many more.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use common::cast::{self, Who};
use common::machines::{Machine, copy_dir, git_in};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

const PEOPLE: [&str; 4] = ["alice", "bob", "carol", "dave"];
/// Machines and the person each belongs to.
const MACHINES: [(&str, usize); 5] = [
    ("alice-1", 0),
    ("alice-2", 0),
    ("bob-1", 1),
    ("carol-1", 2),
    ("dave-1", 3),
];
const KEYS: [&str; 3] = ["K1", "K2", "K3"];
/// The largest vault generation murk accepts: 2^53 - 1.
const GENERATION_CAP: u64 = (1 << 53) - 1;

#[derive(Clone, Copy)]
struct P(usize);
impl fmt::Debug for P {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PEOPLE[self.0])
    }
}

#[derive(Clone, Copy)]
struct M(usize);
impl fmt::Debug for M {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MACHINES[self.0].0)
    }
}

#[derive(Clone, Copy)]
struct K(usize);
impl fmt::Debug for K {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(KEYS[self.0])
    }
}

/// What a machine checks out before it loads.
#[derive(Clone, Copy, Debug)]
enum At {
    /// Its local `main`.
    Main,
    /// A detached HEAD at the n-th commit it knows (newest first, wrapping).
    Detached(usize),
    /// A new branch at the n-th commit it knows.
    NewBranch(usize),
    /// A detached HEAD at the n-th pushed branch.
    Pushed(usize),
    /// A local branch named after the n-th pushed branch, at its tip: a pull
    /// request checked out for review.
    PushedBranch(usize),
    /// A detached HEAD at the remote's `main`, as a fresh pull would see it.
    OriginMain,
}

/// Whom a revoke names.
#[derive(Clone, Copy, Debug)]
enum Target {
    Person(P),
    /// The n-th (wrapping) other person the machine's vault lists.
    OtherMember(usize),
}

/// Who forges.
#[derive(Clone, Copy, Debug)]
enum Attacker {
    Person(P),
    /// The person most recently revoked (the step is skipped before any).
    Revoked,
}

/// The signing key a vouch registers for someone else.
#[derive(Clone, Copy, Debug)]
enum Planted {
    /// A key the voucher holds.
    Sock,
    /// A low-order Ed25519 point (the identity), under which a signature of
    /// all zeros except `R` = identity checks for any message unless the
    /// verifier rejects weak keys.
    Weak,
}

/// How a forgery is signed.
#[derive(Clone, Copy, Debug)]
enum Sign {
    /// With the attacker's own key, as themselves.
    Own,
    /// As a recipient whose registry entry is the planted key.
    AsPlanted(Planted),
    /// As another recipient the base lists, after setting their registry
    /// entry to the planted key in the forgery itself. A weak key can only
    /// arrive this way: no vault murk opens carries one.
    Plants(Planted),
}

/// The identity point, compressed: a weak verifying key.
const WEAK_VK: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

fn weak_vk_b64() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(WEAK_VK)
}

/// Which old revision a replay commits again.
#[derive(Clone, Copy, Debug)]
enum Old {
    /// The n-th commit on the remote, newest first (wrapping).
    Nth(usize),
    /// The newest commit whose vault lists the person most recently revoked.
    ListingRevoked,
}

/// Which revision a forgery starts from.
#[derive(Clone, Copy, Debug)]
enum Base {
    /// The n-th commit on the remote, newest first (wrapping).
    Nth(usize),
    /// The newest commit whose vault lists the attacker.
    NewestOpenable,
}

/// A ref on the remote that CI or the agent checks out.
#[derive(Clone, Copy, Debug)]
enum Ref {
    Main,
    Pushed(usize),
}

/// The generation a forgery claims.
#[derive(Clone, Copy, Debug)]
enum Gen {
    /// One past the base revision's, as a save makes it.
    Next,
    /// A thousand past the base revision's.
    Jump,
    /// The largest generation murk accepts (2^53 - 1, exact in a JSON
    /// number), so the counter cannot move past it.
    Max,
    /// `u64::MAX`, above what murk accepts.
    AboveCap,
}

/// Where an attacker pushes.
#[derive(Clone, Copy, Debug)]
enum Dest {
    Main,
    Branch,
}

#[derive(Clone, Debug)]
enum Op {
    /// `murk add KEY` on a machine, committed there.
    Save {
        m: M,
        key: K,
    },
    Authorize {
        m: M,
        who: P,
    },
    Revoke {
        m: M,
        who: Target,
    },
    /// The machine's person authorizes `who` (if needed) and registers a
    /// signing key the machine's person controls as `who`'s, signed as
    /// themselves. Library code: murk has no command for it.
    Vouch {
        m: M,
        who: P,
        key: Planted,
    },
    /// Fetch, merge `origin/main` into `main` (the murk driver runs on a
    /// conflict), push.
    Sync {
        m: M,
    },
    /// `murk trust --yes`, run only where a person reviewing it would accept:
    /// a vault no observer rule forbids. With `forgery`, that includes a
    /// vault a member wrote with their own code, as a reviewer who takes the
    /// hint to override a refusal would (only stored sequences set it).
    Trust {
        m: M,
        forgery: bool,
    },
    /// Check out and load (`murk export`).
    Load {
        m: M,
        at: At,
    },
    /// `murk diff <rev> --show-values` against the n-th commit the machine knows.
    Diff {
        m: M,
        rev: usize,
    },
    /// `murk agent grant --only K1`, committed; the agent then loads with the
    /// key file murk keeps on the minting machine.
    ///
    /// A key file handed off with `--out` to an agent that runs elsewhere is
    /// left out on purpose: the revoke cannot delete that copy, so its anchor
    /// still trusts the revoked signer, who can sign a vault from before the
    /// revoke in which the grant is live. That is an accepted, documented
    /// limit (the grant's TTL bounds it), not an invariant this harness holds.
    Grant {
        m: M,
    },
    AgentLoad {
        at: Ref,
    },
    CiLoad {
        at: Ref,
    },
    /// `by` rebuilds the n-th revision on the remote (one they can open) with
    /// a changed K1 and the chosen generation, signs it (as themselves, or as
    /// a recipient whose registry entry holds a key they control) and pushes.
    Forge {
        by: Attacker,
        base: Base,
        generation: Gen,
        sign: Sign,
        to: Dest,
    },
    /// Someone with push access commits the n-th revision's vault again.
    Replay {
        rev: Old,
        to: Dest,
    },
    /// Merge the n-th pushed branch into the machine's current checkout (the
    /// murk driver runs on a conflict).
    MergeBranch {
        m: M,
        branch: usize,
    },
    /// Push the machine's current checkout to a new branch on the remote,
    /// as a pull request would.
    Push {
        m: M,
    },
}

fn m() -> impl Strategy<Value = M> {
    prop_oneof![
        3 => Just(M(0)),
        1 => Just(M(1)),
        2 => Just(M(2)),
        2 => Just(M(3)),
        1 => Just(M(4)),
    ]
}

fn p() -> impl Strategy<Value = P> {
    (0..PEOPLE.len()).prop_map(P)
}

fn at() -> impl Strategy<Value = At> {
    prop_oneof![
        3 => Just(At::Main),
        2 => (0..8usize).prop_map(At::Detached),
        2 => (0..8usize).prop_map(At::NewBranch),
        1 => (0..4usize).prop_map(At::Pushed),
        1 => (0..4usize).prop_map(At::PushedBranch),
        3 => Just(At::OriginMain),
    ]
}

fn reference() -> impl Strategy<Value = Ref> {
    prop_oneof![3 => Just(Ref::Main), 1 => (0..4usize).prop_map(Ref::Pushed)]
}

fn dest() -> impl Strategy<Value = Dest> {
    prop_oneof![3 => Just(Dest::Main), 1 => Just(Dest::Branch)]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (m(), (0..KEYS.len()).prop_map(K)).prop_map(|(m, key)| Op::Save { m, key }),
        1 => (m(), p()).prop_map(|(m, who)| Op::Authorize { m, who }),
        3 => (
            m(),
            prop_oneof![1 => p().prop_map(Target::Person), 3 => (0..3usize).prop_map(Target::OtherMember)],
        )
            .prop_map(|(m, who)| Op::Revoke { m, who }),
        1 => (m(), p(), prop_oneof![2 => Just(Planted::Sock), 1 => Just(Planted::Weak)])
            .prop_map(|(m, who, key)| Op::Vouch { m, who, key }),
        3 => m().prop_map(|m| Op::Sync { m }),
        1 => m().prop_map(|m| Op::Trust { m, forgery: false }),
        3 => (m(), at()).prop_map(|(m, at)| Op::Load { m, at }),
        1 => (m(), 0..8usize).prop_map(|(m, rev)| Op::Diff { m, rev }),
        1 => m().prop_map(|m| Op::Grant { m }),
        1 => reference().prop_map(|at| Op::AgentLoad { at }),
        2 => reference().prop_map(|at| Op::CiLoad { at }),
        3 => (
            prop_oneof![1 => p().prop_map(Attacker::Person), 2 => Just(Attacker::Revoked)],
            prop_oneof![1 => (0..8usize).prop_map(Base::Nth), 2 => Just(Base::NewestOpenable)],
            prop_oneof![
                3 => Just(Gen::Next),
                1 => Just(Gen::Jump),
                1 => Just(Gen::Max),
                1 => Just(Gen::AboveCap),
            ],
            prop_oneof![
                3 => Just(Sign::Own),
                1 => Just(Sign::AsPlanted(Planted::Sock)),
                1 => Just(Sign::AsPlanted(Planted::Weak)),
                1 => Just(Sign::Plants(Planted::Sock)),
                1 => Just(Sign::Plants(Planted::Weak)),
            ],
            dest(),
        )
            .prop_map(|(by, base, generation, sign, to)| Op::Forge {
                by,
                base,
                generation,
                sign,
                to
            }),
        2 => (
            prop_oneof![1 => (0..8usize).prop_map(Old::Nth), 1 => Just(Old::ListingRevoked)],
            dest(),
        )
            .prop_map(|(rev, to)| Op::Replay { rev, to }),
        1 => (m(), 0..4usize).prop_map(|(m, branch)| Op::MergeBranch { m, branch }),
        1 => m().prop_map(|m| Op::Push { m }),
    ]
}

/// Who produced a vault file, and at which step.
#[derive(Clone, Copy, Debug)]
struct Origin {
    producer: Option<usize>,
    step: usize,
    /// Written by an attacker's code (a forgery).
    forged: bool,
    /// Written by library code rather than a murk command (a forgery or a
    /// vouch), so murk's own write checks never ran on it.
    custom: bool,
}

/// The identities and the starting state, built once per test binary.
struct Fixture {
    dir: tempfile::TempDir,
    people: Vec<Who>,
    socks: Vec<Who>,
    ci: Who,
    origins: HashMap<u64, Origin>,
}

fn blob_id(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

fn key_path(root: &Path, label: &str) -> PathBuf {
    root.join("keys").join(format!("{label}.key"))
}

/// The trusted-signer entry for an age identity (`age1…:<verifying key>`).
fn signer_entry(who: &Who) -> String {
    format!("{}:{}", who.pubkey, verifying_key(who))
}

/// Write a key file only its owner can read (murk refuses anything looser).
fn write_key(path: &Path, secret: &str) {
    fs::write(path, secret).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn verifying_key(who: &Who) -> String {
    murk_cli::crypto::parse_identity(&who.secret)
        .unwrap()
        .signing_key()
        .expect("age keys sign")
        .verifying_key()
}

fn machine(root: &Path, i: usize) -> Machine {
    let (name, person) = MACHINES[i];
    Machine {
        name: name.to_string(),
        dir: root.join(name),
        home: root.join(format!("{name}-home")),
        key_file: key_path(root, PEOPLE[person]),
    }
}

/// Clones that never sign: the attacker's push clone, CI's and the agent's.
fn bystander(root: &Path, name: &str) -> Machine {
    Machine {
        name: name.to_string(),
        dir: root.join(name),
        home: root.join(format!("{name}-home")),
        key_file: key_path(root, "ci"),
    }
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("live");
    fs::create_dir_all(root.join("keys")).unwrap();
    let out = git_in(&root, &root, None)
        .args(["init", "-q", "--bare", "-b", "main", "origin.git"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    // alice's key comes from `murk init`; everyone else's is generated.
    let a1_home = root.join("alice-1-home");
    let first = Machine::clone(&root, "alice-1", &root.join("unused.key"));
    let mut init = common::murk_bin(&a1_home);
    init.current_dir(&first.dir)
        .arg("init")
        .write_stdin("alice\n")
        .assert()
        .success();
    let env = fs::read_to_string(first.dir.join(".env")).unwrap();
    let stored = env
        .lines()
        .find_map(|l| l.strip_prefix("export MURK_KEY_FILE="))
        .expect("init writes MURK_KEY_FILE")
        .trim_matches('\'');
    let alice = Who::from_secret("alice", &fs::read_to_string(stored).unwrap());
    fs::remove_file(first.dir.join(".env")).unwrap();
    let mut people = vec![alice];
    people.extend(PEOPLE[1..].iter().map(|n| Who::generate(n)));
    let socks: Vec<Who> = PEOPLE
        .iter()
        .map(|n| Who::generate(&format!("sock:{n}")))
        .collect();
    let ci = Who::generate("ci");
    for who in people.iter().chain(std::iter::once(&ci)) {
        write_key(&key_path(&root, &who.label), &who.secret);
    }

    let a1 = machine(&root, 0);
    a1.murk().arg("setup-merge-driver").assert().success();
    for who in [&people[1], &people[2], &ci] {
        a1.murk()
            .args(["circle", "authorize", &who.pubkey, "--name", &who.label])
            .assert()
            .success();
    }
    a1.murk()
        .args(["add", "K1"])
        .write_stdin("init-K1\n")
        .assert()
        .success();
    assert!(a1.commit("p0"));
    a1.git_ok(&["push", "-q", "origin", "main"]);

    for i in 1..MACHINES.len() {
        let mach = Machine::clone(
            &root,
            MACHINES[i].0,
            &key_path(&root, PEOPLE[MACHINES[i].1]),
        );
        mach.murk().arg("setup-merge-driver").assert().success();
        if MACHINES[i].1 != 3 {
            mach.murk().args(["trust", "--yes"]).assert().success();
        }
    }
    for name in ["attacker", "ci-runner", "agent"] {
        Machine::clone(&root, name, &key_path(&root, "ci"));
    }

    // bob and carol each write once, and every member machine confirms their
    // signing keys, so the run starts from a settled team.
    for (i, key) in [(2, "K2"), (3, "K3")] {
        let mach = machine(&root, i);
        mach.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        // Confirm the writes pulled in (carol confirms bob's key first).
        mach.murk().args(["trust", "--yes"]).assert().success();
        mach.murk()
            .args(["add", key])
            .write_stdin(format!("init-{key}\n"))
            .assert()
            .success();
        assert!(mach.commit(&format!("p{}", MACHINES[i].1)));
        mach.git_ok(&["push", "-q", "origin", "main"]);
    }
    for i in 0..4 {
        let mach = machine(&root, i);
        mach.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        mach.murk().args(["trust", "--yes"]).assert().success();
        mach.murk().arg("export").assert().success();
    }
    machine(&root, 4).git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);

    // Every commit so far, by the person named in its message.
    let attacker = bystander(&root, "attacker");
    attacker.git_ok(&["fetch", "-q", "origin"]);
    let mut origins = HashMap::new();
    for rev in attacker.revisions() {
        let msg = attacker.git_ok(&["log", "-1", "--format=%s", &rev]);
        let producer = msg.strip_prefix('p').and_then(|n| n.parse().ok());
        origins.insert(
            blob_id(&attacker.vault_at(&rev)),
            Origin {
                producer,
                step: 0,
                forged: false,
                custom: false,
            },
        );
    }

    copy_dir(&root, &dir.path().join("snapshot"));
    Fixture {
        dir,
        people,
        socks,
        ci,
        origins,
    }
}

static FIXTURE: std::sync::LazyLock<Fixture> = std::sync::LazyLock::new(build_fixture);

/// An observer whose acceptances the invariants constrain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Obs {
    Machine(usize),
    Ci,
    Agent,
}

struct Agent {
    key_file: PathBuf,
    minted_on: usize,
}

/// One case's world.
struct World<'f> {
    fx: &'f Fixture,
    root: PathBuf,
    origins: HashMap<u64, Origin>,
    /// Accepted `circle revoke` / `authorize` (and vouch) steps, per person.
    revokes: Vec<(usize, usize)>,
    authorizes: Vec<(usize, usize)>,
    /// Per observer: person → the revoke step whose removal it accepted.
    removed: BTreeMap<Obs, BTreeMap<usize, usize>>,
    /// People whose entries the CI secret lists.
    ci_signers: BTreeSet<usize>,
    agent: Option<Agent>,
    /// Plaintext → (step written, people the writing vault did not list).
    written: HashMap<String, (usize, BTreeSet<usize>)>,
    branches: Vec<String>,
    /// Grants the last revoke had to take with it.
    last_cascade: usize,
}

impl<'f> World<'f> {
    fn new(fx: &'f Fixture) -> Self {
        let root = fx.dir.path().join("live");
        let _ = fs::remove_dir_all(&root);
        copy_dir(&fx.dir.path().join("snapshot"), &root);
        let fixture_values =
            ["init-K1", "init-K2", "init-K3"].map(|v| (v.to_string(), (0, BTreeSet::from([3]))));
        Self {
            fx,
            root,
            origins: fx.origins.clone(),
            revokes: Vec::new(),
            authorizes: Vec::new(),
            removed: BTreeMap::new(),
            ci_signers: BTreeSet::from([0, 1, 2]),
            agent: None,
            written: fixture_values.into_iter().collect(),
            branches: Vec::new(),
            last_cascade: 0,
        }
    }

    fn machine(&self, i: usize) -> Machine {
        machine(&self.root, i)
    }

    fn record(&mut self, bytes: &[u8], producer: Option<usize>, step: usize, forged: bool) {
        self.record_origin(bytes, producer, step, forged, forged);
    }

    fn record_origin(
        &mut self,
        bytes: &[u8],
        producer: Option<usize>,
        step: usize,
        forged: bool,
        custom: bool,
    ) {
        if bytes.is_empty() {
            return;
        }
        self.origins.entry(blob_id(bytes)).or_insert(Origin {
            producer,
            step,
            forged,
            custom,
        });
    }

    /// The people a vault file lists as recipients.
    fn listed(&self, bytes: &[u8]) -> BTreeSet<usize> {
        let vault: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
        let recipients: BTreeSet<&str> = vault["recipients"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        (0..PEOPLE.len())
            .filter(|&i| recipients.contains(self.fx.people[i].pubkey.as_str()))
            .collect()
    }

    fn authorized_between(&self, who: usize, after: usize, upto: usize) -> bool {
        self.authorizes
            .iter()
            .any(|&(p, a)| p == who && after < a && a <= upto)
    }

    /// The removals `obs` has accepted (the agent follows the machine that
    /// minted it, and its own loads).
    fn removals(&self, obs: &Obs) -> BTreeMap<usize, usize> {
        let mut all = self.removed.get(obs).cloned().unwrap_or_default();
        if let (Obs::Agent, Some(agent)) = (obs, &self.agent) {
            for (who, v) in self
                .removed
                .get(&Obs::Machine(agent.minted_on))
                .cloned()
                .unwrap_or_default()
            {
                all.entry(who).or_insert(v);
            }
        }
        all
    }

    /// Whether accepting `bytes` on `obs` breaks the revoked-signer invariant.
    fn check_accept(&self, obs: &Obs, bytes: &[u8], how: &str) -> Result<(), String> {
        let Some(origin) = self.origins.get(&blob_id(bytes)) else {
            return Ok(());
        };
        let listed = self.listed(bytes);
        let generation = serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| v["generation"].as_u64())
            .unwrap_or(0);
        if generation > GENERATION_CAP {
            return Err(format!(
                "{obs:?} {how} a vault with generation {generation}, above the cap \
                 {GENERATION_CAP}"
            ));
        }
        // CI's secret drops a revoked signer as soon as the revoke is made,
        // so CI must refuse their later vaults whether or not it has loaded
        // the revoke yet.
        if *obs == Obs::Ci
            && let Some(p) = origin.producer
            && !self.ci_signers.contains(&p)
            && let Some(&(_, v)) = self.revokes.iter().rev().find(|&&(r, _)| r == p)
            && origin.step > v
        {
            return Err(format!(
                "CI {how} a vault {} produced at step {}, after the CI secret dropped them at \
                 step {v}",
                PEOPLE[p], origin.step
            ));
        }
        let removals = self.removals(obs);
        // A member this observer still trusts may list anyone with their own
        // code: they could have run `circle authorize` instead.
        let insider = origin.custom && origin.producer.is_some_and(|p| !removals.contains_key(&p));
        for (who, v) in removals.clone() {
            if origin.step <= v {
                continue;
            }
            if origin.producer == Some(who) {
                return Err(format!(
                    "{obs:?} {how} a vault {} produced at step {} (forged: {}), after accepting \
                     their removal at step {v}",
                    PEOPLE[who], origin.step, origin.forged
                ));
            }
            if listed.contains(&who) && !insider && !self.authorized_between(who, v, origin.step) {
                return Err(format!(
                    "{obs:?} {how} a vault produced at step {} that lists {} again, revoked at \
                     step {v} and never authorized since",
                    origin.step, PEOPLE[who]
                ));
            }
        }
        Ok(())
    }

    /// Record that `obs` accepted `bytes`: removals it now knows, and
    /// re-authorizations that undo them.
    fn note_accept(&mut self, obs: Obs, bytes: &[u8]) {
        let Some(origin) = self.origins.get(&blob_id(bytes)).copied() else {
            return;
        };
        let listed = self.listed(bytes);
        for who in 0..PEOPLE.len() {
            let removed = self.removed.entry(obs.clone()).or_default();
            if listed.contains(&who) {
                if let Some(&v) = removed.get(&who)
                    && self.authorized_between(who, v, origin.step)
                {
                    self.removed.entry(obs.clone()).or_default().remove(&who);
                }
                continue;
            }
            let revoke = self
                .revokes
                .iter()
                .filter(|&&(p, v)| p == who && v <= origin.step)
                .map(|&(_, v)| v)
                .max();
            if let Some(v) = revoke
                && !self.authorized_between(who, v, origin.step)
            {
                let removed = self.removed.entry(obs.clone()).or_default();
                let at = removed.entry(who).or_insert(v);
                *at = (*at).max(v);
            }
        }
    }

    fn accept(&mut self, obs: Obs, bytes: &[u8], how: &str) -> Result<(), String> {
        self.check_accept(&obs, bytes, how)?;
        self.note_accept(obs, bytes);
        Ok(())
    }

    /// Every value-reading identity, labelled by person index.
    fn people(&self) -> Vec<Who> {
        self.fx
            .people
            .iter()
            .enumerate()
            .map(|(i, w)| Who {
                label: i.to_string(),
                ..w.clone()
            })
            .collect()
    }

    /// No person reads a value first written in a vault that did not list
    /// them, unless they were authorized again since.
    fn check_reads(&self, what: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        let path = self.root.join("check.murk");
        fs::write(&path, bytes).unwrap();
        for ((key, tier), by) in cast::cells(&path, &self.people()) {
            for (label, plaintext) in by {
                let who: usize = label.parse().unwrap();
                let Some((w, excluded)) = self.written.get(&plaintext) else {
                    continue;
                };
                if excluded.contains(&who) && !self.authorized_between(who, *w, usize::MAX) {
                    return Err(format!(
                        "{} can read {plaintext:?} ({key}, {tier:?}) in {what}, written at step \
                         {w} in a vault that did not list them",
                        PEOPLE[who]
                    ));
                }
            }
        }
        Ok(())
    }

    /// A value a member saved is readable by exactly the vault's recipients.
    fn check_saved(&self, bytes: &[u8], key: &str, value: &str) -> Result<(), String> {
        let path = self.root.join("check.murk");
        fs::write(&path, bytes).unwrap();
        let mut ids = self.people();
        ids.push(Who {
            label: "ci".into(),
            ..self.fx.ci.clone()
        });
        let cells = cast::cells(&path, &ids);
        let readers: BTreeMap<String, String> = cells
            .get(&(key.to_string(), cast::Tier::Shared))
            .cloned()
            .unwrap_or_default();
        let vault: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let expected: BTreeSet<String> = vault["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|pk| ids.iter().find(|w| w.pubkey == pk.as_str().unwrap()))
            .map(|w| w.label.clone())
            .collect();
        let got: BTreeSet<String> = readers.keys().cloned().collect();
        if got != expected || readers.values().any(|v| v != value) {
            return Err(format!(
                "{key} saved as {value:?}: readers {readers:?}, expected exactly {expected:?}"
            ));
        }
        Ok(())
    }

    fn origin_tip(&self, branch: &str) -> Vec<u8> {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.vault_at(&format!("origin/{branch}"))
    }

    fn pushed(&self, i: usize) -> Option<String> {
        (!self.branches.is_empty()).then(|| self.branches[i % self.branches.len()].clone())
    }

    /// Run the library forgery in a child process with its own environment.
    fn forge(&self, base: &[u8], vars: &[(&str, String)]) -> Option<Vec<u8>> {
        let input = self.root.join("forge-in.murk");
        let output = self.root.join("forge-out.murk");
        let home = self.root.join("forge-home");
        fs::write(&input, base).unwrap();
        let _ = fs::remove_file(&output);
        fs::create_dir_all(&home).unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "forge_child", "--ignored", "--nocapture"])
            .env("FORGE_IN", &input)
            .env("FORGE_OUT", &output)
            .env("HOME", &home);
        for var in common::MURK_CONTEXT_VARS {
            cmd.env_remove(var);
        }
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("FORGE-SKIP") || !text.contains("FORGE-OK") {
            return None;
        }
        Some(fs::read(&output).unwrap())
    }

    /// Commit `bytes` as the vault on top of `origin/main` and push it.
    fn push_as_attacker(&mut self, bytes: &[u8], to: Dest, step: usize) {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.git_ok(&["checkout", "-q", "-f", "-B", "work", "origin/main"]);
        fs::write(attacker.dir.join(".murk"), bytes).unwrap();
        attacker.commit(&format!("s{step} attacker"));
        match to {
            Dest::Main => {
                attacker.git_ok(&["push", "-q", "origin", "HEAD:main"]);
            }
            Dest::Branch => {
                let name = format!("attack-{step}");
                attacker.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
                self.branches.push(name);
            }
        }
    }

    /// Check out `rev` (or a branch at it) in a bystander clone for CI/agent.
    fn checkout_ref(&self, clone: &Machine, at: Ref) -> Option<()> {
        clone.git_ok(&["fetch", "-q", "origin"]);
        let target = match at {
            Ref::Main => "origin/main".to_string(),
            Ref::Pushed(i) => format!("origin/{}", self.pushed(i)?),
        };
        clone.git_ok(&["checkout", "-q", "-f", "--detach", &target]);
        Some(())
    }

    /// A step's result: `None` when it does not apply and did not run.
    fn step(&mut self, step: usize, op: &Op) -> Option<Result<Ran, String>> {
        let value = |key: &str| format!("s{step}-{key}");
        match op {
            Op::Save { m, key } => {
                let mach = self.machine(m.0);
                let key = KEYS[key.0];
                let before = mach.vault();
                let out = mach
                    .murk()
                    .args(["add", key])
                    .write_stdin(format!("{}\n", value(key)))
                    .output()
                    .unwrap();
                Some(self.after_write(step, m.0, &before, out, |w, bytes| {
                    let excluded = (0..PEOPLE.len())
                        .filter(|p| !w.listed(bytes).contains(p))
                        .collect();
                    w.written.insert(value(key), (step, excluded));
                    w.check_saved(bytes, key, &value(key))
                }))
            }
            Op::Authorize { m, who } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let w = &self.fx.people[who.0];
                let out = mach
                    .murk()
                    .args(["circle", "authorize", &w.pubkey, "--name", &w.label])
                    .output()
                    .unwrap();
                let who = who.0;
                Some(self.after_write(step, m.0, &before, out, |world, _| {
                    world.authorizes.push((who, step));
                    world.ci_signers.insert(who);
                    Ok(())
                }))
            }
            Op::Revoke { m, who } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let who = match who {
                    Target::Person(p) => p.0,
                    Target::OtherMember(n) => {
                        let others: Vec<usize> = self
                            .listed(&before)
                            .into_iter()
                            .filter(|&p| p != MACHINES[m.0].1)
                            .collect();
                        *others.get(n % others.len().max(1))?
                    }
                };
                let revoker = MACHINES[m.0].1;
                let cascaded = self.grants_anchored_on(&before, revoker, who);
                self.last_cascade = cascaded.len();
                let out = mach
                    .murk()
                    .args(["circle", "revoke", &self.fx.people[who].pubkey])
                    .output()
                    .unwrap();
                // The revoke is known before the writer's own acceptance is
                // noted, so the writer's machine records the removal.
                if out.status.success() {
                    self.revokes.push((who, step));
                    // The operator drops them from the CI secret too.
                    self.ci_signers.remove(&who);
                }
                Some(self.after_write(step, m.0, &before, out, |world, bytes| {
                    world.check_cascade(bytes, revoker, &cascaded, who)
                }))
            }
            Op::Vouch { m, who, key } => {
                let mach = self.machine(m.0);
                let person = MACHINES[m.0].1;
                let w = &self.fx.people[who.0];
                let forged = self.forge(
                    &mach.vault(),
                    &[
                        ("FORGE_KEY", self.fx.people[person].secret.clone()),
                        ("FORGE_AUTHORIZE", format!("{} {}", w.pubkey, w.label)),
                        (
                            "FORGE_REGISTRY",
                            format!("{}={}", w.pubkey, self.planted_vk(*key, person)),
                        ),
                    ],
                )?;
                let newly = !self.listed(&mach.vault()).contains(&who.0);
                fs::write(mach.dir.join(".murk"), &forged).unwrap();
                mach.commit(&format!("s{step} vouch"));
                self.record_origin(&forged, Some(person), step, false, true);
                if newly {
                    self.authorizes.push((who.0, step));
                    self.ci_signers.insert(who.0);
                }
                Some(
                    self.accept(Obs::Machine(m.0), &forged, "wrote")
                        .map(|()| Ran::Accepted),
                )
            }
            Op::Sync { m } => Some(self.sync(step, m.0)),
            Op::MergeBranch { m, branch } => {
                let branch = format!("origin/{}", self.pushed(*branch)?);
                Some(self.merge(step, m.0, &branch, false))
            }
            Op::Trust { m, forgery } => {
                let mach = self.machine(m.0);
                let bytes = mach.vault();
                let origin = self.origins.get(&blob_id(&bytes)).copied()?;
                // A reviewer accepts only what no rule here forbids.
                if (origin.forged && !forgery)
                    || self.check_accept(&Obs::Machine(m.0), &bytes, "").is_err()
                {
                    return None;
                }
                let out = mach.murk().args(["trust", "--yes"]).output().unwrap();
                if !out.status.success() {
                    return Some(refused(&bytes, &mach.vault(), "murk trust", &out));
                }
                let now = mach.vault();
                self.record(&now, MACHINES[m.0].1.into(), step, false);
                Some(self.accepted(Obs::Machine(m.0), &now, "trusted"))
            }
            Op::Load { m, at } => {
                let mach = self.machine(m.0);
                mach.git_ok(&["fetch", "-q", "origin"]);
                let revs = mach.revisions();
                let checkout: Vec<String> = match at {
                    At::Main => vec!["main".into()],
                    At::Detached(i) => vec!["--detach".into(), revs[i % revs.len()].clone()],
                    At::NewBranch(i) => {
                        vec![
                            "-B".into(),
                            format!("b{step}"),
                            revs[i % revs.len()].clone(),
                        ]
                    }
                    At::Pushed(i) => {
                        vec!["--detach".into(), format!("origin/{}", self.pushed(*i)?)]
                    }
                    At::PushedBranch(i) => {
                        let name = self.pushed(*i)?;
                        vec!["-B".into(), name.clone(), format!("origin/{name}")]
                    }
                    At::OriginMain => vec!["--detach".into(), "origin/main".into()],
                };
                let mut args = vec!["checkout", "-q", "-f"];
                args.extend(checkout.iter().map(String::as_str));
                mach.git_ok(&args);
                let bytes = mach.vault();
                let out = mach.murk().args(["export", "--json"]).output().unwrap();
                if !out.status.success() {
                    return Some(refused(&bytes, &mach.vault(), "murk export", &out));
                }
                Some(self.accepted(Obs::Machine(m.0), &bytes, "loaded"))
            }
            Op::Diff { m, rev } => {
                let mach = self.machine(m.0);
                let revs = mach.revisions();
                let rev = revs[rev % revs.len()].clone();
                let at_rev = mach.vault_at(&rev);
                let out = mach
                    .murk()
                    .args(["diff", &rev, "--show-values", "--json"])
                    .output()
                    .unwrap();
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                // diff never extends the pin: check, but note nothing.
                Some(
                    self.check_accept(&Obs::Machine(m.0), &at_rev, "showed (murk diff)")
                        .map(|()| Ran::Accepted),
                )
            }
            Op::Grant { m } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let keys_dir = mach.home.join(".config/murk/agent-keys");
                let kept: BTreeSet<PathBuf> = fs::read_dir(&keys_dir)
                    .map(|d| d.map(|e| e.unwrap().path()).collect())
                    .unwrap_or_default();
                let mut cmd = mach.murk();
                cmd.args([
                    "agent",
                    "grant",
                    "--name",
                    &format!("g{step}"),
                    "--only",
                    "K1",
                ]);
                let out = cmd.output().unwrap();
                if out.status.success() {
                    let key_file = fs::read_dir(&keys_dir)
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| !kept.contains(p))
                        .expect("agent grant keeps a key file");
                    self.agent = Some(Agent {
                        key_file,
                        minted_on: m.0,
                    });
                    self.removed.remove(&Obs::Agent);
                }
                Some(self.after_write(step, m.0, &before, out, |_, _| Ok(())))
            }
            Op::AgentLoad { at } => {
                let agent = self.agent.as_ref()?;
                let clone = bystander(&self.root, "agent");
                self.checkout_ref(&clone, *at)?;
                let bytes = clone.vault();
                let out = common::murk_bin(&clone.home)
                    .current_dir(&clone.dir)
                    .env("MURK_KEY_FILE", &agent.key_file)
                    .args(["get", "K1"])
                    .output()
                    .unwrap();
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                Some(self.accepted(Obs::Agent, &bytes, "loaded"))
            }
            Op::CiLoad { at } => {
                let clone = bystander(&self.root, "ci-runner");
                self.checkout_ref(&clone, *at)?;
                let bytes = clone.vault();
                // A fresh runner: no pin survives between loads.
                let _ = fs::remove_dir_all(&clone.home);
                fs::create_dir_all(&clone.home).unwrap();
                let signers: Vec<String> = self
                    .ci_signers
                    .iter()
                    .map(|&p| signer_entry(&self.fx.people[p]))
                    .collect();
                let out = common::murk_bin(&clone.home)
                    .current_dir(&clone.dir)
                    .env("MURK_KEY_FILE", key_path(&self.root, "ci"))
                    .env("MURK_TRUSTED_SIGNERS", signers.join(","))
                    .args(["export", "--json"])
                    .output()
                    .unwrap();
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                Some(self.accepted(Obs::Ci, &bytes, "loaded"))
            }
            Op::Forge {
                by,
                base,
                generation,
                sign,
                to,
            } => {
                let by = match by {
                    Attacker::Person(p) => p.0,
                    Attacker::Revoked => self.revokes.last()?.0,
                };
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let revs = attacker.revisions();
                let base = match base {
                    Base::Nth(n) => attacker.vault_at(&revs[n % revs.len()]),
                    Base::NewestOpenable => revs
                        .iter()
                        .map(|r| attacker.vault_at(r))
                        .find(|v| self.listed(v).contains(&by) && self.opens(v, by))?,
                };
                let base_gen =
                    serde_json::from_slice::<serde_json::Value>(&base).ok()?["generation"]
                        .as_u64()
                        .unwrap_or(0);
                let claimed = match generation {
                    Gen::Next => base_gen,
                    Gen::Jump => base_gen.saturating_add(999),
                    // The save moves the counter one past the claim.
                    Gen::Max => GENERATION_CAP - 1,
                    Gen::AboveCap => u64::MAX,
                };
                let mut vars = vec![
                    ("FORGE_KEY", self.fx.people[by].secret.clone()),
                    ("FORGE_VALUE", format!("K1=forged-s{step}")),
                    ("FORGE_GEN", claimed.to_string()),
                ];
                let (planted, plants) = match *sign {
                    Sign::Own => (None, false),
                    Sign::AsPlanted(key) => (Some(key), false),
                    Sign::Plants(key) => (Some(key), true),
                };
                if let Some(key) = planted {
                    if plants {
                        let as_whom = self.listed(&base).into_iter().find(|&p| p != by)?;
                        vars.push((
                            "FORGE_REGISTRY",
                            format!(
                                "{}={}",
                                self.fx.people[as_whom].pubkey,
                                self.planted_vk(key, by)
                            ),
                        ));
                    }
                    vars.push((
                        "FORGE_SIGN_AS",
                        match key {
                            Planted::Sock => format!("sock:{}", self.fx.socks[by].secret),
                            Planted::Weak => "weak".into(),
                        },
                    ));
                }
                let forged = self.forge(&base, &vars)?;
                self.record(&forged, Some(by), step, true);
                self.push_as_attacker(&forged, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::Replay { rev, to } => {
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let revs = attacker.revisions();
                let old = match rev {
                    Old::Nth(n) => attacker.vault_at(&revs[n % revs.len()]),
                    Old::ListingRevoked => {
                        let who = self.revokes.last()?.0;
                        revs.iter()
                            .map(|r| attacker.vault_at(r))
                            .find(|v| self.listed(v).contains(&who))?
                    }
                };
                if old.is_empty() {
                    return None;
                }
                self.push_as_attacker(&old, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::Push { m } => {
                let mach = self.machine(m.0);
                let name = format!("push-{step}");
                mach.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
                self.branches.push(name);
                Some(Ok(Ran::Accepted))
            }
        }
    }

    /// The grant keys in `before` that a revoke of `who` must revoke with
    /// them: grants whose anchor names `who`, or that have no anchor.
    fn grants_anchored_on(&self, before: &[u8], revoker: usize, who: usize) -> Vec<String> {
        self.meta(before, revoker)
            .map(|meta| {
                meta.grants
                    .values()
                    .filter(|g| self.anchored_on(g, who))
                    .map(|g| g.pubkey.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn anchored_on(&self, grant: &murk_cli::types::GrantEntry, who: usize) -> bool {
        grant.anchors.is_empty() || grant.anchors.contains(&self.fx.people[who].pubkey)
    }

    /// The revoke cascade: the vault a revoke of `who` wrote keeps no grant
    /// that trusts them, as a grant record or as a recipient.
    ///
    /// This checks the vault, not the grant's key file. murk deletes the key
    /// file in its default slot on this machine, but a copy handed off with
    /// `--out` survives and still trusts the revoked signer until its TTL
    /// ends: an accepted, documented limit that this harness does not hold.
    fn check_cascade(
        &self,
        bytes: &[u8],
        revoker: usize,
        cascaded: &[String],
        who: usize,
    ) -> Result<(), String> {
        let meta = self
            .meta(bytes, revoker)
            .ok_or("the revoker cannot open the meta it wrote")?;
        let vault: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let recipients: BTreeSet<&str> = vault["recipients"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let mut kept = meta
            .grants
            .values()
            .filter(|g| self.anchored_on(g, who))
            .map(|g| &g.pubkey)
            .chain(
                cascaded
                    .iter()
                    .filter(|pk| recipients.contains(pk.as_str())),
            );
        if let Some(pubkey) = kept.next() {
            return Err(format!(
                "the revoke of {} kept the grant {pubkey} that trusts them in the vault",
                PEOPLE[who]
            ));
        }
        Ok(())
    }

    /// Whether person `who` can open a vault file with murk's library.
    fn opens(&self, bytes: &[u8], who: usize) -> bool {
        let path = self.root.join("opens.murk");
        fs::write(&path, bytes).unwrap();
        let Ok(vault) = murk_cli::read_vault(path.to_str().unwrap()) else {
            return false;
        };
        let identity = murk_cli::crypto::parse_identity(&self.fx.people[who].secret).unwrap();
        murk_cli::decrypt_vault(&vault, &identity).is_ok()
    }

    /// The verifying key a `key` plant registers, for person `holder`.
    fn planted_vk(&self, key: Planted, holder: usize) -> String {
        match key {
            Planted::Sock => verifying_key(&self.fx.socks[holder]),
            Planted::Weak => weak_vk_b64(),
        }
    }

    /// The meta of a vault file, as person `reader` opens it.
    fn meta(&self, bytes: &[u8], reader: usize) -> Option<murk_cli::types::Meta> {
        let path = self.root.join("meta.murk");
        fs::write(&path, bytes).ok()?;
        let vault = murk_cli::read_vault(path.to_str()?).ok()?;
        let identity = murk_cli::crypto::parse_identity(&self.fx.people[reader].secret).ok()?;
        murk_cli::decrypt_meta(&vault, &identity).ok()?
    }

    /// Accept `bytes` on `obs` as a step's outcome.
    fn accepted(&mut self, obs: Obs, bytes: &[u8], how: &str) -> Result<Ran, String> {
        self.accept(obs, bytes, how).map(|()| Ran::Accepted)
    }

    /// After a member's write: a refusal changed nothing; an accepted write
    /// is committed, recorded, accepted by the writer's machine, passes
    /// `extra`, and loads again there.
    fn after_write(
        &mut self,
        step: usize,
        m: usize,
        before: &[u8],
        out: std::process::Output,
        extra: impl FnOnce(&mut Self, &[u8]) -> Result<(), String>,
    ) -> Result<Ran, String> {
        let mach = self.machine(m);
        let now = mach.vault();
        if !out.status.success() {
            return refused(before, &now, "refused write", &out);
        }
        mach.commit(&format!("s{step} p{}", MACHINES[m].1));
        self.record(&now, Some(MACHINES[m].1), step, false);
        extra(self, &now)?;
        self.accept(Obs::Machine(m), &now, "wrote")?;
        let reload = mach.murk().args(["export", "--json"]).output().unwrap();
        if !reload.status.success() {
            return Err(format!(
                "the writer's machine refuses its own write: {}",
                String::from_utf8_lossy(&reload.stderr)
            ));
        }
        Ok(Ran::Accepted)
    }

    /// Fetch, merge `origin/main` into `main`, push.
    fn sync(&mut self, step: usize, m: usize) -> Result<Ran, String> {
        let mach = self.machine(m);
        mach.git_ok(&["checkout", "-q", "-f", "main"]);
        self.merge(step, m, "origin/main", true)
    }

    /// Merge `theirs` into the current checkout. When both sides changed the
    /// vault, the murk driver accepted `theirs` and produced the result.
    fn merge(
        &mut self,
        step: usize,
        m: usize,
        theirs_ref: &str,
        push: bool,
    ) -> Result<Ran, String> {
        let mach = self.machine(m);
        mach.git_ok(&["fetch", "-q", "origin"]);
        let ours = mach.vault();
        let theirs = mach.vault_at(theirs_ref);
        let base_rev = mach.git(&["merge-base", "HEAD", theirs_ref]);
        let base = String::from_utf8_lossy(&base_rev.stdout).trim().to_string();
        let ancestor = mach.vault_at(&base);
        let merged = mach.git(&["merge", "-q", "--no-edit", theirs_ref]);
        if !merged.status.success() {
            let _ = mach.git(&["merge", "--abort"]);
            let _ = mach.git(&["reset", "-q", "--hard", "HEAD"]);
            return refused(&ours, &mach.vault(), "refused merge", &merged);
        }
        let driver_ran = ours != ancestor && theirs != ancestor && ours != theirs;
        if driver_ran {
            self.check_accept(&Obs::Machine(m), &theirs, "merged (driver)")?;
            let result = mach.vault();
            self.record(&result, Some(MACHINES[m].1), step, false);
            self.accept(Obs::Machine(m), &result, "wrote (merge result)")?;
        }
        if push {
            let _ = mach.git(&["push", "-q", "origin", "main"]);
        }
        Ok(Ran::Accepted)
    }

    /// The no-reads check over every working vault and the remote tip.
    fn check_all_reads(&self) -> Result<(), String> {
        for (i, (name, _)) in MACHINES.iter().enumerate() {
            self.check_reads(name, &self.machine(i).vault())?;
        }
        self.check_reads("origin/main", &self.origin_tip("main"))
    }
}

fn unchanged(before: &[u8], after: &[u8], what: &str) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!("{what} changed the working vault"))
    }
}

/// What a step that ran did.
#[derive(Debug)]
enum Ran {
    Accepted,
    /// Refused, with the command's error output.
    Refused(String),
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

/// A refused command: it must have left the working vault unchanged.
fn refused(
    before: &[u8],
    after: &[u8],
    what: &str,
    out: &std::process::Output,
) -> Result<Ran, String> {
    unchanged(before, after, what).map(|()| Ran::Refused(stderr(out)))
}

/// What a stored sequence requires of one of its steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// It runs; either outcome.
    Runs,
    /// It runs and is accepted.
    Accepts,
    /// It runs and is refused.
    Refuses,
}

/// A step of a stored sequence.
#[derive(Clone, Debug)]
struct Scripted {
    op: Op,
    expect: Expect,
    /// The step the sequence exists to exercise.
    decisive: bool,
}

fn runs(op: Op) -> Scripted {
    Scripted {
        op,
        expect: Expect::Runs,
        decisive: false,
    }
}

fn accepts(op: Op) -> Scripted {
    Scripted {
        expect: Expect::Accepts,
        ..runs(op)
    }
}

fn refuses(op: Op) -> Scripted {
    Scripted {
        expect: Expect::Refuses,
        ..runs(op)
    }
}

impl Scripted {
    fn decisive(self) -> Self {
        Self {
            decisive: true,
            ..self
        }
    }
}

fn is_load(op: &Op) -> bool {
    matches!(
        op,
        Op::Load { .. } | Op::AgentLoad { .. } | Op::CiLoad { .. }
    )
}

/// Run `ops`, checking the invariants after every step. With `script`, every
/// step must run and meet its expectation; without, a step that does not
/// apply is skipped.
fn run_sequence(ops: &[Op], script: Option<&[Scripted]>) -> Result<(), TestCaseError> {
    let mut world = World::new(&FIXTURE);
    for (i, op) in ops.iter().enumerate() {
        let step = i + 1;
        let fail = |e: String| TestCaseError::fail(format!("step {step} {op:?}: {e}"));
        let expect = script.map(|s| s[i].expect);
        let Some(result) = world.step(step, op) else {
            if expect.is_some() {
                return Err(fail("did not run: it could not be built here".into()));
            }
            continue;
        };
        let ran = result.map_err(fail)?;
        // A decisive revoke is there for its cascade: it must have had a
        // grant to take with it, or the cascade check proved nothing.
        if script.is_some_and(|s| s[i].decisive)
            && matches!(op, Op::Revoke { .. })
            && world.last_cascade == 0
        {
            return Err(fail(
                "no grant trusted the revoked signer: nothing to cascade".into(),
            ));
        }
        match (expect, &ran) {
            (Some(Expect::Accepts), Ran::Refused(why)) => {
                return Err(fail(format!("expected it to be accepted, refused: {why}")));
            }
            (Some(Expect::Refuses), Ran::Accepted) => {
                return Err(fail("expected it to be refused, accepted".into()));
            }
            _ => {}
        }
        world.check_all_reads().map_err(fail)?;
    }
    Ok(())
}

/// Run a stored sequence. Its decisive steps must run and meet their
/// expectations, and a load before the first of them must be accepted, so a
/// refusal there comes from the rule under test and not a broken setup.
fn run_scripted(script: &[Scripted]) -> Result<(), TestCaseError> {
    let first = script
        .iter()
        .position(|s| s.decisive)
        .expect("a stored sequence names its decisive step");
    assert!(
        script
            .iter()
            .all(|s| !s.decisive || s.expect != Expect::Runs),
        "a decisive step expects an outcome"
    );
    assert!(
        script[..first]
            .iter()
            .any(|s| s.expect == Expect::Accepts && is_load(&s.op)),
        "a stored sequence loads an honest vault before its decisive step"
    );
    let ops: Vec<Op> = script.iter().map(|s| s.op.clone()).collect();
    run_sequence(&ops, Some(script))
}

/// Shrunk counterexamples found by this harness, and scenarios a fix must
/// keep, replayed before the random cases (like a fuzz corpus) so a
/// regression fails every run, not only the runs that happen to find it
/// again. Each is scripted: every step must run, and the decisive one must
/// end as expected.
fn known_sequences() -> Vec<(&'static str, Vec<Scripted>)> {
    let (alice, bob_m) = (M(0), M(2));
    let (bob, dave) = (P(1), P(3));
    let forge = |sign| Op::Forge {
        by: Attacker::Revoked,
        base: Base::NewestOpenable,
        generation: Gen::Next,
        sign,
        to: Dest::Main,
    };
    let load_tip = Op::Load {
        m: alice,
        at: At::OriginMain,
    };
    // Loaded on `main`, so the branch's rollback mark applies.
    let load_main = Op::Load {
        m: alice,
        at: At::Main,
    };
    let revoke_bob = Op::Revoke {
        m: alice,
        who: Target::Person(bob),
    };
    let forge_max = Op::Forge {
        by: Attacker::Person(bob),
        base: Base::NewestOpenable,
        generation: Gen::Max,
        sign: Sign::Own,
        to: Dest::Main,
    };
    let vouched = |key| {
        vec![
            accepts(Op::Vouch {
                m: bob_m,
                who: dave,
                key,
            }),
            accepts(Op::Sync { m: bob_m }),
            accepts(Op::Sync { m: alice }),
            runs(load_main.clone()),
            accepts(revoke_bob.clone()),
            accepts(load_main.clone()),
            runs(forge(Sign::AsPlanted(key))),
            refuses(load_tip.clone()).decisive(),
        ]
    };
    let older_revision = |at| {
        vec![
            accepts(revoke_bob.clone()),
            runs(Op::Load { m: alice, at }),
            accepts(load_main.clone()),
            runs(forge(Sign::Own)),
            refuses(load_tip.clone()).decisive(),
        ]
    };
    vec![
        (
            "a revoked member signs with a key they vouched for",
            vouched(Planted::Sock),
        ),
        (
            // No vault murk opens carries a weak key: alice refuses bob's
            // vouch, so she revokes him on the vault before it, and his
            // forgery plants the weak key again itself.
            "a revoked member signs under a weak key they vouched for",
            vec![
                accepts(Op::Vouch {
                    m: bob_m,
                    who: dave,
                    key: Planted::Weak,
                }),
                accepts(Op::Sync { m: bob_m }),
                accepts(revoke_bob.clone()),
                accepts(load_main.clone()),
                refuses(load_tip.clone()),
                runs(forge(Sign::Plants(Planted::Weak))),
                refuses(load_tip.clone()).decisive(),
            ],
        ),
        (
            "an older revision on a detached HEAD trusts a revoked member again",
            older_revision(At::Detached(1)),
        ),
        (
            "an older revision on a new branch trusts a revoked member again",
            older_revision(At::NewBranch(1)),
        ),
        (
            // The jump to the cap is refused. A reviewer who overrides that
            // with `murk trust` leaves the counter at the cap, where every
            // new vault has the same generation: another vault there, or an
            // older revision, is still refused.
            "a saturated generation lets a replayed revision through",
            vec![
                accepts(load_main.clone()),
                runs(forge_max.clone()),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                accepts(Op::Trust {
                    m: alice,
                    forgery: true,
                }),
                accepts(load_main.clone()),
                runs(forge_max),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                runs(Op::Replay {
                    rev: Old::Nth(3),
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            // CI keeps no counter, so only the cap refuses there; on a
            // machine the jump bound refuses it too.
            "a generation above the cap is accepted",
            vec![
                accepts(load_main.clone()),
                accepts(Op::CiLoad { at: Ref::Main }),
                runs(Op::Forge {
                    by: Attacker::Person(bob),
                    base: Base::NewestOpenable,
                    generation: Gen::AboveCap,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                refuses(Op::CiLoad { at: Ref::Main }).decisive(),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            "a save on an older revision writes a revoked member back",
            vec![
                accepts(revoke_bob.clone()),
                accepts(load_main.clone()),
                runs(load_tip.clone()),
                refuses(Op::Save {
                    m: alice,
                    key: K(1),
                })
                .decisive(),
            ],
        ),
        (
            "CI keeps trusting a signer dropped from its secret",
            vec![
                accepts(revoke_bob.clone()),
                accepts(Op::CiLoad { at: Ref::Main }),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Jump,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                refuses(Op::CiLoad { at: Ref::Main }).decisive(),
            ],
        ),
        (
            // The decisive check is the revoke cascade in the vault (see
            // `check_cascade`). The agent's last load is refused because the
            // revoke deleted the key file in murk's default slot; a copy
            // handed off with `--out` would still accept the forgery until
            // its TTL ends, an accepted, documented limit left out here.
            "an agent grant keeps trusting a revoked member",
            vec![
                accepts(Op::Grant { m: alice }),
                accepts(Op::Sync { m: alice }),
                accepts(Op::AgentLoad { at: Ref::Main }),
                accepts(revoke_bob.clone()).decisive(),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Jump,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                runs(Op::AgentLoad { at: Ref::Main }),
            ],
        ),
        (
            "loading an unmerged branch trusts the signer it adds on main",
            vec![
                // bob, a trusted signer, opens a pull request that adds dave
                // and vouches for a signing key as dave's.
                accepts(Op::Load {
                    m: bob_m,
                    at: At::NewBranch(0),
                }),
                accepts(Op::Vouch {
                    m: bob_m,
                    who: dave,
                    key: Planted::Sock,
                }),
                accepts(Op::Push { m: bob_m }),
                // alice checks it out to review it, then goes back to main.
                accepts(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                }),
                accepts(load_main.clone()),
                // The pull request is never merged; a vault signed as dave
                // lands on main.
                runs(Op::Forge {
                    by: Attacker::Person(bob),
                    base: Base::NewestOpenable,
                    generation: Gen::Next,
                    sign: Sign::AsPlanted(Planted::Sock),
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            "a removal saved on a feature branch locks this machine out of main",
            vec![
                accepts(Op::Load {
                    m: alice,
                    at: At::NewBranch(0),
                }),
                accepts(revoke_bob.clone()),
                // main lists bob until the feature branch merges.
                accepts(load_main.clone()).decisive(),
                // A vault bob signs is refused on every branch.
                runs(forge(Sign::Own)),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Next,
                    sign: Sign::Own,
                    to: Dest::Branch,
                }),
                refuses(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                })
                .decisive(),
                refuses(Op::Load {
                    m: alice,
                    at: At::Pushed(0),
                })
                .decisive(),
            ],
        ),
    ]
}

fn cases() -> u32 {
    std::env::var("MURK_TRUST_CASES")
        .ok()
        .map(|n| n.parse().expect("MURK_TRUST_CASES must be a number"))
        .unwrap_or(8)
}

#[test]
fn trust_invariants_hold_across_machines() {
    let config = Config {
        cases: cases(),
        // Shrunk counterexamples are reported in the failure; don't write
        // regression files into the source tree.
        failure_persistence: None,
        // A case is slow (git and murk processes per step), but a shrunk
        // sequence is what makes a failure readable.
        max_shrink_iters: 512,
        ..Config::default()
    };
    // Build the fixture outside the runner so a setup failure reads as one.
    std::sync::LazyLock::force(&FIXTURE);
    let failures: Vec<String> = known_sequences()
        .into_iter()
        .filter_map(|(name, script)| {
            let result = run_scripted(&script);
            println!("known sequence: {name}: {result:?}");
            result
                .err()
                .map(|e| format!("{name}:\n  {script:?}\n  {e}"))
        })
        .collect();
    let mut runner = TestRunner::new(config);
    let result = runner.run(&proptest::collection::vec(op(), 1..=12), |ops| {
        run_sequence(&ops, None)
    });
    let mut report = failures;
    if let Err(e) = result {
        report.push(format!("random sequences: {e}"));
    }
    assert!(report.is_empty(), "{}", report.join("\n\n"));
}

/// The attacker's (or a vouching member's) own code against the library:
/// decrypt a vault they can open, change it, save it with a fresh MAC and
/// their signature, and optionally re-sign it as a recipient whose registry
/// entry holds a key they control. Run in a child process by
/// [`World::forge`]; prints `FORGE-OK` or `FORGE-SKIP`.
#[test]
#[ignore = "spawned by trust_invariants_hold_across_machines"]
fn forge_child() {
    use std::env::var;
    let (Ok(input), Ok(output), Ok(key)) = (var("FORGE_IN"), var("FORGE_OUT"), var("FORGE_KEY"))
    else {
        return;
    };
    let skip = |why: &str| {
        println!("FORGE-SKIP {why}");
        std::process::exit(0);
    };
    fs::copy(&input, &output).unwrap();
    let identity = murk_cli::crypto::parse_identity(&key).unwrap();
    let mut vault = murk_cli::read_vault(&output).unwrap();
    let Ok(original) = murk_cli::decrypt_vault(&vault, &identity) else {
        skip("cannot open this vault");
        return;
    };
    let mut current = original.clone();
    if let Ok(kv) = var("FORGE_VALUE") {
        let (k, v) = kv.split_once('=').unwrap();
        murk_cli::add_secret(&mut vault, &mut current, k, v, None, None, false, &[], None);
    }
    if let Ok(spec) = var("FORGE_AUTHORIZE") {
        let (pk, name) = spec.split_once(' ').unwrap();
        if !vault.recipients.iter().any(|r| r == pk) {
            vault.recipients.push(pk.to_string());
        }
        current.recipients.insert(pk.to_string(), name.to_string());
    }
    if let Ok(generation) = var("FORGE_GEN") {
        // The save moves the counter one past this (saturating).
        vault.generation = generation.parse::<u64>().unwrap();
    }
    unsafe {
        std::env::set_var("MURK_KEY", &key);
        std::env::set_var("MURK_NO_SIGNER_PIN", "1");
    }
    if let Err(e) = murk_cli::save_vault(&output, &mut vault, &original, &current) {
        skip(&format!("save refused: {e}"));
    }
    // A registry entry is planted in the meta directly, as the attacker's own
    // code would: murk's save refuses to write some keys (weak ones), and the
    // point is what a loader does with them. The meta is re-encrypted to the
    // vault's non-grant recipients and the vault re-signed by this key.
    if let Ok(spec) = var("FORGE_REGISTRY") {
        let (pk, vk) = spec.split_once('=').unwrap();
        current.signers.insert(pk.to_string(), vk.to_string());
        let mut vault = murk_cli::read_vault(&output).unwrap();
        let mut meta = murk_cli::decrypt_meta(&vault, &identity)
            .unwrap()
            .expect("the writer opens the meta it wrote");
        meta.signers.insert(pk.to_string(), vk.to_string());
        let grants: BTreeSet<&str> = meta.grants.values().map(|g| g.pubkey.as_str()).collect();
        let recipients: Vec<murk_cli::MurkRecipient> = vault
            .recipients
            .iter()
            .filter(|r| !grants.contains(r.as_str()))
            .map(|r| murk_cli::crypto::parse_recipient(r).unwrap())
            .collect();
        vault.meta =
            murk_cli::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
        vault.sig = None;
        let mut message = b"murk.vault.sig.v2\n".to_vec();
        serde_json::to_writer(&mut message, &vault).unwrap();
        vault.sig = Some(murk_cli::types::VaultSignature {
            signer: identity.pubkey_string().unwrap(),
            v: 2,
            sig: identity.signing_key().unwrap().sign(&message),
        });
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    if let Ok(how) = var("FORGE_SIGN_AS") {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        // The registry key to sign under, and how to sign a message.
        type Signer = Box<dyn Fn(&[u8]) -> String>;
        let (vk, sign): (String, Signer) = match how.strip_prefix("sock:") {
            Some(secret) => {
                let signing = murk_cli::crypto::parse_identity(secret)
                    .unwrap()
                    .signing_key()
                    .unwrap();
                (signing.verifying_key(), Box::new(move |m| signing.sign(m)))
            }
            // R = the identity point, s = 0: [s]B = R + [k]A holds for the
            // identity A whatever k (the message hash) is.
            None => (weak_vk_b64(), {
                let sig: Vec<u8> = WEAK_VK.iter().copied().chain([0u8; 32]).collect();
                let sig = b64.encode(sig);
                Box::new(move |_| sig.clone())
            }),
        };
        let Some(signer) = current
            .signers
            .iter()
            .find(|(_, v)| **v == vk)
            .map(|(pk, _)| pk.clone())
        else {
            skip("no recipient carries the planted key");
            return;
        };
        let mut vault = murk_cli::read_vault(&output).unwrap();
        vault.sig = None;
        let mut message = b"murk.vault.sig.v2\n".to_vec();
        serde_json::to_writer(&mut message, &vault).unwrap();
        vault.sig = Some(murk_cli::types::VaultSignature {
            signer,
            v: 2,
            sig: sign(&message),
        });
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    println!("FORGE-OK");
}
