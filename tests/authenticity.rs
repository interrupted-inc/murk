// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault authenticity against someone who can write the repository.
//!
//! Each attack builds a hostile `.murk` with only public information (the
//! victim's public key from the header) or a narrow credential (an agent
//! grant), drops it where the victim will load it, and checks that murk
//! refuses it instead of handing out the attacker's values. The legitimate
//! flows next to them must keep working.

use std::fs;
use std::path::{Path, PathBuf};

use predicates::prelude::*;
use tempfile::TempDir;
// Shared with the other suites; this one only needs `murk_bin`.
#[allow(dead_code)]
mod common;
use common::murk_bin;

/// One person's machine: a HOME of their own, working in `repo`.
struct Machine {
    home: PathBuf,
}

impl Machine {
    fn new(base: &Path, name: &str) -> Self {
        let home = base.join(format!("{name}-home"));
        fs::create_dir_all(&home).unwrap();
        Self { home }
    }

    /// `murk` run as this person in `dir`, with only their stored key.
    fn murk(&self, dir: &Path) -> assert_cmd::Command {
        let mut cmd = murk_bin(&self.home);
        cmd.current_dir(dir);
        cmd
    }

    /// The age key `murk init` stored for this person (there is one).
    fn key_file(&self) -> PathBuf {
        let dir = self.home.join(".config/murk/keys");
        fs::read_dir(dir).unwrap().next().unwrap().unwrap().path()
    }

    fn secret_key(&self) -> String {
        fs::read_to_string(self.key_file())
            .unwrap()
            .trim()
            .to_string()
    }

    fn pubkey(&self) -> String {
        let id: age::x25519::Identity = self.secret_key().parse().unwrap();
        id.to_public().to_string()
    }

    /// This person's trusted-signer entry, as `murk trust --print-key`
    /// prints it (`age1…:<verifying key>`), and their key fingerprint.
    fn signer_entry(&self, dir: &Path) -> (String, String) {
        let out = self
            .murk(dir)
            .env("MURK_KEY", self.secret_key())
            .args(["trust", "--print-key"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let entry = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let fp = String::from_utf8(out.stderr)
            .unwrap()
            .trim()
            .trim_start_matches("signing key ")
            .to_string();
        (entry, fp)
    }

    fn init(&self, dir: &Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        self.murk(dir)
            .arg("init")
            .write_stdin(format!("{name}\n"))
            .assert()
            .success();
    }

    fn add(&self, dir: &Path, key: &str, value: &str) {
        self.murk(dir)
            .args(["add", key])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .expect("spawn git")
}

fn git_ok(dir: &Path, args: &[&str]) {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn commit(dir: &Path, message: &str) {
    git_ok(dir, &["add", "-A"]);
    git_ok(
        dir,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", message],
    );
}

/// Alice's repo with a signed vault holding `DB_URL=prod-db`, as her machine
/// left it (pinned: she created and wrote it).
fn alice_repo(base: &Path) -> (Machine, PathBuf) {
    let alice = Machine::new(base, "alice");
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init", "-q", "-b", "main"]);
    alice.init(&repo, "alice");
    alice.add(&repo, "DB_URL", "prod-db");
    (alice, repo)
}

/// Mallory builds her own vault, lists `victims` as recipients (their public
/// keys are in the header), and fills in her values. Signed by Mallory.
fn mallory_vault(base: &Path, victims: &[(&str, String)], values: &[(&str, &str)]) -> PathBuf {
    let mallory = Machine::new(base, "mallory");
    let dir = base.join("forge");
    mallory.init(&dir, "mallory");
    for (name, pk) in victims {
        mallory
            .murk(&dir)
            .args(["circle", "authorize", pk, "--name", name])
            .assert()
            .success();
    }
    for (k, v) in values {
        mallory.add(&dir, k, v);
    }
    dir.join(".murk")
}

/// The same forgery with its signature stripped. The signature sits outside
/// the meta and the MAC does not cover it, so the MAC stays valid.
fn strip_signature(vault_path: &Path) {
    let mut vault: murk_cli::types::Vault =
        serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
    vault.sig = None;
    fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
}

/// Every secret-handing command refuses the vault in `repo` for `who`, and
/// none of them prints `poison`.
fn assert_refused_everywhere(who: &Machine, repo: &Path, poison: &str, reason: &str) {
    for args in [
        &["get", "DB_URL"][..],
        &["export"][..],
        &["export", "--json"][..],
        &["exec", "--", "sh", "-c", "echo $DB_URL"][..],
    ] {
        who.murk(repo)
            .args(args)
            .assert()
            .failure()
            .stdout(predicate::str::contains(poison).not())
            .stderr(predicate::str::contains(reason));
    }
}

// ── Unsigned forgery ──

/// A non-recipient builds an unsigned vault encrypted to Alice and replaces
/// `.murk`. On Alice's machine, which saw the vault signed, it is refused.
#[test]
fn unsigned_forgery_is_refused_on_a_machine_that_saw_the_vault_signed() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[
            ("DB_URL", "postgres://attacker"),
            ("LD_PRELOAD", "/tmp/evil.so"),
        ],
    );
    strip_signature(&forged);
    fs::copy(&forged, repo.join(".murk")).unwrap();

    assert_refused_everywhere(&alice, &repo, "attacker", "is now unsigned");
}

/// On a fresh clone there is no memory of a signature, and the unsigned
/// vault is still refused: Alice's key can sign, so unsigned is not normal.
#[test]
fn unsigned_forgery_is_refused_on_a_fresh_clone() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    strip_signature(&forged);
    fs::copy(&forged, repo.join(".murk")).unwrap();

    let laptop = Machine::new(base.path(), "alice-laptop");
    let mut cmd = laptop.murk(&repo);
    cmd.env("MURK_KEY_FILE", alice.key_file())
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("attacker").not())
        .stderr(predicate::str::contains("is unsigned"))
        .stderr(predicate::str::contains("git diff -- .murk"));
}

// ── Self-enrolment ──

/// Mallory lists her own key as a recipient and signs with it. Alice's
/// machine trusts only the signers it pinned, so the vault is refused — also
/// under MURK_STRICT — naming Mallory's key and the recipient she added.
#[test]
fn self_enrolled_signer_is_refused_on_a_pinned_machine() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();

    assert_refused_everywhere(&alice, &repo, "attacker", "not a trusted signer");
    alice
        .murk(&repo)
        .env("MURK_STRICT", "1")
        .env("MURK_KEY_FILE", alice.key_file())
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("signed by mallory"))
        .stderr(predicate::str::contains("recipient added: mallory"));
    // A write would re-sign Mallory's content as Alice: refused as well.
    alice
        .murk(&repo)
        .args(["add", "NEW_SECRET"])
        .write_stdin("for-alice-only\n")
        .assert()
        .failure();
}

/// On a fresh clone nothing is trusted yet: every command refuses until
/// `murk trust`, which shows the signer's actual key, not just its name.
#[test]
fn self_enrolled_signer_on_a_fresh_clone_waits_for_murk_trust() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let forged = mallory_vault(
        base.path(),
        // Mallory even calls herself "alice".
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();
    let mallory_pk = Machine {
        home: base.path().join("mallory-home"),
    }
    .pubkey();

    let laptop = Machine::new(base.path(), "alice-laptop");
    let run = |args: &[&str]| {
        let mut cmd = laptop.murk(&repo);
        cmd.env("MURK_KEY_FILE", alice.key_file()).args(args);
        cmd
    };
    run(&["get", "DB_URL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("not trusted on this machine yet"));
    // Without --yes and no terminal, trust only shows and stops.
    run(&["trust"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(&mallory_pk))
        .stderr(predicate::str::contains("needs confirmation"));
    run(&["get", "DB_URL"]).assert().failure();
}

// ── Merge laundering ──

/// An outsider's branch replaces the vault with one signed by their own key.
/// A keyed merge through the murk driver must record a conflict naming
/// theirs and never re-MAC or sign the result.
#[test]
fn merge_of_a_forged_theirs_is_a_conflict_and_never_signed() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let driver = assert_cmd::cargo::cargo_bin("murk");
    git_ok(
        &repo,
        &[
            "config",
            "merge.murk.driver",
            &format!("'{}' merge-driver %O %A %B %P", driver.display()),
        ],
    );
    fs::write(repo.join(".gitattributes"), ".murk merge=murk\n").unwrap();
    commit(&repo, "base");

    git_ok(&repo, &["checkout", "-q", "-b", "outsider"]);
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();
    commit(&repo, "tweak");

    git_ok(&repo, &["checkout", "-q", "main"]);
    alice.add(&repo, "LATE", "late");
    commit(&repo, "maintainer change");

    let mut merge = std::process::Command::new("git");
    merge
        .args([
            "-c",
            "commit.gpgsign=false",
            "merge",
            "--no-edit",
            "outsider",
        ])
        .current_dir(&repo)
        .env("HOME", &alice.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in common::MURK_CONTEXT_VARS {
        merge.env_remove(var);
    }
    let out = merge.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the merge must not complete: {stderr}"
    );
    assert!(
        stderr.contains("theirs failed its authenticity check"),
        "{stderr}"
    );
    // Whatever git left in the work tree, it is not served.
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .stdout(predicate::str::contains("attacker").not());
}

/// GitHub's web merge and merge queues never run the murk driver. A plain
/// textual merge of two diverged genuine vaults either conflicts (the meta
/// line differs on both sides) or, if git could combine it, fails the
/// integrity check — it is never served.
#[test]
fn a_merge_without_the_murk_driver_is_never_served() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    commit(&repo, "base");
    git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
    alice.add(&repo, "FEATURE", "f");
    commit(&repo, "feature");
    git_ok(&repo, &["checkout", "-q", "main"]);
    alice.add(&repo, "MAIN", "m");
    commit(&repo, "main");

    let out = git(
        &repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "merge",
            "--no-edit",
            "feature",
        ],
    );
    if out.status.success() {
        alice
            .murk(&repo)
            .args(["get", "FEATURE"])
            .assert()
            .failure();
        alice.murk(&repo).args(["verify"]).assert().failure();
    } else {
        // A textual conflict: the file holds conflict markers and is not a
        // vault at all.
        alice
            .murk(&repo)
            .args(["export"])
            .assert()
            .failure()
            .stdout("");
    }
}

// ── Rollback ──

/// Alice revokes Bob and rotates. Bob (revoked, still able to push) replaces
/// the vault with the older revision that lists him. It carries a valid
/// signature by Alice, but its counter is below what Alice's machine accepted
/// on this branch: refused, and Alice's next write never encrypts to Bob.
#[test]
fn rolled_back_vault_is_refused() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    let bob_dir = base.path().join("bob-scratch");
    bob.init(&bob_dir, "bob");
    alice
        .murk(&repo)
        .args(["circle", "authorize", &bob.pubkey(), "--name", "bob"])
        .assert()
        .success();
    commit(&repo, "v1: bob");

    alice
        .murk(&repo)
        .args(["circle", "revoke", "bob"])
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["rotate", "DB_URL"])
        .write_stdin("rotated\n")
        .assert()
        .success();
    commit(&repo, "v2: revoke bob");

    let old = git(&repo, &["show", "HEAD~1:.murk"]).stdout;
    fs::write(repo.join(".murk"), old).unwrap();
    commit(&repo, "bob: roll back");

    assert_refused_everywhere(&alice, &repo, "prod-db", "rolled back");
    alice
        .murk(&repo)
        .args(["add", "NEW_SECRET"])
        .write_stdin("x\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("rolled back"));
}

/// A deliberate revert is two steps: accept the older file with `murk trust`,
/// and the next save is numbered past everything teammates accepted.
#[test]
fn deliberate_revert_via_murk_trust_then_save() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    commit(&repo, "v1");
    alice.add(&repo, "DB_URL", "oops");
    commit(&repo, "v2");
    let old = git(&repo, &["show", "HEAD~1:.murk"]).stdout;
    fs::write(repo.join(".murk"), old).unwrap();

    alice.murk(&repo).args(["get", "DB_URL"]).assert().failure();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");
}

// ── Grant forgery ──

/// An agent grant key, with custom code against the library: it drops its
/// own grant record, renames itself "alice-laptop", adds a recipient and
/// swaps DATABASE_URL, then re-MACs and signs as a plain recipient. Alice's
/// machine has seen the grant key and never trusts it to sign.
#[test]
fn grant_key_that_drops_its_grant_and_signs_is_refused() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    alice.add(&repo, "SENTRY_DSN", "sentry");
    let grant_key = base.path().join("bot.key");
    alice
        .murk(&repo)
        .args([
            "agent",
            "grant",
            "--name",
            "bot",
            "--only",
            "SENTRY_DSN",
            "--out",
        ])
        .arg(&grant_key)
        .assert()
        .success();
    // Alice's machine loads the vault with the grant in it.
    alice.murk(&repo).args(["get", "DB_URL"]).assert().success();
    let evil = Machine::new(base.path(), "evil");
    evil.init(&base.path().join("evil"), "evil");

    // The forgery, run in a child so its environment stays its own.
    let forge = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "grant_forgery_child", "--nocapture", "--ignored"])
        .env("FORGE_VAULT", repo.join(".murk"))
        .env("FORGE_GRANT_KEY", &grant_key)
        .env("FORGE_ADD", evil.pubkey())
        .env("HOME", base.path().join("bot-home"))
        .output()
        .unwrap();
    assert!(
        forge.status.success(),
        "{}{}",
        String::from_utf8_lossy(&forge.stdout),
        String::from_utf8_lossy(&forge.stderr)
    );

    assert_refused_everywhere(&alice, &repo, "attacker", "agent grant");
    alice
        .murk(&repo)
        .env("MURK_STRICT", "1")
        .env("MURK_KEY_FILE", alice.key_file())
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stdout("");
    alice.murk(&repo).args(["verify"]).assert().failure();
}

/// The grant holder's custom code (spawned by the test above).
#[test]
#[ignore = "run by grant_key_that_drops_its_grant_and_signs_is_refused"]
fn grant_forgery_child() {
    let vault_path = std::env::var("FORGE_VAULT").unwrap();
    let grant_key = std::env::var("FORGE_GRANT_KEY").unwrap();
    let key_text = fs::read_to_string(&grant_key).unwrap();
    let key: String = key_text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap()
        .to_string();
    let identity = murk_cli::crypto::parse_identity(&key).unwrap();
    let grant_pk = identity.pubkey_string().unwrap();

    // The grant can't read the meta at all: no MAC key, names, groups or
    // signers to forge from. All it has is its own view from a load.
    let on_disk = murk_cli::read_vault(&vault_path).unwrap();
    assert!(
        murk_cli::decrypt_meta(&on_disk, &identity)
            .unwrap()
            .is_none()
    );
    unsafe { std::env::set_var("MURK_KEY", &key_text) };
    let (mut vault, mut original, _) = murk_cli::load_vault(&vault_path).unwrap();
    // Raw tooling never runs murk's read-only gate for grants; pose as an
    // operator so the library save stands in for it.
    original.loaded_by = None;
    original.loaded_as_grant = false;
    original.grants.clear();
    let mut current = original.clone();
    current
        .recipients
        .insert(grant_pk.clone(), "alice-laptop".into());
    let added = std::env::var("FORGE_ADD").unwrap();
    vault.recipients.push(added);
    current.values.insert(
        "DB_URL".into(),
        zeroize::Zeroizing::new("postgres://attacker".into()),
    );
    // The agent knows its scoped values, so it re-shares them to everyone;
    // murk's save would refuse to carry an unreadable value to a new
    // recipient, and every other value is unreadable to it: drop them.
    for (k, by_pk) in &original.private {
        if let Some(v) = by_pk.get(&grant_pk) {
            current.values.insert(k.clone(), v.clone());
        }
    }
    vault.secrets.retain(|k, _| current.values.contains_key(k));
    // save_vault signs with MURK_KEY and computes a fresh MAC.
    murk_cli::save_vault(&vault_path, &mut vault, &original, &current).unwrap();
}

// ── Recipient aliasing ──

/// A second spelling of a key (bech32 is case-insensitive) would survive
/// `circle revoke` and keep reading rotated values. It is refused when added,
/// and a vault carrying one fails to load.
#[test]
fn a_second_spelling_of_a_recipient_key_is_refused() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    alice
        .murk(&repo)
        .args(["circle", "authorize", &bob.pubkey(), "--name", "bob"])
        .assert()
        .success();
    alice
        .murk(&repo)
        .args([
            "circle",
            "authorize",
            &bob.pubkey().to_uppercase(),
            "--name",
            "bob-alias",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already a recipient"));

    // Hand-edited alias in the header: the vault does not load.
    let path = repo.join(".murk");
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    json["recipients"]
        .as_array_mut()
        .unwrap()
        .push(bob.pubkey().to_uppercase().into());
    fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "duplicate of an earlier recipient",
        ));
}

/// `murk diff` is the review step the refusal points at: it runs on the
/// refused vault and shows the recipient Mallory added and the signer change,
/// not only the values.
#[test]
fn diff_shows_the_added_recipient_and_the_new_signer() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    commit(&repo, "base");
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();

    alice
        .murk(&repo)
        .args(["diff", "HEAD"])
        .assert()
        .success()
        .stdout(predicate::str::contains("+ recipient mallory"))
        .stdout(predicate::str::contains("~ signer alice"))
        .stdout(predicate::str::contains("~ DB_URL"))
        .stderr(predicate::str::contains("not trusted on this machine"));
}

/// A forged revision in history is never decrypted or shown: Alice's machine
/// has a pin, so a revision signed by a stranger fails like a forged working
/// vault would, instead of being diffed against.
#[test]
fn diff_refuses_a_forged_revision() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let genuine = fs::read(repo.join(".murk")).unwrap();
    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();
    commit(&repo, "forged");
    fs::write(repo.join(".murk"), genuine).unwrap();
    // A revision is checked against the trust pin, never recorded in it.
    let pins = || {
        let mut all: Vec<(PathBuf, Vec<u8>)> =
            fs::read_dir(alice.home.join(".config/murk/signer-pins"))
                .unwrap()
                .map(|e| {
                    let path = e.unwrap().path();
                    let bytes = fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect();
        all.sort();
        all
    };
    let pinned = pins();

    for args in [
        &["diff", "HEAD"][..],
        &["diff", "HEAD", "--show-values", "--json"][..],
    ] {
        alice
            .murk(&repo)
            .args(args)
            .assert()
            .failure()
            .stdout("")
            .stderr(predicate::str::contains(
                "failed verification, so it is not shown",
            ))
            .stderr(predicate::str::contains("attacker").not());
    }
    assert_eq!(pins(), pinned, "diff must not change the trust pin");
}

// ── Legitimate flows ──

/// An ssh-rsa key (like a hardware/plugin key) cannot sign. Its user still
/// verifies signed vaults, and works with a vault it wrote unsigned, with a
/// warning. A teammate whose machine saw the vault signed refuses that
/// unsigned write until they review it and `murk trust` re-signs it.
#[test]
fn a_key_that_cannot_sign_gets_the_warning_path() {
    const RSA_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA5jkmGpN5TpKvfi9DRPmuKqW0wW1gVy8ZS/ShQ1rhBeVsHf7v+1aM
yH/c4nkmE5LyH3OVDURX5mkdbKPCwwa8DvIkzzP8XO+VBd0U3tz/Xug0pLToqDM8Bd7JAr
BXGAX+78RlDrRkCFf4xMS0sZOMcIN7hyK5NeIoye4dThmgSConD/lk6/Hd5ahvvIMRAJVI
x4AUMnVAEzOF7lVbMWI9vPaUeCnggOjUxKr1n7n55bjtCzDG/AcVijE7WZZ0tC2u5lTS/Y
fLtsa54ZfF6koVUZuiztHdva86CFqopmqKIkzcB7uUYawz18eL7ad2tcIjOClnBAOd4JqO
WcrVukeGEQAAA8BCAaNiQgGjYgAAAAdzc2gtcnNhAAABAQDmOSYak3lOkq9+L0NE+a4qpb
TBbWBXLxlL9KFDWuEF5Wwd/u/7VozIf9zieSYTkvIfc5UNRFfmaR1so8LDBrwO8iTPM/xc
75UF3RTe3P9e6DSktOioMzwF3skCsFcYBf7vxGUOtGQIV/jExLSxk4xwg3uHIrk14ijJ7h
1OGaBIKicP+WTr8d3lqG+8gxEAlUjHgBQydUATM4XuVVsxYj289pR4KeCA6NTEqvWfufnl
uO0LMMb8BxWKMTtZlnS0La7mVNL9h8u2xrnhl8XqShVRm6LO0d29rzoIWqimaooiTNwHu5
RhrDPXx4vtp3a1wiM4KWcEA53gmo5ZytW6R4YRAAAAAwEAAQAAAQATOAwdRdhnnck2sH1e
IbXPa5vmVdooDQ+AjsBznf+Q/XEEJAcmpTgFeN8YrOJn2emKhJyZye3Il1fUfOtCWqqSWN
aH0aAspfd70NPwMuTCqIHUiiGuAPDu0IVZSx1KLR32KCADlT2QkL98tasb8+RSdDd4tYZe
oC2lhdI+ddcyjuG+ZS2FJ9dcBAeVb9J6MWH+PFyiisrY51MZDT5xFZcB7jtTtJitWympWz
OtISSTyvIwMpbmwLDcVfK1Gs+n0MrxHJxpXblycg/fASo2muJaOHdpxouu+CUXIK3+pozJ
MHfDm3Xly34PVZefn2Ykwag+aHhlcevhVUZz5AFa7JFNAAAAgQCea2fencESK6AwmQl18u
yZTZDSk1vDWsUl+9oNAvmkL0yteuU3f9VsttC2wjtJ+tYE5M/rUBf/PirEqKCHEKzo/1ag
67mIhkGBzHQYviZdfzxKbkUW/+4DJ82nxbaeyRfMatmIs7sLSCGLY1N9oiUicAqsiIbiG6
OvINjmXinvGgAAAIEA+LJ8tuKlCWu0p8BX/R3fQW8BBVk8TcZVn7Dnf4Ssu6U+tjIuK8a3
mHIuqiTYMrR58u3WUHxsje5N/V/He2Je1HW7YCa1htX+4Gk4ypcwXZDhzmT8B/U8XHvkdx
UUl4thRvTUEZkUEJUzUSYts0s4MEwHw1tEL/E+KrHUpoTXVtMAAACBAOz7yeQQ0RZdz90R
BMJHggiseL9CcCSdtzPBycgZo8UHJIH0kYRAujIM6XWfzzcfTNQQ3slZ9Ht9D4Fmn3G7uX
sI+cTp5/1HL1bGywPCCkdCcTm1CEFtfiO5ZJgS7LELv5mP+CUv8KDnuZJdNaUWanUwUiwD
+kddyH0+YIgSBSkLAAAAB2h3QHRlc3QBAgM=
-----END OPENSSH PRIVATE KEY-----
";
    const RSA_PK: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmOSYak3lOkq9+L0NE+a4qpbTBbWBXLxlL9KFDWuEF5Wwd/u/7VozIf9zieSYTkvIfc5UNRFfmaR1so8LDBrwO8iTPM/xc75UF3RTe3P9e6DSktOioMzwF3skCsFcYBf7vxGUOtGQIV/jExLSxk4xwg3uHIrk14ijJ7h1OGaBIKicP+WTr8d3lqG+8gxEAlUjHgBQydUATM4XuVVsxYj289pR4KeCA6NTEqvWfufnluO0LMMb8BxWKMTtZlnS0La7mVNL9h8u2xrnhl8XqShVRm6LO0d29rzoIWqimaooiTNwHu5RhrDPXx4vtp3a1wiM4KWcEA53gmo5ZytW6R4YR hw@test";

    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    alice
        .murk(&repo)
        .args([
            "circle",
            "authorize",
            RSA_PK,
            "--name",
            "hw",
            "--allow-ssh-rsa",
        ])
        .assert()
        .success();
    let hw = Machine::new(base.path(), "hw");
    let key_file = base.path().join("hw_rsa");
    fs::write(&key_file, RSA_SK).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let as_hw = || {
        let mut cmd = hw.murk(&repo);
        cmd.env("MURK_KEY_FILE", &key_file);
        cmd
    };

    // The vault is signed by Alice: the hw user checks that like anyone else.
    as_hw().args(["get", "DB_URL"]).assert().failure();
    as_hw().args(["trust", "--yes"]).assert().success();
    as_hw()
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");

    // Their write is unsigned; their own machine keeps working, with a warning.
    as_hw()
        .args(["add", "FROM_HW"])
        .write_stdin("hw\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("written unsigned"));
    as_hw()
        .args(["get", "FROM_HW"])
        .assert()
        .success()
        .stdout("hw\n")
        .stderr(predicate::str::contains(
            "vault is unsigned and your key cannot sign",
        ));

    // Alice saw it signed: refused until she reviews and re-signs it.
    alice
        .murk(&repo)
        .args(["get", "FROM_HW"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is now unsigned"));
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success()
        .stderr(predicate::str::contains("signed .murk"));
    alice
        .murk(&repo)
        .args(["get", "FROM_HW"])
        .assert()
        .success()
        .stdout("hw\n");
}

/// Alice authorizes Bob. Bob's first write registers his signing key himself,
/// so nothing vouches for it yet: Alice's machine shows its fingerprint and
/// waits for `murk trust` (trust on first use). Once confirmed, Bob's writes
/// load, and Alice's next write vouches for his key to everyone else.
#[test]
fn a_new_members_first_write_waits_for_key_confirmation() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    alice
        .murk(&repo)
        .args(["circle", "authorize", &bob.pubkey(), "--name", "bob"])
        .assert()
        .success();

    // Bob's machine trusts the vault once, then writes.
    bob.murk(&repo)
        .env("MURK_KEY_FILE", bob.key_file())
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.murk(&repo)
        .env("MURK_KEY_FILE", bob.key_file())
        .args(["add", "FROM_BOB"])
        .write_stdin("hi\n")
        .assert()
        .success();

    let (_, bob_fp) = bob.signer_entry(&repo);
    alice
        .murk(&repo)
        .args(["get", "FROM_BOB"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("has not confirmed yet"))
        .stderr(predicate::str::contains(&bob_fp));
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success()
        .stderr(predicate::str::contains(&bob_fp))
        .stderr(predicate::str::contains("trust on first use"));
    alice
        .murk(&repo)
        .args(["get", "FROM_BOB"])
        .assert()
        .success()
        .stdout("hi\n");

    // Alice writes: her signed vault carries Bob's key, so a fresh machine
    // that confirms Alice learns Bob's key without another prompt.
    alice.add(&repo, "FROM_ALICE", "x");
    let carol = Machine::new(base.path(), "carol");
    carol
        .murk(&repo)
        .env("MURK_KEY", alice.secret_key())
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.murk(&repo)
        .env("MURK_KEY_FILE", bob.key_file())
        .args(["add", "AGAIN"])
        .write_stdin("y\n")
        .assert()
        .success();
    carol
        .murk(&repo)
        .env("MURK_KEY", alice.secret_key())
        .args(["get", "AGAIN"])
        .assert()
        .success()
        .stdout("y\n");
}

/// Before Bob ever writes, Mallory forges a "first write by Bob": she
/// registers her own signing key under Bob's public key and signs as Bob.
/// Alice's machine cannot tell this from Bob's real first write, so it
/// refuses it and shows the fingerprint, which is Mallory's, not Bob's.
#[test]
fn a_forged_first_write_under_a_new_members_name_is_refused() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    alice
        .murk(&repo)
        .args(["circle", "authorize", &bob.pubkey(), "--name", "bob"])
        .assert()
        .success();

    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey()), ("bob", bob.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    let mallory = Machine {
        home: base.path().join("mallory-home"),
    };
    let mallory_id = murk_cli::crypto::parse_identity(&mallory.secret_key()).unwrap();
    let mallory_sk = mallory_id.signing_key().unwrap();
    let mut vault: murk_cli::types::Vault =
        serde_json::from_str(&fs::read_to_string(&forged).unwrap()).unwrap();
    let mut meta = murk_cli::decrypt_meta(&vault, &mallory_id)
        .unwrap()
        .unwrap();
    meta.signers = [(bob.pubkey(), mallory_sk.verifying_key())].into();
    let recipients: Vec<murk_cli::MurkRecipient> = vault
        .recipients
        .iter()
        .map(|r| murk_cli::crypto::parse_recipient(r).unwrap())
        .collect();
    vault.meta = murk_cli::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
    vault.sig = None;
    let mut msg = b"murk.vault.sig.v2\n".to_vec();
    msg.extend(serde_json::to_vec(&vault).unwrap());
    vault.sig = Some(murk_cli::types::VaultSignature {
        signer: bob.pubkey(),
        v: 2,
        sig: mallory_sk.sign(&msg),
    });
    fs::write(
        repo.join(".murk"),
        serde_json::to_string_pretty(&vault).unwrap(),
    )
    .unwrap();

    assert_refused_everywhere(&alice, &repo, "attacker", "has not confirmed yet");
    let (_, bob_fp) = bob.signer_entry(&repo);
    let (_, mallory_fp) = mallory.signer_entry(&repo);
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(&mallory_fp))
        .stderr(predicate::str::contains(&bob_fp).not());
}

/// A real unencrypted ssh-ed25519 keypair (test-only), for a teammate whose
/// key is ssh-ed25519 and so carries its own verifying key.
const SSH_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----\n";
const SSH_PK: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

/// Write `SSH_SK` to an owner-only key file under `base`.
fn ssh_key_file(base: &Path, name: &str) -> PathBuf {
    let key = base.join(name);
    fs::write(&key, SSH_SK).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    key
}

/// The main onboarding path. Alice (trusted, age key) runs `circle authorize
/// github:bob`; Bob's GitHub key is ssh-ed25519, which carries its own
/// verifying key. Carol, who already trusts the vault with Alice as a signer,
/// loads Alice's write without a prompt, and her pin now trusts Bob as a
/// signer. Bob on a fresh clone is refused until `murk trust`, then works,
/// and his signed change loads on Carol's machine with no confirmation step.
#[test]
fn github_onboarding_extends_trust_to_the_new_member() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());

    // Carol is on the team already and trusts the vault as Alice left it.
    let carol = Machine::new(base.path(), "carol");
    carol.init(&base.path().join("carol-scratch"), "carol");
    alice
        .murk(&repo)
        .args(["circle", "authorize", &carol.pubkey(), "--name", "carol"])
        .assert()
        .success();
    let as_carol = |args: &[&str]| {
        let mut cmd = carol.murk(&repo);
        cmd.env("MURK_KEY_FILE", carol.key_file()).args(args);
        cmd
    };
    as_carol(&["trust", "--yes"]).assert().success();

    // Alice authorizes Bob from GitHub (served from a fixture, not the network).
    let keys = base.path().join("github-keys");
    fs::create_dir_all(&keys).unwrap();
    fs::write(keys.join("bob.keys"), format!("{SSH_PK}\n")).unwrap();
    alice
        .murk(&repo)
        .env("MURK_TEST_GITHUB_KEYS_DIR", &keys)
        .args(["circle", "authorize", "github:bob"])
        .assert()
        .success();

    // Carol loads Alice's write with no prompt, and now trusts Bob to sign.
    as_carol(&["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");
    let vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo.join(".murk")).unwrap()).unwrap();
    let pin: serde_json::Value = fs::read_dir(carol.home.join(".config/murk/signer-pins"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap())
        .find(|p: &serde_json::Value| p["vault_id"] == vault["vault_id"])
        .expect("Carol's pin for the team vault");
    let trusted: Vec<&str> = pin["trusted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert!(trusted.contains(&SSH_PK), "{trusted:?}");

    // Bob on a fresh clone: refused until he trusts it, then it works.
    let bob = Machine::new(base.path(), "bob");
    let key = base.path().join("bob_ed25519");
    fs::write(&key, SSH_SK).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let as_bob = |args: &[&str]| {
        let mut cmd = bob.murk(&repo);
        cmd.env("MURK_KEY_FILE", &key).args(args);
        cmd
    };
    as_bob(&["get", "DB_URL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("not trusted on this machine yet"));
    as_bob(&["trust", "--yes"]).assert().success();
    as_bob(&["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");

    // Bob's signed change loads on Carol's machine, no confirmation needed.
    as_bob(&["add", "FROM_BOB"])
        .write_stdin("hello\n")
        .assert()
        .success();
    as_carol(&["get", "FROM_BOB"])
        .assert()
        .success()
        .stdout("hello\n");
}

/// A CI runner has no pin. MURK_TRUSTED_SIGNERS (from a CI secret) names the
/// expected signers with their verifying keys: their vault loads, anyone
/// else's is refused, and so is a bare age key without its verifying key.
#[test]
fn ci_with_trusted_signers_from_the_environment() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let runner = Machine::new(base.path(), "runner");
    let ci = |signers: &str| {
        let mut cmd = runner.murk(&repo);
        cmd.env("MURK_KEY", alice.secret_key())
            .env("MURK_TRUSTED_SIGNERS", signers)
            .args(["get", "DB_URL"]);
        cmd
    };
    let (alice_entry, _) = alice.signer_entry(&repo);
    assert!(alice_entry.starts_with(&format!("{}:", alice.pubkey())));
    ci(&alice_entry).assert().success().stdout("prod-db\n");
    ci(&alice.pubkey())
        .assert()
        .failure()
        .stderr(predicate::str::contains("needs its verifying key"));

    let forged = mallory_vault(
        base.path(),
        &[("alice", alice.pubkey())],
        &[("DB_URL", "postgres://attacker")],
    );
    fs::copy(&forged, repo.join(".murk")).unwrap();
    ci(&alice_entry)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("not a trusted signer"));
    ci("not-a-key")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_TRUSTED_SIGNERS"));
}

// ── Reserved environment names ──

/// Keys that steer loaders, shells, git or murk itself are refused by
/// export and exec unless `--allow-reserved` is passed.
#[test]
fn reserved_names_are_refused_by_export_and_exec_unless_allowed() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    alice
        .murk(&repo)
        .args(["add", "GIT_SSH_COMMAND"])
        .write_stdin("touch pwned\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("reserved environment name"));

    for args in [
        &["export"][..],
        &["export", "--json"][..],
        &["exec", "--", "true"][..],
        &[
            "agent",
            "exec",
            "--allow-operator-key",
            "--only",
            "GIT_SSH_COMMAND",
            "--",
            "true",
        ][..],
    ] {
        alice
            .murk(&repo)
            .args(args)
            .assert()
            .failure()
            .stdout(predicate::str::contains("touch pwned").not())
            .stderr(predicate::str::contains("refusing to set GIT_SSH_COMMAND"));
    }
    alice
        .murk(&repo)
        .args(["export", "--allow-reserved"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GIT_SSH_COMMAND"));
    alice
        .murk(&repo)
        .args([
            "exec",
            "--allow-reserved",
            "--",
            "sh",
            "-c",
            "printf %s \"$GIT_SSH_COMMAND\"",
        ])
        .assert()
        .success()
        .stdout("touch pwned");
}

/// MURK_* names are reserved too: a vault must not switch off a nested
/// murk's strict mode or choose its trusted signers.
#[test]
fn a_vault_cannot_set_murk_settings() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    alice.add(&repo, "MURK_STRICT", "0");
    alice
        .murk(&repo)
        .args(["exec", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to set MURK_STRICT"));
}

// ── Rollback through a merge of 0.13-era history ──

const ROLLBACK_ALICE_KEY: &str = include_str!("fixtures/v0_13_rollback_alice.test-only.key");
const ROLLBACK_LEAKED: &str = include_str!("fixtures/v0_13_rollback_leaked.murk");
const ROLLBACK_ROTATED: &str = include_str!("fixtures/v0_13_rollback_rotated.murk");
const ROLLBACK_STAGING: &str = include_str!("fixtures/v0_13_rollback_staging.murk");

/// A repo whose `.murk` has 0.13-era history: `DB_URL` leaked, then rotated
/// (two alice-signed 0.13 revisions), the merge driver configured. A branch
/// `side` forks from the rotation commit and commits `side_file`, if given,
/// as `.murk`.
/// On `main`, alice then trusts the vault with 0.14 and saves (adds `EXTRA`).
/// Returns alice's machine, the repo and the path of her key file.
fn legacy_history_repo(base: &Path, side_file: Option<&str>) -> (Machine, PathBuf, PathBuf) {
    let alice = Machine::new(base, "alice");
    let key = base.join("alice.key");
    fs::write(&key, ROLLBACK_ALICE_KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init", "-q", "-b", "main"]);
    let driver = assert_cmd::cargo::cargo_bin("murk");
    git_ok(
        &repo,
        &[
            "config",
            "merge.murk.driver",
            &format!("'{}' merge-driver %O %A %B %P", driver.display()),
        ],
    );
    fs::write(repo.join(".gitattributes"), ".murk merge=murk\n").unwrap();
    fs::write(repo.join(".murk"), ROLLBACK_LEAKED).unwrap();
    commit(&repo, "0.13: DB_URL set (later leaked)");
    fs::write(repo.join(".murk"), ROLLBACK_ROTATED).unwrap();
    commit(&repo, "0.13: DB_URL rotated");

    git_ok(&repo, &["checkout", "-q", "-b", "side"]);
    if let Some(file) = side_file {
        fs::write(repo.join(".murk"), file).unwrap();
        commit(&repo, "side branch");
    }
    git_ok(&repo, &["checkout", "-q", "main"]);

    let as_alice = |args: &[&str]| {
        let mut cmd = alice.murk(&repo);
        cmd.env("MURK_KEY_FILE", &key).args(args);
        cmd
    };
    as_alice(&["trust", "--yes"]).assert().success();
    as_alice(&["add", "EXTRA"])
        .write_stdin("extra\n")
        .assert()
        .success();
    commit(&repo, "0.14: add EXTRA");
    (alice, repo, key)
}

/// `git merge side` as alice, with the driver; returns (success, stderr).
fn merge_side(alice: &Machine, repo: &Path, key: &Path) -> (bool, String) {
    let mut merge = std::process::Command::new("git");
    merge
        .args(["-c", "commit.gpgsign=false", "merge", "--no-edit", "side"])
        .current_dir(repo)
        .env("HOME", &alice.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in common::MURK_CONTEXT_VARS {
        merge.env_remove(var);
    }
    merge.env("MURK_KEY_FILE", key);
    let out = merge.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An attacker branch forks from the 0.13 rotation commit and commits the
/// older, leaked revision (genuinely signed by alice, public in history).
/// Merging it after the vault was saved by 0.14 must not roll `DB_URL` back.
#[test]
fn a_merge_cannot_roll_back_to_an_older_0_13_revision() {
    let base = TempDir::new().unwrap();
    let (alice, repo, key) = legacy_history_repo(base.path(), Some(ROLLBACK_LEAKED));
    let (merged, stderr) = merge_side(&alice, &repo, &key);
    assert!(!merged, "the merge must not complete: {stderr}");
    assert!(
        stderr.contains("theirs failed its authenticity check") && stderr.contains("0.13"),
        "{stderr}"
    );
    alice
        .murk(&repo)
        .env("MURK_KEY_FILE", &key)
        .args(["get", "DB_URL"])
        .assert()
        .stdout(predicate::str::contains("LEAKED").not());
}

/// The cross-vault variant: the attacker branch commits another 0.13 vault of
/// the team (same recipients, signed by a trusted teammate) as `.murk`.
#[test]
fn a_merge_cannot_substitute_another_0_13_vault() {
    let base = TempDir::new().unwrap();
    let (alice, repo, key) = legacy_history_repo(base.path(), Some(ROLLBACK_STAGING));
    let (merged, stderr) = merge_side(&alice, &repo, &key);
    assert!(!merged, "the merge must not complete: {stderr}");
    assert!(
        stderr.contains("theirs failed its authenticity check") && stderr.contains("0.13"),
        "{stderr}"
    );
    alice
        .murk(&repo)
        .env("MURK_KEY_FILE", &key)
        .args(["get", "DB_URL"])
        .assert()
        .stdout(predicate::str::contains("STAGING").not());
}

/// The legitimate case next to them: a branch forked in the 0.13 era and
/// saved by 0.14 since (by bob, on his machine) merges cleanly with a main
/// also saved by 0.14.
#[test]
fn branches_upgraded_separately_from_0_13_history_merge_cleanly() {
    const BOB_KEY: &str = include_str!("fixtures/v0_13_rollback_bob.test-only.key");
    let base = TempDir::new().unwrap();
    let (alice, repo, key) = legacy_history_repo(base.path(), None);
    let bob = Machine::new(base.path(), "bob");
    let bob_key = base.path().join("bob.key");
    fs::write(&bob_key, BOB_KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bob_key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    git_ok(&repo, &["checkout", "-q", "side"]);
    let as_bob = |args: &[&str]| {
        let mut cmd = bob.murk(&repo);
        cmd.env("MURK_KEY_FILE", &bob_key).args(args);
        cmd
    };
    as_bob(&["trust", "--yes"]).assert().success();
    as_bob(&["add", "FEATURE"])
        .write_stdin("feature\n")
        .assert()
        .success();
    commit(&repo, "0.14 on side: add FEATURE");
    git_ok(&repo, &["checkout", "-q", "main"]);
    let (merged, stderr) = merge_side(&alice, &repo, &key);
    assert!(merged, "{stderr}");
    for (k, v) in [
        ("DB_URL", "ROTATED-db-value\n"),
        ("EXTRA", "extra\n"),
        ("FEATURE", "feature\n"),
    ] {
        alice
            .murk(&repo)
            .env("MURK_KEY_FILE", &key)
            .args(["get", k])
            .assert()
            .success()
            .stdout(v);
    }
}

// ── Removal, registry adders, counters, history ──

impl Machine {
    /// `murk` run as this person in `dir` with the age key in `key` (another
    /// machine holding a key, or an attacker's second machine).
    fn with_key(&self, dir: &Path, key: &Path) -> assert_cmd::Command {
        let mut cmd = self.murk(dir);
        cmd.env("MURK_KEY_FILE", key);
        cmd
    }
}

/// Configure the murk merge driver in `repo` and commit everything.
fn use_merge_driver(repo: &Path) {
    let driver = assert_cmd::cargo::cargo_bin("murk");
    git_ok(
        repo,
        &[
            "config",
            "merge.murk.driver",
            &format!("'{}' merge-driver %O %A %B %P", driver.display()),
        ],
    );
    fs::write(repo.join(".gitattributes"), ".murk merge=murk\n").unwrap();
    commit(repo, "merge driver");
}

/// `git merge <branch>` in `repo` as `who` (their HOME, their stored key),
/// with the murk driver; returns (success, stderr).
fn git_merge(who: &Machine, repo: &Path, branch: &str) -> (bool, String) {
    let mut merge = std::process::Command::new("git");
    merge
        .args(["-c", "commit.gpgsign=false", "merge", "--no-edit", branch])
        .current_dir(repo)
        .env("HOME", &who.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in common::MURK_CONTEXT_VARS {
        merge.env_remove(var);
    }
    let out = merge.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Alice authorizes `who` under `name`.
fn authorize(alice: &Machine, repo: &Path, who: &Machine, name: &str) {
    alice
        .murk(repo)
        .args(["circle", "authorize", &who.pubkey(), "--name", name])
        .assert()
        .success();
}

fn generation_of(vault: &[u8]) -> u64 {
    let json: serde_json::Value = serde_json::from_slice(vault).unwrap();
    json["generation"].as_u64().unwrap()
}

/// Change the trust pin `who` keeps for the vault in `repo` (found by its
/// vault id): their own machine, which they control.
fn edit_pin(who: &Machine, repo: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo.join(".murk")).unwrap()).unwrap();
    let path = fs::read_dir(who.home.join(".config/murk/signer-pins"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.extension().is_some_and(|e| e == "json")
                && serde_json::from_str::<serde_json::Value>(&fs::read_to_string(p).unwrap())
                    .is_ok_and(|pin| pin["vault_id"] == vault["vault_id"])
        })
        .expect("a pin for the vault");
    let mut pin: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    edit(&mut pin);
    fs::write(&path, serde_json::to_string_pretty(&pin).unwrap()).unwrap();
}

/// Have `holder`'s machine number its next save `generation + 1`.
fn set_pin_generation(holder: &Machine, repo: &Path, generation: u64) {
    edit_pin(holder, repo, |pin| pin["generation"] = generation.into());
}

/// Re-sign the vault at `path` as `as_signer` with `holder`'s age signing key:
/// a valid signature by whoever holds the verifying key the registry gives
/// for `as_signer`.
fn resign_as(path: &Path, as_signer: &str, holder: &Machine) {
    let id = murk_cli::crypto::parse_identity(&holder.secret_key()).unwrap();
    let sk = id.signing_key().unwrap();
    let mut vault: murk_cli::types::Vault =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    vault.sig = None;
    let mut msg = b"murk.vault.sig.v2\n".to_vec();
    msg.extend(serde_json::to_vec(&vault).unwrap());
    vault.sig = Some(murk_cli::types::VaultSignature {
        signer: as_signer.to_string(),
        v: 2,
        sig: sk.sign(&msg),
    });
    fs::write(path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
}

/// Rule: removal is permanent in the pin. After machine A (Alice's) accepts a
/// vault that removes Bob, nothing re-trusts Bob there: an older revision
/// listing him (alice-signed) loaded from a branch, his own older signed
/// revision, a newer vault signed by his key and built from a revision older
/// than the removal, the same arriving as a merge side, and `murk trust`
/// that does not name him are all refused. Trust comes back only through a
/// newer vault from a trusted signer that re-adds him, or `murk trust
/// --re-add` naming his key.
#[test]
fn removal_is_permanent_on_the_machine_that_accepted_it() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    use_merge_driver(&repo);
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    let bob_key = bob.key_file();
    authorize(&alice, &repo, &bob, "bob");
    commit(&repo, "add bob");
    let with_bob = fs::read(repo.join(".murk")).unwrap();
    bob.with_key(&repo, &bob_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.with_key(&repo, &bob_key)
        .args(["add", "FROM_BOB"])
        .write_stdin("bob\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    commit(&repo, "bob writes");
    let by_bob = fs::read(repo.join(".murk")).unwrap();
    // A second machine of Alice's, which trusts the vault with Bob in it.
    let laptop = Machine::new(base.path(), "alice-laptop");
    let alice_key = alice.key_file();
    laptop
        .with_key(&repo, &alice_key)
        .args(["trust", "--yes"])
        .assert()
        .success();

    // Bob's own key on a second machine of his builds a newer vault from that
    // older revision, numbered far past anything Alice will have.
    let bob_attack = Machine::new(base.path(), "bob-attack");
    bob_attack
        .with_key(&repo, &bob_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    set_pin_generation(&bob_attack, &repo, 40);
    bob_attack
        .with_key(&repo, &bob_key)
        .args(["add", "BOB_LATE"])
        .write_stdin("bob-late\n")
        .assert()
        .success();
    let bob_late = fs::read(repo.join(".murk")).unwrap();
    git_ok(&repo, &["checkout", "--", ".murk"]);

    alice
        .murk(&repo)
        .args(["circle", "revoke", "bob"])
        .assert()
        .success();
    commit(&repo, "remove bob");
    // The laptop accepts the removal too.
    laptop
        .with_key(&repo, &alice_key)
        .args(["get", "DB_URL"])
        .assert()
        .success();

    // An older revision listing Bob, signed by Alice, loaded from a branch.
    git_ok(&repo, &["checkout", "-q", "-b", "replay"]);
    fs::write(repo.join(".murk"), &with_bob).unwrap();
    commit(&repo, "replay: bob listed");
    assert_refused_everywhere(&alice, &repo, "prod-db", "rolled back");
    // Bob's own older signed revision on that branch.
    fs::write(repo.join(".murk"), &by_bob).unwrap();
    commit(&repo, "replay: by bob");
    assert_refused_everywhere(&alice, &repo, "prod-db", "rolled back");
    // A newer vault signed by Bob's key, built from before the removal.
    fs::write(repo.join(".murk"), &bob_late).unwrap();
    commit(&repo, "replay: bob late");
    assert_refused_everywhere(&alice, &repo, "prod-db", "removed from this vault");
    alice
        .murk(&repo)
        .args(["get", "BOB_LATE"])
        .assert()
        .failure()
        .stdout("");
    // `murk trust` that does not name Bob refuses it.
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--re-add"));

    // The same vault arriving as a merge side (main moved on, so git runs
    // the driver rather than fast-forwarding).
    git_ok(&repo, &["checkout", "-q", "main"]);
    alice.add(&repo, "MAIN_LATER", "later");
    commit(&repo, "main moves on");
    let (merged, stderr) = git_merge(&alice, &repo, "replay");
    assert!(!merged, "the merge must not complete: {stderr}");
    assert!(
        stderr.contains("failed its authenticity check")
            && stderr.contains("removed from this vault"),
        "{stderr}"
    );
    git_ok(&repo, &["merge", "--abort"]);
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");

    // `murk trust` naming Bob re-adds him, on the machine that does so.
    git_ok(&repo, &["checkout", "-q", "replay"]);
    laptop
        .with_key(&repo, &alice_key)
        .args(["get", "BOB_LATE"])
        .assert()
        .failure();
    laptop
        .with_key(&repo, &alice_key)
        .args(["trust", "--yes", "--re-add", "bob"])
        .assert()
        .success();
    laptop
        .with_key(&repo, &alice_key)
        .args(["get", "BOB_LATE"])
        .assert()
        .success()
        .stdout("bob-late\n");
    git_ok(&repo, &["checkout", "-q", "main"]);

    // A trusted signer re-adding Bob in a newer vault is the normal way back.
    authorize(&alice, &repo, &bob, "bob");
    commit(&repo, "re-add bob");
    bob.with_key(&repo, &bob_key)
        .args(["add", "BACK"])
        .write_stdin("back\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["get", "BACK"])
        .assert()
        .success()
        .stdout("back\n");
}

/// Rule: a key-registry entry counts only while whoever added it is trusted.
/// Mallory, a trusted signer, registers her own signing key under Bob's name
/// before Bob ever signs; Alice's machine pins it on Mallory's word, and even
/// accepts a vault "signed by Bob" with it — which proves only that Mallory
/// holds that key. Once Alice removes Mallory, the entry stops counting: a
/// vault signed as Bob with Mallory's key is refused as unconfirmed. Alice's
/// own writes never vouch for the entry, so Carol, a third machine that
/// learns keys only from Alice's writes, refuses it too. And the binding is
/// dropped, not just ignored: Bob's real key is then confirmed with `murk
/// trust` like any first write, and his next write loads.
#[test]
fn a_registry_entry_stops_counting_once_whoever_added_it_is_removed() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    let mallory = Machine::new(base.path(), "mallory");
    mallory.init(&base.path().join("mallory-scratch"), "mallory");
    let mallory_key = mallory.key_file();
    let carol = Machine::new(base.path(), "carol");
    carol.init(&base.path().join("carol-scratch"), "carol");
    let carol_key = carol.key_file();
    authorize(&alice, &repo, &bob, "bob");
    authorize(&alice, &repo, &mallory, "mallory");
    authorize(&alice, &repo, &carol, "carol");
    // Carol, a third teammate, trusts the vault as Alice left it.
    carol
        .with_key(&repo, &carol_key)
        .args(["trust", "--yes"])
        .assert()
        .success();

    // Mallory's machine binds her signing key to Bob; her saves vouch for it.
    mallory
        .with_key(&repo, &mallory_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    let (entry, _) = mallory.signer_entry(&repo);
    let mallory_vk = entry.rsplit_once(':').unwrap().1.to_string();
    edit_pin(&mallory, &repo, |pin| {
        pin["signers"][bob.pubkey()] = mallory_vk.clone().into();
    });
    mallory
        .with_key(&repo, &mallory_key)
        .args(["add", "M1"])
        .write_stdin("m1\n")
        .assert()
        .success();
    alice.murk(&repo).args(["get", "M1"]).assert().failure();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();

    // Alice's next write must not vouch for the key Mallory bound to Bob,
    // or Carol would keep believing it on Alice's word after Mallory goes.
    alice.add(&repo, "A1", "a1");
    carol
        .with_key(&repo, &carol_key)
        .args(["get", "A1"])
        .assert()
        .success()
        .stdout("a1\n");

    // While Mallory is trusted, a vault "by Bob" under her key loads.
    mallory
        .with_key(&repo, &mallory_key)
        .args(["add", "M2"])
        .write_stdin("m2\n")
        .assert()
        .success();
    resign_as(&repo.join(".murk"), &bob.pubkey(), &mallory);
    alice
        .murk(&repo)
        .args(["get", "M2"])
        .assert()
        .success()
        .stdout("m2\n");
    let accepted = fs::read(repo.join(".murk")).unwrap();

    // Mallory prepares a later vault as Bob, numbered past the removal.
    set_pin_generation(&mallory, &repo, 40);
    mallory
        .with_key(&repo, &mallory_key)
        .args(["add", "EVIL"])
        .write_stdin("evil\n")
        .assert()
        .success();
    resign_as(&repo.join(".murk"), &bob.pubkey(), &mallory);
    let forged = fs::read(repo.join(".murk")).unwrap();
    fs::write(repo.join(".murk"), &accepted).unwrap();

    alice
        .murk(&repo)
        .args(["circle", "revoke", "mallory"])
        .assert()
        .success();
    let revoked = fs::read(repo.join(".murk")).unwrap();
    fs::write(repo.join(".murk"), &forged).unwrap();
    alice
        .murk(&repo)
        .args(["get", "EVIL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("has not confirmed yet"));
    // Carol accepts the removal, and is not fooled either.
    fs::write(repo.join(".murk"), &revoked).unwrap();
    carol
        .with_key(&repo, &carol_key)
        .args(["get", "A1"])
        .assert()
        .success();
    fs::write(repo.join(".murk"), &forged).unwrap();
    carol
        .with_key(&repo, &carol_key)
        .args(["get", "EVIL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("has not confirmed yet"));

    // Bob's real key is still confirmed the normal way: his first write
    // waits for `murk trust`, which pins his key in place of the dropped
    // binding, and his next write loads.
    fs::write(repo.join(".murk"), &revoked).unwrap();
    let bob_key = bob.key_file();
    bob.with_key(&repo, &bob_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.with_key(&repo, &bob_key)
        .args(["add", "BOB1"])
        .write_stdin("bob1\n")
        .assert()
        .success();
    let (_, bob_fp) = bob.signer_entry(&repo);
    alice
        .murk(&repo)
        .args(["get", "BOB1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(&bob_fp));
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.with_key(&repo, &bob_key)
        .args(["add", "BOB2"])
        .write_stdin("bob2\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["get", "BOB2"])
        .assert()
        .success()
        .stdout("bob2\n");
}

/// Rule: generations advance in bounded steps. A vault numbered more than
/// the bound above this machine's mark is refused until `murk trust`
/// accepts it on review.
#[test]
fn a_generation_jump_past_the_bound_waits_for_murk_trust() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let laptop = Machine::new(base.path(), "alice-laptop");
    let key = alice.key_file();
    laptop
        .with_key(&repo, &key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    let mark = generation_of(&fs::read(repo.join(".murk")).unwrap());
    set_pin_generation(&laptop, &repo, mark + 1_000_000);
    laptop
        .with_key(&repo, &key)
        .args(["add", "JUMP"])
        .write_stdin("jump\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["get", "JUMP"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("jumps from generation"));
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["get", "JUMP"])
        .assert()
        .success()
        .stdout("jump\n");
}

/// Rule: no vault near the top of the counter is ever accepted, so the
/// counter can't be pushed to where it stops increasing — not on a machine
/// with a mark, not by `murk trust`, not on a fresh machine.
#[test]
fn a_generation_near_the_u64_limit_is_refused_outright() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let laptop = Machine::new(base.path(), "alice-laptop");
    let key = alice.key_file();
    laptop
        .with_key(&repo, &key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    set_pin_generation(&laptop, &repo, u64::MAX - 1);
    laptop
        .with_key(&repo, &key)
        .args(["add", "TOP"])
        .write_stdin("top\n")
        .assert()
        .success();
    assert_eq!(
        generation_of(&fs::read(repo.join(".murk")).unwrap()),
        u64::MAX
    );
    alice
        .murk(&repo)
        .args(["get", "TOP"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("above the largest murk accepts"));
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .failure();
    let fresh = Machine::new(base.path(), "fresh");
    fresh
        .with_key(&repo, &key)
        .args(["trust", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("above the largest murk accepts"));
}

/// Rule: two different vaults with the same generation are a fork. Bob and
/// Alice both save from the same revision; once Alice's machine accepted her
/// save on `main`, Bob's save replacing it on `main` is refused. Merged with
/// the murk driver, the two saves combine normally.
#[test]
fn a_different_vault_with_the_accepted_generation_is_a_fork() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    use_merge_driver(&repo);
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    let bob_key = bob.key_file();
    authorize(&alice, &repo, &bob, "bob");
    bob.with_key(&repo, &bob_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.with_key(&repo, &bob_key)
        .args(["add", "FIRST"])
        .write_stdin("first\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    commit(&repo, "both trusted");

    bob.with_key(&repo, &bob_key)
        .args(["add", "FROM_BOB"])
        .write_stdin("bob\n")
        .assert()
        .success();
    let bobs = fs::read(repo.join(".murk")).unwrap();
    git_ok(&repo, &["checkout", "--", ".murk"]);
    alice.add(&repo, "FROM_ALICE", "alice");
    commit(&repo, "alice saves");
    assert_eq!(
        generation_of(&bobs),
        generation_of(&fs::read(repo.join(".murk")).unwrap())
    );

    fs::write(repo.join(".murk"), &bobs).unwrap();
    alice
        .murk(&repo)
        .args(["get", "FROM_BOB"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("forked"));

    git_ok(&repo, &["checkout", "--", ".murk"]);
    git_ok(&repo, &["checkout", "-q", "-b", "bob", "HEAD~1"]);
    fs::write(repo.join(".murk"), &bobs).unwrap();
    commit(&repo, "bob saves");
    git_ok(&repo, &["checkout", "-q", "main"]);
    let (merged, stderr) = git_merge(&alice, &repo, "bob");
    assert!(merged, "{stderr}");
    for (k, v) in [("FROM_BOB", "bob\n"), ("FROM_ALICE", "alice\n")] {
        alice
            .murk(&repo)
            .args(["get", k])
            .assert()
            .success()
            .stdout(v);
    }
}

/// Rule: reading history never adds trust. Dave was a member and was removed
/// before Alice's laptop first trusted the vault, so the laptop never saw
/// him. Reading the revision that lists him — on a detached HEAD, on a branch,
/// and through `murk diff` — leaves the laptop's trust as it was, so a later
/// vault signed by Dave is refused.
#[test]
fn reading_history_never_adds_trust() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let dave = Machine::new(base.path(), "dave");
    dave.init(&base.path().join("dave-scratch"), "dave");
    let dave_key = dave.key_file();
    authorize(&alice, &repo, &dave, "dave");
    dave.with_key(&repo, &dave_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    dave.with_key(&repo, &dave_key)
        .args(["add", "D1"])
        .write_stdin("d1\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    // Alice's write vouches for Dave's signing key.
    alice.add(&repo, "A1", "a1");
    commit(&repo, "dave vouched for");

    // Dave builds a later vault from that revision, numbered far ahead.
    let dave_attack = Machine::new(base.path(), "dave-attack");
    dave_attack
        .with_key(&repo, &dave_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    set_pin_generation(&dave_attack, &repo, 49);
    dave_attack
        .with_key(&repo, &dave_key)
        .args(["add", "EVIL"])
        .write_stdin("evil\n")
        .assert()
        .success();
    let forged = fs::read(repo.join(".murk")).unwrap();
    git_ok(&repo, &["checkout", "--", ".murk"]);

    alice
        .murk(&repo)
        .args(["circle", "revoke", "dave"])
        .assert()
        .success();
    commit(&repo, "remove dave");

    let laptop = Machine::new(base.path(), "alice-laptop");
    let key = alice.key_file();
    let on_laptop = |args: &[&str]| {
        let mut cmd = laptop.with_key(&repo, &key);
        cmd.args(args);
        cmd
    };
    on_laptop(&["trust", "--yes"]).assert().success();

    git_ok(&repo, &["checkout", "-q", "--detach", "HEAD~1"]);
    on_laptop(&["get", "A1"]).assert().success().stdout("a1\n");
    git_ok(&repo, &["checkout", "-q", "-b", "old"]);
    on_laptop(&["get", "A1"]).assert().success().stdout("a1\n");
    git_ok(&repo, &["checkout", "-q", "main"]);
    on_laptop(&["diff", "HEAD~1"]).assert().success();

    fs::write(repo.join(".murk"), &forged).unwrap();
    on_laptop(&["get", "EVIL"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("not a trusted signer"));
}

/// Rule: merge sides follow removal. After Alice's machine accepts Bob's
/// removal on main, merging on a branch it has no record of, whose commit is
/// not in main's history (so it may be a replay): two branches forked while
/// Bob was a member and saved before his removal still list him, and merging
/// them must not keep him, since neither re-adds him in a newer revision. And
/// an older alice-signed revision that adds Bob, committed on a branch forked
/// from before he was added, is refused as a rollback (both sides add Bob, so
/// the recipient merge itself sees no conflict). On f1, a branch this machine
/// accepted before the removal, Bob is still a member and the same merge goes
/// through.
#[test]
fn a_merge_side_never_brings_a_removed_recipient_back() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    use_merge_driver(&repo);
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    authorize(&alice, &repo, &bob, "bob");
    commit(&repo, "add bob");
    let with_bob = fs::read(repo.join(".murk")).unwrap();
    for branch in ["f1", "f2"] {
        git_ok(&repo, &["checkout", "-q", "-b", branch, "main"]);
        alice.add(&repo, &branch.to_uppercase(), branch);
        commit(&repo, branch);
    }
    git_ok(&repo, &["checkout", "-q", "main"]);
    alice
        .murk(&repo)
        .args(["circle", "revoke", "bob"])
        .assert()
        .success();
    commit(&repo, "remove bob");

    git_ok(&repo, &["checkout", "-q", "-b", "review", "f1"]);
    let (merged, stderr) = git_merge(&alice, &repo, "f2");
    assert!(!merged, "the merge must not complete: {stderr}");
    assert!(stderr.contains("neither side re-adds them"), "{stderr}");
    git_ok(&repo, &["merge", "--abort"]);
    git_ok(&repo, &["checkout", "-q", "f1"]);
    git_ok(&repo, &["branch", "-D", "review"]);

    git_ok(&repo, &["checkout", "-q", "-b", "side", "main~2"]);
    fs::write(repo.join(".murk"), &with_bob).unwrap();
    commit(&repo, "replay the revision that added bob");
    git_ok(&repo, &["checkout", "-q", "-b", "review", "f1"]);
    let (merged, stderr) = git_merge(&alice, &repo, "side");
    assert!(!merged, "the merge must not complete: {stderr}");
    // Both sides are older revisions that add Bob relative to the ancestor.
    assert!(
        stderr.contains("failed its authenticity check")
            && stderr.contains("rolled back: it adds bob"),
        "{stderr}"
    );
    git_ok(&repo, &["merge", "--abort"]);

    git_ok(&repo, &["checkout", "-q", "f1"]);
    let (merged, stderr) = git_merge(&alice, &repo, "f2");
    assert!(merged, "{stderr}");
}

/// Rule: a save never writes a removed recipient back where the removal
/// applies. Alice's machine recorded Bob's removal on main; her working vault
/// is then an older revision that still lists him — main reset to the tip
/// she pulled before the removal, a detached HEAD, or the file itself. `murk
/// add` refuses and tells her to update to the vault that removed him,
/// writing nothing; re-authorizing Bob explicitly on the current vault works.
#[test]
fn a_save_over_an_older_revision_never_writes_a_removed_recipient_back() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    authorize(&alice, &repo, &bob, "bob");
    commit(&repo, "add bob");
    alice
        .murk(&repo)
        .args(["circle", "revoke", "bob"])
        .assert()
        .success();
    commit(&repo, "remove bob");

    let older = git(&repo, &["show", "HEAD~1:.murk"]).stdout;
    let refuse_save = || {
        alice
            .murk(&repo)
            .args(["add", "NEW"])
            .write_stdin("new\n")
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "update to the vault that removed them",
            ));
        assert_eq!(
            fs::read(repo.join(".murk")).unwrap(),
            older,
            "nothing written"
        );
    };
    let tip = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout).unwrap();
    git_ok(&repo, &["reset", "-q", "--hard", "HEAD~1"]);
    refuse_save();
    git_ok(&repo, &["reset", "-q", "--hard", tip.trim()]);
    git_ok(&repo, &["checkout", "-q", "--detach", "main~1"]);
    refuse_save();
    git_ok(&repo, &["checkout", "-q", "main"]);
    git_ok(&repo, &["checkout", "HEAD~1", "--", ".murk"]);
    refuse_save();

    git_ok(&repo, &["checkout", "HEAD", "--", ".murk"]);
    authorize(&alice, &repo, &bob, "bob");
    let header: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo.join(".murk")).unwrap()).unwrap();
    assert!(
        header["recipients"]
            .as_array()
            .unwrap()
            .contains(&bob.pubkey().into())
    );
}

/// Rule: a branch this machine has never accepted is only read, never
/// trusted. Bob, a trusted signer, opens a pull request that authorizes
/// Mallory. Alice checks it out, reads it, and rejects it. Mallory, who can
/// push to main but signs nothing on main, then takes the pull request's
/// vault (she is a recipient there), changes a value and commits it to main.
/// Alice's machine refuses it: reading the pull request did not trust Mallory.
#[test]
fn reading_a_pull_request_never_trusts_what_it_adds() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let bob = Machine::new(base.path(), "bob");
    bob.init(&base.path().join("bob-scratch"), "bob");
    let bob_key = bob.key_file();
    authorize(&alice, &repo, &bob, "bob");
    bob.with_key(&repo, &bob_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    bob.with_key(&repo, &bob_key)
        .args(["add", "FROM_BOB"])
        .write_stdin("bob\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    commit(&repo, "bob is a signer");

    git_ok(&repo, &["checkout", "-q", "-b", "pr"]);
    bob.with_key(&repo, &bob_key)
        .args(["circle", "authorize", SSH_PK, "--name", "mallory"])
        .assert()
        .success();
    commit(&repo, "pr: authorize mallory");
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");

    let mallory = Machine::new(base.path(), "mallory");
    let mallory_key = ssh_key_file(base.path(), "mallory_ed25519");
    mallory
        .with_key(&repo, &mallory_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    mallory
        .with_key(&repo, &mallory_key)
        .args(["add", "DB_URL"])
        .write_stdin("EVIL\n")
        .assert()
        .success();
    let forged = fs::read(repo.join(".murk")).unwrap();
    git_ok(&repo, &["checkout", "--", ".murk"]);
    git_ok(&repo, &["checkout", "-q", "main"]);
    fs::write(repo.join(".murk"), &forged).unwrap();
    commit(&repo, "mallory on main");

    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("EVIL").not())
        .stderr(predicate::str::contains("not a trusted signer"));
}

/// Rule: a removal applies where it happened. Alice revokes Carol on a
/// feature branch that is not merged yet. On main, which still lists Carol,
/// everything keeps working: Alice reads and writes, and Carol's own writes
/// load. On the feature branch, a replay of the vault that still listed
/// Carol is refused, and the message points at merging the removal first.
#[test]
fn a_removal_on_a_feature_branch_leaves_other_branches_working() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    let carol = Machine::new(base.path(), "carol");
    carol.init(&base.path().join("carol-scratch"), "carol");
    let carol_key = carol.key_file();
    authorize(&alice, &repo, &carol, "carol");
    // Alice's own signed vault that lists Carol, before Carol writes.
    let with_carol = fs::read(repo.join(".murk")).unwrap();
    carol
        .with_key(&repo, &carol_key)
        .args(["trust", "--yes"])
        .assert()
        .success();
    carol
        .with_key(&repo, &carol_key)
        .args(["add", "C1"])
        .write_stdin("c1\n")
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["trust", "--yes"])
        .assert()
        .success();
    commit(&repo, "carol is a member");

    git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
    alice
        .murk(&repo)
        .args(["circle", "revoke", "carol"])
        .assert()
        .success();
    commit(&repo, "revoke carol");

    git_ok(&repo, &["checkout", "-q", "main"]);
    alice
        .murk(&repo)
        .args(["get", "C1"])
        .assert()
        .success()
        .stdout("c1\n");
    alice.add(&repo, "MAIN2", "main2");
    commit(&repo, "main moves on");
    carol
        .with_key(&repo, &carol_key)
        .args(["add", "C2"])
        .write_stdin("c2\n")
        .assert()
        .success();
    commit(&repo, "carol writes on main");
    alice
        .murk(&repo)
        .args(["get", "C2"])
        .assert()
        .success()
        .stdout("c2\n");

    git_ok(&repo, &["checkout", "-q", "feature"]);
    alice
        .murk(&repo)
        .args(["get", "DB_URL"])
        .assert()
        .success()
        .stdout("prod-db\n");
    fs::write(repo.join(".murk"), &with_carol).unwrap();
    commit(&repo, "replay: carol listed");
    let out = alice.murk(&repo).args(["get", "DB_URL"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("rolled back"), "{stderr}");
    let merge_hint = stderr.find("merge the removal into this branch");
    let re_add_hint = stderr.find("--re-add");
    assert!(
        merge_hint.is_some_and(|m| re_add_hint.is_none_or(|r| m < r)),
        "the first fix offered is merging the removal: {stderr}"
    );
}

/// Rule: a removal applies where it happened, on one machine with no other
/// branch history. Alice creates the vault before `git init`, so main has
/// never been accepted on a branch. She revokes Carol and rotates X on branch
/// `theirs`, then revokes Carol on main as well, whose commit is still in
/// `theirs`' history from before the removal. Both revokes work, and the
/// keyed merge of the two goes through.
#[test]
fn both_branches_revoke_the_same_member_on_one_machine() {
    let base = TempDir::new().unwrap();
    let alice = Machine::new(base.path(), "alice");
    let repo = base.path().join("repo");
    alice.init(&repo, "alice");
    let carol = Machine::new(base.path(), "carol");
    carol.init(&base.path().join("carol-scratch"), "carol");
    authorize(&alice, &repo, &carol, "carol");
    for args in [
        &["group", "create", "ops"][..],
        &["generate", "X", "--group", "ops"],
    ] {
        alice.murk(&repo).args(args).assert().success();
    }
    git_ok(&repo, &["init", "-q", "-b", "main"]);
    use_merge_driver(&repo);

    git_ok(&repo, &["checkout", "-q", "-b", "theirs"]);
    alice
        .murk(&repo)
        .args(["circle", "revoke", "carol"])
        .assert()
        .success();
    alice
        .murk(&repo)
        .args(["rotate", "X", "--generate"])
        .assert()
        .success();
    commit(&repo, "theirs: revoke carol, rotate X");

    git_ok(&repo, &["checkout", "-q", "main"]);
    alice
        .murk(&repo)
        .args(["circle", "revoke", "carol"])
        .assert()
        .success();
    alice.add(&repo, "Z", "v");
    commit(&repo, "ours: revoke carol, add Z");

    let (merged, stderr) = git_merge(&alice, &repo, "theirs");
    assert!(merged, "{stderr}");
    alice
        .murk(&repo)
        .args(["get", "Z"])
        .assert()
        .success()
        .stdout("v\n");
    let verify = alice.murk(&repo).arg("verify").output().unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(all.contains("vault integrity verified"), "{all}");
}
