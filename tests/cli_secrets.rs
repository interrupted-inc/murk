// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI coverage for the secret commands: tier routing (`me` / named group) on
//! add/import/generate/edit, rotate and listing modes, and JSON output.

use std::fs;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk};

/// Alice's vault with a `prod` group (Alice is its only member) and Carol
/// authorized as a plain recipient outside `prod`. Returns `(alice, carol)` keys.
fn vault_with_outsider(dir: &TempDir) -> (String, String) {
    let (alice, _) = init_vault(dir);
    let carol_dir = TempDir::new().unwrap();
    let (carol, carol_pk) = init_vault(&carol_dir);

    murk(dir, &alice)
        .args([
            "circle",
            "authorize",
            &carol_pk,
            "--name",
            "carol",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(dir, &alice)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    (alice, carol)
}

fn add(dir: &TempDir, key: &str, name: &str, value: &str, extra: &[&str]) {
    murk(dir, key)
        .args(["add", name, "--vault", "test.murk"])
        .args(extra)
        .write_stdin(format!("{value}\n"))
        .assert()
        .success();
}

fn get_ok(dir: &TempDir, key: &str, name: &str, expected: &str) {
    murk(dir, key)
        .args(["get", name, "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(format!("{expected}\n"));
}

fn get_fails(dir: &TempDir, key: &str, name: &str, secret: &str) {
    murk(dir, key)
        .args(["get", name, "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains(secret).not());
}

/// Editor script that appends the scratch file's contents to `log`, then runs
/// `body` (with the scratch path in `$1`).
#[cfg(unix)]
fn editor(dir: &TempDir, name: &str, log: &std::path::Path, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.path().join(name);
    fs::write(
        &script,
        format!("#!/bin/sh\ncat \"$1\" >> '{}'\n{body}\n", log.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script.display().to_string()
}

// ── tier flags ──

#[test]
fn group_and_scoped_together_is_refused_before_writing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "TOKEN",
            "--group",
            "prod",
            "--scoped",
            "--vault",
            "test.murk",
        ])
        .write_stdin("v\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "pass either --group or --scoped, not both",
        ));

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN").not());
}

// ── import ──

#[test]
fn import_skips_murk_and_invalid_keys_but_imports_the_rest() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(
        dir.path().join("in.env"),
        "MURK_KEY=stolen\n1BAD=nope\nnot a pair\nGOOD=yes\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("skipping MURK_KEY: murk variables cannot be imported")
                .and(predicate::str::contains("skipping invalid key name: 1BAD"))
                .and(predicate::str::contains("imported 1 secret\n")),
        );

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("GOOD\n");
    get_ok(&dir, &key, "GOOD", "yes");
}

#[test]
fn import_into_me_is_a_private_override() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    fs::write(dir.path().join("in.env"), "A=alpha\nB=beta\n").unwrap();

    murk(&dir, &alice)
        .args(["import", "in.env", "--group", "me", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("imported 2 secrets (me)"));

    get_ok(&dir, &alice, "A", "alpha");
    get_ok(&dir, &alice, "B", "beta");
    get_fails(&dir, &carol, "A", "alpha");
}

#[test]
fn import_into_group_is_readable_only_by_members() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    fs::write(dir.path().join("in.env"), "DB=prod_db\n").unwrap();

    murk(&dir, &alice)
        .args([
            "import",
            "in.env",
            "--group",
            "prod",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "imported 1 secret into group prod",
        ));

    get_ok(&dir, &alice, "DB", "prod_db");
    get_fails(&dir, &carol, "DB", "prod_db");

    // An unknown group is refused and nothing is imported.
    fs::write(dir.path().join("more.env"), "OTHER=x\n").unwrap();
    murk(&dir, &alice)
        .args([
            "import",
            "more.env",
            "--group",
            "nope",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nope"));
    murk(&dir, &alice)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OTHER").not());
}

// ── generate ──

#[test]
fn generate_into_group_or_me_hides_value_from_outsiders() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);

    murk(&dir, &alice)
        .args(["generate", "G", "--group", "prod", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("generated G (group prod)"));
    murk(&dir, &alice)
        .args(["generate", "M", "--group", "me", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("generated M (me)"));

    for name in ["G", "M"] {
        let out = murk(&dir, &alice)
            .args(["get", name, "--vault", "test.murk"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value = String::from_utf8(out).unwrap();
        // 32 random bytes, URL-safe base64 without padding.
        assert_eq!(value.trim_end().len(), 43, "{name}: {value:?}");
        get_fails(&dir, &carol, name, value.trim_end());
    }
}

// ── rotate ──

#[test]
fn rotate_refuses_key_together_with_all() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TOKEN", "old", &[]);

    murk(&dir, &key)
        .args(["rotate", "TOKEN", "--all", "--vault", "test.murk"])
        .write_stdin("new\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "cannot specify both a key name and --all",
        ));
    get_ok(&dir, &key, "TOKEN", "old");
}

#[test]
fn rotate_all_on_empty_vault_is_a_no_op() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no secrets to rotate"));
}

#[test]
fn rotate_values_from_on_empty_vault_still_refuses_unknown_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "-",
            "--vault",
            "test.murk",
        ])
        .write_stdin("NOPE=x\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("NOPE: not in this vault"));
}

#[test]
fn rotate_all_reads_one_value_per_key_in_key_order() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "ZED", "z0", &[]);
    add(&dir, &key, "ALPHA", "a0", &[]);

    murk(&dir, &key)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .write_stdin("first\nsecond\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated 2 secrets"));

    get_ok(&dir, &key, "ALPHA", "first");
    get_ok(&dir, &key, "ZED", "second");
}

#[test]
fn rotate_list_reports_expired_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TOKEN", "v", &[]);

    // Clean vault: human mode exits 0, JSON is an empty array.
    murk(&dir, &key)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no keys need rotation"));
    murk(&dir, &key)
        .args(["rotate", "--list", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("[]\n");

    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "api token",
            "--expires",
            "2020-01-01",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Expired key: human mode gates scripts with exit 1; JSON still exits 0.
    murk(&dir, &key)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("TOKEN"));
    murk(&dir, &key)
        .args(["rotate", "--list", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(r#""reason": "expired""#)
                .and(predicate::str::contains(r#""key": "TOKEN""#))
                .and(predicate::str::contains(
                    r#""expired_at": "2020-01-01T23:59:59Z""#,
                )),
        );
}

/// The on-disk entry for `name` in the test vault.
fn vault_entry(dir: &TempDir, name: &str) -> serde_json::Value {
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap()).unwrap();
    json["secrets"][name].clone()
}

/// Seed one key per tier: `G` in group `prod`, `M` as Alice's override only, and
/// `S` shared with an Alice override on top.
fn seed_tiers(dir: &TempDir, alice: &str) {
    add(dir, alice, "G", "g0", &["--group", "prod"]);
    add(dir, alice, "M", "m0", &["--group", "me"]);
    add(dir, alice, "S", "s0", &[]);
    add(dir, alice, "S", "mine", &["--group", "me"]);
}

/// After rotating to `g1`/`m1`/`s1`, every value is in the tier it started in.
fn assert_tiers_kept(dir: &TempDir, alice: &str, carol: &str) {
    get_ok(dir, alice, "G", "g1");
    get_fails(dir, carol, "G", "g1");
    let g = vault_entry(dir, "G");
    assert_eq!(g["shared"], "", "G gained a shared value: {g}");
    assert!(g["grouped"]["prod"].is_string(), "G left prod: {g}");

    get_ok(dir, alice, "M", "m1");
    get_fails(dir, carol, "M", "m1");
    let m = vault_entry(dir, "M");
    assert_eq!(m["shared"], "", "M gained a shared value: {m}");
    assert_eq!(m["scoped"].as_object().unwrap().len(), 1, "{m}");

    // The shared value is rotated; Alice's override of it is left alone.
    get_ok(dir, carol, "S", "s1");
    get_ok(dir, alice, "S", "mine");
}

#[test]
fn rotate_key_keeps_each_value_in_its_tier() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    seed_tiers(&dir, &alice);

    for (name, value) in [("G", "g1"), ("M", "m1"), ("S", "s1")] {
        murk(&dir, &alice)
            .args(["rotate", name, "--vault", "test.murk"])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }

    assert_tiers_kept(&dir, &alice, &carol);
}

#[test]
fn rotate_all_keeps_each_value_in_its_tier() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    seed_tiers(&dir, &alice);

    // One value per key, in key order: G, M, S.
    murk(&dir, &alice)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .write_stdin("g1\nm1\ns1\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated 3 secrets"));

    assert_tiers_kept(&dir, &alice, &carol);
}

#[test]
fn rotate_by_a_non_member_never_moves_a_group_value_to_shared() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "G", "g0", &["--group", "prod"]);
    add(&dir, &alice, "S", "s0", &[]);

    murk(&dir, &carol)
        .args(["rotate", "G", "--vault", "test.murk"])
        .write_stdin("leak\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("a member must rotate it"));

    // Piped --all would skip G and shift its value onto S, so the batch is
    // refused before any value is read, with a pointer to --values-from.
    murk(&dir, &carol)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .write_stdin("g1\ns1\n")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("refusing piped values")
                .and(predicate::str::contains("--values-from")),
        );
    get_ok(&dir, &alice, "S", "s0");

    // Naming a key Carol can't rotate (or one not in the vault) refuses the
    // whole batch, so S is not rotated either.
    fs::write(dir.path().join("bad.env"), "S=s9\nG=leak\nNOPE=x\n").unwrap();
    murk(&dir, &carol)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "bad.env",
            "--vault",
            "test.murk",
        ])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("refusing --values-from")
                .and(predicate::str::contains("G: it is held by group prod"))
                .and(predicate::str::contains("NOPE: not in this vault")),
        );
    get_ok(&dir, &alice, "S", "s0");

    // Values matched by name: S gets its own value and G is skipped.
    fs::write(dir.path().join("ok.env"), "S=s1\n").unwrap();
    murk(&dir, &carol)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "ok.env",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("skipped G"));

    get_ok(&dir, &alice, "G", "g0");
    get_fails(&dir, &carol, "G", "g0");
    assert_eq!(vault_entry(&dir, "G")["shared"], "");
    get_ok(&dir, &alice, "S", "s1");
}

#[test]
fn rotate_values_from_puts_each_value_in_its_tier_and_leaves_unnamed_keys() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    seed_tiers(&dir, &alice);

    // `-` reads the values from stdin; M is not named.
    murk(&dir, &alice)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "-",
            "--vault",
            "test.murk",
        ])
        .write_stdin("S=\"s1\"\nG=g1\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("not named in --values-from: M"));

    get_ok(&dir, &alice, "G", "g1");
    get_fails(&dir, &carol, "G", "g1");
    assert_eq!(vault_entry(&dir, "G")["shared"], "");
    get_ok(&dir, &carol, "S", "s1");
    get_ok(&dir, &alice, "M", "m0");

    // --values-from and --generate don't mix.
    murk(&dir, &alice)
        .args([
            "rotate",
            "S",
            "--generate",
            "--values-from",
            "-",
            "--vault",
            "test.murk",
        ])
        .assert()
        .code(2);
}

/// Alice's vault where Carol owns group `ops` (holding `G`), which Alice is not
/// in, plus shared `S` and `T`. Returns `(alice, carol)` keys.
fn vault_with_foreign_group(dir: &TempDir) -> (String, String) {
    let (alice, carol) = vault_with_outsider(dir);
    murk(dir, &carol)
        .args(["group", "create", "ops", "--vault", "test.murk"])
        .assert()
        .success();
    add(dir, &carol, "G", "g0", &["--group", "ops"]);
    add(dir, &alice, "S", "s0", &[]);
    add(dir, &alice, "T", "t0", &[]);
    (alice, carol)
}

fn revoke_carol(dir: &TempDir, alice: &str, extra: &[&str]) -> assert_cmd::assert::Assert {
    murk(dir, alice)
        .args([
            "circle",
            "revoke",
            "carol",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .args(extra)
        .assert()
}

#[test]
fn revoke_rotate_refuses_unsafe_input_before_writing_anything() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_foreign_group(&dir);

    // Positional piped values would shift past the skipped G.
    murk(&dir, &alice)
        .args([
            "circle",
            "revoke",
            "carol",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("g1\ns1\nt1\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing piped values"));

    // A named key Alice can't rotate refuses the batch.
    fs::write(dir.path().join("bad.env"), "S=s1\nG=g1\n").unwrap();
    revoke_carol(&dir, &alice, &["--values-from", "bad.env"])
        .code(1)
        .stderr(predicate::str::contains("G: it is held by group ops"));

    // Nothing was written: Carol is still a recipient and nothing is owed.
    get_ok(&dir, &carol, "S", "s0");
    murk(&dir, &alice)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn revoke_rotate_values_from_rotates_named_keys_and_keeps_the_rest_owed() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_foreign_group(&dir);
    fs::write(dir.path().join("vals.env"), "S=s1\n").unwrap();

    revoke_carol(&dir, &alice, &["--values-from", "vals.env"])
        .success()
        .stderr(
            predicate::str::contains("skipped G")
                .and(predicate::str::contains("not named in --values-from: T")),
        );

    get_ok(&dir, &alice, "S", "s1");
    get_ok(&dir, &alice, "T", "t0");
    get_fails(&dir, &carol, "S", "s1");
    assert_eq!(vault_entry(&dir, "G")["shared"], "");

    // G (only an ops member can rotate it) and T (not named) stay owed; S is done.
    murk(&dir, &alice)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("G not rotated")
                .and(predicate::str::contains("T not rotated"))
                .and(predicate::str::contains("S not rotated").not()),
        );
}

#[test]
fn agent_revoke_rotate_values_from_rotates_the_granted_shared_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "S", "s0", &[]);
    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "S", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = fs::read_to_string(&agent_key_path)
        .unwrap()
        .trim()
        .to_string();

    fs::write(dir.path().join("vals.env"), "S=s1\n").unwrap();
    murk(&dir, &key)
        .args([
            "agent",
            "revoke",
            "codex",
            "--rotate",
            "--values-from",
            "vals.env",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated S"));

    get_ok(&dir, &key, "S", "s1");
    get_fails(&dir, &agent_key, "S", "s1");
}

#[test]
fn revoke_rotate_keeps_group_values_in_the_group() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    let bob_dir = TempDir::new().unwrap();
    let (bob, bob_pk) = init_vault(&bob_dir);
    murk(&dir, &alice)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &alice)
        .args([
            "group",
            "add",
            "prod",
            "--member",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    add(&dir, &alice, "G", "g0", &["--group", "prod"]);
    add(&dir, &alice, "M", "m0", &["--group", "me"]);
    add(&dir, &alice, "S", "s0", &[]);

    // Bob could read G (via prod) and S; M is Alice's alone and isn't prompted.
    murk(&dir, &alice)
        .args([
            "circle",
            "revoke",
            "bob",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("g1\ns1\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated G (group prod)"));

    get_ok(&dir, &alice, "G", "g1");
    get_fails(&dir, &carol, "G", "g1");
    let g = vault_entry(&dir, "G");
    assert_eq!(g["shared"], "", "G gained a shared value: {g}");
    get_ok(&dir, &alice, "M", "m0");
    get_fails(&dir, &carol, "M", "m0");
    get_ok(&dir, &carol, "S", "s1");

    // Bob's key no longer opens the live group or shared ciphertext.
    let bob_id = murk_cli::crypto::parse_identity(&bob).unwrap();
    let group_ct = g["grouped"]["prod"].as_str().unwrap();
    assert!(murk_cli::decrypt_value(group_ct, &bob_id).is_err());
    let shared_ct = vault_entry(&dir, "S")["shared"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(murk_cli::decrypt_value(&shared_ct, &bob_id).is_err());
}

#[test]
fn revoke_rotate_leaves_no_pending_marker_for_a_key_only_the_revoked_override_held() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "S", "s0", &[]);
    // Carol's personal-only key: once her override is removed nothing is left to rotate.
    add(&dir, &carol, "K", "mine", &["--group", "me"]);

    murk(&dir, &alice)
        .args([
            "circle",
            "revoke",
            "carol",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("s1\n")
        .assert()
        .success();

    // Nothing owes a rotation, so `rotate --list` (a script gate) exits 0.
    murk(&dir, &alice)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .success();
}

/// `rotate --list` exit status: 1 while anything owes a rotation.
fn rotation_owed(dir: &TempDir, key: &str) -> bool {
    let code = murk(dir, key)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .output()
        .unwrap()
        .status
        .code();
    code == Some(1)
}

#[test]
fn personal_override_write_keeps_the_pending_rotation_marker() {
    let dir = TempDir::new().unwrap();
    let (alice, _) = vault_with_outsider(&dir);
    add(&dir, &alice, "S", "s0", &[]);
    murk(&dir, &alice)
        .args(["circle", "revoke", "carol", "--vault", "test.murk"])
        .assert()
        .success();
    assert!(rotation_owed(&dir, &alice));

    // Carol read the shared value, which an override leaves in place.
    add(&dir, &alice, "S", "mine", &["--group", "me"]);
    assert!(rotation_owed(&dir, &alice));

    // Rotating the shared value settles it.
    murk(&dir, &alice)
        .args(["rotate", "S", "--vault", "test.murk"])
        .write_stdin("s1\n")
        .assert()
        .success();
    assert!(!rotation_owed(&dir, &alice));
}

#[test]
fn removing_a_group_member_marks_the_group_values_owed() {
    let dir = TempDir::new().unwrap();
    let (alice, _) = vault_with_outsider(&dir);
    murk(&dir, &alice)
        .args([
            "group",
            "add",
            "prod",
            "--member",
            "carol",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    add(&dir, &alice, "G", "g0", &["--group", "prod"]);
    add(&dir, &alice, "S", "s0", &[]);

    murk(&dir, &alice)
        .args([
            "group",
            "rm",
            "prod",
            "--member",
            "carol",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotate them"));
    murk(&dir, &alice)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("G not rotated").and(predicate::str::contains("S not").not()),
        );

    murk(&dir, &alice)
        .args(["rotate", "G", "--vault", "test.murk"])
        .write_stdin("g1\n")
        .assert()
        .success();
    assert!(!rotation_owed(&dir, &alice));
}

#[test]
fn short_rotation_input_writes_and_reports_nothing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "A", "a0", &[]);
    add(&dir, &key, "B", "b0", &[]);
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "bot", "--only", "A", "--only", "B",
        ])
        .args(["--out", "agent.key", "--vault", "test.murk"])
        .assert()
        .success();

    // One value for two keys: the batch aborts before anything is written.
    murk(&dir, &key)
        .args(["agent", "revoke", "bot", "--rotate", "--vault", "test.murk"])
        .write_stdin("a1\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("rotated").not());
    murk(&dir, &key)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .write_stdin("a1\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("rotated").not());

    get_ok(&dir, &key, "A", "a0");
    get_ok(&dir, &key, "B", "b0");
}

#[test]
fn absurd_grant_ttl_is_refused_cleanly() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "A", "a0", &[]);

    for ttl in ["999999999999d", "99999999999999999999s", "366d"] {
        murk(&dir, &key)
            .args([
                "agent", "grant", "--name", "bot", "--only", "A", "--ttl", ttl,
            ])
            .args(["--out", "agent.key", "--vault", "test.murk"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("too long"));
    }
}

#[test]
fn piped_single_value_keeps_every_line() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----";

    add(&dir, &key, "TLS_KEY", pem, &[]);
    get_ok(&dir, &key, "TLS_KEY", pem);

    let rotated = pem.replace("AAAA", "CCCC");
    murk(&dir, &key)
        .args(["rotate", "TLS_KEY", "--vault", "test.murk"])
        .write_stdin(format!("{rotated}\n"))
        .assert()
        .success();
    get_ok(&dir, &key, "TLS_KEY", &rotated);
}

#[test]
fn piped_batch_with_extra_lines_is_refused() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "AAA", "a0", &[]);
    add(&dir, &key, "BBB", "b0", &[]);

    // A two-line value for AAA would push its second line onto BBB. Leftover
    // input is refused even when it is only whitespace.
    for input in [
        "line1-of-AAA\nline2-of-AAA\nvalue-for-BBB\n",
        "AAA-line1\nAAA-line2\n  \n",
    ] {
        murk(&dir, &key)
            .args(["rotate", "--all", "--vault", "test.murk"])
            .write_stdin(input)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("more lines than"));
    }
    get_ok(&dir, &key, "AAA", "a0");
    get_ok(&dir, &key, "BBB", "b0");
}

#[test]
fn revoke_by_a_non_member_says_the_group_value_stays_readable() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    let bob_dir = TempDir::new().unwrap();
    let (_, bob_pk) = init_vault(&bob_dir);
    murk(&dir, &alice)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    // Carol's group `ops` (with Bob) holds G; Alice is not in it.
    murk(&dir, &carol)
        .args(["group", "create", "ops", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &carol)
        .args([
            "group",
            "add",
            "ops",
            "--member",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    add(&dir, &carol, "G", "g0", &["--group", "ops"]);

    murk(&dir, &alice)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "you are not in group ops, so G could not be re-encrypted",
        ));
    murk(&dir, &alice)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("G not rotated"));
}

#[test]
fn non_member_cannot_remove_or_describe_group_keys_or_delete_the_group() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "G", "g0", &["--group", "prod"]);
    murk(&dir, &alice)
        .args(["group", "create", "staging", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &carol)
        .args(["rm", "G", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("only a member can change it"));
    murk(&dir, &carol)
        .args([
            "describe",
            "G",
            "hijacked",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .assert()
        .code(1);
    murk(&dir, &carol)
        .args(["group", "rm", "staging", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must be a member"));

    get_ok(&dir, &alice, "G", "g0");
    murk(&dir, &alice)
        .args(["ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"G\""));
    let vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap()).unwrap();
    assert_ne!(vault["schema"]["G"]["description"], "hijacked");
    murk(&dir, &alice)
        .args(["group", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("staging"));
}

#[test]
fn agent_revoke_and_renew_mark_the_scope_owed() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "A", "a0", &[]);
    let grant = |extra: &[&str]| {
        murk(&dir, &key)
            .args(["agent", "grant", "--name", "bot", "--only", "A"])
            .args(extra)
            .args(["--out", "agent.key", "--vault", "test.murk"])
            .assert()
            .success();
    };

    grant(&[]);
    murk(&dir, &key)
        .args(["agent", "revoke", "bot", "--vault", "test.murk"])
        .assert()
        .success();
    assert!(rotation_owed(&dir, &key));

    murk(&dir, &key)
        .args(["rotate", "A", "--vault", "test.murk"])
        .write_stdin("a1\n")
        .assert()
        .success();
    assert!(!rotation_owed(&dir, &key));

    grant(&[]);
    grant(&["--renew"]);
    assert!(rotation_owed(&dir, &key));
}

#[test]
fn refused_revoke_rotate_says_how_to_revoke_now() {
    let dir = TempDir::new().unwrap();
    let (alice, _) = vault_with_foreign_group(&dir);

    murk(&dir, &alice)
        .args([
            "circle",
            "revoke",
            "carol",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("s1\nt1\n")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("murk circle revoke carol` without --rotate").and(
                predicate::str::contains("murk rotate --all --values-from FILE"),
            ),
        );
}

#[cfg(unix)]
#[test]
fn values_from_refuses_symlinks_and_warns_on_loose_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "S", "s0", &[]);
    let vals = dir.path().join("vals.env");
    fs::write(&vals, "S=s1\n").unwrap();
    fs::set_permissions(&vals, fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&vals, dir.path().join("link.env")).unwrap();

    murk(&dir, &key)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "link.env",
            "--vault",
            "test.murk",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("symlink"));
    get_ok(&dir, &key, "S", "s0");

    murk(&dir, &key)
        .args([
            "rotate",
            "--all",
            "--values-from",
            "vals.env",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("readable by others (mode 644)"));
    get_ok(&dir, &key, "S", "s1");
}

/// Grant `name` read access to `only` with a 1-second TTL and wait it out.
fn expired_grant(dir: &TempDir, key: &str, name: &str, only: &str) {
    murk(dir, key)
        .args([
            "agent", "grant", "--name", name, "--only", only, "--ttl", "1s",
        ])
        .args(["--out", &format!("{name}.key"), "--vault", "test.murk"])
        .assert()
        .success();
    std::thread::sleep(std::time::Duration::from_millis(1100));
}

#[test]
fn revoke_rotate_values_from_works_with_an_expired_grant_present() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "S", "s0", &[]);
    add(&dir, &alice, "T", "t0", &[]);
    expired_grant(&dir, &alice, "old-bot", "T");
    fs::write(dir.path().join("vals.env"), "S=s1\nT=t1\n").unwrap();

    murk(&dir, &alice)
        .args([
            "circle",
            "revoke",
            "carol",
            "--rotate",
            "--values-from",
            "vals.env",
        ])
        .args(["--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated 2 secrets"));

    get_ok(&dir, &alice, "S", "s1");
    get_ok(&dir, &alice, "T", "t1");
    get_fails(&dir, &carol, "S", "s1");
    assert!(!rotation_owed(&dir, &alice));
}

#[test]
fn agent_revoke_rotate_values_from_works_with_another_expired_grant() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "S", "s0", &[]);
    add(&dir, &key, "T", "t0", &[]);
    // Mint `bot` first: the expired grant must still be on disk when the
    // revoke under test loads the vault, so no other save may follow it.
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "S"])
        .args(["--out", "bot.key", "--vault", "test.murk"])
        .assert()
        .success();
    expired_grant(&dir, &key, "old-bot", "T");
    fs::write(dir.path().join("vals.env"), "S=s1\n").unwrap();

    murk(&dir, &key)
        .args([
            "agent",
            "revoke",
            "bot",
            "--rotate",
            "--values-from",
            "vals.env",
        ])
        .args(["--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated S"));
    get_ok(&dir, &key, "S", "s1");
}

// ── ls / export JSON ──

#[test]
fn ls_json_lists_tag_filtered_names() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "DB_URL", "postgres://x", &["--tag", "db"]);
    add(&dir, &key, "API_KEY", "sk", &[]);

    murk(&dir, &key)
        .args(["ls", "--json", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("[\n  \"DB_URL\"\n]\n");
}

#[test]
fn export_json_emits_plaintext_map_and_respects_self_scope() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "ALLOWED", "it's \"ok\"", &["--tag", "agents"]);
    add(&dir, &key, "FORBIDDEN", "nope", &[]);

    murk(&dir, &key)
        .args(["export", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("{\n  \"ALLOWED\": \"it's \\\"ok\\\"\",\n  \"FORBIDDEN\": \"nope\"\n}\n");

    murk(&dir, &key)
        .args([
            "policy",
            "set",
            "--allow-tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Self-scope drops the forbidden key from JSON too, and says so.
    murk(&dir, &key)
        .args(["export", "--json", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("nope").not())
        .stderr(predicate::str::contains(
            "withholding 1 key(s) not allowed by policy: FORBIDDEN",
        ));

    // Nothing to withhold: no warning.
    murk(&dir, &key)
        .args(["export", "--tag", "agents", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("export ALLOWED="))
        .stderr(predicate::str::contains("withholding").not());
}

// ── edit ──

#[cfg(unix)]
#[test]
fn edit_group_requires_membership() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "prod_db", &["--group", "prod"]);
    let marker = dir.path().join("editor-ran");
    let ed = editor(&dir, "ed.sh", &marker, "true");

    murk(&dir, &carol)
        .args(["edit", "DB", "--group", "prod", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "you must be a member of group \"prod\" to edit it",
        ));
    assert!(!marker.exists(), "editor must not open for a non-member");
}

#[cfg(unix)]
#[test]
fn edit_single_key_scoped_overrides_without_touching_shared() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "TOKEN", "shared", &[]);
    add(&dir, &alice, "TOKEN", "mine", &["--group", "me"]);
    let log = dir.path().join("seen");
    let ed = editor(&dir, "ed.sh", &log, r#"echo "mine2" > "$1""#);

    murk(&dir, &alice)
        .args(["edit", "TOKEN", "--scoped", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(predicate::str::contains("updated TOKEN (me)"));

    // The editor was handed the override, not the shared value.
    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("# Editing TOKEN (me)") && seen.ends_with("mine"),
        "{seen:?}"
    );
    get_ok(&dir, &alice, "TOKEN", "mine2");
    get_ok(&dir, &carol, "TOKEN", "shared");
}

#[cfg(unix)]
#[test]
fn edit_single_key_group_replaces_group_value() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);
    let log = dir.path().join("seen");
    let ed = editor(&dir, "ed.sh", &log, r#"echo "new_db" > "$1""#);

    murk(&dir, &alice)
        .args(["edit", "DB", "--group", "prod", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(predicate::str::contains("updated DB (group prod)"));

    get_ok(&dir, &alice, "DB", "new_db");
    get_fails(&dir, &carol, "DB", "new_db");
}

#[cfg(unix)]
#[test]
fn edit_single_key_empty_value_keeps_old_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TOKEN", "keep", &[]);
    let log = dir.path().join("seen");
    let ed = editor(&dir, "ed.sh", &log, r#": > "$1""#);

    murk(&dir, &key)
        .args(["edit", "TOKEN", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(predicate::str::contains("empty value — no changes"));
    get_ok(&dir, &key, "TOKEN", "keep");
}

#[cfg(unix)]
#[test]
fn bulk_edit_scoped_lists_and_removes_only_my_overrides() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "SHARED_ONLY", "s", &[]);
    add(&dir, &alice, "TOKEN", "shared", &[]);
    add(&dir, &alice, "TOKEN", "mine", &["--group", "me"]);
    let log = dir.path().join("seen");
    let ed = editor(&dir, "ed.sh", &log, r#": > "$1""#);

    murk(&dir, &alice)
        .args(["edit", "--scoped", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(predicate::str::contains("1 removed"));

    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("# Editing your personal (me) values.")
            && seen.contains("TOKEN=mine\n")
            && !seen.contains("SHARED_ONLY"),
        "{seen:?}"
    );
    // Dropping the override falls back to the shared value; the key survives.
    get_ok(&dir, &alice, "TOKEN", "shared");
    get_ok(&dir, &carol, "TOKEN", "shared");
}

#[cfg(unix)]
#[test]
fn bulk_edit_group_lists_and_removes_group_values() {
    let dir = TempDir::new().unwrap();
    let (alice, _) = vault_with_outsider(&dir);
    add(&dir, &alice, "SHARED", "s", &[]);
    add(&dir, &alice, "DB", "prod_db", &["--group", "prod"]);
    let log = dir.path().join("seen");
    let ed = editor(&dir, "ed.sh", &log, r#": > "$1""#);

    murk(&dir, &alice)
        .args(["edit", "--group", "prod", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(predicate::str::contains("1 removed"));

    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("# Editing group prod values.")
            && seen.contains("DB=prod_db\n")
            && !seen.contains("SHARED="),
        "{seen:?}"
    );
    get_fails(&dir, &alice, "DB", "prod_db");
    get_ok(&dir, &alice, "SHARED", "s");
}

#[cfg(unix)]
#[test]
fn bulk_edit_skips_malformed_and_invalid_lines() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TOKEN", "v", &[]);
    let log = dir.path().join("seen");
    let ed = editor(
        &dir,
        "ed.sh",
        &log,
        r#"printf "garbage line\n1BAD=x\n" >> "$1""#,
    );

    murk(&dir, &key)
        .args(["edit", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("skipping malformed line: garbage line")
                .and(predicate::str::contains("skipping invalid key name: 1BAD"))
                .and(predicate::str::contains("no changes")),
        );

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("TOKEN\n");
    get_ok(&dir, &key, "TOKEN", "v");
}
