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

/// Which base tiers hold `name` in the on-disk vault: whether it has a shared
/// value, and the names of the groups holding a value.
fn stored_tiers(dir: &TempDir, name: &str) -> (bool, Vec<String>) {
    let raw = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let vault: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let entry = &vault["secrets"][name];
    let shared = entry["shared"].as_str().is_some_and(|s| !s.is_empty());
    let groups = entry["grouped"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    (shared, groups)
}

/// Run `murk edit` (all keys, default tier) as `key` with an editor that
/// appends `line` to the buffer.
#[cfg(unix)]
fn bulk_edit_appending(dir: &TempDir, key: &str, line: &str) -> assert_cmd::assert::Assert {
    let log = dir.path().join("seen");
    let ed = editor(
        dir,
        "append.sh",
        &log,
        &format!(r#"printf '{line}\n' >> "$1""#),
    );
    murk(dir, key)
        .args(["edit", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
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
        "MURK_KEY=stolen\n1BAD=nope\nnot a pair\nMURK_FOO=bar\nGOOD=yes\n",
    )
    .unwrap();

    let out = murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "skipping MURK_KEY (line 1): murk variables cannot be imported",
            )
            .and(predicate::str::contains(
                "skipping line 2: invalid key name",
            ))
            .and(predicate::str::contains("skipping line 3: not KEY=VALUE"))
            .and(predicate::str::contains("skipping MURK_FOO (line 4)"))
            .and(predicate::str::contains("imported 1 secret\n")),
        );
    // Skipped lines are named by number; their text is never echoed.
    let output = out.get_output();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for text in ["stolen", "1BAD", "nope", "not a pair"] {
        assert!(!printed.contains(text), "{text} echoed: {printed}");
    }

    // Every name murk warns about is left out, MURK_FOO included.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("GOOD\n");
    get_ok(&dir, &key, "GOOD", "yes");
}

/// A PEM private key, with base64 body lines that look like `IDENT=...`.
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n\
Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==\n\
JwGmMlqvl6dkjzN4CoQYOI2NNQOegHiz0AwyvIfIMpOTDSYfu7WJLZY=\n\
-----END RSA PRIVATE KEY-----\n";

#[test]
fn import_keeps_a_quoted_pem_whole() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(
        dir.path().join("in.env"),
        format!("API_URL=https://x\nTLS_KEY=\"{PEM}\"\nexport SIGNING_KEY='{PEM}' # pem\n"),
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("imported 3 secrets\n"));
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("API_URL\nSIGNING_KEY\nTLS_KEY\n");
    get_ok(&dir, &key, "TLS_KEY", PEM);
    get_ok(&dir, &key, "SIGNING_KEY", PEM);
    // No fragment of the key reached the vault's plaintext header.
    let vault = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(!vault.contains("Zm9vYmFy") && !vault.contains("JwGmMlqv"));
}

#[test]
fn import_with_an_unclosed_quote_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let before = fs::read(dir.path().join("test.murk")).unwrap();
    let body = &PEM[..PEM.len() - 30]; // cut before the closing quote's line
    fs::write(
        dir.path().join("in.env"),
        format!("API_URL=https://x\nTLS_KEY=\"{body}\nNEXT=1\n"),
    )
    .unwrap();

    let out = murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "line 2: the \" opened here is never closed — nothing imported",
        ));
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).into_owned();
    assert!(
        !stderr.contains("MIIEow") && !stderr.contains("Zm9vYmFy"),
        "{stderr}"
    );
    assert_eq!(fs::read(dir.path().join("test.murk")).unwrap(), before);
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

    // Clean vault: human mode exits 0; JSON has no issues and says a key verified it.
    murk(&dir, &key)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no keys need rotation"));
    let clean = murk(&dir, &key)
        .args(["rotate", "--list", "--json", "--vault", "test.murk"])
        .assert()
        .success();
    let clean: serde_json::Value = serde_json::from_slice(&clean.get_output().stdout).unwrap();
    assert_eq!(clean, serde_json::json!({ "verified": true, "issues": [] }));

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
            predicate::str::contains(r#""verified": true"#)
                .and(predicate::str::contains(r#""reason": "expired""#))
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

    // agent.key holds the revoked grant's key now: replacing it takes --force.
    grant(&["--force"]);
    grant(&["--renew", "--force"]);
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

/// Editor script that replaces the scratch file with exactly `contents`.
#[cfg(unix)]
fn writing_editor(dir: &TempDir, name: &str, contents: &str) -> String {
    let source = dir.path().join(format!("{name}.contents"));
    fs::write(&source, contents).unwrap();
    let log = dir.path().join(format!("{name}.seen"));
    editor(
        dir,
        name,
        &log,
        &format!("cp '{}' \"$1\"", source.display()),
    )
}

#[cfg(unix)]
fn edit(dir: &TempDir, key: &str, args: &[&str], editor: &str) -> assert_cmd::assert::Assert {
    murk(dir, key)
        .arg("edit")
        .args(args)
        .args(["--vault", "test.murk"])
        .env("EDITOR", editor)
        .assert()
}

/// Values that are easy to mangle in a text buffer, as (key, value, the value
/// as typed in a bulk buffer).
#[cfg(unix)]
const AWKWARD: &[(&str, &str, &str)] = &[
    ("MULTI", "line one\nline two\n", r#""line one\nline two\n""#),
    ("QUOTES", r#"say "hi" and 'bye'"#, r#"say "hi" and 'bye'"#),
    ("EQUALS", "a=b==c=", "a=b==c="),
    ("TRAILING", "trailing spaces  ", r#""trailing spaces  ""#),
    ("NEWLINES", "\n\nx\n\n", r#""\n\nx\n\n""#),
    ("HASH", "#not a comment", r##""#not a comment""##),
    ("EMPTY", "", ""),
];

#[cfg(unix)]
#[test]
fn bulk_edit_saved_untouched_keeps_multi_line_values() {
    // Saving the bulk buffer as murk wrote it used to cut a multi-line value
    // to its first line and report "1 updated".
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "CERT", "old", &[]);
    let ed = writing_editor(&dir, "ed.sh", "line one\nline two\n");
    edit(&dir, &key, &["CERT"], &ed).success();
    get_ok(&dir, &key, "CERT", "line one\nline two");

    edit(&dir, &key, &[], "cat")
        .success()
        .stderr(predicate::str::contains("no changes"));
    get_ok(&dir, &key, "CERT", "line one\nline two");
}

#[cfg(unix)]
#[test]
fn bulk_edit_keeps_a_multi_line_value_whole() {
    // A quoted multi-line value used to be cut to its first line, its other
    // lines skipped or (`abc==`) added as keys of their own.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "CERT", "old", &[]);
    let ed = writing_editor(
        &dir,
        "ed.sh",
        "CERT=\"-----BEGIN-----\nabc==\n-----END-----\n\"\n",
    );

    edit(&dir, &key, &[], &ed)
        .success()
        .stderr(predicate::str::contains("1 updated").and(predicate::str::contains("added").not()));
    get_ok(
        &dir,
        &key,
        "CERT",
        "-----BEGIN-----\nabc==\n-----END-----\n",
    );
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("CERT\n");
}

#[cfg(unix)]
#[test]
fn edit_round_trips_awkward_values_byte_for_byte() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let buffer: String = AWKWARD
        .iter()
        .map(|(k, _, typed)| format!("{k}={typed}\n"))
        .collect();
    let ed = writing_editor(&dir, "ed.sh", &buffer);
    edit(&dir, &key, &[], &ed)
        .success()
        .stderr(predicate::str::contains(format!("{} added", AWKWARD.len())));
    for (k, v, _) in AWKWARD {
        get_ok(&dir, &key, k, v);
    }

    // Saving murk's own buffers untouched, in bulk and per key, changes nothing.
    edit(&dir, &key, &[], "cat")
        .success()
        .stderr(predicate::str::contains("no changes"));
    for (k, _, _) in AWKWARD {
        edit(&dir, &key, &[k], "cat")
            .success()
            .stderr(predicate::str::contains("no changes"));
    }
    for (k, v, _) in AWKWARD {
        get_ok(&dir, &key, k, v);
    }
}

#[cfg(unix)]
#[test]
fn edit_single_key_reads_pasted_and_quoted_values_exactly() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TLS", "old", &[]);

    // Pasted as is: every line after the header is the value, `#` lines too.
    let pasted = "-----BEGIN-----\n# not a comment\n\nabc==\n-----END-----";
    let ed = writing_editor(&dir, "paste.sh", &format!("{pasted}\n"));
    edit(&dir, &key, &["TLS"], &ed)
        .success()
        .stderr(predicate::str::contains("updated TLS"));
    get_ok(&dir, &key, "TLS", pasted);
    edit(&dir, &key, &[], "cat")
        .success()
        .stderr(predicate::str::contains("no changes"));
    get_ok(&dir, &key, "TLS", pasted);

    // Quoted: the trailing newline and spaces are part of the value.
    let ed = writing_editor(&dir, "quoted.sh", "# comment\n\"ends with  \\n\"\n");
    edit(&dir, &key, &["TLS"], &ed).success();
    get_ok(&dir, &key, "TLS", "ends with  \n");
}

#[cfg(unix)]
#[test]
fn bulk_edit_refuses_a_buffer_it_cannot_read() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "TOKEN", "v", &[]);

    for (contents, reason) in [
        ("garbage SECRETISH\n", "line 1: expected KEY=VALUE"),
        ("TOKEN=v\n1BAD=SECRETISH\n", "line 2: invalid key name"),
        (
            "TOKEN=\"SECRETISH\n",
            "line 1: the \" opened here is never closed",
        ),
        (
            "TOKEN=v\nTOKEN=SECRETISH\n",
            "line 2: TOKEN is already set on line 1",
        ),
    ] {
        let ed = writing_editor(&dir, "ed.sh", contents);
        edit(&dir, &key, &[], &ed).code(1).stderr(
            predicate::str::contains(reason)
                .and(predicate::str::contains("nothing saved"))
                .and(predicate::str::contains("SECRETISH").not()),
        );
        murk(&dir, &key)
            .args(["ls", "--vault", "test.murk"])
            .assert()
            .success()
            .stdout("TOKEN\n");
        get_ok(&dir, &key, "TOKEN", "v");
    }
}

#[cfg(unix)]
#[test]
fn edit_refuses_to_save_over_a_vault_changed_meanwhile() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "K1", "v1", &[]);

    // A teammate's change, as a `git pull` in another terminal brings it in.
    // This machine never loaded that change, so its trust pin is put back too
    // (else the restored vault reads as a rollback).
    let vault = dir.path().join("test.murk");
    let before = fs::read(&vault).unwrap();
    let pins = dir.path().join(".config/murk/signer-pins");
    let pinned: Vec<(std::path::PathBuf, Vec<u8>)> = fs::read_dir(&pins)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    add(&dir, &key, "TEAMMATE", "theirs", &[]);
    let theirs = dir.path().join("theirs.murk");
    fs::copy(&vault, &theirs).unwrap();
    fs::write(&vault, &before).unwrap();
    for (path, bytes) in &pinned {
        fs::write(path, bytes).unwrap();
    }

    let log = dir.path().join("seen");
    let ed = editor(
        &dir,
        "ed.sh",
        &log,
        &format!(
            "cp '{}' '{}'\nprintf 'K1=mine\\n' > \"$1\"",
            theirs.display(),
            vault.display()
        ),
    );
    edit(&dir, &key, &[], &ed)
        .code(1)
        .stderr(predicate::str::contains(
            "test.murk changed on disk while the editor was open — nothing saved",
        ));

    // The teammate's vault stands as they wrote it.
    assert_eq!(fs::read(&vault).unwrap(), fs::read(&theirs).unwrap());
    get_ok(&dir, &key, "TEAMMATE", "theirs");
    get_ok(&dir, &key, "K1", "v1");
}

#[cfg(unix)]
#[test]
fn edit_single_key_keeps_value_lines_starting_with_hash() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "SCRIPT", "placeholder", &[]);

    // Keep murk's header, replace the value below it.
    let log = dir.path().join("seen");
    let ed = editor(
        &dir,
        "ed.sh",
        &log,
        r#"awk '{print} /^# ---- the value starts below this line ----$/{exit}' "$1" > "$1.new"
printf '#!/bin/sh\n# say hi\necho hi\n' >> "$1.new"
mv "$1.new" "$1""#,
    );
    edit(&dir, &key, &["SCRIPT"], &ed)
        .success()
        .stderr(predicate::str::contains("updated SCRIPT"));
    get_ok(&dir, &key, "SCRIPT", "#!/bin/sh\n# say hi\necho hi");

    // A value that is just `#…` survives an untouched save too.
    let ed = writing_editor(
        &dir,
        "pw.sh",
        "# Editing PW\n# ---- the value starts below this line ----\n#Passw0rd\n",
    );
    edit(&dir, &key, &["SCRIPT"], &ed).success();
    get_ok(&dir, &key, "SCRIPT", "#Passw0rd");
    edit(&dir, &key, &["SCRIPT"], "cat")
        .success()
        .stderr(predicate::str::contains("no changes"));
}

#[cfg(unix)]
#[test]
fn edit_warns_when_the_scratch_file_is_not_in_ram() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "K", "v", &[]);
    // Under the target dir: on disk on every platform murk is tested on.
    let disk = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();

    murk(&dir, &key)
        .args(["edit", "K", "--vault", "test.murk"])
        .env("XDG_RUNTIME_DIR", disk.path())
        .env("EDITOR", "cat")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("which is not RAM-backed")
                .and(predicate::str::contains("MURK_STRICT=1 to refuse")),
        );
    assert_eq!(fs::read_dir(disk.path()).unwrap().count(), 0);
}

#[test]
fn import_keeps_a_hash_in_a_bare_value_and_says_so() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(
        dir.path().join("in.env"),
        "PASS=hunter2 #not-a-comment\nQUOTED=\"a #b\"\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "line 1: value contains \" #\"; quote the value if the # is part of it, or remove the comment",
            )
            .and(predicate::str::contains("line 2:").not())
            .and(predicate::str::contains("hunter2").not()),
        );
    get_ok(&dir, &key, "PASS", "hunter2 #not-a-comment");
    get_ok(&dir, &key, "QUOTED", "a #b");
}

#[test]
fn import_reports_each_duplicate_key_and_keeps_the_last_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(
        dir.path().join("in.env"),
        "TOKEN=first-secret\nOTHER=x\nTOKEN=second-secret\nTOKEN=third-secret\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "in.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains(
                "line 3: TOKEN is already set on line 1; the later value is kept",
            )
            .and(predicate::str::contains(
                "line 4: TOKEN is already set on line 3; the later value is kept",
            ))
            .and(predicate::str::contains("-secret").not())
            .and(predicate::str::contains("imported 2 secrets\n")),
        );
    get_ok(&dir, &key, "TOKEN", "third-secret");
}

// ── updating a key without --group keeps its tier ──

#[test]
fn add_without_group_keeps_a_group_key_in_its_group() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);

    murk(&dir, &alice)
        .args(["add", "DB", "--vault", "test.murk"])
        .write_stdin("new_db\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("added DB (group prod)"));

    get_ok(&dir, &alice, "DB", "new_db");
    get_fails(&dir, &carol, "DB", "new_db");
    assert_eq!(stored_tiers(&dir, "DB"), (false, vec!["prod".to_string()]));
}

#[test]
fn add_without_group_keeps_shared_keys_shared_and_new_keys_shared() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "TOKEN", "old", &[]);
    add(&dir, &alice, "TOKEN", "new", &[]);
    add(&dir, &alice, "FRESH", "fresh", &[]);

    get_ok(&dir, &carol, "TOKEN", "new");
    get_ok(&dir, &carol, "FRESH", "fresh");
    assert_eq!(stored_tiers(&dir, "TOKEN"), (true, vec![]));
    assert_eq!(stored_tiers(&dir, "FRESH"), (true, vec![]));
}

#[test]
fn add_without_group_keeps_a_personal_override_personal() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "MINE", "old", &["--group", "me"]);

    murk(&dir, &alice)
        .args(["add", "MINE", "--vault", "test.murk"])
        .write_stdin("new\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("added MINE (me)"));

    get_ok(&dir, &alice, "MINE", "new");
    get_fails(&dir, &carol, "MINE", "new");
    assert_eq!(stored_tiers(&dir, "MINE"), (false, vec![]));
}

#[test]
fn add_without_group_to_a_key_with_only_others_overrides_is_refused() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &carol, "CAROLS", "carol_only", &["--group", "me"]);
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();

    murk(&dir, &alice)
        .args(["add", "CAROLS", "--vault", "test.murk"])
        .write_stdin("alice_value\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "CAROLS holds only other recipients' personal overrides",
        ));

    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );
    assert_eq!(stored_tiers(&dir, "CAROLS"), (false, vec![]));
}

#[test]
fn add_with_explicit_group_everyone_moves_a_group_key_and_says_so() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);

    murk(&dir, &alice)
        .args(["add", "DB", "--group", "everyone", "--vault", "test.murk"])
        .write_stdin("open_db\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "moved DB from group prod to everyone",
        ));

    get_ok(&dir, &carol, "DB", "open_db");
    assert_eq!(stored_tiers(&dir, "DB"), (true, vec![]));
}

#[test]
fn add_by_a_non_member_to_a_group_key_is_refused() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "prod_db", &["--group", "prod"]);
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();

    for extra in [&[][..], &["--group", "everyone"][..]] {
        murk(&dir, &carol)
            .args(["add", "DB", "--vault", "test.murk"])
            .args(extra)
            .write_stdin("carol_db\n")
            .assert()
            .code(1)
            .stderr(predicate::str::contains(
                "DB is held by group prod, which you are not a member of",
            ));
    }

    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );
    get_ok(&dir, &alice, "DB", "prod_db");
}

#[test]
fn import_without_group_keeps_each_key_in_its_tier() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);
    add(&dir, &alice, "TOKEN", "old", &[]);
    add(&dir, &alice, "MINE", "old", &["--group", "me"]);
    fs::write(
        dir.path().join("in.env"),
        "DB=new_db\nTOKEN=new\nMINE=new\nFRESH=fresh\n",
    )
    .unwrap();

    murk(&dir, &alice)
        .args(["import", "in.env", "--force", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("DB (group prod)")
                .and(predicate::str::contains("MINE (me)"))
                .and(predicate::str::contains("imported 4 secrets\n")),
        );

    get_ok(&dir, &alice, "DB", "new_db");
    get_fails(&dir, &carol, "DB", "new_db");
    get_fails(&dir, &carol, "MINE", "new");
    get_ok(&dir, &carol, "TOKEN", "new");
    get_ok(&dir, &carol, "FRESH", "fresh");
    assert_eq!(stored_tiers(&dir, "DB"), (false, vec!["prod".to_string()]));
    assert_eq!(stored_tiers(&dir, "MINE"), (false, vec![]));
    assert_eq!(stored_tiers(&dir, "TOKEN"), (true, vec![]));
    assert_eq!(stored_tiers(&dir, "FRESH"), (true, vec![]));
}

#[test]
fn import_with_explicit_group_everyone_moves_a_group_key_and_says_so() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);
    fs::write(dir.path().join("in.env"), "DB=open_db\n").unwrap();

    murk(&dir, &alice)
        .args(["import", "in.env", "--force", "--group", "everyone"])
        .args(["--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "moved DB from group prod to everyone",
        ));

    get_ok(&dir, &carol, "DB", "open_db");
    assert_eq!(stored_tiers(&dir, "DB"), (true, vec![]));
}

#[test]
fn import_by_a_non_member_touching_a_group_key_is_refused_whole() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "prod_db", &["--group", "prod"]);
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    fs::write(dir.path().join("in.env"), "OTHER=x\nDB=carol_db\n").unwrap();

    murk(&dir, &carol)
        .args(["import", "in.env", "--force", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "DB is held by group prod, which you are not a member of",
        ));

    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );
}

#[test]
fn generate_without_group_keeps_a_group_key_in_its_group() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);

    murk(&dir, &alice)
        .args(["generate", "DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("generated DB (group prod)"));

    get_fails(&dir, &carol, "DB", "old_db");
    assert_eq!(stored_tiers(&dir, "DB"), (false, vec!["prod".to_string()]));
}

#[cfg(unix)]
#[test]
fn bulk_edit_adding_a_group_key_keeps_it_in_its_group() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "old_db", &["--group", "prod"]);

    // The shared view doesn't list DB; a DB line written there updates the
    // group value instead of creating a shared one.
    bulk_edit_appending(&dir, &alice, "DB=new_db")
        .success()
        .stderr(predicate::str::contains("1 updated"));

    get_ok(&dir, &alice, "DB", "new_db");
    get_fails(&dir, &carol, "DB", "new_db");
    assert_eq!(stored_tiers(&dir, "DB"), (false, vec!["prod".to_string()]));
}

#[cfg(unix)]
#[test]
fn bulk_edit_by_a_non_member_adding_a_group_key_is_refused() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    add(&dir, &alice, "DB", "prod_db", &["--group", "prod"]);
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();

    bulk_edit_appending(&dir, &carol, "DB=carol_db")
        .code(1)
        .stderr(predicate::str::contains(
            "DB is held by group prod, which you are not a member of",
        ));

    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );
}

/// Give `name` both a shared value and a `prod` group value, as `alice` (a
/// `prod` member). Current murk never writes this; older murk did when a
/// non-member updated a group key, so `edit` must still cope with it.
#[cfg(unix)]
fn write_shared_beside_group(dir: &TempDir, alice: &str, name: &str) {
    // save_vault signs with MURK_KEY from the environment, so the write runs
    // in a child whose environment is its own, not in this shared process.
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "write_shared_beside_group_child",
            "--nocapture",
            "--ignored",
        ])
        .env("MURK_KEY", alice)
        .env("HOME", dir.path())
        .env("SHARED_BESIDE_VAULT", dir.path().join("test.murk"))
        .env("SHARED_BESIDE_NAME", name)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The library write for [`write_shared_beside_group`].
#[cfg(unix)]
#[test]
#[ignore = "run by write_shared_beside_group"]
fn write_shared_beside_group_child() {
    let path = std::env::var("SHARED_BESIDE_VAULT").unwrap();
    let name = std::env::var("SHARED_BESIDE_NAME").unwrap();
    let alice = std::env::var("MURK_KEY").unwrap();
    let mut vault = murk_cli::vault::read(std::path::Path::new(&path)).unwrap();
    let identity = murk_cli::crypto::parse_identity(&alice).unwrap();
    let original = murk_cli::decrypt_vault(&vault, &identity).unwrap();
    let mut current = original.clone();
    current
        .values
        .insert(name.clone(), zeroize::Zeroizing::new("shared_db".into()));
    current
        .grouped
        .entry(name)
        .or_default()
        .insert("prod".into(), zeroize::Zeroizing::new("prod_db".into()));
    murk_cli::save_vault(&path, &mut vault, &original, &current).unwrap();
}

#[cfg(unix)]
#[test]
fn edit_by_a_non_member_of_a_shared_value_beside_a_group_value_is_refused() {
    let dir = TempDir::new().unwrap();
    let (alice, carol) = vault_with_outsider(&dir);
    write_shared_beside_group(&dir, &alice, "DB");
    get_ok(&dir, &carol, "DB", "shared_db");
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let log = dir.path().join("seen");

    // Single key: refused before the editor opens.
    let ed = editor(&dir, "one.sh", &log, r#"echo "carol_db" > "$1""#);
    murk(&dir, &carol)
        .args(["edit", "DB", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "DB is held by group prod, which you are not a member of",
        ));
    assert!(!log.exists(), "editor must not open");

    // All keys: the changed DB line is refused and nothing is saved.
    let ed = editor(&dir, "all.sh", &log, r#"printf 'DB=carol_db\n' > "$1""#);
    murk(&dir, &carol)
        .args(["edit", "--vault", "test.murk"])
        .env("EDITOR", &ed)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "DB is held by group prod, which you are not a member of",
        ));

    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );
}

#[test]
fn values_from_uses_the_import_parser_and_refuses_duplicates() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(&dir, &key, "S", "s0", &[]);
    add(&dir, &key, "PEM", "p0", &[]);
    let rotate = |input: &str| {
        murk(&dir, &key)
            .args([
                "rotate",
                "--all",
                "--values-from",
                "-",
                "--vault",
                "test.murk",
            ])
            .write_stdin(input.to_string())
            .assert()
    };

    // Unclosed quote and duplicate keys: refused, nothing rotated.
    rotate("S=\"open\n")
        .code(1)
        .stderr(predicate::str::contains("nothing rotated"));
    rotate("S=s1\nS=s2\n")
        .code(1)
        .stderr(predicate::str::contains("S is already set on line 1"));
    get_ok(&dir, &key, "S", "s0");

    // A quoted multi-line value arrives whole; notices name lines, not values.
    rotate("PEM=\"-----BEGIN-----\nAAAA\n-----END-----\"\nS=s1 #note\n")
        .success()
        .stderr(predicate::str::contains("line 4").and(predicate::str::contains("s1").not()));
    get_ok(&dir, &key, "PEM", "-----BEGIN-----\nAAAA\n-----END-----");
    get_ok(&dir, &key, "S", "s1 #note");
}
