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
            "add", "TOKEN", "--group", "prod", "--scoped", "--vault", "test.murk",
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
        .args(["import", "in.env", "--group", "prod", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("imported 1 secret into group prod"));

    get_ok(&dir, &alice, "DB", "prod_db");
    get_fails(&dir, &carol, "DB", "prod_db");

    // An unknown group is refused and nothing is imported.
    fs::write(dir.path().join("more.env"), "OTHER=x\n").unwrap();
    murk(&dir, &alice)
        .args(["import", "more.env", "--group", "nope", "--vault", "test.murk"])
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
                .and(predicate::str::contains(r#""expired_at": "2020-01-01T23:59:59Z""#)),
        );
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
        .stderr(predicate::str::contains("withholding 1 key(s) not allowed by policy: FORBIDDEN"));

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
    assert!(seen.contains("# Editing TOKEN (me)") && seen.ends_with("mine"), "{seen:?}");
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
