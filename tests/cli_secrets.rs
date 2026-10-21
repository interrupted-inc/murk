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
    let path = dir.path().join("test.murk");
    let mut vault = murk_cli::vault::read(&path).unwrap();
    let identity = murk_cli::crypto::parse_identity(alice).unwrap();
    let original = murk_cli::decrypt_vault(&vault, &identity).unwrap();
    let mut current = original.clone();
    current
        .values
        .insert(name.into(), zeroize::Zeroizing::new("shared_db".into()));
    current
        .grouped
        .entry(name.into())
        .or_default()
        .insert("prod".into(), zeroize::Zeroizing::new("prod_db".into()));
    murk_cli::save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();
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
