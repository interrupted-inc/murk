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
    let vault = dir.path().join("test.murk");
    let before = fs::read(&vault).unwrap();
    add(&dir, &key, "TEAMMATE", "theirs", &[]);
    let theirs = dir.path().join("theirs.murk");
    fs::copy(&vault, &theirs).unwrap();
    fs::write(&vault, &before).unwrap();

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
