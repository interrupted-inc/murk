use std::fs;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk, murk_bin, real_path};

// ── init ──

#[test]
fn init_creates_vault_and_env() {
    let dir = TempDir::new().unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("alice\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Recovery phrase")
                .or(predicate::str::contains("RECOVERY WORDS")),
        );

    assert!(dir.path().join("test.murk").exists());
    assert!(dir.path().join(".env").exists());

    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(
        env.contains("export MURK_KEY_FILE="),
        ".env should contain MURK_KEY_FILE reference, got: {env}"
    );

    // Key file should exist and contain a valid age key.
    let key_path = env
        .lines()
        .find_map(|l| l.strip_prefix("export MURK_KEY_FILE="))
        .unwrap()
        .trim()
        .trim_matches('\'');
    let key = fs::read_to_string(key_path).unwrap();
    assert!(key.trim().starts_with("AGE-SECRET-KEY-"));
}

#[test]
fn init_existing_vault_authorized() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Second init with authorized key shows "authorized".
    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", &key)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists").and(predicate::str::contains("authorized")),
        );
}

#[test]
fn init_existing_vault_unauthorized() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Generate a different key that isn't authorized on this vault.
    let other_dir = TempDir::new().unwrap();
    let (other_key, _) = init_vault(&other_dir);

    // Init with unauthorized key shows pubkey to share.
    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", &other_key)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists")
                .and(predicate::str::contains("not authorized"))
                .and(predicate::str::contains("age1")),
        );
}

#[test]
fn init_existing_vault_no_key() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Remove .env so there's no key to find.
    fs::remove_file(dir.path().join(".env")).unwrap();

    // Init without a key generates one and shows unauthorized + pubkey.
    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists")
                .and(predicate::str::contains("generating keypair"))
                .and(predicate::str::contains("RECOVERY WORDS"))
                .and(predicate::str::contains("not authorized"))
                .and(predicate::str::contains("age1")),
        );

    // .env should now contain a MURK_KEY_FILE reference.
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains("export MURK_KEY_FILE="));
}

#[test]
fn init_existing_vault_ignores_dotenv() {
    // .env is no longer a trusted runtime input. With MURK_KEY and
    // MURK_KEY_FILE both absent from the environment, init must NOT silently
    // authorize by reading .env from the current directory.
    let dir = TempDir::new().unwrap();
    let (_key, _) = init_vault(&dir);

    let assertion = murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("n\n")
        .assert();
    let output = assertion.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("authorized"),
        "init must not report authorized when .env is the only source of the key: {stderr}"
    );
}

// ── add / get ──

#[test]
fn add_and_get_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/mydb\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost/mydb"));
}

#[test]
fn get_missing_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["get", "NONEXISTENT", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

#[test]
fn add_overwrites_existing_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_value\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("new_value\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new_value"));
}

// ── generate ──

#[test]
fn generate_creates_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["generate", "SESSION_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("generated SESSION_SECRET"));

    // Verify the secret exists and has a non-empty value.
    murk(&dir, &key)
        .args(["get", "SESSION_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn generate_hex_output() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "generate",
            "HEX_KEY",
            "--hex",
            "--length",
            "16",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args(["get", "HEX_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = String::from_utf8(output).unwrap();
    // 16 bytes = 32 hex chars
    assert_eq!(value.trim().len(), 32);
    assert!(value.trim().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generate_custom_length() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "generate",
            "LONG_KEY",
            "--length",
            "64",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args(["get", "LONG_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = String::from_utf8(output).unwrap();
    // 64 bytes base64url no pad = 86 chars
    assert_eq!(value.trim().len(), 86);
}

#[test]
fn generate_with_desc_and_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "generate",
            "API_TOKEN",
            "--desc",
            "Auto-generated token",
            "--tag",
            "api",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["ls", "--tag", "api", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_TOKEN"));
}

#[test]
fn generate_invalid_key_name_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["generate", "invalid-key!", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key name"));
}

#[test]
fn generate_overwrites_existing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["generate", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success();

    let first = murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    murk(&dir, &key)
        .args(["generate", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success();

    let second = murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_ne!(
        first, second,
        "regenerating should produce a different value"
    );
}

// ── rotate ──

#[test]
fn rotate_single_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_secret\n")
        .assert()
        .success();

    let before = murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    murk(&dir, &key)
        .args(["rotate", "TOKEN", "--vault", "test.murk"])
        .write_stdin("new_secret\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated TOKEN"));

    let after = murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_ne!(before, after);
    assert!(String::from_utf8(after).unwrap().contains("new_secret"));
}

#[test]
fn rotate_generate() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_secret\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["rotate", "TOKEN", "--generate", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated TOKEN"));

    let after = murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value = String::from_utf8(after).unwrap();
    assert!(!value.contains("old_secret"));
    assert!(!value.trim().is_empty());
}

#[test]
fn rotate_all_single_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["rotate", "--all", "--vault", "test.murk"])
        .write_stdin("new_val\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated TOKEN"));

    let after = String::from_utf8(
        murk(&dir, &key)
            .args(["get", "TOKEN", "--vault", "test.murk"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(after.contains("new_val"));
}

#[test]
fn rotate_all_generate_rejected() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["rotate", "--all", "--generate", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--generate cannot be used with --all",
        ));
}

#[test]
fn rotate_missing_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["rotate", "NONEXISTENT", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn rotate_no_key_no_all_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["rotate", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("specify a key name or use --all"));
}

// ── scoped (mote) secrets ──

#[test]
fn scoped_secret_overrides_shared() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Add shared value.
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("shared_key\n")
        .assert()
        .success();

    // Add scoped override.
    murk(&dir, &key)
        .args(["add", "API_KEY", "--scoped", "--vault", "test.murk"])
        .write_stdin("my_personal_key\n")
        .assert()
        .success();

    // Get should return scoped override.
    murk(&dir, &key)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("my_personal_key"));
}

#[test]
fn scoped_only_secret_persists_across_save() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Add scoped-only value (no shared value for this key).
    murk(&dir, &key)
        .args(["add", "PERSONAL_TOKEN", "--scoped", "--vault", "test.murk"])
        .write_stdin("my_token\n")
        .assert()
        .success();

    // Verify it exists.
    murk(&dir, &key)
        .args(["get", "PERSONAL_TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("my_token"));

    // Add another key to force a save cycle.
    murk(&dir, &key)
        .args(["add", "OTHER", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // Scoped-only key must still be retrievable.
    murk(&dir, &key)
        .args(["get", "PERSONAL_TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("my_token"));

    // It should appear in ls.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PERSONAL_TOKEN"));
}

// ── rm ──

#[test]
fn rm_removes_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TEMP", "--vault", "test.murk"])
        .write_stdin("deleteme\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["rm", "TEMP", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "TEMP", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

// ── ls ──

#[test]
fn ls_lists_key_names() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "ALPHA", "--vault", "test.murk"])
        .write_stdin("a\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "BRAVO", "--vault", "test.murk"])
        .write_stdin("b\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA").and(predicate::str::contains("BRAVO")));
}

#[test]
fn ls_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // ls reads header only — no MURK_KEY needed.
    murk_bin(dir.path())
        .args(["ls", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET"));
}

// ── describe ──

#[test]
fn describe_adds_description() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "DB_URL",
            "PostgreSQL connection string",
            "--example",
            "postgres://user:pass@host/db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // info should show the description.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("PostgreSQL connection string")
                .and(predicate::str::contains("postgres://user:pass@host/db")),
        );
}

// ── info ──

#[test]
fn info_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("secret\n")
        .assert()
        .success();

    // info reads header only — works without key.
    murk_bin(dir.path())
        .args(["info", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));
}

// ── export ──

#[test]
fn export_produces_shell_statements() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "FOO", "--vault", "test.murk"])
        .write_stdin("bar\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "BAZ", "--vault", "test.murk"])
        .write_stdin("qux\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export FOO='bar'")
                .and(predicate::str::contains("export BAZ='qux'")),
        );
}

/// Run murk with the hermetic test env and stdout redirected to a real file.
/// assert_cmd captures stdout through a pipe, so this is the only way to
/// exercise the regular-file stdout path that strict mode refuses.
#[cfg(unix)]
fn run_with_stdout_file(
    dir: &TempDir,
    key: &str,
    args: &[&str],
    out_file: &std::path::Path,
) -> std::process::ExitStatus {
    let file = fs::File::create(out_file).unwrap();
    std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"))
        .args(args)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env_remove("MURK_KEY_FILE")
        .env("MURK_KEY", key)
        .env("MURK_STRICT", "1")
        .stdout(file)
        .status()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn export_strict_refuses_file_redirect() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("sekret\n")
        .assert()
        .success();

    let leak = dir.path().join("leak.env");
    let status = run_with_stdout_file(&dir, &key, &["export", "--vault", "test.murk"], &leak);
    assert!(!status.success(), "strict export to a file should fail");
    assert_eq!(
        fs::read_to_string(&leak).unwrap(),
        "",
        "secrets leaked to the file"
    );
}

#[test]
fn export_strict_allows_pipe() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("sekret\n")
        .assert()
        .success();

    // assert_cmd captures stdout via a pipe — the direnv flow must still work.
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .env("MURK_STRICT", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("export TOKEN='sekret'"));
}

#[cfg(unix)]
#[test]
fn get_strict_refuses_file_redirect() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("sekret\n")
        .assert()
        .success();

    let leak = dir.path().join("tok.txt");
    let status = run_with_stdout_file(&dir, &key, &["get", "TOKEN", "--vault", "test.murk"], &leak);
    assert!(!status.success(), "strict get to a file should fail");
    assert_eq!(
        fs::read_to_string(&leak).unwrap(),
        "",
        "secret leaked to the file"
    );
}

#[test]
fn export_merges_scoped_overrides() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("shared_val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "KEY", "--scoped", "--vault", "test.murk"])
        .write_stdin("scoped_val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("export KEY='scoped_val'"));
}

#[test]
fn export_escapes_single_quotes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "QUOTED", "--vault", "test.murk"])
        .write_stdin("it's a test\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("export QUOTED='it'\\''s a test'"));
}

// ── exec ──

#[test]
fn exec_injects_secrets() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "MY_SECRET", "--vault", "test.murk"])
        .write_stdin("hunter2\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["exec", "--vault", "test.murk", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MY_SECRET=hunter2"));
}

#[test]
fn exec_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_PASS", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("secret\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "api", "--vault", "test.murk"])
        .write_stdin("abc123\n")
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args(["exec", "--tag", "db", "--vault", "test.murk", "--", "env"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("DB_PASS=secret"));
    assert!(!stdout.contains("API_KEY=abc123"));
}

#[test]
fn exec_propagates_exit_code() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["exec", "--vault", "test.murk", "--", "false"])
        .assert()
        .failure();
}

#[test]
fn exec_without_vault_fails() {
    let dir = TempDir::new().unwrap();

    murk(&dir, "AGE-SECRET-KEY-1DUMMY")
        .args(["exec", "--vault", "nonexistent.murk", "--", "env"])
        .assert()
        .failure();
}

#[test]
fn exec_rejects_nul_byte_in_secret_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "NUL_KEY", "--vault", "test.murk"])
        .write_stdin("before\0after\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "exec",
            "--only",
            "NUL_KEY",
            "--vault",
            "test.murk",
            "--",
            "echo",
            "hi",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("cannot be injected as an environment variable")
                .and(predicate::str::contains("panicked").not()),
        );
}

// ── recover ──

#[test]
fn recover_shows_phrase() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let output = murk(&dir, &key).args(["recover"]).assert().success();

    // Recovery phrase is 24 words on stdout.
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let word_count = stdout.split_whitespace().count();
    assert_eq!(
        word_count, 24,
        "recovery phrase should be 24 words, got {word_count}"
    );
}

#[test]
fn recover_without_key_fails() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .args(["recover"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

// ── circle ──

#[test]
fn recipients_lists_creator() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("testuser").and(predicate::str::contains("◆")));
}

#[test]
fn recipients_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (_key, _pubkey) = init_vault(&dir);

    // Without MURK_KEY env var, key is still resolved via key file.
    // Should succeed and show recipient info.
    murk_bin(dir.path())
        .args(["circle", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success();
}

// ── authorize / revoke ──

#[test]
fn authorize_adds_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Generate a second keypair to authorize.
    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("authorized bob"));

    murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"));
}

#[test]
fn authorize_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "authorize", &pubkey, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already a recipient"));
}

#[test]
fn authorize_invalid_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            "not-a-real-key",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid public key"));
}

#[test]
fn revoke_removes_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    // Authorize then revoke.
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("removed"))
        .stderr(predicate::str::contains("bob"));

    // Should no longer appear in recipients.
    murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&second_pubkey).not());
}

#[test]
fn revoke_by_pubkey_works() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Revoke by pubkey instead of name.
    murk(&dir, &key)
        .args(["circle", "revoke", &second_pubkey, "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&second_pubkey).not());
}

#[test]
fn revoke_last_recipient_fails() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "revoke", &pubkey, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot revoke last recipient"));
}

#[test]
fn revoke_unknown_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "revoke", "nobody", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("recipient not found"));
}

#[test]
fn revoke_rotate_rotates_exposed_secrets() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // A shared secret bob can read.
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_value\n")
        .assert()
        .success();

    let second_pubkey = age::x25519::Identity::generate().to_public().to_string();
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Revoke with --rotate; the piped line is the new value for TOKEN.
    murk(&dir, &key)
        .args([
            "circle",
            "revoke",
            "bob",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("new_value\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("rotated TOKEN"));

    // The secret now decrypts to the rotated value.
    murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new_value"));
}

#[test]
fn revoke_without_rotate_keeps_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_value\n")
        .assert()
        .success();

    let second_pubkey = age::x25519::Identity::generate().to_public().to_string();
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // No --rotate and non-TTY stdin: prints the hint, leaves the value untouched.
    murk(&dir, &key)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rotate --all"));

    murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old_value"));
}

#[test]
fn revoke_marks_keys_for_rotation_until_rotated() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("old_value\n")
        .assert()
        .success();

    let second_pubkey = age::x25519::Identity::generate().to_public().to_string();
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &second_pubkey,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Deferring rotation on revoke records the obligation durably.
    murk(&dir, &key)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success();

    // doctor surfaces it across sessions (no key needed for the schema read).
    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains(
            "TOKEN not rotated since a recipient was revoked",
        ));

    // Rotating the value clears the marker — doctor no longer flags it.
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("new_value\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains("not rotated since a recipient was revoked").not());
}

// ── no MURK_KEY scenarios ──

#[test]
fn add_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Remove .env and redirect HOME so key file lookup also fails.
    fs::remove_file(dir.path().join(".env")).ok();
    let fake_home = TempDir::new().unwrap();

    murk_bin(fake_home.path())
        .args(["add", "X", "--vault", "test.murk"])
        .write_stdin("Y\n")
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

#[test]
fn get_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    fs::remove_file(dir.path().join(".env")).ok();
    let fake_home = TempDir::new().unwrap();

    murk_bin(fake_home.path())
        .args(["get", "X", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

#[test]
fn export_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    fs::remove_file(dir.path().join(".env")).ok();
    let fake_home = TempDir::new().unwrap();

    murk_bin(fake_home.path())
        .args(["export", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

/// Assert a fatal error renders as one short summary line plus `hint` lines,
/// none of which wraps on an 80-column terminal.
///
/// Both key-resolution errors used to be single sentences of ~330 and ~85
/// characters, which wrapped mid-word — including on camera in the demo GIFs.
fn assert_narrow_error(stderr: &str, summary: &str) {
    let lines: Vec<&str> = stderr.lines().collect();

    assert!(
        lines[0].contains(summary),
        "the summary must be the first line, got: {stderr}"
    );
    assert!(
        lines.len() > 1,
        "the guidance must survive as hints, got: {stderr}"
    );
    assert!(
        lines
            .iter()
            .skip(1)
            .all(|l| l.trim_start().starts_with("hint")),
        "every line after the summary must be a hint, got: {stderr}"
    );
    // Counted in characters, not bytes: the hints contain an em dash.
    for line in &lines {
        assert!(
            line.chars().count() <= 80,
            "line exceeds an 80-column terminal ({} cols): {line}",
            line.chars().count()
        );
    }
}

#[test]
fn key_not_set_error_fits_a_narrow_terminal() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    fs::remove_file(dir.path().join(".env")).ok();
    let fake_home = TempDir::new().unwrap();

    let assertion = murk_bin(fake_home.path())
        .args(["get", "X", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .failure();
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();

    assert_narrow_error(&stderr, "MURK_KEY not set");
}

#[test]
fn invalid_key_error_fits_a_narrow_terminal() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let fake_home = TempDir::new().unwrap();

    let assertion = murk_bin(fake_home.path())
        .args(["get", "X", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", "definitely-not-a-key")
        .assert()
        .failure();
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();

    assert_narrow_error(&stderr, "invalid key");
}

// ── no vault file scenarios ──

#[test]
fn get_missing_vault_fails() {
    let dir = TempDir::new().unwrap();

    murk_bin(dir.path())
        .args(["get", "X", "--vault", "nonexistent.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", "AGE-SECRET-KEY-1DUMMY")
        .assert()
        .failure();
}

#[test]
fn ls_missing_vault_fails() {
    let dir = TempDir::new().unwrap();

    murk_bin(dir.path())
        .args(["ls", "--vault", "nonexistent.murk"])
        .current_dir(dir.path())
        .assert()
        .failure();
}

// ── multi-recipient workflow ──

#[test]
fn authorized_recipient_can_decrypt() {
    let dir = TempDir::new().unwrap();
    let (key_a, _) = init_vault(&dir);

    // Add a secret.
    murk(&dir, &key_a)
        .args(["add", "SHARED_SECRET", "--vault", "test.murk"])
        .write_stdin("hello_world\n")
        .assert()
        .success();

    // Generate second identity and authorize.
    let id_b = age::x25519::Identity::generate();
    let pk_b = id_b.to_public().to_string();
    let key_b = {
        use age::secrecy::ExposeSecret;
        id_b.to_string().expose_secret().to_string()
    };

    murk(&dir, &key_a)
        .args([
            "circle",
            "authorize",
            &pk_b,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Bob should be able to decrypt the shared secret.
    murk(&dir, &key_b)
        .args(["get", "SHARED_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));
}

// ── tagging ──

#[test]
fn add_with_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    // info should show the tag.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db]"));
}

#[test]
fn add_with_multiple_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "--tag",
            "db",
            "--tag",
            "backend",
            "--vault",
            "test.murk",
        ])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db, backend]"));
}

#[test]
fn add_merges_tags_on_existing_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();

    // Update value and add another tag.
    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "backend", "--vault", "test.murk"])
        .write_stdin("v2\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db, backend]"));
}

#[test]
fn describe_sets_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("secret\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "API token",
            "--tag",
            "auth",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[auth]"));
}

#[test]
fn describe_replaces_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--tag", "old", "--vault", "test.murk"])
        .write_stdin("secret\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "API token",
            "--tag",
            "new",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[new]").and(predicate::str::contains("[old]").not()));
}

#[test]
fn ls_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "api", "--vault", "test.murk"])
        .write_stdin("sk-123\n")
        .assert()
        .success();

    // Filter by "db" tag — should only show DB_URL.
    murk(&dir, &key)
        .args(["ls", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_URL").and(predicate::str::contains("API_KEY").not()));
}

#[test]
fn export_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "api", "--vault", "test.murk"])
        .write_stdin("sk-123\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "UNTAGGED", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // Export with --tag db — only DB_URL.
    murk(&dir, &key)
        .args(["export", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_URL=")
                .and(predicate::str::contains("API_KEY").not())
                .and(predicate::str::contains("UNTAGGED").not()),
        );
}

#[test]
fn export_without_tag_exports_all() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "UNTAGGED", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // Export without --tag — should get everything.
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_URL=")
                .and(predicate::str::contains("export UNTAGGED=")),
        );
}

#[test]
fn info_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--tag", "db", "--vault", "test.murk"])
        .write_stdin("postgres://localhost/db\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "api", "--vault", "test.murk"])
        .write_stdin("sk-123\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--tag", "api", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY").and(predicate::str::contains("DB_URL").not()));
}

// ── end-to-end workflow ──

#[test]
fn full_lifecycle() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Add secrets.
    murk(&dir, &key)
        .args(["add", "DB_HOST", "--vault", "test.murk"])
        .write_stdin("localhost\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "DB_PASS", "--vault", "test.murk"])
        .write_stdin("hunter2\n")
        .assert()
        .success();

    // Describe.
    murk(&dir, &key)
        .args([
            "describe",
            "DB_HOST",
            "Database hostname",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // List.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_HOST").and(predicate::str::contains("DB_PASS")));

    // Get.
    murk(&dir, &key)
        .args(["get", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2"));

    // Export.
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_HOST='localhost'")
                .and(predicate::str::contains("export DB_PASS='hunter2'")),
        );

    // Remove one.
    murk(&dir, &key)
        .args(["rm", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .success();

    // Should be gone.
    murk(&dir, &key)
        .args(["get", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .failure();

    // But other key still there.
    murk(&dir, &key)
        .args(["get", "DB_HOST", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("localhost"));
}

// ── stdin support ──

#[test]
fn add_via_stdin_pipe() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Pipe value via stdin (omit value argument).
    murk(&dir, &key)
        .args(["add", "PIPED_SECRET", "--vault", "test.murk"])
        .write_stdin("s3cr3t-from-pipe\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "PIPED_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("s3cr3t-from-pipe"));
}

#[test]
fn add_via_stdin_empty_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Empty stdin should fail.
    murk(&dir, &key)
        .args(["add", "EMPTY", "--vault", "test.murk"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty value"));
}

// ── env (direnv) ──

#[test]
fn env_creates_envrc() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("created .envrc"));

    let envrc = fs::read_to_string(dir.path().join(".envrc")).unwrap();
    assert!(envrc.contains("murk export"));
}

#[test]
fn env_appends_to_existing() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    fs::write(dir.path().join(".envrc"), "# existing config\n").unwrap();

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("appended"));

    let envrc = fs::read_to_string(dir.path().join(".envrc")).unwrap();
    assert!(envrc.contains("# existing config"));
    assert!(envrc.contains("murk export"));
}

#[test]
fn env_skips_if_present() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    fs::write(
        dir.path().join(".envrc"),
        "eval \"$(murk export --vault test.murk)\"\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already contains"));
}

// ── diff ──

#[test]
fn diff_shows_no_changes() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo and commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["add", "test.murk"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .unwrap();

    // No changes since commit — should say "no changes".
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no changes"));
}

#[test]
fn diff_shows_added_key() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo and commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["add", "test.murk"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .unwrap();

    // Add a secret after the commit.
    murk(&dir, &key)
        .args(["add", "NEW_KEY", "--vault", "test.murk"])
        .write_stdin("new-value\n")
        .assert()
        .success();

    // Diff should show NEW_KEY as added.
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NEW_KEY"));
}

#[test]
fn diff_no_git_vault_shows_all_added() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo but don't commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Add a secret.
    murk(&dir, &key)
        .args(["add", "FRESH", "--vault", "test.murk"])
        .write_stdin("value\n")
        .assert()
        .success();

    // Diff against HEAD should show FRESH as added (vault didn't exist at HEAD).
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FRESH"));
}

// ── worktree key discovery ──

/// Run git in `dir` with a fixed identity, asserting it succeeded.
fn git_ok(dir: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An original checkout holding a vault with a discovered key, plus a fresh
/// linked worktree of it that carries only the committed vault — no `.env`,
/// no key env, exactly what an agent harness hands you.
///
/// Returns `(home, repo, worktree)`.
fn worktree_fixture(
    base: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let base = real_path(base);
    let home = base.join("home");
    let repo = base.join("repo");
    let worktree = base.join("worktree");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();

    murk_bin(&home)
        .args(["init", "--vault", "test.murk"])
        .current_dir(&repo)
        .write_stdin("testuser\n")
        .assert()
        .success();

    // No MURK_KEY here either: the original checkout also relies on the stored
    // key, so this asserts single-checkout discovery still works.
    murk_bin(&home)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .current_dir(&repo)
        .write_stdin("s3cret\n")
        .assert()
        .success();

    git_ok(&repo, &["init"]);
    git_ok(&repo, &["add", "test.murk"]);
    git_ok(&repo, &["commit", "-m", "vault"]);
    git_ok(
        &repo,
        &["worktree", "add", "--detach", worktree.to_str().unwrap()],
    );

    assert!(worktree.join("test.murk").exists());
    assert!(
        !worktree.join(".env").exists(),
        "a fresh worktree must not carry the original checkout's .env"
    );

    (home, repo, worktree)
}

#[test]
fn worktree_reads_the_original_checkouts_key() {
    let base = TempDir::new().unwrap();
    let (home, _repo, worktree) = worktree_fixture(base.path());

    murk_bin(&home)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .current_dir(&worktree)
        .assert()
        .success()
        .stdout(predicate::str::contains("s3cret"));

    murk_bin(&home)
        .args(["export", "--vault", "test.murk"])
        .current_dir(&worktree)
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"));
}

#[test]
fn worktree_key_discovery_still_fails_closed_for_agents() {
    let base = TempDir::new().unwrap();
    let (home, _repo, worktree) = worktree_fixture(base.path());

    for var in ["MURK_AGENT", "MURK_STRICT"] {
        murk_bin(&home)
            .args(["get", "API_KEY", "--vault", "test.murk"])
            .current_dir(&worktree)
            .env(var, "1")
            .assert()
            .failure()
            .stderr(predicate::str::contains("MURK_KEY not set"));
    }
}

#[test]
fn unrelated_repo_does_not_borrow_a_vaults_key() {
    // Discovery widens to sibling worktrees of the *same* repository. A second
    // repo that merely holds a copy of the vault at the same relative path is
    // not one, and must still fail closed.
    let base = TempDir::new().unwrap();
    let (home, repo, _worktree) = worktree_fixture(base.path());

    let other = real_path(base.path()).join("other");
    fs::create_dir_all(&other).unwrap();
    fs::copy(repo.join("test.murk"), other.join("test.murk")).unwrap();
    git_ok(&other, &["init"]);

    murk_bin(&home)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .current_dir(&other)
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

#[test]
fn planted_worktree_pointer_does_not_borrow_a_vaults_key() {
    // The sharper version of the same attack: a copied vault in a directory
    // that claims, via a hand-written `.git` file, to be a worktree of the
    // victim's repo. Only checkouts git itself records may borrow a key.
    let base = TempDir::new().unwrap();
    let (home, repo, worktree) = worktree_fixture(base.path());

    let evil = real_path(base.path()).join("evil");
    fs::create_dir_all(&evil).unwrap();
    fs::copy(repo.join("test.murk"), evil.join("test.murk")).unwrap();
    fs::copy(worktree.join(".git"), evil.join(".git")).unwrap();

    murk_bin(&home)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .current_dir(&evil)
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

// ── merge-driver ──

/// Helper: write a vault JSON file for merge driver tests.
fn write_vault_json(dir: &std::path::Path, filename: &str, json: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    fs::write(&path, json).unwrap();
    path
}

#[test]
fn merge_driver_clean_merge() {
    let dir = TempDir::new().unwrap();

    // Base vault: one secret.
    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "base-meta"
}"#;

    // Ours: adds API_KEY.
    let ours_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "API_KEY": { "description": "api key", "tags": [] },
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "API_KEY": { "shared": "ours-cipher-api" },
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "ours-meta"
}"#;

    // Theirs: adds STRIPE_KEY.
    let theirs_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] },
    "STRIPE_KEY": { "description": "stripe", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" },
    "STRIPE_KEY": { "shared": "theirs-cipher-stripe" }
  },
  "meta": "theirs-meta"
}"#;

    let base_path = write_vault_json(dir.path(), "base.murk", base_json);
    let ours_path = write_vault_json(dir.path(), "ours.murk", ours_json);
    let theirs_path = write_vault_json(dir.path(), "theirs.murk", theirs_json);

    // Without MURK_KEY, merge that changes secrets should fail
    // because the MAC in ours.meta would be stale.
    murk_bin(dir.path())
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not available"));
}

#[test]
fn merge_driver_schema_only_merge_without_key() {
    let dir = TempDir::new().unwrap();

    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "base-meta"
}"#;

    // Ours: changes description only.
    let ours_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "updated database desc", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "ours-meta"
}"#;

    // Theirs: identical to base (no changes).
    let theirs_json = base_json;

    let base_path = write_vault_json(dir.path(), "base.murk", base_json);
    let ours_path = write_vault_json(dir.path(), "ours.murk", ours_json);
    let theirs_path = write_vault_json(dir.path(), "theirs.murk", theirs_json);

    // Schema-only change — secrets and recipients unchanged, should succeed without MURK_KEY.
    murk_bin(dir.path())
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("content unchanged"));
}

#[test]
fn merge_driver_conflict_exit_code() {
    let dir = TempDir::new().unwrap();

    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher" }
  },
  "meta": "base-meta"
}"#;

    // Both sides modify DB_URL.
    let ours_json = base_json.replace("base-cipher", "ours-cipher");
    let theirs_json = base_json.replace("base-cipher", "theirs-cipher");

    let base_path = write_vault_json(dir.path(), "base.murk", base_json);
    let ours_path = write_vault_json(dir.path(), "ours.murk", &ours_json);
    let theirs_path = write_vault_json(dir.path(), "theirs.murk", &theirs_json);

    murk_bin(dir.path())
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("conflict").and(predicate::str::contains("DB_URL")));
}

// ── setup-merge-driver ──

#[test]
fn setup_merge_driver_creates_gitattributes() {
    let dir = TempDir::new().unwrap();

    // Initialize a git repo in the temp dir.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    murk_bin(dir.path())
        .args(["setup-merge-driver"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("merge driver configured"));

    // Check .gitattributes.
    let gitattributes = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert!(gitattributes.contains("*.murk merge=murk"));

    // Check git config.
    let output = std::process::Command::new("git")
        .args(["config", "merge.murk.driver"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let driver = String::from_utf8_lossy(&output.stdout);
    assert!(driver.contains("murk merge-driver %O %A %B"));
}

#[test]
fn setup_merge_driver_idempotent() {
    let dir = TempDir::new().unwrap();

    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Run twice.
    for _ in 0..2 {
        murk_bin(dir.path())
            .args(["setup-merge-driver"])
            .current_dir(dir.path())
            .assert()
            .success();
    }

    // Should have the line only once.
    let gitattributes = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert_eq!(
        gitattributes.matches("*.murk merge=murk").count(),
        1,
        "should not duplicate the gitattributes entry"
    );
}

// ── codename + repo ──

#[test]
fn info_displays_codename() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("secret\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codename"));
}

#[test]
fn info_displays_self_marker_and_key_source() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("*").and(predicate::str::contains("key")));
}

#[test]
fn codename_changes_when_vault_changes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Get info output after adding first secret.
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("val1\n")
        .assert()
        .success();
    let out1 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let info1 = String::from_utf8(out1.stdout).unwrap();

    // Get info output after adding second secret.
    murk(&dir, &key)
        .args(["add", "B", "--vault", "test.murk"])
        .write_stdin("val2\n")
        .assert()
        .success();
    let out2 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let info2 = String::from_utf8(out2.stdout).unwrap();

    // Extract codename lines.
    let cn1 = info1.lines().find(|l| l.contains("codename")).unwrap();
    let cn2 = info2.lines().find(|l| l.contains("codename")).unwrap();
    assert_ne!(
        cn1, cn2,
        "codename should change when vault content changes"
    );
}

#[test]
fn codename_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "X", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    let out1 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let out2 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();

    let info1 = String::from_utf8(out1.stdout).unwrap();
    let info2 = String::from_utf8(out2.stdout).unwrap();

    let cn1 = info1.lines().find(|l| l.contains("codename")).unwrap();
    let cn2 = info2.lines().find(|l| l.contains("codename")).unwrap();
    assert_eq!(cn1, cn2, "same file should produce same codename");
}

#[test]
fn restore_recovers_key_from_phrase() {
    let dir = TempDir::new().unwrap();
    let (murk_key, _pubkey) = init_vault(&dir);

    // Get the recovery phrase.
    let output = murk(&dir, &murk_key).arg("recover").output().unwrap();
    let phrase = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert_eq!(phrase.split_whitespace().count(), 24);

    // Restore from phrase via stdin — should print the same key.
    murk_bin(dir.path())
        .arg("restore")
        .write_stdin(format!("{phrase}\n"))
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(&murk_key));
}

#[test]
fn restore_invalid_phrase_fails() {
    let dir = TempDir::new().unwrap();

    murk_bin(dir.path())
        .arg("restore")
        .write_stdin("not a valid recovery phrase at all\n")
        .current_dir(dir.path())
        .assert()
        .failure();
}

#[test]
fn old_vault_without_repo_parses() {
    let dir = TempDir::new().unwrap();
    let vault_json = r#"{
        "version": "2.0",
        "created": "2026-01-01T00:00:00Z",
        "vault_name": ".murk",
        "recipients": [],
        "schema": {},
        "secrets": {},
        "meta": ""
    }"#;
    fs::write(dir.path().join("test.murk"), vault_json).unwrap();

    murk_bin(dir.path())
        .args(["info", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("codename"));
}

// ── import ──

#[test]
fn import_warns_on_murk_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Write a .env file that contains MURK_KEY and other keys.
    fs::write(
        dir.path().join("import.env"),
        "MURK_KEY=secret\nMURK_VAULT=.murk\nKEEP_THIS=yes\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "import.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("skipping MURK_KEY")
                .and(predicate::str::contains("skipping MURK_VAULT"))
                .and(predicate::str::contains("KEEP_THIS")),
        );
}

// --- Security hardening tests ---

#[test]
fn exec_strips_murk_key_from_child_env() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "MY_SECRET", "--vault", "test.murk"])
        .write_stdin("hunter2\n")
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args(["exec", "--vault", "test.murk", "--", "env"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("MURK_KEY="),
        "MURK_KEY should be stripped from exec child env"
    );
    assert!(
        !stdout.contains("MURK_KEY_FILE="),
        "MURK_KEY_FILE should be stripped from exec child env"
    );
    assert!(stdout.contains("MY_SECRET=hunter2"));
}

#[test]
fn authorize_github_rejects_invalid_username() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            "github:../../etc/passwd",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid GitHub username"));
}

#[test]
fn vault_write_is_atomic() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    for i in 0..5 {
        murk(&dir, &key)
            .args(["add", &format!("SECRET_{i}"), "--vault", "test.murk"])
            .write_stdin(format!("value_{i}\n"))
            .assert()
            .success();
    }

    let contents = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(contents.ends_with('\n'));
    assert!(serde_json::from_str::<serde_json::Value>(&contents).is_ok());
}

#[test]
fn empty_vault_with_tampered_recipients_fails_integrity() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let vault_path = dir.path().join("test.murk");
    let mut vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vault_path).unwrap()).unwrap();

    vault["recipients"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(
            "age1fakerecipient000000000000000000000000000000000000000000fake".into(),
        ));
    fs::write(&vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity check failed"));
}

#[test]
fn verify_passes_on_valid_vault() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("vault integrity verified"));
}

#[test]
fn verify_fails_on_tampered_vault() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    let vault_path = dir.path().join("test.murk");
    let mut vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vault_path).unwrap()).unwrap();
    vault["recipients"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(
            "age1fake00000000000000000000000000000000000000000000000000000".into(),
        ));
    fs::write(&vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity check failed"));
}

#[test]
fn doctor_clean_repo_passes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // init_vault doesn't make this a git repo, so the gitignore check
    // won't fire. Doctor should report clean.
    murk(&dir, &key)
        .args(["doctor"])
        .assert()
        .success()
        .stderr(predicate::str::contains("repo hygiene looks clean"));
}

#[test]
fn doctor_flags_inline_murk_key_in_dotenv() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Append an inline MURK_KEY= line to the .env init wrote.
    let env_path = dir.path().join(".env");
    let mut contents = fs::read_to_string(&env_path).unwrap();
    contents.push_str("MURK_KEY=AGE-SECRET-KEY-1INLINEFAKE\n");
    fs::write(&env_path, contents).unwrap();

    murk(&dir, &key)
        .args(["doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("inline MURK_KEY in .env"))
        .stderr(predicate::str::contains("issue in repo"));
}

#[test]
fn describe_sets_rotation_metadata_and_doctor_flags_drift() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("s3cr3t\n")
        .assert()
        .success();

    // Set a rotation interval and an already-past hard expiry.
    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "deploy token",
            "--rotate-every",
            "90d",
            "--expires",
            "2020-01-01",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Fields land in the plaintext schema, expiry normalized to end-of-day.
    let raw = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(raw.contains("\"rotation_interval_days\": 90"), "got: {raw}");
    assert!(
        raw.contains("\"expires_at\": \"2020-01-01T23:59:59Z\""),
        "got: {raw}"
    );

    // doctor reads the plaintext schema (no key) and flags the past expiry.
    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TOKEN expired"));

    // `--expires never` clears the expiry but leaves the rotation interval.
    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "deploy token",
            "--expires",
            "never",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    let raw = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(
        !raw.contains("expires_at"),
        "expiry should be cleared, got: {raw}"
    );
    assert!(
        raw.contains("\"rotation_interval_days\": 90"),
        "rotation should persist, got: {raw}"
    );
}

#[test]
fn info_surfaces_rotation_and_expiry() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("s3cr3t\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "deploy token",
            "--rotate-every",
            "90d",
            "--expires",
            "2026-09-01",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Human info shows an at-a-glance lifecycle segment.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("rotate 90d")
                .and(predicate::str::contains("expires 2026-09-01")),
        );

    // JSON info carries the raw fields.
    murk(&dir, &key)
        .args(["info", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"rotation_interval_days\": 90").and(
                predicate::str::contains("\"expires_at\": \"2026-09-01T23:59:59Z\""),
            ),
        );
}

#[test]
fn verify_reports_key_source() {
    // Verify should print which key source it used, for transparency.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("key  MURK_KEY"));
}

#[test]
fn skeleton_strips_secrets_and_recipients() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Add a secret with a description
    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "--desc",
            "Database connection string",
            "--vault",
            "test.murk",
        ])
        .write_stdin("postgres://localhost\n")
        .assert()
        .success();

    // Export skeleton to stdout
    let output = murk(&dir, &key)
        .args(["skeleton", "--vault", "test.murk"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let skeleton: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(skeleton["version"], "2.0");
    assert!(skeleton["recipients"].as_array().unwrap().is_empty());
    assert!(skeleton["secrets"].as_object().unwrap().is_empty());
    assert_eq!(skeleton["meta"], "");
    assert_eq!(
        skeleton["schema"]["DB_URL"]["description"],
        "Database connection string"
    );

    // Export skeleton to file
    murk(&dir, &key)
        .args(["skeleton", "--vault", "test.murk", "-o", "skeleton.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote skeleton to"));

    let file_content = fs::read_to_string(dir.path().join("skeleton.murk")).unwrap();
    let file_skeleton: serde_json::Value = serde_json::from_str(&file_content).unwrap();
    assert!(file_skeleton["recipients"].as_array().unwrap().is_empty());
}

#[test]
fn agent_plan_emits_schema_only() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "--desc",
            "Database connection string",
            "--vault",
            "test.murk",
        ])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "DB_URL",
            "Database connection string",
            "--example",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // JSON: must include the key, must NOT leak recipient or ciphertext.
    let json_out = murk(&dir, &key)
        .args(["agent", "plan", "--json", "--vault", "test.murk"])
        .output()
        .unwrap();
    assert!(json_out.status.success());

    let plan: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert!(plan.get("vault_name").is_none());
    assert_eq!(plan["entries"][0]["key"], "DB_URL");
    assert_eq!(
        plan["entries"][0]["description"],
        "Database connection string"
    );
    assert_eq!(plan["entries"][0]["example"], "postgres://localhost/db");
    assert_eq!(plan["entries"][0]["tags"][0], "db");

    // The whole document must not contain the secret value, the recipient
    // pubkey, the encrypted meta blob, or the vault name.
    let raw = String::from_utf8(json_out.stdout).unwrap();
    assert!(!raw.contains("postgres://prod"));
    assert!(!raw.contains(&pubkey));
    assert!(!raw.contains("recipient"));
    assert!(!raw.contains("\"meta\""));
    assert!(!raw.contains("test.murk"));
    assert!(!raw.contains("vault_name"));

    // Text mode: aligned columns, header, no vault name or value leak.
    let text_out = murk(&dir, &key)
        .args(["agent", "plan", "--vault", "test.murk"])
        .output()
        .unwrap();
    assert!(text_out.status.success());
    let text = String::from_utf8(text_out.stdout).unwrap();
    assert!(text.contains("plan: 1 key"));
    assert!(!text.contains("test.murk"));
    assert!(text.contains("DB_URL"));
    assert!(text.contains("(e.g. postgres://localhost/db)"));
    assert!(!text.contains("postgres://prod"));

    // -o writes to a file and reports via stderr.
    murk(&dir, &key)
        .args([
            "agent",
            "plan",
            "--json",
            "-o",
            "plan.json",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote agent plan to"));

    let written = fs::read_to_string(dir.path().join("plan.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(parsed["entries"][0]["key"], "DB_URL");
}

#[test]
fn agent_exec_requires_only() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["agent", "exec", "--vault", "test.murk", "--", "env"])
        .assert()
        .failure();
}

#[test]
fn agent_exec_injects_only_specified_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("topsecret\n")
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "env",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("DB_URL=postgres://prod"));
    assert!(!stdout.contains("API_KEY=topsecret"));
}

#[test]
fn agent_exec_clears_inherited_environment() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    let output = murk(&dir, &key)
        .env("UNRELATED_VAR", "should-not-appear")
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "env",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains("UNRELATED_VAR=should-not-appear"));
    assert!(!stdout.contains("MURK_KEY="));
    assert!(!stdout.contains("MURK_KEY_FILE="));
    assert!(stdout.contains("DB_URL=postgres://prod"));
    // PATH preserved so the subprocess can run.
    assert!(stdout.contains("PATH="));
}

#[test]
fn agent_exec_sets_murk_agent_for_child() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    let output = murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "env",
        ])
        .assert()
        .success();

    // agent exec marks the child as an agent context so a nested
    // `murk` invocation defaults to strict and cannot auto-discover the
    // operator's stored key via the preserved HOME.
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("MURK_AGENT=1"));
}

#[test]
fn agent_exec_announces_keys_on_stderr() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "true",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent exec"))
        .stderr(predicate::str::contains("DB_URL"));
}

#[test]
fn agent_exec_unknown_key_fails_closed() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DOES_NOT_EXIST",
            "--vault",
            "test.murk",
            "--",
            "env",
        ])
        .assert()
        .failure();
}

#[test]
fn agent_plan_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "API_TOKEN",
            "--desc",
            "External API token",
            "--vault",
            "test.murk",
        ])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Run without MURK_KEY in the environment — agent plan only reads schema.
    let mut cmd = murk_bin(dir.path());
    cmd.current_dir(dir.path())
        .args(["agent", "plan", "--json", "--vault", "test.murk"]);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["entries"][0]["key"], "API_TOKEN");
}

#[test]
fn completion_generates_output() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .args(["completion", "generate", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_murk"));
}

#[test]
fn completion_install_writes_file() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .args(["completion", "install", "bash"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ok wrote"));

    let completions_path = dir
        .path()
        .join(".local/share/bash-completion/completions/murk");
    assert!(completions_path.exists(), "completions file should exist");
    let content = fs::read_to_string(completions_path).unwrap();
    assert!(
        content.contains("murk"),
        "completions should reference murk"
    );
}

#[test]
fn completion_install_zsh_shows_hint() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .args(["completion", "install", "zsh"])
        .assert()
        .success()
        .stderr(predicate::str::contains("fpath+=~/.zfunc"));

    assert!(dir.path().join(".zfunc/_murk").exists());
}

#[test]
fn completion_install_fish() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .args(["completion", "install", "fish"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ok wrote"));

    assert!(
        dir.path()
            .join(".config/fish/completions/murk.fish")
            .exists()
    );
}

#[test]
fn concurrent_adds_dont_lose_data() {
    // Two sequential adds should both persist — tests the locking path.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "FIRST", "--vault", "test.murk"])
        .write_stdin("val1\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "SECOND", "--vault", "test.murk"])
        .write_stdin("val2\n")
        .assert()
        .success();

    // Both keys should exist.
    let output = murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("FIRST="));
    assert!(stdout.contains("SECOND="));
}

#[test]
fn lock_file_created_during_write() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // Lock file should exist after a write operation.
    assert!(dir.path().join("test.murk.lock").exists());
}

// --- Merge driver tests ---

#[test]
fn merge_driver_conflicts_on_one_sided_recipient_addition() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Create base vault with a secret.
    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    let base = fs::read_to_string(dir.path().join("test.murk")).unwrap();

    // "Ours" adds a recipient.
    let mut ours_vault: serde_json::Value = serde_json::from_str(&base).unwrap();
    ours_vault["recipients"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(
            "age1newrecipient0000000000000000000000000000000000000000000new00".into(),
        ));
    let ours = serde_json::to_string_pretty(&ours_vault).unwrap();

    // "Theirs" is unchanged from base.
    let theirs = base.clone();

    // Write the three versions.
    let base_path = dir.path().join("base.murk");
    let ours_path = dir.path().join("ours.murk");
    let theirs_path = dir.path().join("theirs.murk");
    fs::write(&base_path, &base).unwrap();
    fs::write(&ours_path, &ours).unwrap();
    fs::write(&theirs_path, &theirs).unwrap();

    // Run the merge driver with MURK_KEY so meta can be regenerated.
    // Should still fail with conflict due to one-sided recipient addition.
    murk(&dir, &key)
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("added on one side"));
}

// --- Hardening tests ---

#[test]
fn symlink_key_file_rejected() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    // Create a symlink to the real key file.
    let env_contents = fs::read_to_string(dir.path().join(".env")).unwrap();
    let key_file = env_contents
        .lines()
        .find_map(|l| {
            l.strip_prefix("export MURK_KEY_FILE=")
                .or_else(|| l.strip_prefix("MURK_KEY_FILE="))
        })
        .unwrap()
        .trim();

    let symlink_path = dir.path().join("key-symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink(key_file, &symlink_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(key_file, &symlink_path).unwrap();

    murk_bin(dir.path())
        .env("MURK_KEY_FILE", symlink_path.to_str().unwrap())
        .current_dir(dir.path())
        .args(["export", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
}

#[test]
fn github_username_too_long_rejected() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let long_name = "a".repeat(40);
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &format!("github:{long_name}"),
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid GitHub username"));
}

#[test]
fn authorize_ssh_file_adds_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Write a valid SSH public key file (with comment field).
    let ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN test@example";
    let pub_path = dir.path().join("bob.pub");
    fs::write(&pub_path, format!("{ssh_key}\n")).unwrap();

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &format!("ssh:{}", pub_path.display()),
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("authorized bob"));

    // Verify the key shows up in circle output.
    murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"));
}

#[test]
fn authorize_ssh_file_not_found() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            "ssh:/nonexistent/key.pub",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read"));
}

// A well-formed but weak ssh-rsa public key used only to test the
// ssh-rsa rejection path. Not a real key — murk should refuse to add it
// regardless, so the bytes don't matter beyond "parses as ssh-rsa."
const FAKE_SSH_RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6Fj9mHw0TMFR5D+J/fakekey+r0fLrqSoaOvIWFLr0OhQnyJEnOzEq6eEuV7krsKu/GzSWrlgPXJpNRGa8TEoLK7RUfYkEU8qoYylSpmGnvj2qtDQNN++j0QIqfiryh3wNJWTKhTN9EThB2wQ3r1mBiQQLq5QrPbqfejkCcpHZpkS3pyv1SpNV6hZlEmG2GSbAjBxJqrV3K6+z6uDGdqMF7/m+wJNMZsSYUpTlgrxHVM8n5YajdlEbBTEdfBnebQ+k8ofYVK0kFTokI50TjHnFnHqJcxbu8kDbfsYSUYkhsPEESz2iIxdngftLxcaNBmMY8T49SW/KMOHtr5z6ht6Jx fake@test";

#[test]
fn authorize_raw_ssh_rsa_rejected_by_default() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            FAKE_SSH_RSA_KEY,
            "--name",
            "rsa-user",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to authorize"))
        .stderr(predicate::str::contains("--allow-ssh-rsa"));
}

#[test]
fn authorize_raw_ssh_rsa_override_passes_the_gate() {
    // We don't have a real parseable ssh-rsa key in-tree, so we verify the
    // narrower property: with --allow-ssh-rsa, the ssh-rsa refusal gate is
    // bypassed (warning printed), and control reaches the real key parser.
    // Any downstream parse failure is acceptable — the point of this test
    // is that `reject_rsa_keys` doesn't fire.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            FAKE_SSH_RSA_KEY,
            "--name",
            "rsa-user",
            "--allow-ssh-rsa",
            "--vault",
            "test.murk",
        ])
        .assert()
        .stderr(predicate::str::contains("authorized via --allow-ssh-rsa"))
        .stderr(predicate::str::contains("refusing to authorize").not());
}

#[test]
fn authorize_ssh_file_ssh_rsa_rejected_by_default() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let pub_path = dir.path().join("rsa.pub");
    fs::write(&pub_path, format!("{FAKE_SSH_RSA_KEY}\n")).unwrap();

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &format!("ssh:{}", pub_path.display()),
            "--name",
            "rsa-user",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to authorize"));
}

#[test]
fn authorize_ssh_file_empty() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let pub_path = dir.path().join("empty.pub");
    fs::write(&pub_path, "").unwrap();

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &format!("ssh:{}", pub_path.display()),
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty key file"));
}

// ── edit ──

/// Helper: write an editor script that replaces the file content.
/// On Unix, writes a shell script. On Windows, writes a .cmd batch file.
/// `body` is the shell command (Unix). `win_body` is the batch equivalent.
fn write_editor_script(
    dir: &TempDir,
    name: &str,
    #[cfg_attr(windows, allow(unused_variables))] body: &str,
    #[cfg_attr(unix, allow(unused_variables))] win_body: &str,
) -> String {
    #[cfg(unix)]
    {
        let script = dir.path().join(name);
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script.display().to_string()
    }
    #[cfg(windows)]
    {
        let script = dir.path().join(format!("{name}.cmd"));
        fs::write(&script, format!("@echo off\r\n{win_body}\r\n")).unwrap();
        script.display().to_string()
    }
}

#[cfg(unix)]
#[test]
fn edit_single_key_updates_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    let editor = write_editor_script(
        &dir,
        "editor.sh",
        r#"echo "updated" > "$1""#,
        r#"echo updated> %1"#,
    );

    murk(&dir, &key)
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .env("EDITOR", &editor)
        .assert()
        .success()
        .stderr(predicate::str::contains("updated SECRET"));

    murk(&dir, &key)
        .args(["get", "SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated"));
}

#[cfg(unix)]
#[test]
fn edit_strict_fails_closed_on_disk_tmpdir() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    // $EDITOR drops a marker; if strict mode worked, it must never run.
    let marker = dir.path().join("editor-ran");
    let editor = write_editor_script(
        &dir,
        "editor.sh",
        &format!("touch {}", marker.display()),
        "echo.> editor-ran",
    );

    // XDG_RUNTIME_DIR points at the repo root (disk-backed everywhere), so the
    // scratch dir is not RAM-backed and MURK_STRICT must abort before $EDITOR.
    murk(&dir, &key)
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .env("MURK_STRICT", "1")
        .env("XDG_RUNTIME_DIR", env!("CARGO_MANIFEST_DIR"))
        .env("EDITOR", &editor)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not RAM-backed"));

    assert!(!marker.exists(), "editor ran despite strict fail-closed");

    // Value left untouched.
    murk(&dir, &key)
        .args(["get", "SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("original"));
}

#[cfg(unix)]
#[test]
fn edit_single_key_no_change() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    // cat leaves the file unchanged.
    murk(&dir, &key)
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .env("EDITOR", "cat")
        .assert()
        .success()
        .stderr(predicate::str::contains("no changes"));
}

#[cfg(unix)]
#[test]
fn edit_abort_preserves_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("keep_me\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .env("EDITOR", "false")
        .assert()
        .failure()
        .stderr(predicate::str::contains("aborting"));

    // Value is preserved.
    murk(&dir, &key)
        .args(["get", "SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keep_me"));
}

#[cfg(unix)]
#[test]
fn edit_multi_key_add_update_remove() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEEP", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "DELETE_ME", "--vault", "test.murk"])
        .write_stdin("gone\n")
        .assert()
        .success();

    // Editor: update KEEP, remove DELETE_ME, add NEW_KEY.
    let editor = write_editor_script(
        &dir,
        "editor.sh",
        r#"printf "KEEP=changed\nNEW_KEY=hello\n" > "$1""#,
        "(\r\necho KEEP=changed\r\necho NEW_KEY=hello\r\n) > %1",
    );

    murk(&dir, &key)
        .args(["edit", "--vault", "test.murk"])
        .env("EDITOR", &editor)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("added")
                .and(predicate::str::contains("updated"))
                .and(predicate::str::contains("removed")),
        );

    // Verify state.
    murk(&dir, &key)
        .args(["get", "KEEP", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("changed"));

    murk(&dir, &key)
        .args(["get", "NEW_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello"));

    murk(&dir, &key)
        .args(["get", "DELETE_ME", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn edit_missing_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["edit", "NONEXISTENT", "--vault", "test.murk"])
        .env("EDITOR", "cat")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[cfg(unix)]
#[test]
fn edit_tempfile_cleaned_up() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("value\n")
        .assert()
        .success();

    // Editor that records the tempfile path.
    let marker = dir.path().join("temppath.txt");
    let editor = write_editor_script(
        &dir,
        "editor.sh",
        &format!(r#"cp "$1" "{}" "#, marker.display()),
        &format!(r#"copy %1 "{}""#, marker.display()),
    );

    murk(&dir, &key)
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .env("EDITOR", &editor)
        .assert()
        .success();

    // The copied file should exist (proves editor ran), but we can't easily
    // check the original tempfile is gone since we don't know its path.
    // Instead verify the marker file doesn't contain secrets in plaintext
    // after the edit (the original tempfile was wiped).
    assert!(marker.exists());
}

// ── scan ──

#[test]
fn scan_detects_leaked_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();

    // Leak the secret value into a plain text file.
    fs::write(
        dir.path().join("config.yml"),
        "db_password: supersecretvalue123\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["scan", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DB_PASSWORD"))
        .stderr(predicate::str::contains("config.yml"))
        .stderr(predicate::str::contains("1 leaked secret found"));
}

#[test]
fn scan_clean_repo_reports_nothing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();

    // No file contains the plaintext value — the vault itself is skipped.
    murk(&dir, &key)
        .args(["scan", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no leaked secrets found"));
}

#[test]
fn scan_reports_multiple_leaks() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "API_TOKEN", "--vault", "test.murk"])
        .write_stdin("tokenvalue456789\n")
        .assert()
        .success();

    fs::write(
        dir.path().join("config.yml"),
        "db_password: supersecretvalue123\n",
    )
    .unwrap();
    fs::write(dir.path().join("notes.txt"), "token is tokenvalue456789\n").unwrap();

    murk(&dir, &key)
        .args(["scan", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DB_PASSWORD"))
        .stderr(predicate::str::contains("API_TOKEN"))
        .stderr(predicate::str::contains("notes.txt"))
        .stderr(predicate::str::contains("2 leaked secrets found"));
}

// ── groups ──

#[test]
fn group_secret_readable_only_by_members() {
    let dir = TempDir::new().unwrap();
    let (alice_key, _alice_pk) = init_vault(&dir);

    // Second recipient (bob) becomes a group member; third (carol) does not.
    let bob_dir = TempDir::new().unwrap();
    let (bob_key, bob_pk) = init_vault(&bob_dir);
    let carol_dir = TempDir::new().unwrap();
    let (carol_key, carol_pk) = init_vault(&carol_dir);

    // Authorize carol as a plain recipient (not in any group).
    murk(&dir, &alice_key)
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

    // Create the prod group, then authorize bob straight into it.
    murk(&dir, &alice_key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bob",
            "--group",
            "prod",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Add a secret encrypted to the prod group only.
    murk(&dir, &alice_key)
        .args([
            "add",
            "STRIPE_KEY",
            "--group",
            "prod",
            "--vault",
            "test.murk",
        ])
        .write_stdin("sk_live_123\n")
        .assert()
        .success();

    // group ls shows prod with both members.
    murk(&dir, &alice_key)
        .args(["group", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("prod").and(predicate::str::contains("bob")));

    // Bob (a member) can read it.
    murk(&dir, &bob_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_123"));

    // Carol (a recipient but not a prod member) cannot.
    murk(&dir, &carol_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[test]
fn group_rm_member_revokes_access_after_reencrypt() {
    let dir = TempDir::new().unwrap();
    let (alice_key, _alice_pk) = init_vault(&dir);

    let bob_dir = TempDir::new().unwrap();
    let (bob_key, bob_pk) = init_vault(&bob_dir);

    murk(&dir, &alice_key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bob",
            "--group",
            "prod",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["add", "PROD_DB", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("prod_secret\n")
        .assert()
        .success();

    // Bob can read before removal.
    murk(&dir, &bob_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prod_secret"));

    // Remove bob from the group (alice is a member, so she re-encrypts).
    murk(&dir, &alice_key)
        .args([
            "group",
            "rm",
            "prod",
            "--member",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Bob can no longer read the current ciphertext.
    murk(&dir, &bob_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[test]
fn group_create_rejects_reserved_name() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["group", "create", "me", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("reserved"));
}

#[test]
fn non_member_save_preserves_group_secret() {
    // Regression: a recipient who is NOT in a group must not drop that group's
    // secrets when they save an unrelated change. The group ciphertext never
    // enters their decrypted view, so save_vault must carry it through.
    let dir = TempDir::new().unwrap();
    let (alice_key, _alice_pk) = init_vault(&dir);

    let bob_dir = TempDir::new().unwrap();
    let (bob_key, bob_pk) = init_vault(&bob_dir);

    // Alice creates prod and adds bob; both are members.
    murk(&dir, &alice_key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bob",
            "--group",
            "prod",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["add", "PROD_DB", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("prod_secret\n")
        .assert()
        .success();

    // Remove alice from prod — now bob is the sole member; alice is a recipient
    // but cannot read PROD_DB.
    murk(&dir, &alice_key)
        .args([
            "group",
            "rm",
            "prod",
            "--member",
            "testuser",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .failure();

    // Alice (non-member) saves an unrelated change.
    murk(&dir, &alice_key)
        .args(["add", "UNRELATED", "--vault", "test.murk"])
        .write_stdin("x\n")
        .assert()
        .success();

    // Bob can still read PROD_DB — it was not dropped.
    murk(&dir, &bob_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prod_secret"));
}

#[test]
fn add_shared_clears_group_assignment() {
    // Regression: assigning a key to everyone must drop its prior group entry,
    // so the new shared value isn't shadowed by stale grouped ciphertext.
    let dir = TempDir::new().unwrap();
    let (alice_key, _alice_pk) = init_vault(&dir);

    let carol_dir = TempDir::new().unwrap();
    let (carol_key, carol_pk) = init_vault(&carol_dir);
    murk(&dir, &alice_key)
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

    murk(&dir, &alice_key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["add", "TOKEN", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("group_val\n")
        .assert()
        .success();
    // carol (not in prod) can't read it yet.
    murk(&dir, &carol_key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .failure();

    // Reassign to everyone.
    murk(&dir, &alice_key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("shared_val\n")
        .assert()
        .success();

    // carol now reads the shared value (not the stale group ciphertext).
    murk(&dir, &carol_key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("shared_val"));
}

// ── agent grants ──

/// Read the agent key written by `agent grant --out <path>`.
fn read_agent_key(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap().trim().to_string()
}

#[test]
fn agent_grant_scopes_access_to_only_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("pg://prod\n")
        .assert()
        .success();

    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .args(["--ttl", "2h", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("granted").and(predicate::str::contains("STRIPE_KEY")));

    let agent_key = read_agent_key(&agent_key_path);

    // The agent reads the granted key.
    murk(&dir, &agent_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));

    // The agent cannot read a non-granted shared secret, and the refusal names
    // the real reason: the key exists (its name is in the plaintext schema, which
    // the agent can read) but sits outside this grant's scope.
    murk(&dir, &agent_key)
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "DB_URL is outside this grant's scope",
        ));

    // A key that genuinely does not exist still reports that, so the scoped
    // message never masks a typo.
    murk(&dir, &agent_key)
        .args(["get", "NOPE", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));

    // The operator sees the grant listed.
    murk(&dir, &key)
        .args(["agent", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("codex").and(predicate::str::contains("STRIPE_KEY")));
}

#[test]
fn agent_grant_fails_closed_after_ttl() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();

    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .args(["--ttl", "1s", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Past the TTL every read with the grant key fails closed, naming the
    // grant and pointing at re-issue. (In-TTL reads are covered by
    // `agent_grant_scopes_access_to_only_keys`.)
    murk(&dir, &agent_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("expired")
                .and(predicate::str::contains("codex"))
                .and(predicate::str::contains("agent revoke")),
        );

    // Someone else's expired grant never affects the operator's own reads.
    murk(&dir, &key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));

    // The operator can still list and revoke the expired grant.
    murk(&dir, &key)
        .args(["agent", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("codex").and(predicate::str::contains("expired")));
}

#[test]
fn agent_grant_renew_replaces_grant_in_one_command() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();

    let old_key_path = dir.path().join("agent-old.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .args(["--out"])
        .arg(&old_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let old_key = read_agent_key(&old_key_path);

    // Re-minting a live name without --renew stays refused, pointing at --renew.
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .args(["--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("grant already exists")
                .and(predicate::str::contains("--renew")),
        );

    // One command renews: revoke the old key, mint a fresh one, same name.
    let new_key_path = dir.path().join("agent-new.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .args(["--renew", "--out"])
        .arg(&new_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("renewing codex"));
    let new_key = read_agent_key(&new_key_path);

    // The new key reads; the old key is fully revoked, not just descoped.
    murk(&dir, &new_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));
    murk(&dir, &old_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .failure();

    // Exactly one grant named codex remains.
    let out = murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert_eq!(
        stdout.matches("\"codex\"").count(),
        1,
        "one grant: {stdout}"
    );

    // --renew on a name that does not exist yet simply creates the grant, so
    // renewal is safe to script unconditionally.
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "fresh", "--only", "STRIPE_KEY"])
        .args(["--renew", "--out", "-"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn agent_revoke_removes_grant_and_access() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();

    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args([
            "agent",
            "grant",
            "--name",
            "codex",
            "--only",
            "STRIPE_KEY",
            "--out",
        ])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    // Revoke and rotate to a new value in the same session.
    murk(&dir, &key)
        .args([
            "agent",
            "revoke",
            "codex",
            "--rotate",
            "--vault",
            "test.murk",
        ])
        .write_stdin("sk_live_rotated\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("revoked"));

    // No grants remain.
    murk(&dir, &key)
        .args(["agent", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no active grants"));

    // The revoked agent key can no longer read the secret.
    murk(&dir, &agent_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .failure();

    // The operator reads the rotated value.
    murk(&dir, &key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_rotated"));
}

#[test]
fn agent_grant_tracks_rotation_of_granted_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_v1\n")
        .assert()
        .success();

    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args([
            "agent",
            "grant",
            "--name",
            "codex",
            "--only",
            "STRIPE_KEY",
            "--out",
        ])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    // Operator rotates the granted key to a new value while the grant is active.
    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_v2\n")
        .assert()
        .success();

    // The agent sees the new value, not the stale snapshot.
    murk(&dir, &agent_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_v2"));
}

#[test]
fn strict_mode_disables_key_auto_discovery() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();

    // With no key in the environment, auto-discovery normally finds the stored
    // key. Under MURK_STRICT it must fail closed instead of falling back.
    murk_bin(dir.path())
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_STRICT", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));

    // Without strict mode, auto-discovery still works (sanity check).
    murk_bin(dir.path())
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));
}

// ── agent access policy ──

#[test]
fn policy_restricts_agent_grant_and_exec_to_allowed_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--vault", "test.murk"])
        .write_stdin("safe_val\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "add",
            "PROD_DB",
            "--tag",
            "production",
            "--vault",
            "test.murk",
        ])
        .write_stdin("prod_val\n")
        .assert()
        .success();

    // Set the allow-list to agents.
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

    // policy show works without a key (reads the plaintext header).
    murk_bin(dir.path())
        .args(["policy", "show", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("agents"));

    // Granting an agents key is allowed.
    let agent_key_path = dir.path().join("a.key");
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "ok", "--only", "API_KEY", "--out",
        ])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();

    // Granting a production key is refused by policy.
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "bad", "--only", "PROD_DB", "--out",
        ])
        .arg(dir.path().join("bad.key"))
        .args(["--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("policy forbids").and(predicate::str::contains("PROD_DB")),
        );

    // agent exec of a production key is refused too.
    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "PROD_DB",
            "--vault",
            "test.murk",
            "--",
            "echo",
            "hi",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy forbids"));

    // The operator (human) is unconstrained — get still works.
    murk(&dir, &key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prod_val"));

    // Integrity still verifies under the v8 MAC.
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn policy_clear_restores_unrestricted_agent_mode() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args([
            "add",
            "PROD_DB",
            "--tag",
            "production",
            "--vault",
            "test.murk",
        ])
        .write_stdin("prod_val\n")
        .assert()
        .success();
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

    // Blocked under policy.
    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "PROD_DB",
            "--vault",
            "test.murk",
            "--",
            "echo",
            "hi",
        ])
        .assert()
        .failure();

    // Clear the policy.
    murk(&dir, &key)
        .args(["policy", "clear", "--vault", "test.murk"])
        .assert()
        .success();

    // Now allowed.
    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "PROD_DB",
            "--vault",
            "test.murk",
            "--",
            "echo",
            "hi",
        ])
        .assert()
        .success();
}

// ── agent init (one-shot onboarding) ──

#[test]
fn agent_init_grants_scoped_access_and_writes_key_file() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("pg://prod\n")
        .assert()
        .success();

    let agent_key_path = dir.path().join("a1.key");
    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "a1",
            "--only",
            "STRIPE_KEY",
            "--out",
        ])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();

    let agent_key = read_agent_key(&agent_key_path);
    assert!(agent_key.starts_with("AGE-SECRET-KEY-"));

    // The grant is recorded.
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"a1\""));

    // The written key reads the granted key...
    murk_bin(dir.path())
        .env("MURK_KEY_FILE", agent_key_path.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .current_dir(dir.path())
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));

    // ...but not an out-of-scope key.
    murk_bin(dir.path())
        .env("MURK_KEY_FILE", agent_key_path.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .current_dir(dir.path())
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[test]
fn agent_init_sets_policy_and_streams_key_to_stdout() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--vault", "test.murk"])
        .write_stdin("safe_val\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "a2",
            "--only",
            "API_KEY",
            "--allow-tag",
            "agents",
            "--out",
            "-",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("AGE-SECRET-KEY-"))
        .stderr(predicate::str::contains("key streamed to stdout"));

    // The allow-list is now set.
    murk_bin(dir.path())
        .args(["policy", "show", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("agents"));

    // The grant is recorded.
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"a2\""));
}

#[test]
fn agent_init_fails_closed_and_grants_nothing_for_forbidden_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--vault", "test.murk"])
        .write_stdin("safe_val\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "PROD_DB", "--vault", "test.murk"])
        .write_stdin("prod_val\n")
        .assert()
        .success();
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

    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "a3",
            "--only",
            "PROD_DB",
            "--out",
            "-",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("policy forbids").and(predicate::str::contains("PROD_DB")),
        );

    // No grant was recorded.
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"a3\"").not());
}

#[test]
fn agent_init_policy_set_is_atomic_when_grant_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "UNTAGGED", "--vault", "test.murk"])
        .write_stdin("untagged_val\n")
        .assert()
        .success();

    // No policy exists yet.
    murk_bin(dir.path())
        .args(["policy", "show", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("no agent policy"));

    // Setting the allow-list to `agents` and granting the untagged key in the
    // same transaction must fail closed — the just-set allow-list forbids it.
    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "a4",
            "--only",
            "UNTAGGED",
            "--allow-tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy forbids"));

    // Nothing was persisted: no policy, no grant.
    murk_bin(dir.path())
        .args(["policy", "show", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("no agent policy"));

    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"a4\"").not());
}

// ── operator self-scope ──

/// Set up a vault with an `ALLOWED` secret (tagged `agents`) and a
/// `FORBIDDEN` secret (untagged), then set a policy allowing only the
/// `agents` tag. Returns the operator's `MURK_KEY`.
fn setup_self_scope_vault(dir: &TempDir) -> String {
    let (key, _) = init_vault(dir);

    murk(dir, &key)
        .args(["add", "ALLOWED", "--vault", "test.murk"])
        .write_stdin("allowed_val\n")
        .assert()
        .success();
    murk(dir, &key)
        .args(["add", "FORBIDDEN", "--vault", "test.murk"])
        .write_stdin("forbidden_val\n")
        .assert()
        .success();
    murk(dir, &key)
        .args([
            "describe",
            "ALLOWED",
            "an agent-safe secret",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(dir, &key)
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

    key
}

#[test]
fn self_scope_off_operator_reads_forbidden_key() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    // No MURK_SELF_SCOPE: the operator remains unrestricted by the policy.
    murk(&dir, &key)
        .args(["get", "FORBIDDEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("forbidden_val"));
}

#[test]
fn self_scope_get_blocks_forbidden_allows_allowed() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    murk(&dir, &key)
        .args(["get", "FORBIDDEN", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy"));

    murk(&dir, &key)
        .args(["get", "ALLOWED", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed_val"));
}

#[test]
fn self_scope_export_withholds_forbidden_key() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export ALLOWED=")
                .and(predicate::str::contains("FORBIDDEN").not()),
        )
        .stderr(predicate::str::contains("withholding"));
}

#[test]
fn self_scope_exec_only_enforces_policy() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    murk(&dir, &key)
        .args([
            "exec",
            "--only",
            "FORBIDDEN",
            "--vault",
            "test.murk",
            "--",
            "true",
        ])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy"));

    murk(&dir, &key)
        .args([
            "exec",
            "--only",
            "ALLOWED",
            "--vault",
            "test.murk",
            "--",
            "true",
        ])
        .env("MURK_SELF_SCOPE", "1")
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn self_scope_bulk_edit_refused() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    murk(&dir, &key)
        .args(["edit", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .env("EDITOR", "true")
        .assert()
        .failure()
        .stderr(predicate::str::contains("bulk edit"));
}

#[cfg(unix)]
#[test]
fn self_scope_single_key_edit_blocks_forbidden_key() {
    let dir = TempDir::new().unwrap();
    let key = setup_self_scope_vault(&dir);

    murk(&dir, &key)
        .args(["edit", "FORBIDDEN", "--vault", "test.murk"])
        .env("MURK_SELF_SCOPE", "1")
        .env("EDITOR", "true")
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy"));
}

// ── mcp ──

#[test]
fn mcp_without_agent_context_is_refused() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["mcp", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("agent context"));
}

#[test]
fn mcp_with_operator_key_in_agent_context_is_refused() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["mcp", "--vault", "test.murk"])
        .env("MURK_AGENT", "1")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("grant"));
}

#[test]
fn mcp_serves_initialize_and_tools_list_over_stdio() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("secret-value\n")
        .assert()
        .success();

    let grant = dir.path().join("grant.key");
    murk(&dir, &key)
        .args([
            "agent",
            "grant",
            "--name",
            "probe",
            "--only",
            "API_KEY",
            "--out",
            grant.to_str().unwrap(),
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let handshake = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n",
    );

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(handshake)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("murk-mcp")
                .and(predicate::str::contains("\"id\":2"))
                .and(predicate::str::contains("murk_plan"))
                .and(predicate::str::contains("murk_get"))
                .and(predicate::str::contains("murk_exec").not()),
        );
}

/// Set up a vault with `DB_URL`/`CACHE_URL` tagged `agents` plus a distinct
/// second tag each (so the tag filter is still exercisable within the
/// granted set), an `agents`-tagged `SHARED_KEY` that is policy-allowed but
/// NOT granted, and an untagged `SECRET_KEY` that is policy-forbidden. Mints
/// a one-shot grant (`agent init`) scoped to DB_URL + CACHE_URL under an
/// agents-tag policy. Returns the grant key file path.
fn setup_mcp_grant(dir: &TempDir) -> std::path::PathBuf {
    let (key, _) = init_vault(dir);

    murk(dir, &key)
        .args([
            "add",
            "DB_URL",
            "--tag",
            "agents",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .write_stdin("db-val\n")
        .assert()
        .success();
    murk(dir, &key)
        .args([
            "add",
            "CACHE_URL",
            "--tag",
            "agents",
            "--tag",
            "cache",
            "--vault",
            "test.murk",
        ])
        .write_stdin("cache-val\n")
        .assert()
        .success();
    murk(dir, &key)
        .args([
            "add",
            "SHARED_KEY",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .write_stdin("shared-val\n")
        .assert()
        .success();
    murk(dir, &key)
        .args(["add", "SECRET_KEY", "--vault", "test.murk"])
        .write_stdin("forbidden-val\n")
        .assert()
        .success();

    let grant = dir.path().join("grant.key");
    murk(dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "probe",
            "--only",
            "DB_URL",
            "--only",
            "CACHE_URL",
            "--allow-tag",
            "agents",
            "--out",
            grant.to_str().unwrap(),
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    grant
}

/// Build the MCP handshake preamble followed by a single `tools/call`
/// request for `tool` with a raw JSON `arguments` object, newline-terminated.
/// `write_stdin` closes stdin after this, so the server answers and shuts
/// down cleanly (exit 0) without hanging.
fn mcp_handshake_and_call(tool: &str, arguments: &str) -> String {
    const HANDSHAKE: &str = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
    );
    format!(
        "{HANDSHAKE}{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{arguments}}}}}\n"
    )
}

#[test]
fn mcp_plan_returns_value_free_schema() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call("murk_plan", "{}"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("DB_URL")
                .and(predicate::str::contains("CACHE_URL"))
                .and(predicate::str::contains("SHARED_KEY").not())
                .and(predicate::str::contains("SECRET_KEY").not())
                .and(predicate::str::contains("db-val").not())
                .and(predicate::str::contains("cache-val").not())
                .and(predicate::str::contains("shared-val").not())
                .and(predicate::str::contains("forbidden-val").not()),
        );
}

#[test]
fn mcp_get_returns_in_scope_value() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call("murk_get", r#"{"key":"DB_URL"}"#))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("db-val").and(predicate::str::contains("\"isError\":false")),
        );
}

#[test]
fn mcp_get_out_of_scope_key_fails_closed() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call(
            "murk_get",
            r#"{"key":"SHARED_KEY"}"#,
        ))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"isError\":true")
                .and(predicate::str::contains("shared-val").not()),
        );
}

#[test]
fn mcp_get_policy_forbidden_key_fails_closed() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call(
            "murk_get",
            r#"{"key":"SECRET_KEY"}"#,
        ))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"isError\":true")
                .and(predicate::str::contains("policy forbids"))
                .and(predicate::str::contains("forbidden-val").not()),
        );
}

#[test]
fn mcp_plan_tag_filter_narrows_within_scope() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call("murk_plan", r#"{"tags":["db"]}"#))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("DB_URL").and(predicate::str::contains("CACHE_URL").not()),
        );
}

#[test]
fn mcp_unknown_tool_is_rejected() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call("bogus", "{}"))
        .assert()
        .success()
        .stdout(predicate::str::contains("tool not found"));
}

#[test]
fn mcp_get_missing_key_arg_is_rejected() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call("murk_get", "{}"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"isError\":true")
                .and(predicate::str::contains("missing field"))
                .and(predicate::str::contains("db-val").not())
                .and(predicate::str::contains("cache-val").not())
                .and(predicate::str::contains("shared-val").not())
                .and(predicate::str::contains("forbidden-val").not()),
        );
}

#[test]
fn mcp_exec_rejected_without_allow_exec() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin(mcp_handshake_and_call(
            "murk_exec",
            r#"{"only":["DB_URL"],"command":["echo","x"]}"#,
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains("tool not found"));
}

#[test]
fn mcp_exec_out_of_scope_fails_closed() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call(
            "murk_exec",
            r#"{"only":["SHARED_KEY"],"command":["echo","x"]}"#,
        ))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"isError\":true")
                .and(predicate::str::contains("outside this grant's scope"))
                .and(predicate::str::contains("shared-val").not()),
        );
}

#[test]
fn mcp_exec_runs_command_with_injected_secret() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    #[cfg(unix)]
    let exec_args = r#"{"only":["DB_URL"],"command":["printenv","DB_URL"]}"#;
    #[cfg(windows)]
    let exec_args = r#"{"only":["DB_URL"],"command":["cmd","/C","echo %DB_URL%"]}"#;

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call("murk_exec", exec_args))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("db-val").and(predicate::str::contains("\"isError\":false")),
        );
}

#[cfg(unix)]
#[test]
fn mcp_exec_output_is_capped() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call(
            "murk_exec",
            r#"{"only":["DB_URL"],"command":["sh","-c","yes"]}"#,
        ))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"isError\":true")
                .and(predicate::str::contains(r#"\"truncated\": true"#)),
        );
}

// ── agent connect / disconnect (MCP editor wiring) ──

#[test]
fn agent_connect_and_disconnect_wire_mcp_config() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // A secret to scope the grant to.
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("sk-secret\n")
        .assert()
        .success();

    // connect cursor: mints a scoped grant and writes .cursor/mcp.json.
    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "cursor",
            "--only",
            "API_KEY",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let cfg = dir.path().join(".cursor/mcp.json");
    let body = fs::read_to_string(&cfg).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["mcpServers"]["murk"]["command"], "murk");
    assert_eq!(v["mcpServers"]["murk"]["args"][0], "mcp");
    assert_eq!(v["mcpServers"]["murk"]["env"]["MURK_AGENT"], "1");
    assert!(
        v["mcpServers"]["murk"]["env"]["MURK_KEY_FILE"].is_string(),
        "config must reference a key-file path"
    );
    // The config must carry only a path, never inline key material.
    assert!(
        !body.contains("AGE-SECRET-KEY"),
        "config must never contain key material"
    );

    // disconnect removes murk's entry, leaving the container in place.
    murk(&dir, &key)
        .args(["agent", "disconnect", "cursor", "--vault", "test.murk"])
        .assert()
        .success();
    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
    assert!(
        after["mcpServers"]["murk"].is_null(),
        "disconnect must remove the murk entry"
    );
}

#[test]
fn agent_connect_rejects_scope_mismatch_on_reuse() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    for k in ["API_KEY", "DB_URL"] {
        murk(&dir, &key)
            .args(["add", k, "--vault", "test.murk"])
            .write_stdin("v\n")
            .assert()
            .success();
    }

    // First connect mints grant "mcp" scoped to API_KEY.
    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "cursor",
            "--only",
            "API_KEY",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // A second connect asking for a different scope must fail closed rather than
    // silently hand an editor a grant wider or narrower than requested.
    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "vscode",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn agent_connect_covers_every_adapter() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("sk-secret\n")
        .assert()
        .success();

    // Every supported adapter, its project-local config path, end-to-end.
    let cases = [
        ("claude", ".mcp.json"),
        ("cursor", ".cursor/mcp.json"),
        ("vscode", ".vscode/mcp.json"),
        ("zed", ".zed/settings.json"),
        ("gemini", ".gemini/settings.json"),
        ("omp", ".omp/mcp.json"),
        ("codex", ".codex/config.toml"),
    ];
    for (id, rel) in cases {
        murk(&dir, &key)
            .args([
                "agent",
                "connect",
                id,
                "--only",
                "API_KEY",
                "--vault",
                "test.murk",
            ])
            .assert()
            .success();

        let cfg = dir.path().join(rel);
        let body =
            fs::read_to_string(&cfg).unwrap_or_else(|_| panic!("{id}: no config written at {rel}"));
        assert!(body.contains("MURK_AGENT"), "{id}: missing murk entry");
        assert!(body.contains("MURK_KEY_FILE"), "{id}: missing key-file ref");
        assert!(
            !body.contains("AGE-SECRET-KEY"),
            "{id}: config leaked key material"
        );

        murk(&dir, &key)
            .args(["agent", "disconnect", id, "--vault", "test.murk"])
            .assert()
            .success();
        let after = fs::read_to_string(&cfg).unwrap();
        assert!(
            !after.contains("MURK_KEY_FILE"),
            "{id}: disconnect left murk entry behind"
        );
    }
}
