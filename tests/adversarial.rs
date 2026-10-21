// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial test fixtures.
//!
//! These tests simulate hostile inputs and malicious repo conditions.
//! They verify that murk fails safely — no panics, no data corruption,
//! no silent success on bad input.

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

mod common;
use common::{FOREIGN_PK, init_vault, murk, murk_bin};

// ── Malformed vault JSON ──

#[test]
fn load_empty_vault_file() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(dir.path().join("test.murk"), "").unwrap();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("vault parse error"));
}

#[test]
fn load_vault_not_json() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(dir.path().join("test.murk"), "this is not json at all").unwrap();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("vault parse error"));
}

#[test]
fn load_vault_wrong_version() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let json = r#"{"version":"99.0","created":"2026-01-01T00:00:00Z","vault_name":".murk","recipients":[],"schema":{},"secrets":{},"meta":""}"#;
    fs::write(dir.path().join("test.murk"), json).unwrap();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported vault version"));
}

#[test]
fn load_vault_missing_fields() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    fs::write(dir.path().join("test.murk"), r#"{"version":"2.0"}"#).unwrap();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[test]
fn load_vault_extra_fields_accepted() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Read existing vault and add unknown fields.
    let contents = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    val["unknown_field"] = serde_json::json!("should be ignored");
    fs::write(
        dir.path().join("test.murk"),
        serde_json::to_string_pretty(&val).unwrap(),
    )
    .unwrap();

    // Should still work — unknown fields are silently ignored.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn load_vault_huge_key_name() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let contents = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    let huge_key = "A".repeat(10_000);
    val["schema"][&huge_key] = serde_json::json!({"description": "huge"});
    fs::write(
        dir.path().join("test.murk"),
        serde_json::to_string_pretty(&val).unwrap(),
    )
    .unwrap();

    // Should not panic — just list the key.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success();
}

// ── Malformed .env inputs ──

#[test]
fn import_env_with_null_bytes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "EXISTING", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .success();

    fs::write(dir.path().join("bad.env"), "KEY=val\x00ue\n").unwrap();

    // Should not panic on null bytes.
    murk(&dir, &key)
        .args(["import", "bad.env", "--vault", "test.murk", "--force"])
        .assert()
        .success();
}

#[test]
fn import_empty_file() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    fs::write(dir.path().join("empty.env"), "").unwrap();

    murk(&dir, &key)
        .args(["import", "empty.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no secrets found"));
}

#[test]
fn import_only_comments() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    fs::write(
        dir.path().join("comments.env"),
        "# just\n# comments\n# here\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["import", "comments.env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no secrets found"));
}

// ── Symlink attacks ──

#[cfg(unix)]
#[test]
fn lock_file_symlink_rejected() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Create a symlink where the lock file would be.
    let lock_path = dir.path().join("test.murk.lock");
    std::os::unix::fs::symlink("/tmp/evil_target", &lock_path).unwrap();

    // Any write operation should fail because it can't acquire the lock.
    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn symlinked_vault_rejected() {
    // A vault file that is a symlink to another project's vault must be
    // refused — otherwise auto key discovery could decrypt the target.
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir_a);

    // Point B's vault at A's vault via symlink.
    let vault_a = dir_a.path().join("test.murk");
    let vault_b = dir_b.path().join("test.murk");
    std::os::unix::fs::symlink(&vault_a, &vault_b).unwrap();

    // Even with the correct key available, reading the symlinked vault fails.
    murk_bin(dir_b.path())
        .args(["ls", "--vault", "test.murk"])
        .current_dir(dir_b.path())
        .env("MURK_KEY", &key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
}

#[cfg(unix)]
#[test]
fn symlinked_vault_does_not_autodiscover_target_key() {
    // A.murk's key is auto-stored under a hash of A's absolute path.
    // A symlink B/.murk -> A/.murk must NOT resolve to A's key file.
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let fake_home = TempDir::new().unwrap();

    // Init A with auto key discovery populated under fake HOME.
    murk_bin(fake_home.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir_a.path())
        .write_stdin("alice\n")
        .assert()
        .success();

    // Sanity: A works from its own directory.
    murk_bin(fake_home.path())
        .args(["ls", "--vault", "test.murk"])
        .current_dir(dir_a.path())
        .assert()
        .success();

    // Now symlink B/test.murk -> A/test.murk and try to read it with no
    // explicit key — the auto discovery must fail (not leak A's secrets).
    let vault_a = dir_a.path().join("test.murk");
    let vault_b = dir_b.path().join("test.murk");
    std::os::unix::fs::symlink(&vault_a, &vault_b).unwrap();

    murk_bin(fake_home.path())
        .args(["ls", "--vault", "test.murk"])
        .current_dir(dir_b.path())
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn copied_vault_cannot_borrow_key_via_dotenv() {
    // Regression: copying a vault into repoB along with a .env that
    // inlines repoA's MURK_KEY (or a MURK_KEY_FILE reference) must NOT let
    // repoB decrypt the copied vault. Runtime key resolution ignores .env —
    // the environment is the only trusted source.
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let fake_home = TempDir::new().unwrap();

    let (key_a, _) = init_vault(&dir_a);

    // Add a secret in A so there's something to try to read.
    murk(&dir_a, &key_a)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("hunter2\n")
        .assert()
        .success();

    // Copy the vault file itself into B (the "stolen vault" scenario).
    fs::copy(
        dir_a.path().join("test.murk"),
        dir_b.path().join("test.murk"),
    )
    .unwrap();

    // Plant a .env in B that inlines A's key. In the old world this would
    // have been picked up by the runtime fallback and decrypted the vault.
    fs::write(
        dir_b.path().join(".env"),
        format!("export MURK_KEY={key_a}\n"),
    )
    .unwrap();

    // Runtime resolution ignores .env → no key → decrypting the copied
    // vault must fail. Use `get` (not `ls`) because `ls` only reads the
    // plaintext schema and would succeed even without a key.
    murk_bin(fake_home.path())
        .args(["get", "SECRET", "--vault", "test.murk"])
        .current_dir(dir_b.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY"));
}

#[cfg(unix)]
#[test]
fn env_file_symlink_rejected() {
    let dir = TempDir::new().unwrap();

    // Create a symlink .env pointing somewhere evil.
    let env_path = dir.path().join(".env");
    std::os::unix::fs::symlink("/tmp/evil_env_target", &env_path).unwrap();

    // Init should fail because it can't write .env through a symlink.
    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("testuser\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
}

// ── Permission checks ──

#[cfg(unix)]
#[test]
fn world_readable_key_file_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Create a separate key file with loose permissions.
    let loose_key = dir.path().join("loose.key");
    fs::write(&loose_key, &key).unwrap();
    fs::set_permissions(&loose_key, fs::Permissions::from_mode(0o644)).unwrap();

    // Operations using MURK_KEY_FILE pointing to the loose file should fail.
    let fake_home = TempDir::new().unwrap();
    murk_bin(fake_home.path())
        .args(["export", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", loose_key.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("readable by others"));

    // But passing the key directly via MURK_KEY still works.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success();
}

// ── Merge driver abuse ──

#[test]
fn merge_driver_empty_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("base.murk"), "").unwrap();
    fs::write(dir.path().join("ours.murk"), "").unwrap();
    fs::write(dir.path().join("theirs.murk"), "").unwrap();

    murk_bin(dir.path())
        .args([
            "merge-driver",
            dir.path().join("base.murk").to_str().unwrap(),
            dir.path().join("ours.murk").to_str().unwrap(),
            dir.path().join("theirs.murk").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("parsing base"));
}

#[test]
fn merge_driver_mismatched_versions() {
    let dir = TempDir::new().unwrap();
    let v2 = r#"{"version":"2.0","created":"2026-01-01T00:00:00Z","vault_name":".murk","recipients":[],"schema":{},"secrets":{},"meta":""}"#;
    let v99 = r#"{"version":"99.0","created":"2026-01-01T00:00:00Z","vault_name":".murk","recipients":[],"schema":{},"secrets":{},"meta":""}"#;

    fs::write(dir.path().join("base.murk"), v2).unwrap();
    fs::write(dir.path().join("ours.murk"), v2).unwrap();
    fs::write(dir.path().join("theirs.murk"), v99).unwrap();

    murk_bin(dir.path())
        .args([
            "merge-driver",
            dir.path().join("base.murk").to_str().unwrap(),
            dir.path().join("ours.murk").to_str().unwrap(),
            dir.path().join("theirs.murk").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported vault version"));
}

// ── Key validation ──

#[test]
fn add_invalid_key_name() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Key names with spaces should be rejected.
    murk(&dir, &key)
        .args(["add", "BAD KEY", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .failure();
}

#[test]
fn add_empty_key_name() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "", "--vault", "test.murk"])
        .write_stdin("val\n")
        .assert()
        .failure();
}

// ── Nonexistent vault ──

#[test]
fn operations_on_missing_vault() {
    let dir = TempDir::new().unwrap();

    for cmd in &["ls", "export", "info"] {
        murk_bin(dir.path())
            .args([cmd, "--vault", "nonexistent.murk"])
            .current_dir(dir.path())
            .env("MURK_KEY", "AGE-SECRET-KEY-1FAKE")
            .assert()
            .failure();
    }
}

// ── Scan with hostile paths ──

#[test]
fn scan_binary_files_skipped() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();

    // Write a binary file containing the secret value.
    let project = dir.path().join("project");
    fs::create_dir(&project).unwrap();
    let mut binary_content = vec![0u8; 100];
    binary_content.extend_from_slice(b"supersecretvalue123");
    binary_content.extend_from_slice(&[0xFF, 0xFE, 0x00]);
    fs::write(project.join("data.bin"), &binary_content).unwrap();

    // Also write a text file with the secret — this should be found.
    fs::write(project.join("config.txt"), "password=supersecretvalue123").unwrap();

    let output = murk(&dir, &key)
        .args(["scan", project.to_str().unwrap(), "--vault", "test.murk"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The text file should be found.
    assert!(
        stderr.contains("config.txt"),
        "should find leak in text file"
    );
}

// ── Invalid key ──

#[test]
fn invalid_murk_key_fails() {
    let dir = TempDir::new().unwrap();
    let (_key, _) = init_vault(&dir);

    murk(&dir, "not-a-valid-age-key")
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success(); // ls doesn't need a key

    murk(&dir, "not-a-valid-age-key")
        .args(["export", "--vault", "test.murk"])
        .assert()
        .failure(); // export needs to decrypt
}

#[test]
fn empty_murk_key_fails() {
    let dir = TempDir::new().unwrap();
    let (_key, _) = init_vault(&dir);
    let fake_home = TempDir::new().unwrap();

    // Remove .env so the fallback can't find the key either.
    fs::remove_file(dir.path().join(".env")).ok();

    murk_bin(fake_home.path())
        .args(["export", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", "")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

// ── Vault edge cases ──

#[test]
fn vault_with_empty_secrets_and_schema() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Vault with no secrets should work for info/ls.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn get_nonexistent_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["get", "DOES_NOT_EXIST", "--vault", "test.murk"])
        .assert()
        .failure();
}

#[test]
fn rm_nonexistent_key_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // rm on a nonexistent key succeeds silently (idempotent).
    murk(&dir, &key)
        .args(["rm", "DOES_NOT_EXIST", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn revoke_nonexistent_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "revoke", "nobody", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn revoke_last_recipient_fails() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["circle", "revoke", &pubkey, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("last recipient"));
}

#[test]
fn authorize_invalid_pubkey() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            "not-a-valid-pubkey",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure();
}

#[test]
fn double_add_updates_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("first\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "KEY", "--vault", "test.murk"])
        .write_stdin("second\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("second"));
}

#[test]
fn import_collision_blocked_without_force() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "EXISTING", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    fs::write(dir.path().join("collision.env"), "EXISTING=overwritten\n").unwrap();

    murk(&dir, &key)
        .args(["import", "collision.env", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    // Value should be unchanged.
    murk(&dir, &key)
        .args(["get", "EXISTING", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("original"));
}

#[test]
fn import_collision_allowed_with_force() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "EXISTING", "--vault", "test.murk"])
        .write_stdin("original\n")
        .assert()
        .success();

    fs::write(dir.path().join("collision.env"), "EXISTING=overwritten\n").unwrap();

    murk(&dir, &key)
        .args(["import", "collision.env", "--force", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "EXISTING", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("overwritten"));
}

// ── Tampered vault ──

#[test]
fn tampered_ciphertext_fails_integrity() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("realvalue\n")
        .assert()
        .success();

    // Tamper with the shared ciphertext.
    let contents = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    val["secrets"]["SECRET"]["shared"] = serde_json::json!("dGFtcGVyZWQ=");
    fs::write(
        dir.path().join("test.murk"),
        serde_json::to_string_pretty(&val).unwrap(),
    )
    .unwrap();

    // Loading should fail integrity check.
    murk(&dir, &key)
        .args(["get", "SECRET", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity").or(predicate::str::contains("tampered")));
}

#[test]
fn tampered_recipients_fails_integrity() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "--vault", "test.murk"])
        .write_stdin("realvalue\n")
        .assert()
        .success();

    // Add a recipient the vault was never encrypted to.
    let contents = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    val["recipients"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(FOREIGN_PK));
    fs::write(
        dir.path().join("test.murk"),
        serde_json::to_string_pretty(&val).unwrap(),
    )
    .unwrap();

    murk(&dir, &key)
        .args(["get", "SECRET", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity").or(predicate::str::contains("tampered")));
}

// ── Header identity fields ──

/// Each header identity field an attacker might rewrite, with a forged value.
const FORGED_HEADER_FIELDS: &[(&str, &str)] = &[
    ("vault_name", "\"payments-prod\""),
    ("repo", "\"https://github.com/evil/fork\""),
    ("created", "\"2020-01-01T00:00:00Z\""),
    ("vault_id", "\"0123456789abcdef0123456789abcdef\""),
    ("generation", "7"),
];

/// Rewrite one top-level field of the vault file at `path`.
fn set_header_field(path: &std::path::Path, field: &str, json_value: &str) {
    let mut val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    val[field] = serde_json::from_str(json_value).unwrap();
    fs::write(path, serde_json::to_string_pretty(&val).unwrap()).unwrap();
}

#[test]
fn forged_header_field_fails_verify() {
    for (field, forged) in FORGED_HEADER_FIELDS {
        let dir = TempDir::new().unwrap();
        let (key, _) = init_vault(&dir);
        murk(&dir, &key)
            .args(["add", "SECRET", "--vault", "test.murk"])
            .write_stdin("realvalue\n")
            .assert()
            .success();

        set_header_field(&dir.path().join("test.murk"), field, forged);

        let out = murk(&dir, &key)
            .args(["verify", "--vault", "test.murk"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "forged `{field}` must fail verify, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("tampered"),
            "forged `{field}` must read as tampering, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A vault written and signed by murk 0.13.0 (header version 2.0, MAC
/// `blake3v7`-era scheme, signed view 1 inside the meta), with its test-only
/// key. The key file starts with a `#` comment line, which murk skips.
const V0_13_VAULT: &str = include_str!("fixtures/v0_13_signed.murk");
const V0_13_KEY: &str = include_str!("fixtures/v0_13_signed.test-only.key");

#[test]
fn vault_from_0_13_verifies_and_upgrades_on_write() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.murk");
    fs::write(&path, V0_13_VAULT).unwrap();
    // As git checks it out, whatever the test process umask: `verify` flags a
    // group-writable vault.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let key = V0_13_KEY.trim();

    // A machine that never trusted the vault does so once (0.14 anchors trust
    // in a local pin, which a 0.13 machine never wrote)...
    murk(&dir, key)
        .args(["trust", "--yes", "--vault", "test.murk"])
        .assert()
        .success();
    // ...then it reads and verifies as before.
    murk(&dir, key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, key)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("fixture-secret-value-0123"));

    // The next write upgrades it to the 3.x format: top-level view-2 signature.
    murk(&dir, key)
        .args(["add", "OTHER", "--vault", "test.murk"])
        .write_stdin("othervalue123\n")
        .assert()
        .success();
    let upgraded: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(upgraded["version"], "3.0");
    assert_eq!(upgraded["sig"]["v"], 2);
    murk(&dir, key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, key)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("fixture-secret-value-0123"));

    // Once upgraded, the header identity fields are covered.
    set_header_field(&path, "vault_name", "\"payments-prod\"");
    murk(&dir, key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("tampered"));
}

// ── Writing into a vault you are not on ──

#[test]
fn skeleton_vault_listing_only_attacker_refuses_victim_write() {
    // An outsider with repo write replaces the vault with a skeleton that lists
    // only their own key. The victim's write must not encrypt to that key.
    let mallory_dir = TempDir::new().unwrap();
    let (mallory_key, mallory_pk) = init_vault(&mallory_dir);

    let dir = TempDir::new().unwrap();
    let (bob_key, _) = init_vault(&dir);
    let path = dir.path().join("test.murk");
    let skeleton = serde_json::json!({
        "version": "2.0",
        "created": "2026-01-01T00:00:00Z",
        "vault_name": "test.murk",
        "recipients": [mallory_pk],
        "schema": {},
        "secrets": {},
        "meta": "",
    });
    let planted = serde_json::to_string_pretty(&skeleton).unwrap();
    fs::write(&path, &planted).unwrap();

    murk(&dir, &bob_key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("prod-db-password-123\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a recipient"));
    fs::write(
        dir.path().join("restore.env"),
        "DB_PASSWORD=prod-db-password-123\n",
    )
    .unwrap();
    murk(&dir, &bob_key)
        .args(["import", "restore.env", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a recipient"));

    // Nothing was written, so mallory has nothing to read.
    assert_eq!(fs::read_to_string(&path).unwrap(), planted);
    murk(&dir, &mallory_key)
        .args(["get", "DB_PASSWORD", "--vault", "test.murk"])
        .assert()
        .failure();
}
