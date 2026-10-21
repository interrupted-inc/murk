// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{FOREIGN_PK, MURK_CONTEXT_VARS, init_vault, murk, murk_bin, real_path};

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
fn init_existing_vault_new_teammate_generates_key() {
    // A teammate with their own HOME has no key for this vault: init must still
    // generate one and show the pubkey to share.
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    fs::remove_file(dir.path().join(".env")).unwrap();
    let teammate_home = TempDir::new().unwrap();

    murk_bin(teammate_home.path())
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

    // .env should now reference the teammate's new key file.
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains("export MURK_KEY_FILE="));
    assert!(env.contains(teammate_home.path().to_str().unwrap()));
}

#[test]
fn init_existing_vault_ignores_dotenv() {
    // .env is no longer a trusted runtime input. With MURK_KEY and
    // MURK_KEY_FILE both absent from the environment and no stored key for the
    // vault, init must NOT silently authorize by reading .env from the current
    // directory.
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let stored = stored_key_path(dir.path());
    let elsewhere = dir.path().join("moved.key");
    fs::rename(&stored, &elsewhere).unwrap();
    fs::write(
        dir.path().join(".env"),
        format!("export MURK_KEY_FILE='{}'\n", elsewhere.display()),
    )
    .unwrap();

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

/// The single key file `murk init` stored under `home`.
fn stored_key_path(home: &std::path::Path) -> std::path::PathBuf {
    let keys: Vec<_> = fs::read_dir(home.join(".config/murk/keys"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(keys.len(), 1, "expected one stored key: {keys:?}");
    keys.into_iter().next().unwrap()
}

/// A vault with one secret, readable through the stored key alone.
fn vault_with_stored_key(dir: &TempDir) -> (std::path::PathBuf, Vec<u8>) {
    init_vault(dir);
    murk_bin(dir.path())
        .args(["add", "FOO", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("bar\n")
        .assert()
        .success();
    let key_path = stored_key_path(dir.path());
    let bytes = fs::read(&key_path).unwrap();
    (key_path, bytes)
}

fn assert_get_still_works(dir: &TempDir) {
    murk_bin(dir.path())
        .args(["get", "FOO", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("bar"));
}

#[test]
fn init_reuses_stored_key_when_dotenv_is_missing() {
    // A fresh clone or a deleted .env: the stored key must survive a second
    // init, and .env gets its reference back.
    let dir = TempDir::new().unwrap();
    let (key_path, before) = vault_with_stored_key(&dir);
    fs::remove_file(dir.path().join(".env")).unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains(
                    "added MURK_KEY_FILE reference to .env",
                ))
                .and(predicate::str::contains("authorized"))
                .and(predicate::str::contains("not authorized").not())
                .and(predicate::str::contains("generating keypair").not()),
        );

    assert_eq!(fs::read(&key_path).unwrap(), before, "key file replaced");
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains(key_path.to_str().unwrap()), ".env: {env}");
    assert_get_still_works(&dir);
}

#[test]
fn init_reuses_stored_key_without_touching_dotenv() {
    // .env already references the key but direnv has not exported it: init
    // reuses the key without prompting and leaves .env alone.
    let dir = TempDir::new().unwrap();
    let (key_path, before) = vault_with_stored_key(&dir);
    let env_before = fs::read(dir.path().join(".env")).unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("y/N").not())
                .and(predicate::str::contains("added MURK_KEY_FILE").not()),
        );

    assert_eq!(fs::read(&key_path).unwrap(), before, "key file replaced");
    assert_eq!(fs::read(dir.path().join(".env")).unwrap(), env_before);
    assert_get_still_works(&dir);
}

#[test]
fn init_reuses_env_key_file_and_restores_dotenv_reference() {
    // MURK_KEY_FILE names a key outside ~/.config/murk/keys and .env is gone:
    // init reuses that key, says so, and points .env back at it, except in
    // strict mode, where MURK_KEY_FILE is an agent or CI key.
    let dir = TempDir::new().unwrap();
    let (stored, before) = vault_with_stored_key(&dir);
    let key_file = dir.path().join("elsewhere.key");
    fs::rename(&stored, &key_file).unwrap();
    fs::remove_file(dir.path().join(".env")).unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &key_file)
        .env("MURK_AGENT", "1")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("added MURK_KEY_FILE").not()),
        );
    assert!(!dir.path().join(".env").exists(), "strict init wrote .env");

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &key_file)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains(
                    "added MURK_KEY_FILE reference to .env",
                ))
                .and(predicate::str::contains("generating keypair").not()),
        );

    assert_eq!(fs::read(&key_file).unwrap(), before, "key file replaced");
    assert!(!stored.exists(), "init stored a second key");
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains(key_file.to_str().unwrap()), ".env: {env}");
}

#[cfg(unix)]
#[test]
fn init_shows_recovery_words_even_when_dotenv_write_fails() {
    // The key is stored before .env is written, and a retry reuses it without
    // a phrase, so the phrase must print before the .env write can fail.
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    fs::remove_file(dir.path().join(".env")).unwrap();
    std::os::unix::fs::symlink("/dev/null", dir.path().join(".env")).unwrap();
    let teammate_home = TempDir::new().unwrap();

    murk_bin(teammate_home.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("RECOVERY WORDS").and(predicate::str::contains("symlink")),
        );
}

#[test]
fn init_with_a_corrupt_stored_key_says_how_to_get_out() {
    let dir = TempDir::new().unwrap();
    let (key_path, _) = vault_with_stored_key(&dir);
    fs::write(&key_path, "hello\n").unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "move it aside and run murk init again",
        ));
    assert_eq!(fs::read(&key_path).unwrap(), b"hello\n");
}

#[test]
fn init_new_vault_reuses_stored_key_at_the_same_path() {
    // Deleting the vault file must not cost the key stored for its path.
    let dir = TempDir::new().unwrap();
    let (key_path, before) = vault_with_stored_key(&dir);
    let identity: age::x25519::Identity = fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pubkey = identity.to_public().to_string();
    fs::remove_file(dir.path().join("test.murk")).unwrap();
    fs::remove_file(dir.path().join(".env")).unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("alice\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("RECOVERY WORDS").not()),
        );

    assert_eq!(fs::read(&key_path).unwrap(), before, "key file replaced");
    let vault = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(
        vault.contains(&pubkey),
        "stored key is not the new recipient"
    );
}

#[test]
fn init_does_not_replace_a_vault_that_appears_during_the_name_prompt() {
    use std::io::{Read, Write};
    use std::process::Stdio;

    // A real vault to drop in while init waits for a name, as a `git pull`
    // in another terminal would.
    let source = TempDir::new().unwrap();
    init_vault(&source);
    let pulled = fs::read(source.path().join("test.murk")).unwrap();

    let dir = TempDir::new().unwrap();
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"));
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the prompt: init has decided this is a new vault.
    let mut stderr = child.stderr.take().unwrap();
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while !String::from_utf8_lossy(&seen).contains("Enter your name") {
        assert_eq!(stderr.read(&mut byte).unwrap(), 1, "init exited early");
        seen.push(byte[0]);
    }
    fs::write(dir.path().join("test.murk"), &pulled).unwrap();
    child.stdin.take().unwrap().write_all(b"alice\n").unwrap();
    stderr.read_to_end(&mut seen).unwrap();
    let status = child.wait().unwrap();
    let stderr = String::from_utf8_lossy(&seen);

    assert!(
        !status.success(),
        "init succeeded over the new vault: {stderr}"
    );
    assert!(stderr.contains("left unchanged"), "{stderr}");
    assert_eq!(fs::read(dir.path().join("test.murk")).unwrap(), pulled);
}

#[test]
fn vault_discovery_does_not_walk_outside_git_and_home() {
    // Not in a git repo and not under HOME (say /tmp): a vault in an ancestor
    // directory may have been planted by another user and must not be used.
    let base = TempDir::new().unwrap();
    let (key, _) = init_vault(&base);
    let nested = base.path().join("a").join("b");
    fs::create_dir_all(&nested).unwrap();
    fs::rename(base.path().join("test.murk"), base.path().join(".murk")).unwrap();
    let elsewhere = TempDir::new().unwrap();

    murk_bin(elsewhere.path())
        .args(["ls"])
        .current_dir(&nested)
        .env("MURK_KEY", &key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));

    // Under HOME the walk still finds it, up to HOME itself.
    murk_bin(base.path())
        .args(["ls"])
        .current_dir(&nested)
        .env("MURK_KEY", &key)
        .assert()
        .success();
}

/// The age public key for an `AGE-SECRET-KEY-…` string.
fn pubkey_of(key: &str) -> String {
    let identity: age::x25519::Identity = key.trim().parse().unwrap();
    identity.to_public().to_string()
}

#[test]
fn init_new_vault_in_strict_mode_uses_murk_key_file_over_a_stored_key() {
    // The strict refusal says "set MURK_KEY_FILE"; for a new vault that must
    // work: the named key becomes the first recipient, the stored key is left
    // alone.
    let dir = TempDir::new().unwrap();
    let (stored, before) = vault_with_stored_key(&dir);
    fs::remove_file(dir.path().join("test.murk")).unwrap();
    fs::remove_file(dir.path().join(".env")).unwrap();
    // Another identity's key file, outside this HOME's key store (0600).
    let other = TempDir::new().unwrap();
    let (agent_key, _) = init_vault(&other);
    let agent_key_file = stored_key_path(other.path());

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &agent_key_file)
        .env("MURK_STRICT", "1")
        .write_stdin("alice\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("RECOVERY WORDS").not()),
        );

    assert_eq!(fs::read(&stored).unwrap(), before, "stored key changed");
    let vault = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(
        vault.contains(&pubkey_of(&agent_key)),
        "MURK_KEY_FILE key is not the recipient"
    );
    let stored_pubkey = pubkey_of(&String::from_utf8(before).unwrap());
    assert!(!vault.contains(&stored_pubkey), "stored key was used");
}

#[test]
fn init_new_vault_uses_murk_key_from_the_environment() {
    let other = TempDir::new().unwrap();
    let (key, _) = init_vault(&other);
    let dir = TempDir::new().unwrap();

    murk_bin(dir.path())
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", &key)
        .write_stdin("alice\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key from MURK_KEY")
                .and(predicate::str::contains("RECOVERY WORDS").not()),
        );

    let vault = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(vault.contains(&pubkey_of(&key)));
    assert!(
        !dir.path().join(".config/murk/keys").exists(),
        "init stored a key"
    );
}

#[test]
fn init_in_strict_mode_neither_uses_nor_replaces_a_stored_key() {
    let dir = TempDir::new().unwrap();
    let (key_path, before) = vault_with_stored_key(&dir);
    fs::remove_file(dir.path().join(".env")).unwrap();

    for var in ["MURK_AGENT", "MURK_STRICT"] {
        murk_bin(dir.path())
            .args(["init", "--vault", "test.murk"])
            .current_dir(dir.path())
            .env(var, "1")
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("already stored at")
                    .and(predicate::str::contains("set MURK_KEY_FILE=")),
            );
        assert_eq!(fs::read(&key_path).unwrap(), before, "{var}: key replaced");
        assert!(!dir.path().join(".env").exists(), "{var}: .env written");
    }
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
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"));
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd.args(args)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
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
fn diff_rejects_invalid_vault_in_git_history() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    let vault_path = dir.path().join("test.murk");
    let good = fs::read_to_string(&vault_path).unwrap();

    // Commit a hostile revision: a key name that would be a shell injection
    // vector if exported.
    let mut bad: serde_json::Value = serde_json::from_str(&good).unwrap();
    bad["schema"]["X;rm -rf ~"] = serde_json::json!({"description": ""});
    fs::write(&vault_path, bad.to_string()).unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .unwrap();
    };
    git(&["init"]);
    git(&["add", "test.murk"]);
    git(&["commit", "-m", "hostile"]);
    fs::write(&vault_path, &good).unwrap();

    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("parsing vault at HEAD").and(predicate::str::contains(
                "schema: invalid key name X;rm -rf ~",
            )),
        );
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

/// Add `name = value` to `test.murk` in `dir`, with any extra `add` arguments.
fn add_to_test_vault(dir: &TempDir, key: &str, name: &str, value: &str, extra: &[&str]) {
    murk(dir, key)
        .args(["add", name, "--vault", "test.murk"])
        .args(extra)
        .write_stdin(format!("{value}\n"))
        .assert()
        .success();
}

/// Commit `test.murk` as it stands into a fresh git repository in `dir`.
fn commit_test_vault(dir: &std::path::Path) {
    git_ok(dir, &["init", "-q"]);
    git_ok(dir, &["add", "test.murk"]);
    git_ok(
        dir,
        &["-c", "commit.gpgsign=false", "commit", "-qm", "vault"],
    );
}

#[test]
fn diff_reads_group_secrets_at_the_ref() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["group", "create", "ops", "--vault", "test.murk"])
        .assert()
        .success();
    add_to_test_vault(&dir, &key, "GRP", "group-value", &["--group", "ops"]);
    commit_test_vault(dir.path());

    // Nothing changed, so the group secret must not show as added.
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains("no changes"));
}

#[test]
fn diff_fails_on_an_unknown_ref() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "db-value", &[]);
    commit_test_vault(dir.path());

    murk(&dir, &key)
        .args(["diff", "no-such-ref", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "no-such-ref does not name a git commit",
        ));
}

#[test]
fn diff_from_a_subdirectory_reads_the_vault_at_the_ref() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "db-value", &[]);
    commit_test_vault(dir.path());
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();

    murk(&dir, &key)
        .current_dir(&sub)
        // A bare name is discovered in the parent directory, as an absolute path.
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains("no changes"));
}

/// A ref is untrusted input: one that starts with `-` must never reach git as
/// an option (here `git show --output=FILE` would write a file).
#[test]
fn diff_refuses_a_ref_that_is_a_git_option() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "db-value", &[]);
    commit_test_vault(dir.path());
    let target = dir.path().join("injected");

    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk", "--"])
        .arg(format!("--output={}", target.display()))
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid git revision"));
    let written: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("injected"))
        .collect();
    assert!(written.is_empty(), "git wrote {written:?}");
}

/// A revision that fails the MAC check must not be decrypted, even though its
/// ciphertexts are still readable.
#[test]
fn diff_refuses_a_tampered_revision() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "A", "value-of-a", &[]);
    add_to_test_vault(&dir, &key, "B", "value-of-b", &[]);
    let vault_path = dir.path().join("test.murk");
    let good = fs::read_to_string(&vault_path).unwrap();

    // Swap two ciphertexts: each still decrypts, but under the other key.
    let mut bad: serde_json::Value = serde_json::from_str(&good).unwrap();
    let a = bad["secrets"]["A"]["shared"].take();
    let b = bad["secrets"]["B"]["shared"].take();
    bad["secrets"]["A"]["shared"] = b;
    bad["secrets"]["B"]["shared"] = a;
    fs::write(&vault_path, bad.to_string()).unwrap();
    commit_test_vault(dir.path());
    fs::write(&vault_path, &good).unwrap();

    murk(&dir, &key)
        .args(["diff", "--show-values", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "vault at HEAD failed verification",
        ));
}

#[cfg(unix)]
#[test]
fn diff_strict_refuses_values_into_a_file() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "old-value", &[]);
    commit_test_vault(dir.path());
    add_to_test_vault(&dir, &key, "DB", "new-value", &[]);

    let leak = dir.path().join("diff.txt");
    let status = run_with_stdout_file(
        &dir,
        &key,
        &["diff", "--show-values", "--vault", "test.murk"],
        &leak,
    );
    assert!(
        !status.success(),
        "strict diff --show-values to a file should fail"
    );
    assert_eq!(fs::read_to_string(&leak).unwrap(), "", "values leaked");
}

/// Commit the current `test.murk` on top of the repository's history.
fn commit_test_vault_again(dir: &std::path::Path, message: &str) {
    git_ok(
        dir,
        &["-c", "commit.gpgsign=false", "commit", "-qam", message],
    );
}

/// A HEAD branch that exists but points at a missing object is a broken
/// repository, not one without commits: diff must fail, not show every
/// secret as added.
#[test]
fn diff_fails_when_head_points_at_a_missing_commit() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "db-value", &[]);
    commit_test_vault(dir.path());
    let branch = std::process::Command::new("git")
        .args(["symbolic-ref", "HEAD"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let branch = String::from_utf8(branch.stdout).unwrap();
    fs::write(
        dir.path().join(".git").join(branch.trim()),
        "1111111111111111111111111111111111111111\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("HEAD does not name a git commit"));
}

/// History written by an ordinary later save still verifies.
#[test]
fn diff_against_the_previous_save_succeeds() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_to_test_vault(&dir, &key, "DB", "first", &[]);
    commit_test_vault(dir.path());
    add_to_test_vault(&dir, &key, "DB", "second", &[]);
    commit_test_vault_again(dir.path(), "second save");

    murk(&dir, &key)
        .args(["diff", "HEAD~1", "--show-values", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("~ DB first → second"));
}

/// A revision signed by a teammate who was revoked later was legitimate when
/// written, so it still verifies.
#[test]
fn diff_across_a_revoke_of_the_old_signer_succeeds() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let bob_home = TempDir::new().unwrap();
    let (bob_key, bob_pk) = init_vault(&bob_home);
    add_to_test_vault(&dir, &key, "DB", "db-value", &[]);
    murk(&dir, &key)
        .args(["circle", "authorize", &bob_pk, "--name", "bob"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    // Bob writes last, so the committed revision carries his signature.
    add_to_test_vault(&dir, &bob_key, "API", "api-value", &[]);
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("signed by trusted signer bob"));
    commit_test_vault(dir.path());

    murk(&dir, &key)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success();
    commit_test_vault_again(dir.path(), "revoke bob");

    // The revision verifies; only the revoke itself shows. Reading it never
    // records anything in the trust pin: bob stays revoked here.
    let pins = || {
        let mut all: Vec<(std::path::PathBuf, Vec<u8>)> =
            fs::read_dir(dir.path().join(".config/murk/signer-pins"))
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
    murk(&dir, &key)
        .args(["diff", "HEAD~1", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("- recipient bob ("))
        .stdout(predicate::str::contains("~ signer bob ("))
        .stdout(predicate::str::contains("DB").not())
        .stderr("");
    assert_eq!(pins(), pinned, "diff must not change the trust pin");
}

/// git runs hooks, filters and helpers with its own environment, so murk must
/// not hand it the key. A stand-in `git` first on `PATH` records what it sees.
#[cfg(unix)]
#[test]
fn git_does_not_inherit_the_key() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    let bin = dir.path().join("fake-bin");
    fs::create_dir(&bin).unwrap();
    let seen = dir.path().join("git-env");
    let git = bin.join("git");
    fs::write(
        &git,
        format!("#!/bin/sh\nenv > '{}'\nexit 1\n", seen.display()),
    )
    .unwrap();
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());

    // Key passed inline. The stand-in git fails, and diff fails with it.
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .env("PATH", &path)
        .assert()
        .failure();
    let env = fs::read_to_string(&seen).unwrap();
    assert!(!env.contains(&key), "git saw MURK_KEY's value");
    assert!(!env.contains("MURK_KEY"), "git env: {env}");

    // Key passed by file.
    fs::remove_file(&seen).unwrap();
    let key_file = dir.path().join("key");
    fs::write(&key_file, &key).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .env_remove("MURK_KEY")
        .env("MURK_KEY_FILE", &key_file)
        .env("PATH", &path)
        .assert()
        .failure();
    let env = fs::read_to_string(&seen).unwrap();
    assert!(!env.contains("MURK_KEY_FILE"), "git env: {env}");
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

/// A restricting flag murk does not recognise turns the restriction on: a typo
/// or an `on` must not leave strict mode silently off.
#[test]
fn unrecognised_strict_values_fail_closed() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let get = || {
        let mut cmd = murk_bin(dir.path());
        cmd.current_dir(dir.path())
            .args(["get", "NOPE", "--vault", "test.murk"]);
        cmd
    };
    // Auto-discovery finds the stored key; `NOPE` is simply absent.
    get()
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
    for (var, value) in [
        ("MURK_STRICT", "on"),
        ("MURK_STRICT", "enabled"),
        ("MURK_STRICT", "ture"),
        ("MURK_AGENT", "y"),
    ] {
        get()
            .env(var, value)
            .assert()
            .failure()
            .stderr(predicate::str::contains("MURK_KEY not set"));
    }
    get()
        .env("MURK_STRICT", "off")
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

/// A same-user process cannot read a running murk's environment (where
/// `MURK_KEY` lives) or memory through `/proc`, while murk's own children,
/// reset by `execve`, are unaffected. `agent exec` stays the child's parent
/// (it supervises rather than `exec`s), so the child can try.
#[cfg(target_os = "linux")]
#[test]
fn murk_process_is_not_readable_through_proc() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("sekret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "TOKEN",
            // The operator's own key: no grant is needed to test the process.
            "--allow-operator-key",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "grep -q murk /proc/$PPID/cmdline && echo PARENT-IS-MURK; cat /proc/$PPID/environ >/dev/null 2>&1 && echo PARENT-READABLE; cat /proc/self/environ >/dev/null && echo SELF-OK",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PARENT-IS-MURK"))
        .stdout(predicate::str::contains("SELF-OK"))
        .stdout(predicate::str::contains("PARENT-READABLE").not());
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
fn init_in_a_new_worktree_reuses_the_original_checkouts_key() {
    // A new worktree has the vault but no .env. init must reuse the key the
    // runtime would find, not generate a second identity for the operator.
    let base = TempDir::new().unwrap();
    let (home, _repo, worktree) = worktree_fixture(base.path());
    let key_path = stored_key_path(&home);
    let before = fs::read(&key_path).unwrap();

    murk_bin(&home)
        .args(["init", "--vault", "test.murk"])
        .current_dir(&worktree)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("generating keypair").not())
                .and(predicate::str::contains("not authorized").not()),
        );

    assert_eq!(fs::read(&key_path).unwrap(), before, "key file replaced");
    // Still exactly one stored key: no second identity shadows the original.
    stored_key_path(&home);
    let env = fs::read_to_string(worktree.join(".env")).unwrap();
    assert!(env.contains(key_path.to_str().unwrap()), ".env: {env}");
    murk_bin(&home)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .current_dir(&worktree)
        .assert()
        .success()
        .stdout(predicate::str::contains("s3cret"));
}

#[test]
fn init_new_vault_in_a_worktree_reuses_the_sibling_checkouts_key() {
    // The sibling checkout has an uncommitted vault and its key; the worktree
    // creates the same vault path from scratch. A fresh key stored for the
    // worktree's path would shadow the sibling's key there, leaving the
    // operator two identities for one vault path.
    let base = TempDir::new().unwrap();
    let (home, repo, worktree) = worktree_fixture(base.path());
    murk_bin(&home)
        .args(["init", "--vault", "other.murk"])
        .current_dir(&repo)
        // The repo's .env already references test.murk's key: replace it.
        .write_stdin("testuser\ny\n")
        .assert()
        .success();
    let keys_dir = home.join(".config/murk/keys");
    let keys_before: Vec<_> = fs::read_dir(&keys_dir).unwrap().collect();
    assert_eq!(keys_before.len(), 2);

    murk_bin(&home)
        .args(["init", "--vault", "other.murk"])
        .current_dir(&worktree)
        .write_stdin("testuser\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("using existing key")
                .and(predicate::str::contains("generating keypair").not()),
        );

    assert_eq!(
        fs::read_dir(&keys_dir).unwrap().count(),
        2,
        "init stored a second key for the worktree"
    );
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
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "YmFzZS1kYg==" }
  },
  "meta": "YmFzZS1tZXRh"
}"#;

    // Ours: adds API_KEY.
    let ours_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "schema": {
    "API_KEY": { "description": "api key", "tags": [] },
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "API_KEY": { "shared": "b3Vycy1hcGk=" },
    "DB_URL": { "shared": "YmFzZS1kYg==" }
  },
  "meta": "b3Vycy1tZXRh"
}"#;

    // Theirs: adds STRIPE_KEY.
    let theirs_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] },
    "STRIPE_KEY": { "description": "stripe", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "YmFzZS1kYg==" },
    "STRIPE_KEY": { "shared": "dGhlaXJzLXN0cmlwZQ==" }
  },
  "meta": "dGhlaXJzLW1ldGE="
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
fn merge_driver_conflict_exit_code() {
    let dir = TempDir::new().unwrap();

    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "YmFzZQ==" }
  },
  "meta": "YmFzZS1tZXRh"
}"#;

    // Both sides modify DB_URL.
    let ours_json = base_json.replace("YmFzZQ==", "b3Vycw==");
    let theirs_json = base_json.replace("YmFzZQ==", "dGhlaXJz");

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

/// Every writer path must produce a vault that load-time validation accepts.
/// Drives each CLI writer once so the resulting file carries every field shape
/// murk writes, then reloads it through the validating readers.
#[test]
fn every_writer_path_round_trips_through_validation() {
    const BOB_SSH: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let run = |args: &[&str], stdin: &str| {
        murk(&dir, &key)
            .args(args)
            .args(["--vault", "test.murk"])
            .write_stdin(stdin)
            .assert()
            .success();
    };

    run(
        &[
            "add",
            "DB_URL",
            "--desc",
            "primary db",
            "--example",
            "postgres://h/db",
            "--tag",
            "db",
        ],
        "pg://prod\n",
    );
    run(
        &[
            "describe",
            "DB_URL",
            "multi-line\ndescription\twith tab",
            "--example",
            "postgres://h/db",
            "--tag",
            "db",
            "--tag",
            "agents",
            "--rotate-every",
            "90d",
            "--expires",
            "2030-01-01",
        ],
        "",
    );
    run(
        &["circle", "authorize", BOB_SSH, "--name", "Bob (laptop) ✓"],
        "",
    );
    run(&["circle", "authorize", FOREIGN_PK, "--name", "carol"], "");
    run(&["group", "create", "prod-team_1"], "");
    run(&["group", "add", "prod-team_1", "--member", "carol"], "");
    run(
        &["add", "STRIPE_KEY", "--group", "prod-team_1"],
        "sk_live\n",
    );
    run(&["add", "MY_TOKEN", "--group", "me"], "mine\n");
    run(&["policy", "set", "--allow-tag", "agents"], "");
    let agent_key = dir.path().join("agent.key");
    run(
        &[
            "agent",
            "grant",
            "--name",
            "codex-1",
            "--only",
            "DB_URL",
            "--out",
            agent_key.to_str().unwrap(),
        ],
        "",
    );
    // Deferred rotation leaves `revoked_at` markers in the schema.
    run(&["circle", "revoke", "Bob (laptop) ✓"], "");
    run(&["skeleton", "--output", "skeleton.murk"], "");

    // The run produced every optional field shape, not just a minimal vault.
    let raw = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let db = &v["schema"]["DB_URL"];
    for field in [
        "example",
        "tags",
        "created",
        "updated",
        "rotation_interval_days",
        "expires_at",
        "revoked_at",
    ] {
        assert!(!db[field].is_null(), "schema.DB_URL.{field} missing: {db}");
    }
    assert!(v["policy"]["agent_allow_tags"].is_array());
    assert!(v["secrets"]["STRIPE_KEY"]["grouped"]["prod-team_1"].is_string());
    assert!(v["secrets"]["MY_TOKEN"]["scoped"].is_object());

    // Header readers (no meta) and full readers (meta, MAC, signature).
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success();
    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success();
    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["info", "--vault", "skeleton.murk"])
        .assert()
        .success();
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
        .push(serde_json::Value::String(FOREIGN_PK.into()));
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
        .push(serde_json::Value::String(FOREIGN_PK.into()));
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

/// Write `key` to `path` with `mode` (Unix permission bits).
#[cfg(unix)]
fn write_key_file(path: &std::path::Path, key: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, key).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

// A key file murk refuses to load (group/world-readable) is still located, so
// the inside-the-repo check fires and the loose mode is reported too.
#[cfg(unix)]
#[test]
fn doctor_flags_loose_key_file_inside_repo() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let key_path = dir.path().join("murk.key");
    write_key_file(&key_path, &key, 0o644);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &key_path)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "murk.key is inside the working tree",
        ))
        .stderr(predicate::str::contains(
            "murk.key is readable by others (mode 644)",
        ))
        .stderr(predicate::str::contains("chmod 600"));
}

#[cfg(unix)]
#[test]
fn doctor_flags_owner_only_key_file_inside_repo() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let key_path = dir.path().join("murk.key");
    write_key_file(&key_path, &key, 0o600);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &key_path)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "murk.key is inside the working tree",
        ))
        .stderr(predicate::str::contains("readable by others").not());
}

#[cfg(unix)]
#[test]
fn doctor_accepts_key_file_outside_repo() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let elsewhere = TempDir::new().unwrap();
    let key_path = elsewhere.path().join("murk.key");
    write_key_file(&key_path, &key, 0o600);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &key_path)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("repo hygiene looks clean"));
}

// Both key variables set is an error for every command, so doctor reports it
// with the fix instead of checking whichever one it might have picked.
#[test]
fn doctor_flags_both_key_variables_set() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let elsewhere = TempDir::new().unwrap();
    let key_path = elsewhere.path().join("murk.key");
    fs::write(&key_path, &key).unwrap();

    murk(&dir, &key)
        .env("MURK_KEY_FILE", &key_path)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "MURK_KEY and MURK_KEY_FILE are both set",
        ))
        .stderr(predicate::str::contains("unset one of them"));
}

// The auto-discovered key is looked up for the vault the user selected, not
// `.murk`. HOME is the repo here, so the stored key sits inside the tree.
#[test]
fn doctor_checks_auto_discovered_key_for_selected_vault() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["init", "--vault", "other.murk"])
        .write_stdin("testuser\n")
        .assert()
        .success();

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["doctor", "--vault", "other.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is inside the working tree"));
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
fn describe_invalid_lifecycle_value_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("s3cr3t\n")
        .assert()
        .success();

    for (flag, value) in [("--rotate-every", "soon"), ("--expires", "tomorrow")] {
        murk(&dir, &key)
            .args([
                "describe",
                "TOKEN",
                "deploy token",
                flag,
                value,
                "--vault",
                "test.murk",
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(format!("invalid {flag}")));
    }
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
    assert_eq!(skeleton["version"], "3.0");
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
fn agent_plan_shows_example_set_by_add() {
    // `add --example` must set the schema example in a single command, with no
    // follow-up `describe` — and surface it in `agent plan` exactly like describe.
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "--desc",
            "Primary database",
            "--example",
            "postgres://localhost/db",
            "--vault",
            "test.murk",
        ])
        .write_stdin("postgres://prod\n")
        .assert()
        .success();

    let json_out = murk(&dir, &key)
        .args(["agent", "plan", "--json", "--vault", "test.murk"])
        .output()
        .unwrap();
    assert!(json_out.status.success());

    let plan: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(plan["entries"][0]["key"], "DB_URL");
    assert_eq!(plan["entries"][0]["example"], "postgres://localhost/db");
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

    let grant = mint_exec_grant(&dir, &key, "exec", &["DB_URL"]);
    let output = murk(&dir, &grant)
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

    // Injected values come back masked; the placeholder proves which keys
    // reached the child.
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("DB_URL=***DB_URL***"));
    assert!(!stdout.contains("API_KEY="));
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

    let grant = mint_exec_grant(&dir, &key, "exec", &["DB_URL"]);
    let output = murk(&dir, &grant)
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
    assert!(stdout.contains("DB_URL=***DB_URL***"));
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

    let grant = mint_exec_grant(&dir, &key, "exec", &["DB_URL"]);
    let output = murk(&dir, &grant)
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

    let grant = mint_exec_grant(&dir, &key, "exec", &["DB_URL"]);
    murk(&dir, &grant)
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

/// A murk command as an agent shell would run it: `HOME` holds the operator's
/// stored key (written by `init_vault`), and no `MURK_*` or `CI` variable is
/// set (`murk_bin` strips them), so key resolution falls through to
/// auto-discovery.
fn operator_shell(dir: &TempDir) -> assert_cmd::Command {
    let mut cmd = murk_bin(dir.path());
    cmd.current_dir(dir.path());
    cmd
}

/// `murk agent exec --only DB_URL -- sh -c <script>` as a spawnable
/// `std::process::Command` with the hermetic test env, for tests that signal
/// murk while it runs (assert_cmd only runs to completion).
#[cfg(unix)]
fn spawn_agent_exec_sh(dir: &TempDir, script: &str) -> std::process::Command {
    let key = exec_grant_key(dir);
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"));
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("MURK_KEY", key.trim())
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            script,
        ]);
    cmd
}

/// The operator's auto-discovered key file under `<dir>/.config/murk/keys`.
fn stored_key_file(dir: &TempDir) -> std::path::PathBuf {
    fs::read_dir(dir.path().join(".config/murk/keys"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

/// Add `DB_URL`, mint an `exec` grant for it (key at `exec.key`, read back with
/// [`exec_grant_key`]), and return the dir, ready for agent exec.
fn agent_exec_vault() -> TempDir {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod-sentinel\n")
        .assert()
        .success();
    mint_exec_grant(&dir, &key, "exec", &["DB_URL"]);
    dir
}

/// Mint grant `name` over `only` with the operator `key`, writing its key to
/// `<name>.key` in `dir`, and return the grant key. `agent exec` needs one.
fn mint_exec_grant(dir: &TempDir, key: &str, name: &str, only: &[&str]) -> String {
    let path = dir.path().join(format!("{name}.key"));
    let mut cmd = murk(dir, key);
    cmd.args(["agent", "grant", "--name", name]);
    for k in only {
        cmd.args(["--only", k]);
    }
    cmd.arg("--out")
        .arg(&path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    read_agent_key(&path)
}

/// The `exec` grant key minted by [`agent_exec_vault`].
fn exec_grant_key(dir: &TempDir) -> String {
    read_agent_key(&dir.path().join("exec.key"))
}

#[test]
fn agent_exec_refuses_auto_discovered_operator_key() {
    let dir = agent_exec_vault();

    let assertion = operator_shell(&dir)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "echo",
            "ran",
        ])
        .assert()
        .failure()
        .stdout("");
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();

    // It says why and names both ways forward, and fails before the run starts.
    assert_narrow_error(&stderr, "agent exec refuses your personal key");
    assert!(stderr.contains("MURK_KEY_FILE"), "{stderr}");
    assert!(stderr.contains("--allow-operator-key"), "{stderr}");
    assert!(!stderr.contains("injecting"), "{stderr}");
}

#[test]
fn agent_exec_allow_operator_key_runs_and_always_warns() {
    let dir = agent_exec_vault();

    // CI is set to show the warning is not CI-gated, and that it replaces the
    // CI personal-key hint instead of stacking a second notice on top.
    let assertion = operator_shell(&dir)
        .env("CI", "true")
        .args([
            "agent",
            "exec",
            "--allow-operator-key",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "test \"$DB_URL\" = postgres://prod-sentinel && echo injected-ok",
        ])
        .assert()
        .success()
        .stdout("injected-ok\n");
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();

    assert!(
        stderr.contains("warn agent exec is decrypting with your personal key"),
        "{stderr}"
    );
    assert!(!stderr.contains("CI is decrypting"), "{stderr}");
}

#[test]
fn agent_exec_refuses_an_operator_key_from_an_explicit_key_file() {
    // A key handed over in MURK_KEY_FILE (say by direnv from `murk init`'s
    // .env) is still the operator's: agent exec decides by identity, not by
    // where the key came from.
    let dir = agent_exec_vault();

    let assertion = operator_shell(&dir)
        .env("MURK_KEY_FILE", stored_key_file(&dir))
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "echo \"leaked=$DB_URL\"",
        ])
        .assert()
        .failure()
        .stdout("");
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("agent exec needs an agent grant key"),
        "{stderr}"
    );
    assert!(stderr.contains("--allow-operator-key"), "{stderr}");
}

#[test]
fn agent_exec_runs_with_a_grant_key_file() {
    let dir = agent_exec_vault();

    operator_shell(&dir)
        .env("MURK_KEY_FILE", dir.path().join("exec.key"))
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "test \"$DB_URL\" = postgres://prod-sentinel && echo injected-ok",
        ])
        .assert()
        .success()
        .stdout("injected-ok\n")
        .stderr(predicate::str::contains("personal key").not());
}

#[test]
fn key_and_key_file_together_are_refused() {
    let dir = agent_exec_vault();
    let key = fs::read_to_string(stored_key_file(&dir)).unwrap();

    // Refused even when both name the same key: murk never picks a winner.
    let assertion = operator_shell(&dir)
        .env("MURK_KEY", key.trim())
        .env("MURK_KEY_FILE", stored_key_file(&dir))
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("");
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("MURK_KEY and MURK_KEY_FILE are both set"),
        "{stderr}"
    );
}

#[test]
fn empty_key_with_key_file_decrypts() {
    // The shape of a `murk agent connect` MCP entry: MURK_KEY blanked to mask
    // an inherited one, the key handed over in MURK_KEY_FILE.
    let dir = agent_exec_vault();

    operator_shell(&dir)
        .env("MURK_KEY", "")
        .env("MURK_KEY_FILE", stored_key_file(&dir))
        .env("MURK_AGENT", "1")
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("postgres://prod-sentinel\n");
}

/// Values are masked on both streams: repeated, written in two pieces with a
/// pause between (so murk reads them separately), and at the end of a stream
/// with no newline. A value under the 4-byte floor is left alone.
#[cfg(unix)]
#[test]
fn agent_exec_masks_injected_values_on_both_streams() {
    let dir = agent_exec_vault();
    let key = fs::read_to_string(stored_key_file(&dir)).unwrap();
    murk(&dir, &key)
        .args(["add", "SHORT", "--vault", "test.murk"])
        .write_stdin("abc\n")
        .assert()
        .success();

    let grant = mint_exec_grant(&dir, &key, "mask", &["DB_URL", "SHORT"]);

    let script = r#"
        echo "DB_URL=$DB_URL DB_URL=$DB_URL$DB_URL"
        printf %s "$(printf %s "$DB_URL" | cut -c1-12)"
        sleep 0.3
        printf '%s\n' "$(printf %s "$DB_URL" | cut -c13-)"
        echo "SHORT=$SHORT"
        printf 'err %s' "$DB_URL" >&2
    "#;
    let assertion = murk(&dir, &grant)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--only",
            "SHORT",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            script,
        ])
        .assert()
        .success();
    let out = assertion.get_output();
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();

    assert_eq!(
        stdout,
        "DB_URL=***DB_URL*** DB_URL=***DB_URL******DB_URL***\n***DB_URL***\nSHORT=abc\n"
    );
    assert!(stderr.ends_with("err ***DB_URL***"), "{stderr}");
    assert!(!stderr.contains("prod-sentinel"), "{stderr}");
}

#[test]
fn agent_exec_propagates_exit_code() {
    let dir = agent_exec_vault();
    let key = exec_grant_key(&dir);

    #[cfg(unix)]
    let command = ["sh", "-c", "exit 7"];
    #[cfg(windows)]
    let command = ["cmd", "/C", "exit 7"];

    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
        ])
        .args(command)
        .assert()
        .code(7);
}

#[cfg(unix)]
#[test]
fn agent_exec_propagates_signal_death() {
    use std::os::unix::process::ExitStatusExt;

    let dir = agent_exec_vault();
    let key = exec_grant_key(&dir);

    let output = murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "kill -TERM $$",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15), "{:?}", output.status);
}

/// The child writes more than a pipe buffer to stderr before it writes to
/// stdout, then the reverse. Reading one stream to EOF first would deadlock.
#[cfg(unix)]
#[test]
fn agent_exec_large_output_on_both_streams_does_not_hang() {
    let dir = agent_exec_vault();
    let key = exec_grant_key(&dir);

    let assertion = murk(&dir, &key)
        .timeout(std::time::Duration::from_secs(60))
        .args([
            "agent",
            "exec",
            "--only",
            "DB_URL",
            "--vault",
            "test.murk",
            "--",
            "sh",
            "-c",
            "head -c 300000 /dev/zero >&2; head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2",
        ])
        .assert()
        .success();
    let out = assertion.get_output();
    assert_eq!(out.stdout.len(), 300_000);
    // stderr also carries murk's own two-line agent exec banner.
    assert_eq!(out.stderr.iter().filter(|&&b| b == 0).count(), 600_000);
}

/// A SIGTERM sent to murk alone reaches the child, which can handle it; murk
/// then exits with the child's code.
#[cfg(unix)]
#[test]
fn agent_exec_forwards_sigterm_to_the_child() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let dir = agent_exec_vault();
    let mut murk_proc = spawn_agent_exec_sh(
        &dir,
        "trap 'echo got-term; exit 5' TERM; echo ready; while :; do sleep 0.1; done",
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    let mut lines = BufReader::new(murk_proc.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");

    let killed = Command::new("kill")
        .args(["-TERM", &murk_proc.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());

    assert_eq!(lines.next().unwrap().unwrap(), "got-term");
    assert_eq!(murk_proc.wait().unwrap().code(), Some(5));
}

/// A child that signals murk as soon as it starts can do so before murk has
/// recorded its pid; that signal must not be echoed back either. The window
/// is narrow, so run many children, several at once.
#[cfg(unix)]
#[test]
fn agent_exec_does_not_echo_a_signal_the_child_sends_at_startup() {
    let dir = agent_exec_vault();
    let script = "trap 'echo echoed; exit 9' TERM; kill -TERM $PPID; sleep 0.2; echo done";
    for _ in 0..5 {
        std::thread::scope(|s| {
            let runs: Vec<_> = (0..10)
                .map(|_| {
                    s.spawn(|| {
                        spawn_agent_exec_sh(&dir, script)
                            .stderr(std::process::Stdio::null())
                            .output()
                            .unwrap()
                    })
                })
                .collect();
            for run in runs {
                let out = run.join().unwrap();
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert_eq!(stdout, "done\n", "{:?}", out.status);
                assert_eq!(out.status.code(), Some(0));
            }
        });
    }
}

/// A SIGTERM sent to murk at any point around the child's spawn must end
/// the child: before murk knows its pid the signal is kept, and must be
/// delivered once it does, never lost. The window cannot be hit on demand,
/// so send it at staggered delays to many runs at once; a lost signal shows
/// as the child's 5 s sleep running out instead.
#[cfg(unix)]
#[test]
fn agent_exec_sigterm_around_spawn_always_ends_the_child() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let dir = agent_exec_vault();
    std::thread::scope(|s| {
        let runs: Vec<_> = (0..50u64)
            .map(|i| {
                let dir = &dir;
                s.spawn(move || {
                    let mut murk_proc = spawn_agent_exec_sh(dir, "exec sleep 5")
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                    std::thread::sleep(Duration::from_micros(i * 1500));
                    // SAFETY: plain syscall on a child we have not reaped.
                    unsafe {
                        libc::kill(murk_proc.id() as libc::pid_t, libc::SIGTERM);
                    }
                    let deadline = Instant::now() + Duration::from_secs(3);
                    loop {
                        if let Some(status) = murk_proc.try_wait().unwrap() {
                            return status;
                        }
                        if Instant::now() > deadline {
                            murk_proc.kill().unwrap();
                            panic!("SIGTERM {} ms after start was lost", i * 3 / 2);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                })
            })
            .collect();
        for run in runs {
            let status = run.join().unwrap();
            assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        }
    });
}

/// Once the child has exited, murk may still be draining pipes a background
/// descendant holds open. A SIGTERM then has no child to go to, so murk must
/// die from it instead of swallowing it and waiting for the pipes to close.
#[cfg(unix)]
#[test]
fn agent_exec_dies_from_sigterm_after_child_exits_with_pipes_held_open() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let dir = agent_exec_vault();
    // `sh` exits at once; the backgrounded `sleep` inherits and holds both pipes.
    let mut murk_proc = spawn_agent_exec_sh(&dir, "sleep 10 & echo ready")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(murk_proc.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    // Give `sh` time to exit and murk time to reap it.
    std::thread::sleep(Duration::from_millis(300));

    let killed = Command::new("kill")
        .args(["-TERM", &murk_proc.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());

    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = murk_proc.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            murk_proc.kill().unwrap();
            panic!("murk ignored SIGTERM while a background process held its pipes");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(libc::SIGTERM));
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
        .push(serde_json::Value::String(FOREIGN_PK.into()));
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

/// A real 2048-bit ssh-rsa public key (age can parse it), so the spellings
/// below would be authorized if the ssh-rsa gate missed them.
const SSH_RSA_KEY_BLOB: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaRHg0uOKAavZimU/uWvaGT2lZfd94fHg86IgLPqik1mUYQnrP5Fpn9CzY9eMH1agGu111KLt+bY2uFUBxmz37kUW2PIqdjx33q+k4fEz6K2ndoQVx0y/8ZhIJUlG9KyCh8C/OAfK+7ruyZMp3hE/o6YZjBfSO7jrHAEQ3Z2UnwbAWiLsGFDNb2pBLz1rXRMwF3upSGmdUZq9/OacOgKvdNBhxdTEmLIAu5kKa9oLvc+S/b68nJn2Rd6IuY7KPIIhuLsMsvGl6e5p3Xpx96fJB+xaU/7VARLi5SqfnjgZfIgFH3BNm1pcXNAKbuPW7vHXcQDBwvdeeHZHJuOpqx/X/";

/// murk stores SSH keys in canonical form, so leading whitespace, tabs or
/// repeated spaces must not slip an ssh-rsa key past the gate, raw or via
/// `ssh:`.
#[test]
fn authorize_ssh_rsa_rejected_in_any_spelling() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let pub_file = dir.path().join("rsa.pub");
    fs::write(&pub_file, format!("ssh-rsa\t{SSH_RSA_KEY_BLOB}\tme@host\n")).unwrap();

    for spelling in [
        format!(" ssh-rsa {SSH_RSA_KEY_BLOB}"),
        format!("ssh-rsa\t{SSH_RSA_KEY_BLOB}"),
        format!("ssh-rsa   {SSH_RSA_KEY_BLOB}  me@host"),
        format!("ssh:{}", pub_file.display()),
    ] {
        murk(&dir, &key)
            .args(["circle", "authorize", &spelling, "--vault", "test.murk"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing to authorize"));
    }
}

/// With `--allow-ssh-rsa` the gate warns instead of refusing, and a real
/// ssh-rsa key is authorized and stored in canonical form under its name.
#[test]
fn authorize_raw_ssh_rsa_override_passes_the_gate() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let rsa = format!("ssh-rsa {SSH_RSA_KEY_BLOB}");

    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &format!("{rsa} me@host"),
            "--name",
            "rsa-user",
            "--allow-ssh-rsa",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("authorized via --allow-ssh-rsa"))
        .stderr(predicate::str::contains("refusing to authorize").not());

    let out = murk(&dir, &key)
        .args(["circle", "--json", "--vault", "test.murk"])
        .assert()
        .success();
    let circle: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert!(
        circle
            .as_array()
            .unwrap()
            .contains(&serde_json::json!({"pubkey": rsa, "name": "rsa-user", "is_self": false})),
        "{circle}"
    );
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

#[test]
fn scan_nonexistent_path_is_an_error() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();

    // A mistyped pre-commit path must not report a clean scan.
    murk(&dir, &key)
        .args(["scan", "no-such-dir", "--vault", "test.murk"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot scan no-such-dir"))
        .stderr(predicate::str::contains("no leaked secrets found").not());
}

/// Remove all permissions from `path`; `false` when that doesn't stop this
/// process reading it (root ignores mode bits), so the caller skips.
#[cfg(unix)]
fn make_unreadable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = if path.is_dir() {
        fs::read_dir(path).is_ok()
    } else {
        fs::File::open(path).is_ok()
    };
    if readable {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    !readable
}

#[cfg(unix)]
#[test]
fn scan_unreadable_path_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "DB_PASSWORD", "--vault", "test.murk"])
        .write_stdin("supersecretvalue123\n")
        .assert()
        .success();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(
        locked.join("config.yml"),
        "db_password: supersecretvalue123\n",
    )
    .unwrap();
    if !make_unreadable(&locked) {
        return;
    }

    // Named directly: a bad argument, exit 2.
    murk(&dir, &key)
        .args(["scan", "locked", "--vault", "test.murk"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot scan locked"));

    // Reached while walking: the scan is incomplete, so it fails (exit 1)
    // instead of reporting "no leaked secrets found".
    murk(&dir, &key)
        .args(["scan", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot read"))
        .stderr(predicate::str::contains("scan incomplete"))
        .stderr(predicate::str::contains("no leaked secrets found").not());

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
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
fn agent_grant_key_cannot_change_the_vault() {
    // A grant reads its scope and nothing else. Every write path must refuse
    // it and leave the vault byte-identical. On 0.13.0 `add --group me` with a
    // grant key blanked every shared secret, and policy/group/circle changes
    // went through. No MURK_AGENT here: the gate reads the grant list from the
    // vault, not the environment.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let (_, other_pk) = init_vault(TempDir::new().unwrap());
    for (k, v) in [("A", "aval"), ("B", "bval")] {
        murk(&dir, &key)
            .args(["add", k, "--vault", "test.murk"])
            .write_stdin(format!("{v}\n"))
            .assert()
            .success();
    }
    murk(&dir, &key)
        .args(["group", "create", "ops", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "G", "--group", "ops", "--vault", "test.murk"])
        .write_stdin("gval\n")
        .assert()
        .success();
    // An editor wired up by the operator, so a refused disconnect shows whether
    // it touched the config first.
    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "claude",
            "--only",
            "A",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "A", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    let vault_path = dir.path().join("test.murk");
    let mcp_path = dir.path().join(".mcp.json");
    let vault_before = fs::read(&vault_path).unwrap();
    let mcp_before = fs::read(&mcp_path).unwrap();
    let env_file = dir.path().join("agent.env");
    fs::write(&env_file, "C=cval\n").unwrap();
    let env_file = env_file.to_str().unwrap();

    let attempts: &[(&[&str], &str)] = &[
        (&["add", "C", "--group", "me"], "cval\n"),
        (&["add", "A"], "new\n"),
        (&["generate", "D"], ""),
        (&["describe", "A", "changed"], ""),
        (&["rm", "B"], ""),
        (&["import", env_file], ""),
        (&["edit", "A"], ""),
        (&["rotate", "A"], "new\n"),
        (&["circle", "authorize", &other_pk], ""),
        (&["circle", "revoke", "testuser"], ""),
        (&["group", "create", "evil"], ""),
        (&["group", "add", "ops", "--member", &other_pk], ""),
        (&["group", "rm", "ops"], ""),
        (&["policy", "set", "--allow-tag", "x"], ""),
        (&["policy", "clear"], ""),
        (
            &[
                "agent", "grant", "--name", "bot2", "--only", "A", "--out", "-",
            ],
            "",
        ),
        (&["agent", "revoke", "bot"], ""),
        (&["agent", "connect", "claude", "--only", "A"], ""),
        (&["agent", "disconnect", "claude", "--rotate"], ""),
    ];
    for (args, stdin) in attempts {
        // The key file path, as in the field report.
        murk_bin(dir.path())
            .current_dir(dir.path())
            .env("MURK_KEY_FILE", &agent_key_path)
            .env("EDITOR", "true")
            .args(*args)
            .args(["--vault", "test.murk"])
            .write_stdin(*stdin)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "agent grants are read-only; ask the operator to make this change",
            ));
        assert_eq!(
            fs::read(&vault_path).unwrap(),
            vault_before,
            "{args:?} changed the vault"
        );
        assert_eq!(
            fs::read(&mcp_path).unwrap(),
            mcp_before,
            "{args:?} changed .mcp.json"
        );
    }

    // Reads still work for the grant, and the operator's values are intact.
    murk(&dir, &agent_key)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aval"));
    for (k, v) in [("A", "aval"), ("B", "bval"), ("G", "gval")] {
        murk(&dir, &key)
            .args(["get", k, "--vault", "test.murk"])
            .assert()
            .success()
            .stdout(predicate::str::contains(v));
    }
}

#[test]
fn agent_grant_is_held_to_the_policy_without_murk_agent() {
    // The allow-tag policy applies to a grant key on every CLI read path even
    // when MURK_AGENT is unset (the harness strips it), as it already did in
    // the bindings and MCP. On 0.13.0 `get`/`export`/`exec` with a grant key
    // ignored the policy outside agent mode.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    for (k, v, tags) in [
        ("OK", "okval", &["agents", "keep"][..]),
        ("NOPE", "nopeval", &["agents"][..]),
    ] {
        murk(&dir, &key)
            .args(["add", k, "--vault", "test.murk"])
            .write_stdin(format!("{v}\n"))
            .assert()
            .success();
        let mut describe = murk(&dir, &key);
        describe.args(["describe", k, "d", "--vault", "test.murk"]);
        for t in tags {
            describe.args(["--tag", t]);
        }
        describe.assert().success();
    }
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
    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "bot", "--only", "OK", "--only", "NOPE",
        ])
        .args(["--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    // Tighten the policy: NOPE stays in the grant's scope but is now forbidden.
    murk(&dir, &key)
        .args([
            "policy",
            "set",
            "--allow-tag",
            "keep",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    murk(&dir, &agent_key)
        .args(["get", "NOPE", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("nopeval").not())
        .stderr(predicate::str::contains("policy forbids NOPE"));
    murk(&dir, &agent_key)
        .args(["get", "OK", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("okval"));
    murk(&dir, &agent_key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("okval").and(predicate::str::contains("nopeval").not()))
        .stderr(predicate::str::contains(
            "withholding 1 key(s) not allowed by policy: NOPE",
        ));
    murk(&dir, &agent_key)
        .args(["exec", "--vault", "test.murk", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("policy forbids NOPE"));
}

/// The public key of a grant key file, as it appears in the vault.
fn grant_pubkey(agent_key: &str) -> String {
    let secret = agent_key
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap();
    let id: age::x25519::Identity = secret.parse().unwrap();
    id.to_public().to_string()
}

/// The vault file as JSON, for checks on who holds which ciphertext.
fn vault_json(dir: &TempDir) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap()).unwrap()
}

#[test]
fn an_expired_grant_never_receives_a_rotated_value() {
    // Past its TTL a grant must be cut off for good: the next write drops it,
    // so a rotation is not encrypted to the expired key. On 0.13.0 every
    // rotation after expiry was re-encrypted to it (raw age decrypted it).
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "bot", "--only", "A", "--ttl", "3s",
        ])
        .arg("--out")
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let bot = grant_pubkey(&read_agent_key(&agent_key_path));
    std::thread::sleep(std::time::Duration::from_millis(3100));

    murk(&dir, &key)
        .args(["rotate", "A", "--vault", "test.murk"])
        .write_stdin("v2\n")
        .assert()
        .success();

    let v = vault_json(&dir);
    assert!(
        v["secrets"]["A"]["scoped"].get(&bot).is_none(),
        "rotated value encrypted to the expired grant: {}",
        v["secrets"]["A"]
    );
    assert!(
        !v["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == &bot),
        "expired grant is still a recipient"
    );
    murk(&dir, &key)
        .args(["agent", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("bot").not());
}

#[test]
fn moving_a_granted_key_to_a_group_drops_the_agents_copy() {
    // Scope binds to the shared secret that was granted. Moving the key to a
    // group must take it away from the agent, not leave its old copy readable.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    for (k, v) in [("X", "sharedval"), ("Y", "other")] {
        murk(&dir, &key)
            .args(["add", k, "--vault", "test.murk"])
            .write_stdin(format!("{v}\n"))
            .assert()
            .success();
    }
    let agent_key = mint_exec_grant(&dir, &key, "bot", &["X", "Y"]);
    murk(&dir, &key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "X", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("prod-only\n")
        .assert()
        .success();

    murk(&dir, &agent_key)
        .args(["get", "X", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("sharedval").not());
    let v = vault_json(&dir);
    assert!(
        v["secrets"]["X"]["scoped"]
            .get(grant_pubkey(&agent_key))
            .is_none()
    );
    // The rest of the grant is untouched.
    murk(&dir, &agent_key)
        .args(["get", "Y", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("other"));
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"Y\"").and(predicate::str::contains("\"X\"").not()));
}

#[test]
fn a_removed_then_re_added_key_is_not_handed_to_the_agent() {
    // `rm X` then `add X` is a different secret under a reused name; the
    // grant for the old X must not pick it up.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    for (k, v) in [("X", "old"), ("Y", "other")] {
        murk(&dir, &key)
            .args(["add", k, "--vault", "test.murk"])
            .write_stdin(format!("{v}\n"))
            .assert()
            .success();
    }
    let agent_key = mint_exec_grant(&dir, &key, "bot", &["X", "Y"]);
    murk(&dir, &key)
        .args(["rm", "X", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "X", "--vault", "test.murk"])
        .write_stdin("unrelated-new-secret\n")
        .assert()
        .success();

    murk(&dir, &agent_key)
        .args(["get", "X", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("unrelated-new-secret").not());
}

/// Decrypt a base64 age ciphertext from the vault with a grant key file's key.
fn decrypt_with_grant(agent_key: &str, ciphertext_b64: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let secret = agent_key
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap();
    let id: age::x25519::Identity = secret.parse().unwrap();
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .unwrap();
    age::decrypt(&id, &ct).ok()
}

#[test]
fn an_agent_grant_cannot_read_the_team_structure() {
    // A grant gets its own record and its scoped values, nothing else: not the
    // meta (MAC key, recipient names, groups, signers, other grants). On 0.13 a
    // grant was a meta recipient and `circle`/`info` listed every name.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let (_, bob_pk) = init_vault(TempDir::new().unwrap());
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            &bob_pk,
            "--name",
            "bobby",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["group", "create", "opsteam", "--vault", "test.murk"])
        .assert()
        .success();
    let bot = mint_exec_grant(&dir, &key, "bot", &["A"]);
    mint_exec_grant(&dir, &key, "othergrant", &["A"]);

    for args in [
        &["circle"][..],
        &["info"][..],
        &["group", "ls"][..],
        &["agent", "ls"][..],
    ] {
        let out = murk(&dir, &bot)
            .args(args)
            .args(["--vault", "test.murk"])
            .output()
            .unwrap();
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for secret_name in ["testuser", "bobby", "opsteam", "othergrant"] {
            assert!(
                !all.contains(secret_name),
                "{args:?} showed {secret_name}: {all}"
            );
        }
    }

    let v = vault_json(&dir);
    assert!(
        decrypt_with_grant(&bot, v["meta"].as_str().unwrap()).is_none(),
        "the meta must not be encrypted to a grant"
    );
    let record = decrypt_with_grant(&bot, v["agents"][grant_pubkey(&bot)].as_str().unwrap())
        .expect("the grant opens its own record");
    let record = String::from_utf8(record).unwrap();
    assert!(record.contains("\"bot\""), "{record}");
    for leaked in ["othergrant", "mac_key", "bobby", "opsteam"] {
        assert!(!record.contains(leaked), "record leaks {leaked}: {record}");
    }
    // It still reads its scope.
    murk(&dir, &bot)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("v1"));
}

/// A vault with `A`, recipient `bob`, an expired grant `old` and a live grant
/// `bot`, both over `A`.
fn vault_with_an_expired_grant() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let (_, bob_pk) = init_vault(TempDir::new().unwrap());
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
    murk(&dir, &key)
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
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "old", "--only", "A", "--ttl", "3s",
        ])
        .args(["--out", "-", "--vault", "test.murk"])
        .assert()
        .success();
    mint_exec_grant(&dir, &key, "bot", &["A"]);
    std::thread::sleep(std::time::Duration::from_millis(3100));
    (dir, key)
}

#[test]
fn revoke_and_rotate_work_with_an_expired_grant_present() {
    // Each of these saves the revoke, then saves again for the rotation. The
    // first save drops the expired grant; the second, from the same loaded
    // state, must not fail trying to drop it again ("recipient not found").
    let cases: &[&[&str]] = &[
        &["circle", "revoke", "bob", "--rotate"],
        &["agent", "revoke", "bot", "--rotate"],
        &["agent", "disconnect", "--name", "bot", "--rotate"],
    ];
    for args in cases {
        let (dir, key) = vault_with_an_expired_grant();
        murk(&dir, &key)
            .args(*args)
            .args(["--vault", "test.murk"])
            .write_stdin("v2\n")
            .assert()
            .success()
            .stderr(predicate::str::contains("rotated A"));
        murk(&dir, &key)
            .args(["get", "A", "--vault", "test.murk"])
            .assert()
            .success()
            .stdout(predicate::str::contains("v2"));
        murk(&dir, &key)
            .args(["agent", "ls", "--vault", "test.murk"])
            .assert()
            .success()
            .stderr(predicate::str::contains("old").not());
    }
}

#[test]
fn a_grant_trusts_only_the_signers_in_its_key_file() {
    // A grant can't read the meta, so it trusts a vault only by its signature,
    // and only against the signers its key file names. A vault last signed by
    // anyone else, a teammate or the agent itself, is refused until the
    // operator re-mints or MURK_TRUSTED_SIGNERS names the signer.
    let dir = TempDir::new().unwrap();
    let (alice, _) = init_vault(&dir);
    let (bob, bob_pk) = init_vault(TempDir::new().unwrap());
    murk(&dir, &alice)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
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
    let bot = mint_exec_grant(&dir, &alice, "bot", &["A"]);
    murk(&dir, &bot)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("v1"));

    // Bob saves: a trusted teammate on alice's machine, but not in bot's anchor.
    murk(&dir, &bob)
        .env("MURK_TRUSTED_SIGNERS", alice_entry(&dir, &alice))
        .args(["add", "B", "--vault", "test.murk"])
        .write_stdin("b\n")
        .assert()
        .success();
    murk(&dir, &bot)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "not a trusted signer in this grant's key file",
        ));

    // Naming bob in MURK_TRUSTED_SIGNERS adds him to the anchor.
    let bob_entry = String::from_utf8(
        murk(&dir, &bob)
            .args(["trust", "--print-key", "--vault", "test.murk"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let bob_entry = bob_entry.lines().next().unwrap().trim().to_string();
    murk(&dir, &bot)
        .env("MURK_TRUSTED_SIGNERS", &bob_entry)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("v1"));
}

#[test]
fn revoking_a_signer_revokes_the_grants_that_trust_it() {
    // A grant's key file trusts the signers pinned when it was minted, and
    // nothing updates a key file. Without this, after `circle revoke bob`, bob
    // signs a vault from his pre-revoke copy and the agent accepts it (and
    // `agent exec` injects his value) while every pinned machine refuses it.
    let dir = TempDir::new().unwrap();
    let (alice, _) = init_vault(&dir);
    let bob_home = TempDir::new().unwrap();
    let (bob, bob_pk) = init_vault(&bob_home);
    let as_bob = || {
        let mut cmd = murk_bin(bob_home.path());
        cmd.current_dir(dir.path()).env("MURK_KEY", &bob);
        cmd
    };
    murk(&dir, &alice)
        .args(["add", "DATABASE_URL", "--vault", "test.murk"])
        .write_stdin("real-db-pass\n")
        .assert()
        .success();
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
    // Minted while only alice signs: its anchor doesn't list bob.
    let solo = mint_exec_grant(&dir, &alice, "solo", &["DATABASE_URL"]);
    // Bob writes, and alice confirms his key: from now on her grants trust him.
    as_bob()
        .args(["trust", "--yes", "--vault", "test.murk"])
        .assert()
        .success();
    as_bob()
        .args(["add", "B_MARKER", "--vault", "test.murk"])
        .write_stdin("x\n")
        .assert()
        .success();
    murk(&dir, &alice)
        .args(["trust", "--yes", "--vault", "test.murk"])
        .assert()
        .success();
    // Minted to murk's own key path, which the agent is pointed at.
    murk(&dir, &alice)
        .args(["agent", "grant", "--name", "bot", "--only", "DATABASE_URL"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let bot_file = fs::read_dir(dir.path().join(".config/murk/agent-keys"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with("-bot"))
        .unwrap();
    let bot = read_agent_key(&bot_file);
    assert_eq!(bot.matches("# murk-trusted-signer: ").count(), 2, "{bot}");
    let as_agent = || {
        let mut cmd = murk_bin(dir.path());
        cmd.current_dir(dir.path()).env("MURK_KEY_FILE", &bot_file);
        cmd
    };
    let vault = dir.path().join("test.murk");
    let pre_revoke = fs::read(&vault).unwrap();

    let revoke = murk(&dir, &alice)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success();
    let stderr = String::from_utf8(revoke.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("revoked agent grant bot"), "{stderr}");
    assert!(!stderr.contains("revoked agent grant solo"), "{stderr}");
    assert!(stderr.contains("--renew"), "{stderr}");
    assert!(
        stderr.contains("MURK_TRUSTED_SIGNERS") && stderr.contains(&bob_pk),
        "the external-anchor warning must name bob's entry: {stderr}"
    );
    murk(&dir, &alice)
        .args(["agent", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("solo").and(predicate::str::contains("bot").not()));
    // The grant whose anchor never listed bob survives and still reads.
    murk(&dir, &solo)
        .args(["get", "DATABASE_URL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("real-db-pass"));
    assert!(
        !bot_file.exists(),
        "the revoked grant's key file must be gone"
    );
    as_agent()
        .args(["get", "DATABASE_URL", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("");

    // Bob forges from his pre-revoke copy, where bot is still live.
    let post_revoke = fs::read(&vault).unwrap();
    fs::write(&vault, &pre_revoke).unwrap();
    as_bob()
        .args(["add", "DATABASE_URL", "--vault", "test.murk"])
        .write_stdin("attacker-controlled-db\n")
        .assert()
        .success();
    let forged = fs::read(&vault).unwrap();
    let agent_refuses = || {
        as_agent()
            .args(["get", "DATABASE_URL", "--vault", "test.murk"])
            .assert()
            .failure()
            .stdout(predicate::str::contains("attacker").not());
        as_agent()
            .args([
                "agent",
                "exec",
                "--only",
                "DATABASE_URL",
                "--vault",
                "test.murk",
            ])
            .args(["--", "sh", "-c", "echo \"app sees $DATABASE_URL\""])
            .assert()
            .failure()
            .stdout(predicate::str::contains("app sees").not());
    };
    agent_refuses();

    // Re-minting (on the real vault) writes a key file that no longer trusts
    // bob, at the path the agent uses; bob's forgery is still refused.
    fs::write(&vault, &post_revoke).unwrap();
    murk(&dir, &alice)
        .args([
            "agent",
            "grant",
            "--name",
            "bot",
            "--only",
            "DATABASE_URL",
            "--renew",
        ])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let renewed = read_agent_key(&bot_file);
    assert!(!renewed.contains(&bob_pk), "{renewed}");
    as_agent()
        .args(["get", "DATABASE_URL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("real-db-pass"));
    fs::write(&vault, &forged).unwrap();
    agent_refuses();
}

/// Alice's trusted-signer entry, as `murk trust --print-key` prints it.
fn alice_entry(dir: &TempDir, alice: &str) -> String {
    let out = murk(dir, alice)
        .args(["trust", "--print-key", "--vault", "test.murk"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn a_grant_key_without_trusted_signers_is_told_to_re_mint() {
    // A key file from before 0.14 (or with its anchor lines stripped) names no
    // signer, so murk can't check the vault for it: refused, with the fix.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
    let bot = mint_exec_grant(&dir, &key, "bot", &["A"]);
    let bare: String = bot
        .lines()
        .filter(|l| l.starts_with("AGE-SECRET-KEY-"))
        .collect();
    murk(&dir, &bare)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout("")
        .stderr(
            predicate::str::contains("names no trusted signers")
                .and(predicate::str::contains("--renew")),
        );
}

#[test]
fn an_agent_grant_cannot_join_a_group() {
    // A grant reads exactly its --only keys; group membership would widen it.
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("v1\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "PROD_DB", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("prodvalue\n")
        .assert()
        .success();
    let agent_key = mint_exec_grant(&dir, &key, "bot", &["A"]);
    let before = fs::read(dir.path().join("test.murk")).unwrap();

    murk(&dir, &key)
        .args([
            "group",
            "add",
            "prod",
            "--member",
            "agent:bot",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "agent grant bot can't join a group",
        ));
    assert_eq!(fs::read(dir.path().join("test.murk")).unwrap(), before);
    murk(&dir, &agent_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("prodvalue").not());
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
        .args(["--ttl", "3s", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = read_agent_key(&agent_key_path);

    std::thread::sleep(std::time::Duration::from_millis(3100));

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

/// An explicit `--out` never replaces an existing file (it may be the
/// operator's own key) unless `--force` is passed, and every key file murk
/// writes is owner-only, even where a looser file stood before.
#[cfg(unix)]
#[test]
fn agent_grant_key_files_are_never_clobbered_and_always_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();

    let out = dir.path().join("operator.key");
    fs::write(&out, "AGE-SECRET-KEY-1OPERATOR\n").unwrap();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .arg("--out")
        .arg(&out)
        .args(["--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("already exists").and(predicate::str::contains("--force")),
        );
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "AGE-SECRET-KEY-1OPERATOR\n"
    );
    // Refused before the vault changed: no grant whose key was never handed off.
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codex").not());

    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .arg("--out")
        .arg(&out)
        .args(["--force", "--vault", "test.murk"])
        .assert()
        .success();
    assert_eq!(mode(&out), 0o600);
    let agent_key = read_agent_key(&out);
    murk(&dir, &agent_key)
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));

    // murk's own per-grant slot: renewal replaces a loosened file owner-only.
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "STRIPE_KEY"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let slot = fs::read_dir(dir.path().join(".config/murk/agent-keys"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with("-bot"))
        .expect("default grant key file");
    fs::set_permissions(&slot, fs::Permissions::from_mode(0o644)).unwrap();
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "STRIPE_KEY"])
        .args(["--renew", "--vault", "test.murk"])
        .assert()
        .success();
    assert_eq!(mode(&slot), 0o600);
}

/// A key file that cannot be written leaves the vault as it was: no new grant
/// whose key nobody holds, and a `--renew` does not revoke the working key.
#[test]
fn agent_grant_with_unwritable_out_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();
    let missing = dir.path().join("no-such-dir").join("agent.key");

    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .arg("--out")
        .arg(&missing)
        .args(["--vault", "test.murk"])
        .assert()
        .failure();
    murk(&dir, &key)
        .args(["agent", "ls", "--json", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codex").not());

    let live = dir.path().join("live.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .arg("--out")
        .arg(&live)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "codex", "--only", "STRIPE_KEY"])
        .arg("--out")
        .arg(&missing)
        .args(["--renew", "--vault", "test.murk"])
        .assert()
        .failure();
    murk(&dir, &read_agent_key(&live))
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));
}

/// A `--renew` whose vault save fails leaves the old grant's key file
/// byte-for-byte as it was, and still able to read its scope: the new key is
/// only renamed into place once the vault records it.
#[cfg(unix)]
#[test]
fn agent_grant_renew_with_failed_save_keeps_the_old_key() {
    use std::os::unix::fs::PermissionsExt;
    // Root ignores the read-only directory that makes the save fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "STRIPE_KEY", "--vault", "test.murk"])
        .write_stdin("sk_live_secret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "STRIPE_KEY"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let slots = dir.path().join(".config/murk/agent-keys");
    let slot = fs::read_dir(&slots)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with("-bot"))
        .expect("default grant key file");
    let before = fs::read(&slot).unwrap();

    // The vault's directory refuses the save's temporary file; the key slot
    // (its own directory) stays writable, so the key is staged first.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let renew = murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "STRIPE_KEY"])
        .args(["--renew", "--vault", "test.murk"])
        .output()
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!renew.status.success(), "the save was expected to fail");

    assert_eq!(fs::read(&slot).unwrap(), before);
    assert_eq!(
        fs::read_dir(&slots).unwrap().count(),
        1,
        "no staged key left behind"
    );
    let old_key = String::from_utf8(before).unwrap();
    murk(&dir, old_key.trim())
        .args(["get", "STRIPE_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_secret"));
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

    // agent exec of a production key is refused too, even with the
    // operator's key let through on purpose.
    murk(&dir, &key)
        .args([
            "agent",
            "exec",
            "--allow-operator-key",
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
            "--allow-operator-key",
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
            "--allow-operator-key",
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
    assert!(agent_key.lines().any(|l| l.starts_with("AGE-SECRET-KEY-")));
    assert!(agent_key.starts_with("# murk-trusted-signer: "));

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
        .stdout(
            predicate::str::starts_with("# murk-trusted-signer: ")
                .and(predicate::str::contains("\nAGE-SECRET-KEY-")),
        )
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

    // The child proves it received the value without printing it: the output
    // that comes back is masked (see `mcp_exec_masks_injected_values`).
    #[cfg(unix)]
    let exec_args = r#"{"only":["DB_URL"],"command":["sh","-c","test \"$DB_URL\" = db-val && echo injected-ok"]}"#;
    #[cfg(windows)]
    let exec_args =
        r#"{"only":["DB_URL"],"command":["cmd","/C","if %DB_URL%==db-val echo injected-ok"]}"#;

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call("murk_exec", exec_args))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("injected-ok")
                .and(predicate::str::contains("\"isError\":false")),
        );
}

/// An env-style dump of the injected values comes back masked on both streams:
/// a value repeated back to back, a value at the very end of stdout with no
/// newline, and the same value again at the very start of stderr.
#[cfg(unix)]
#[test]
fn mcp_exec_masks_injected_values() {
    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);

    let script = r#"echo \"DB_URL=$DB_URL\"; echo \"CACHE_URL=$CACHE_URL$CACHE_URL\"; printf %s \"$DB_URL\"; printf '%s\\n' \"$CACHE_URL\" >&2"#;
    let exec_args =
        format!(r#"{{"only":["DB_URL","CACHE_URL"],"command":["sh","-c","{script}"]}}"#);

    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call("murk_exec", &exec_args))
        .assert()
        .success()
        // The payload is JSON text inside a JSON-RPC string, so a newline in the
        // child's output arrives as `\\n` and a quote as `\"`.
        .stdout(
            predicate::str::contains(r"DB_URL=***DB_URL***\\n")
                .and(predicate::str::contains(
                    r"CACHE_URL=***CACHE_URL******CACHE_URL***\\n***DB_URL***",
                ))
                .and(predicate::str::contains(
                    r#"\"stderr\": \"***CACHE_URL***\\n"#,
                ))
                .and(predicate::str::contains("db-val").not())
                .and(predicate::str::contains("cache-val").not()),
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

/// A value cut in half by the 1 MiB output cap must not leak its first half:
/// the stream is padded so `cache-val` starts 5 bytes before the cap, which
/// leaves `cache` as the last bytes read.
#[cfg(unix)]
#[test]
fn mcp_exec_value_straddling_the_output_cap_leaks_no_prefix() {
    const OUTPUT_CAP: usize = 1 << 20; // src/mcp.rs
    let pad = OUTPUT_CAP - 5;

    let dir = TempDir::new().unwrap();
    let grant = setup_mcp_grant(&dir);
    let script = format!(r#"head -c {pad} /dev/zero | tr '\\0' x; printf %s \"$CACHE_URL\"; yes"#);
    let exec_args = format!(r#"{{"only":["CACHE_URL"],"command":["sh","-c","{script}"]}}"#);

    let out = murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", grant.to_str().unwrap())
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk", "--allow-exec"])
        .write_stdin(mcp_handshake_and_call("murk_exec", &exec_args))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let response: serde_json::Value = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["id"] == 2)
        .expect("tools/call response");
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    let payload: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["truncated"], true);
    let stdout = payload["stdout"].as_str().unwrap();
    // Exactly the padding survives: the cut-off `cache` is dropped, not passed
    // through and not masked into a placeholder that would hint at it.
    assert_eq!(stdout.len(), pad, "stdout must end where the padding ends");
    assert!(stdout.bytes().all(|b| b == b'x'), "only padding may remain");
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
fn agent_connect_and_disconnect_unknown_editor_is_usage_error() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("v\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "notepad",
            "--only",
            "API_KEY",
            "--vault",
            "test.murk",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown editor 'notepad'"));
    murk(&dir, &key)
        .args(["agent", "disconnect", "notepad", "--vault", "test.murk"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown editor 'notepad'"));
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
