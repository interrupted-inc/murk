// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk verify`, `murk doctor`, git integration (`diff`, `merge-driver`,
//! `setup-merge-driver`) and key recovery (`recover`, `restore`).

use std::fs;
use std::path::Path;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk, murk_bin};

/// A real unencrypted ssh-ed25519 keypair (twin of `SSH_ED25519_SK` in
/// `src/testutil.rs`).
const SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
const SSH_ED25519_PK: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

/// Run git in `dir` with a fixed identity and `HOME` pinned to `dir`, so the
/// developer's global git config (e.g. `commit.gpgsign`) can't leak in.
fn git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn add_secret(dir: &Path, key: &str, name: &str, value: &str) {
    murk(dir, key)
        .args(["add", name, "--vault", "test.murk"])
        .write_stdin(format!("{value}\n"))
        .assert()
        .success();
}

/// Write a key file the way murk requires: unreadable by group/other.
fn write_key_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn rm_secret(dir: &Path, key: &str, name: &str) {
    murk(dir, key)
        .args(["rm", name, "--vault", "test.murk"])
        .assert()
        .success();
}

/// Commit `test.murk` as it stands in `dir` (unsigned).
fn commit_vault(dir: &Path) {
    git(dir, &["add", "test.murk"]);
    git(
        dir,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "vault"],
    );
}

// ── verify ──

#[test]
fn verify_reports_signature_downgrade_and_unsigned_vault() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "A", "one");
    let base = fs::read(dir.path().join("test.murk")).unwrap();
    add_secret(dir.path(), &key, "B", "two");

    // A signed load pins the signer on this machine.
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();

    // A key-holding merge regenerates meta without a signature.
    fs::rename(dir.path().join("test.murk"), dir.path().join("theirs.murk")).unwrap();
    fs::write(dir.path().join("base.murk"), &base).unwrap();
    fs::write(dir.path().join("test.murk"), &base).unwrap();
    murk(&dir, &key)
        .args(["merge-driver", "base.murk", "test.murk", "theirs.murk"])
        .assert()
        .success();

    // Same machine: the pin remembers the vault was signed — fail on the downgrade.
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "vault was signed before and is now unsigned",
        ))
        .stderr(predicate::str::contains("relies on git").not());

    // Fresh machine (no pins): no downgrade to detect, but an unsigned vault
    // holding secrets is still a failing finding.
    let fresh_home = TempDir::new().unwrap();
    murk_bin(fresh_home.path())
        .current_dir(dir.path())
        .env("MURK_KEY", &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "vault is unsigned — content integrity relies on git",
        ))
        .stderr(predicate::str::contains("signed before").not());
}

#[test]
fn verify_names_ssh_signer_authorized_with_commented_pubkey() {
    let dir = TempDir::new().unwrap();
    let (alice_key, _) = init_vault(&dir);

    // A raw pubkey is stored with its comment; bob's signature names the bare key.
    murk(&dir, &alice_key)
        .args([
            "circle",
            "authorize",
            &format!("{SSH_ED25519_PK} bob@laptop"),
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let bob_key_file = dir.path().join("bob_ed25519");
    write_key_file(&bob_key_file, SSH_ED25519_SK);
    let bob = || {
        let mut cmd = murk_bin(dir.path());
        cmd.current_dir(dir.path())
            .env("MURK_KEY_FILE", &bob_key_file);
        cmd
    };
    bob()
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("v\n")
        .assert()
        .success();

    bob()
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("signed by bob"));
}

/// The last commit touching the vault is the authorship anchor: unsigned and
/// bad (revoked-key) signatures fail verify, a good one is reported ok.
#[cfg(unix)]
#[test]
fn verify_checks_last_vault_commit_signature() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "A", "one");
    git(dir.path(), &["init", "-q"]);
    commit_vault(dir.path());

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("last .murk commit is unsigned"));

    // Sign the next vault commit with a throwaway ssh key git trusts.
    let keys = TempDir::new().unwrap();
    let signing_key = keys.path().join("id");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "t", "-f"])
        .arg(&signing_key)
        .status()
        .expect("ssh-keygen");
    assert!(status.success());
    let pubkey = fs::read_to_string(keys.path().join("id.pub")).unwrap();
    let allowed = keys.path().join("allowed");
    fs::write(&allowed, format!("test@test.com {pubkey}")).unwrap();
    let signing_key = signing_key.to_str().unwrap();
    let allowed = allowed.to_str().unwrap();
    git(dir.path(), &["config", "gpg.format", "ssh"]);
    git(dir.path(), &["config", "user.signingkey", signing_key]);
    git(
        dir.path(),
        &["config", "gpg.ssh.allowedSignersFile", allowed],
    );
    add_secret(dir.path(), &key, "B", "two");
    git(dir.path(), &["add", "test.murk"]);
    git(dir.path(), &["commit", "-q", "-S", "-m", "signed"]);

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("last .murk commit is signed"));

    // Revoking the signing key turns the same commit into a bad signature.
    let revoked = keys.path().join("revoked");
    fs::write(&revoked, &pubkey).unwrap();
    git(
        dir.path(),
        &[
            "config",
            "gpg.ssh.revocationFile",
            revoked.to_str().unwrap(),
        ],
    );
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "last .murk commit has a bad signature",
        ));
}

#[cfg(unix)]
#[test]
fn verify_flags_group_writable_vault() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let vault = dir.path().join("test.murk");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o664)).unwrap();

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "vault file is group/world writable (mode 664)",
        ))
        .stderr(predicate::str::contains("chmod 644 test.murk"));

    fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success();
}

// ── doctor ──

#[test]
fn doctor_flags_dotenv_not_ignored_by_git() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    git(dir.path(), &["init", "-q"]);

    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(".env is not excluded from git"));

    // git decides: a .gitignore rule clears the finding.
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("repo hygiene looks clean"));
}

#[test]
fn doctor_flags_key_file_inside_working_tree() {
    let dir = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let doctor = |key_file: &Path| {
        let mut cmd = murk_bin(home.path());
        cmd.current_dir(dir.path())
            .env("MURK_KEY_FILE", key_file)
            .args(["doctor", "--vault", "test.murk"]);
        cmd
    };

    let inside = dir.path().join("murk.key");
    write_key_file(&inside, &key);
    doctor(&inside)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is inside the working tree"))
        .stderr(predicate::str::contains("move it out of the repo"));

    let outside = home.path().join("murk.key");
    write_key_file(&outside, &key);
    doctor(&outside)
        .assert()
        .success()
        .stderr(predicate::str::contains("repo hygiene looks clean"));
}

// ── diff ──

#[test]
fn diff_hides_values_unless_asked_and_reports_each_change_kind() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "CHANGED", "old-value");
    add_secret(dir.path(), &key, "REMOVED", "gone-value");
    git(dir.path(), &["init", "-q"]);
    commit_vault(dir.path());

    add_secret(dir.path(), &key, "CHANGED", "new-value");
    rm_secret(dir.path(), &key, "REMOVED");
    add_secret(dir.path(), &key, "ADDED", "fresh-value");

    let diff = |extra: &[&str]| {
        let out = murk(&dir, &key)
            .args(["diff", "--vault", "test.murk"])
            .args(extra)
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };

    let names_only = diff(&[]);
    for name in ["+ ADDED", "- REMOVED", "~ CHANGED"] {
        assert!(names_only.contains(name), "missing {name}:\n{names_only}");
    }
    for value in ["old-value", "new-value", "gone-value", "fresh-value"] {
        assert!(!names_only.contains(value), "leaked {value}:\n{names_only}");
    }

    let with_values = diff(&["--show-values"]);
    for line in [
        "+ ADDED = fresh-value",
        "- REMOVED = gone-value",
        "~ CHANGED old-value → new-value",
    ] {
        assert!(with_values.contains(line), "missing {line}:\n{with_values}");
    }

    let json: serde_json::Value = serde_json::from_str(&diff(&["--json"])).unwrap();
    let entry = |k: &str| {
        json.as_array()
            .unwrap()
            .iter()
            .find(|e| e["key"] == k)
            .unwrap_or_else(|| panic!("no {k} in {json}"))
            .clone()
    };
    assert_eq!(
        entry("CHANGED"),
        serde_json::json!({"key": "CHANGED", "kind": "changed", "old_value": "old-value", "new_value": "new-value"})
    );
    assert_eq!(
        entry("REMOVED"),
        serde_json::json!({"key": "REMOVED", "kind": "removed", "old_value": "gone-value", "new_value": null})
    );
    assert_eq!(
        entry("ADDED"),
        serde_json::json!({"key": "ADDED", "kind": "added", "old_value": null, "new_value": "fresh-value"})
    );
}

#[test]
fn diff_warns_when_old_vault_is_not_decryptable() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "MINE", "v");
    let mine = fs::read(dir.path().join("test.murk")).unwrap();

    // HEAD holds someone else's vault, encrypted to a key we don't have.
    let other = TempDir::new().unwrap();
    let (other_key, _) = init_vault(&other);
    add_secret(other.path(), &other_key, "THEIRS", "v");
    fs::copy(other.path().join("test.murk"), dir.path().join("test.murk")).unwrap();
    git(dir.path(), &["init", "-q"]);
    commit_vault(dir.path());
    fs::write(dir.path().join("test.murk"), &mine).unwrap();

    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "cannot decrypt vault at HEAD — you may not have been a recipient",
        ))
        .stdout(predicate::str::contains("MINE"));
}

#[test]
fn diff_fails_on_unparseable_vault_at_ref() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let mine = fs::read(dir.path().join("test.murk")).unwrap();
    fs::write(dir.path().join("test.murk"), "not a vault").unwrap();
    git(dir.path(), &["init", "-q"]);
    commit_vault(dir.path());
    fs::write(dir.path().join("test.murk"), &mine).unwrap();

    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("parsing vault at HEAD"));
}

// ── merge-driver / setup-merge-driver ──

#[test]
fn merge_driver_lists_every_conflict() {
    let dir = TempDir::new().unwrap();
    let base = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] },
    "API_KEY": { "description": "api", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-db" },
    "API_KEY": { "shared": "base-api" }
  },
  "meta": "base-meta"
}"#;
    fs::write(dir.path().join("base.murk"), base).unwrap();
    fs::write(dir.path().join("ours.murk"), base.replace("base-", "ours-")).unwrap();
    fs::write(
        dir.path().join("theirs.murk"),
        base.replace("base-", "theirs-"),
    )
    .unwrap();

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["merge-driver", "base.murk", "ours.murk", "theirs.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("2 conflicts"))
        .stderr(predicate::str::contains("DB_URL"))
        .stderr(predicate::str::contains("API_KEY"));
}

#[test]
fn setup_merge_driver_appends_to_existing_gitattributes() {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["setup-merge-driver"])
        .assert()
        .success()
        .stderr(predicate::str::contains("appended to .gitattributes"));

    let attrs = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert!(
        attrs.contains("*.png binary"),
        "existing rule lost:\n{attrs}"
    );
    assert!(
        attrs.contains("*.murk merge=murk"),
        "entry missing:\n{attrs}"
    );
}

// ── recover / restore ──

#[test]
fn restore_requires_a_phrase() {
    let dir = TempDir::new().unwrap();
    murk_bin(dir.path())
        .current_dir(dir.path())
        .arg("restore")
        .write_stdin("\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("recovery phrase is required"))
        .stdout(predicate::str::is_empty());
}

/// A different valid phrase decodes to a working but foreign key; restore
/// still prints it, but warns that it is not a recipient of the local vault.
#[test]
fn restore_warns_when_phrase_yields_a_non_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let other = TempDir::new().unwrap();
    let (other_key, _) = init_vault(&other);

    let phrase_of = |d: &TempDir, k: &str| {
        let out = murk(d, k).arg("recover").output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let restore = |phrase: String| {
        murk_bin(dir.path())
            .current_dir(dir.path())
            .args(["restore", "--vault", "test.murk"])
            .write_stdin(format!("{phrase}\n"))
            .assert()
            .success()
    };

    restore(phrase_of(&dir, &key))
        .stdout(predicate::str::contains(&key))
        .stderr(predicate::str::contains("not a recipient").not());

    restore(phrase_of(&other, &other_key))
        .stdout(predicate::str::contains(&other_key))
        .stderr(predicate::str::contains(
            "restored identity is not a recipient of test.murk",
        ));
}

#[test]
fn recover_refuses_keys_without_a_phrase() {
    let dir = TempDir::new().unwrap();
    let (_, pubkey) = init_vault(&dir);

    let ssh_key = dir.path().join("id_ed25519");
    write_key_file(&ssh_key, SSH_ED25519_SK);
    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &ssh_key)
        .arg("recover")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "recovery phrases are for age keys only",
        ))
        .stdout(predicate::str::is_empty());

    let plugin = bech32::encode_upper::<bech32::Bech32>(
        bech32::Hrp::parse("age-plugin-test-").unwrap(),
        &[7u8; 32],
    )
    .unwrap();
    let plugin_file = dir.path().join("plugin-identity.txt");
    write_key_file(&plugin_file, &format!("# public key: {pubkey}\n{plugin}\n"));
    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &plugin_file)
        .arg("recover")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "plugin identities (YubiKey, Secure Enclave, FIDO2) do not have recovery phrases",
        ))
        .stdout(predicate::str::is_empty());
}
