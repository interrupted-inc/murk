// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk verify`, `murk doctor`, git integration (`diff`, `merge-driver`,
//! `setup-merge-driver`) and key recovery (`recover`, `restore`).

use std::fs;
use std::path::Path;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{FOREIGN_PK, init_vault, murk, murk_bin};

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
fn verify_reports_why_a_vault_is_not_trusted() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "A", "one");

    // The machine that wrote it trusts it.
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "signed by trusted signer testuser",
        ));

    // A fresh machine has no trust decision yet: verify says so and fails,
    // naming the next step, without refusing to run.
    let fresh_home = TempDir::new().unwrap();
    murk_bin(fresh_home.path())
        .current_dir(dir.path())
        .env("MURK_KEY", &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "vault test.murk is not trusted on this machine yet",
        ))
        .stderr(predicate::str::contains("murk trust"));
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
        .stderr(predicate::str::contains("signed by trusted signer bob"));
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

    // Sign the next vault commit with a throwaway ssh key git trusts. The
    // verification settings go in the user's global config (HOME is `dir`):
    // murk ignores signature checks the repository configures for itself.
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
    git(dir.path(), &["config", "--global", "gpg.format", "ssh"]);
    git(dir.path(), &["config", "user.signingkey", signing_key]);
    git(
        dir.path(),
        &["config", "--global", "gpg.ssh.allowedSignersFile", allowed],
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
            "--global",
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

/// A planted `.git/config` must not run code through murk. `doctor` and
/// `verify` are documented as safe to auto-approve, and both spawn git in a
/// working tree whose config may come from an archive or a shared volume.
#[cfg(unix)]
#[test]
fn repo_git_config_runs_no_program() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "A", "one");
    git(dir.path(), &["init", "-q"]);

    // A commit carrying a signature, so `%G?` has something to verify.
    git(dir.path(), &["add", "test.murk"]);
    let tree = std::process::Command::new("git")
        .args(["write-tree"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let tree = String::from_utf8(tree.stdout).unwrap();
    let commit = format!(
        "tree {}\nauthor t <t@t> 1 +0000\ncommitter t <t@t> 1 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n\nvault\n",
        tree.trim()
    );
    fs::write(dir.path().join("commit.txt"), commit).unwrap();
    let id = std::process::Command::new("git")
        .args(["hash-object", "-t", "commit", "-w", "commit.txt"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let id = String::from_utf8(id.stdout).unwrap();
    git(dir.path(), &["update-ref", "HEAD", id.trim()]);

    let marker = dir.path().join("pwned");
    let script = dir.path().join("evil.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\necho \"$0\" >> '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let script = script.to_str().unwrap();
    // fsmonitor runs on any index refresh; the gpg programs run to verify the
    // signature, and `log.showSignature` would verify it on every `git log`.
    for (name, value) in [
        ("core.fsmonitor", script),
        ("gpg.program", script),
        ("gpg.ssh.program", script),
        ("log.showSignature", "true"),
    ] {
        git(dir.path(), &["config", name, value]);
    }

    let ran_nothing = |after: &str| {
        assert!(
            !marker.exists(),
            "repo config ran a program during {after}: {}",
            fs::read_to_string(&marker).unwrap()
        );
    };

    // doctor's check-ignore still answers: the finding is git's, not a guess.
    murk(&dir, &key)
        .args(["doctor", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(".env is not excluded from git"));
    ran_nothing("doctor");
    murk(&dir, &key)
        .args(["diff", "HEAD", "--vault", "test.murk"])
        .assert()
        .success();
    ran_nothing("diff");
    let verify = murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .code(1);
    ran_nothing("verify");
    verify.stderr(predicate::str::contains(
        "last .murk commit signature not checked",
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

    // --json is one object: value changes and structural changes. Values
    // appear only with --show-values, and never in a change entry.
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            FOREIGN_PK,
            "--name",
            "bob",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    let bob = serde_json::json!({
        "kind": "recipient", "op": "added", "key": FOREIGN_PK, "name": "bob",
    });
    let names_json: serde_json::Value = serde_json::from_str(&diff(&["--json"])).unwrap();
    assert_eq!(
        names_json,
        serde_json::json!({
            "secrets": [
                {"key": "ADDED", "kind": "added"},
                {"key": "CHANGED", "kind": "changed"},
                {"key": "REMOVED", "kind": "removed"},
            ],
            "changes": [bob],
        })
    );

    let json: serde_json::Value =
        serde_json::from_str(&diff(&["--json", "--show-values"])).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "secrets": [
                {"key": "ADDED", "kind": "added", "old_value": null, "new_value": "fresh-value"},
                {"key": "CHANGED", "kind": "changed", "old_value": "old-value", "new_value": "new-value"},
                {"key": "REMOVED", "kind": "removed", "old_value": "gone-value", "new_value": null},
            ],
            "changes": [bob],
        })
    );
}

#[test]
fn diff_shows_values_without_terminal_controls() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    git(dir.path(), &["init", "-q"]);
    // An escape sequence (clear screen), a carriage return and a bidi override.
    add_secret(dir.path(), &key, "HOSTILE", "a\u{1b}[2Jb\rc\u{202e}d");

    let out = murk(&dir, &key)
        .args(["diff", "--show-values", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(r#"+ HOSTILE = "a\u{1b}[2Jb\rc\u{202e}d""#),
        "{stdout:?}"
    );
    assert!(!stdout.contains(['\u{1b}', '\r', '\u{202e}']), "{stdout:?}");
}

#[test]
fn header_text_cannot_forge_lines_in_info() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(dir.path(), &key, "DB", "v");

    // New text with a carriage return (rewrites the line) or a bidi override
    // is refused, without echoing it.
    for (forged, why) in [
        ("prod db\rok  vault verified", "contains control characters"),
        (
            "prod \u{202e}bd dorp",
            "contains invisible or text-direction",
        ),
    ] {
        murk(&dir, &key)
            .args(["describe", "DB", forged, "--vault", "test.murk"])
            .assert()
            .code(2)
            .stderr(
                predicate::str::contains(format!("<DESCRIPTION> {why}"))
                    .and(predicate::str::contains("prod").not()),
            );
    }
    murk(&dir, &key)
        .args(["circle", "authorize", "age1x", "--name", "x\ny"])
        .args(["--vault", "test.murk"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--name <NAME> contains control"));

    // A description may span lines, but `info` shows it on its key's row.
    murk(&dir, &key)
        .args([
            "describe",
            "DB",
            "prod db\nwarn: none",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(
            predicate::str::contains(r"prod db\nwarn: none")
                .and(predicate::str::contains("\nwarn: none").not()),
        );
}

#[test]
fn diff_fails_when_old_vault_is_not_decryptable() {
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

    // Unreadable is not empty: reporting every current secret as added would
    // misstate what changed.
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("cannot decrypt vault at HEAD"));
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
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] },
    "API_KEY": { "description": "api", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "BASEdb==" },
    "API_KEY": { "shared": "BASEapi=" }
  },
  "meta": "BASEmeta"
}"#;
    fs::write(dir.path().join("base.murk"), base).unwrap();
    fs::write(dir.path().join("ours.murk"), base.replace("BASE", "OURS")).unwrap();
    fs::write(dir.path().join("theirs.murk"), base.replace("BASE", "THRS")).unwrap();

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
fn keyless_identity_merge_with_unsorted_recipients_is_clean() {
    // `authorize` appends, so header recipients are often unsorted; that order
    // must not read as a recipient change.
    let vault = format!(
        r#"{{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["{SSH_ED25519_PK}", "{FOREIGN_PK}"],
  "schema": {{ "DB_URL": {{ "description": "database", "tags": [] }} }},
  "secrets": {{ "DB_URL": {{ "shared": "Y2lwaGVy" }} }},
  "meta": "bWV0YQ=="
}}"#
    );
    let dir = TempDir::new().unwrap();
    for name in ["base.murk", "ours.murk", "theirs.murk"] {
        fs::write(dir.path().join(name), &vault).unwrap();
    }

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["merge-driver", "base.murk", "ours.murk", "theirs.murk"])
        .assert()
        .success();
}

/// A git repo whose `test.murk` (secret `A`, described "base desc") merges
/// through the real driver binary. Branch `theirs` runs `murk <theirs_change>`;
/// the default branch then adds secret `D`, so a merge always has to combine
/// both sides. Returns the repo and its key.
fn diverged_vault_repo(theirs_change: &[&str]) -> (TempDir, String) {
    vault_repo(
        &[&["add", "A"], &["describe", "A", "base desc"]],
        &[theirs_change],
        &[&["add", "D"]],
    )
}

/// Run each `murk` command against `test.murk` with `v` on stdin.
fn murk_steps(dir: &Path, key: &str, steps: &[&[&str]]) {
    for step in steps {
        murk(dir, key)
            .args(*step)
            .args(["--vault", "test.murk"])
            .write_stdin("v\n")
            .assert()
            .success();
    }
}

/// A git repo with the merge driver configured: `base` builds the committed
/// vault on `main`, then branch `theirs` runs `theirs` and `main` runs `ours`,
/// each committed. Every step is a `murk` command (see [`murk_steps`]).
fn vault_repo(base: &[&[&str]], theirs: &[&[&str]], ours: &[&[&str]]) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk_steps(dir.path(), &key, base);

    let driver = assert_cmd::cargo::cargo_bin("murk");
    git(dir.path(), &["init", "-q", "-b", "main"]);
    git(
        dir.path(),
        &[
            "config",
            "merge.murk.driver",
            &format!("'{}' merge-driver %O %A %B %P", driver.display()),
        ],
    );
    fs::write(dir.path().join(".gitattributes"), "*.murk merge=murk\n").unwrap();
    git(dir.path(), &["add", ".gitattributes"]);
    commit_vault(dir.path());

    // Branch `theirs` always exists; with no steps it stays at base, for tests
    // that commit their own change there.
    git(dir.path(), &["checkout", "-q", "-b", "theirs"]);
    if !theirs.is_empty() {
        murk_steps(dir.path(), &key, theirs);
        commit_vault(dir.path());
    }

    git(dir.path(), &["checkout", "-q", "main"]);
    murk_steps(dir.path(), &key, ours);
    commit_vault(dir.path());

    (dir, key)
}

/// `git merge theirs` with `HOME` at `home` and the murk env stripped, so the
/// driver sees `MURK_KEY` only when `key` is given.
fn git_merge_theirs(dir: &Path, home: &Path, key: Option<&str>) -> std::process::Output {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-c", "commit.gpgsign=false", "merge", "--no-edit", "theirs"])
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com");
    for var in common::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    if let Some(key) = key {
        cmd.env("MURK_KEY", key);
    }
    cmd.output().expect("spawn git merge")
}

fn unmerged_paths(dir: &Path) -> String {
    let output = std::process::Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=U"])
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn git diff");
    String::from_utf8(output.stdout).unwrap()
}

/// `murk verify` passes the MAC check on `test.murk`. The exit code is not
/// asserted: these fixtures make unsigned commits, which `verify` also reports.
fn assert_integrity_verified(dir: &Path, key: &str) {
    murk(dir, key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains("vault integrity verified"));
}

#[test]
fn keyless_merge_of_header_change_is_a_conflict() {
    let cases: &[(&str, &[&str])] = &[
        ("description", &["describe", "A", "theirs desc"]),
        ("tag", &["describe", "A", "base desc", "--tag", "ops"]),
        (
            "rotation",
            &["describe", "A", "base desc", "--rotate-every", "90d"],
        ),
        ("policy", &["policy", "set", "--allow-tag", "ops"]),
        (
            "empty example",
            &["describe", "A", "base desc", "--example", ""],
        ),
    ];
    for (what, change) in cases {
        let (dir, key) = diverged_vault_repo(change);
        let home = TempDir::new().unwrap();

        let output = git_merge_theirs(dir.path(), home.path(), None);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{what}: keyless merge must not succeed\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            unmerged_paths(dir.path()).trim(),
            "test.murk",
            "{what}: git must record the vault as conflicted"
        );

        // What git leaves in the work tree still passes the integrity check.
        assert_integrity_verified(dir.path(), &key);
    }
}

#[test]
fn keyless_merge_without_covered_change_stays_clean() {
    // Theirs edits only a header field nothing covers, keeping its meta.
    let (dir, key) = vault_repo(
        &[&["add", "A"], &["describe", "A", "base desc"]],
        &[],
        &[&["add", "D"]],
    );
    git(dir.path(), &["checkout", "-q", "theirs"]);
    let path = dir.path().join("test.murk");
    let mut vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    vault["repo"] = "https://example.com/theirs.git".into();
    fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
    commit_vault(dir.path());
    git(dir.path(), &["checkout", "-q", "main"]);
    let home = TempDir::new().unwrap();

    let output = git_merge_theirs(dir.path(), home.path(), None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "keyless merge failed: {stderr}");
    assert!(
        stderr.contains("meta not regenerated"),
        "the driver must have run: {stderr}"
    );
    assert!(unmerged_paths(dir.path()).is_empty());

    assert_integrity_verified(dir.path(), &key);
}

#[test]
fn keyless_merge_refuses_a_theirs_meta_change() {
    // Theirs removes bob from ops: a change only in the encrypted meta. Without
    // a key the driver cannot merge it, and dropping it would keep bob a member.
    let (dir, _) = vault_repo(
        &[
            &["circle", "authorize", FOREIGN_PK, "--name", "bob"],
            &["group", "create", "ops"],
            &["group", "add", "ops", "--member", "bob"],
        ],
        &[&["group", "rm", "ops", "--member", "bob"]],
        &[&["add", "D"]],
    );
    let home = TempDir::new().unwrap();

    let output = git_merge_theirs(dir.path(), home.path(), None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "keyless merge must not succeed: {stderr}"
    );
    assert_eq!(unmerged_paths(dir.path()).trim(), "test.murk");
}

#[test]
fn keyed_merge_of_schema_only_change_is_clean_and_verifies() {
    let (dir, key) = diverged_vault_repo(&["describe", "A", "theirs desc"]);

    let output = git_merge_theirs(dir.path(), dir.path(), Some(&key));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "keyed merge failed: {stderr}");
    assert!(unmerged_paths(dir.path()).is_empty());

    let merged = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    assert!(merged.contains("theirs desc"), "theirs' description kept");

    // The driver leaves the merge unsigned; the next write re-signs it, and that
    // write's load fails if the regenerated MAC does not cover the merge.
    add_secret(dir.path(), &key, "E", "five");
    assert_integrity_verified(dir.path(), &key);
}

/// Base for the group tests: `bob` (an outsider key) is a member of group
/// `ops`, which holds secret `S`.
const BOB_IN_OPS: &[&[&str]] = &[
    &["circle", "authorize", FOREIGN_PK, "--name", "bob"],
    &["group", "create", "ops"],
    &["group", "add", "ops", "--member", "bob"],
    &["add", "S", "--group", "ops"],
];

fn ops_members(dir: &Path, key: &str) -> Vec<String> {
    let output = murk(dir, key)
        .args(["group", "ls", "--json", "--vault", "test.murk"])
        .output()
        .unwrap();
    let groups: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    serde_json::from_value(groups["ops"].clone()).unwrap()
}

#[test]
fn keyed_merge_keeps_a_group_member_removal_from_either_side() {
    let remove_bob: &[&[&str]] = &[&["group", "rm", "ops", "--member", "bob"]];
    let unrelated: &[&[&str]] = &[&["add", "D"]];
    for (side, theirs, ours) in [
        ("theirs", remove_bob, unrelated),
        ("ours", unrelated, remove_bob),
    ] {
        let (dir, key) = vault_repo(BOB_IN_OPS, theirs, ours);

        let output = git_merge_theirs(dir.path(), dir.path(), Some(&key));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{side}: keyed merge failed: {stderr}"
        );

        let members = ops_members(dir.path(), &key);
        assert_eq!(members.len(), 1, "{side}: only the operator stays in ops");
        assert!(
            !members.iter().any(|m| m == FOREIGN_PK),
            "{side}: bob's removal was reverted: {members:?}"
        );
    }
}

#[test]
fn keyed_merge_conflicts_on_a_value_encrypted_to_a_member_the_other_side_removed() {
    // One side writes T to ops while bob is still a member there, so T's
    // ciphertext is readable by bob; the other side removed bob.
    let remove_bob: &[&[&str]] = &[&["group", "rm", "ops", "--member", "bob"]];
    let add_t: &[&[&str]] = &[&["add", "T", "--group", "ops"]];
    for (writer, theirs, ours) in [("ours", remove_bob, add_t), ("theirs", add_t, remove_bob)] {
        let (dir, key) = vault_repo(BOB_IN_OPS, theirs, ours);

        let output = git_merge_theirs(dir.path(), dir.path(), Some(&key));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{writer}: merge must not succeed: {stderr}"
        );
        assert!(stderr.contains("secrets.T"), "{writer}: {stderr}");
        assert_eq!(unmerged_paths(dir.path()).trim(), "test.murk");

        // Accepting the conflicted file as-is must not keep T's bob-readable
        // ciphertext or give it fresh integrity metadata.
        let vault: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap())
                .unwrap();
        assert!(
            vault["secrets"].get("T").is_none(),
            "{writer}: T kept in the written file"
        );
        murk(dir.path(), &key)
            .args(["verify", "--vault", "test.murk"])
            .assert()
            .stderr(predicate::str::contains("integrity check failed"));
    }
}

#[test]
fn keyed_merge_of_concurrent_grant_renewals_leaves_no_ungranted_agent_key() {
    // Each side renews grant `codex`, minting its own agent key. Whichever grant
    // the merge cannot keep must not leave its key behind as a plain recipient,
    // which the next write would encrypt every shared value to.
    let renew: &[&[&str]] = &[&[
        "agent", "grant", "--name", "codex", "--only", "A", "--renew", "--out", "-",
    ]];
    let (dir, key) = vault_repo(
        &[
            &["add", "A"],
            &[
                "agent", "grant", "--name", "codex", "--only", "A", "--out", "-",
            ],
        ],
        renew,
        renew,
    );

    let output = git_merge_theirs(dir.path(), dir.path(), Some(&key));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "merge must not succeed: {stderr}");
    assert_eq!(unmerged_paths(dir.path()).trim(), "test.murk");

    // What git leaves in the work tree holds no agent key without a grant.
    let vault: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap()).unwrap();
    let recipients = vault["recipients"].as_array().unwrap();
    assert_eq!(
        recipients.len(),
        1,
        "only the operator may stay a recipient: {recipients:?}"
    );
}

#[test]
fn merge_driver_refuses_a_grant_key_and_leaves_ours_untouched() {
    // A real `git merge` through the driver, run with an agent grant key. The
    // merge conflicts (both sides change A) and theirs adds B, so a driver that
    // writes %A changes the file. Grants are read-only: the driver must refuse
    // before writing, leaving the working copy byte-identical to ours.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    git(d, &["init", "-q", "-b", "main"]);
    let (key, _) = init_vault(d);
    let murk_exe = env!("CARGO_BIN_EXE_murk");
    git(
        d,
        &[
            "config",
            "merge.murk.driver",
            &format!("'{murk_exe}' merge-driver %O %A %B"),
        ],
    );
    fs::write(d.join(".gitattributes"), "*.murk merge=murk\n").unwrap();
    add_secret(d, &key, "A", "base");
    let agent_key_path = d.join("agent.key");
    murk(d, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "A", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = fs::read_to_string(&agent_key_path).unwrap();
    git(d, &["add", "test.murk", ".gitattributes"]);
    git(d, &["commit", "-q", "-m", "base"]);

    git(d, &["checkout", "-q", "-b", "theirs"]);
    add_secret(d, &key, "A", "theirs");
    add_secret(d, &key, "B", "new");
    git(d, &["commit", "-q", "-am", "theirs"]);
    git(d, &["checkout", "-q", "main"]);
    add_secret(d, &key, "A", "ours");
    git(d, &["commit", "-q", "-am", "ours"]);
    let ours = fs::read(d.join("test.murk")).unwrap();

    let mut merge = std::process::Command::new("git");
    merge
        .args(["merge", "--no-edit", "theirs"])
        .current_dir(d)
        .env("HOME", d)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com");
    for var in common::MURK_CONTEXT_VARS {
        merge.env_remove(var);
    }
    let out = merge.env("MURK_KEY", agent_key.trim()).output().unwrap();

    assert!(
        !out.status.success(),
        "merge with a grant key must not succeed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        fs::read(d.join("test.murk")).unwrap(),
        ours,
        "the driver wrote %A: {stderr}"
    );
    assert!(
        stderr.contains("agent grants are read-only"),
        "driver must say why: {stderr}"
    );
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

/// A vault written by murk 0.13.0, whose `DB` description holds a bidi
/// override (U+202E), and its throwaway test key.
const LEGACY_VAULT: &str = include_str!("fixtures/legacy-bidi-description.murk");
// TEST KEY - not secret; only decrypts tests/fixtures/legacy-bidi-description.murk
const LEGACY_KEY: &str =
    "AGE-SECRET-KEY-1T397VF5VLMZZ80SL6LFHM833Y99896EZFDC505PH668UZRNA5UGQCQ7RJE";

#[test]
fn legacy_bidi_description_loads_shows_escaped_and_can_be_replaced() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.murk"), LEGACY_VAULT).unwrap();
    let murk = || murk(&dir, LEGACY_KEY);

    // It loads, and `info` shows the character escaped.
    murk()
        .args(["info", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(
            predicate::str::contains(r"prod \u{202e}bd dorp")
                .and(predicate::str::contains('\u{202e}').not()),
        );
    // 0.14 anchors trust in a local pin, which a 0.13 machine never wrote.
    murk()
        .args(["trust", "--yes", "--vault", "test.murk"])
        .assert()
        .success();
    murk()
        .args(["get", "DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("v\n");

    // `verify` names the field.
    murk()
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains(
            "schema.DB.description contains control, invisible or text-direction characters",
        ));

    // Other writes keep working while the old text is there.
    murk()
        .args(["add", "OTHER", "--vault", "test.murk"])
        .write_stdin("o\n")
        .assert()
        .success();

    // New text with it is refused, without echoing it; clean text replaces it.
    murk()
        .args(["describe", "DB", "again \u{202e}x", "--vault", "test.murk"])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("contains invisible or text-direction characters")
                .and(predicate::str::contains('\u{202e}').not()),
        );
    murk()
        .args(["describe", "DB", "prod db", "--vault", "test.murk"])
        .assert()
        .success();
    murk()
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains("schema.DB.description").not());
    murk()
        .args(["info", "--vault", "test.murk"])
        .env("NO_COLOR", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("prod db"));
}
