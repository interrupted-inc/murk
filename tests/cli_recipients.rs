// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI behavior of the recipient circle, groups and agent policy, the shared
//! load/prompt plumbing every command runs through, and `murk agent exec`
//! supervision edge cases.

use std::fs;
use std::path::Path;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk, murk_bin};

/// A fresh age recipient, as a string.
fn age_pubkey() -> String {
    age::x25519::Identity::generate().to_public().to_string()
}

fn authorize(dir: &TempDir, key: &str, pubkey: &str, name: Option<&str>) {
    let mut args = vec!["circle", "authorize", pubkey, "--vault", "test.murk"];
    if let Some(name) = name {
        args.extend(["--name", name]);
    }
    murk(dir, key).args(args).assert().success();
}

fn stdout_json(cmd: &mut assert_cmd::Command) -> serde_json::Value {
    let out = cmd.assert().success();
    serde_json::from_slice(&out.get_output().stdout).unwrap()
}

fn stderr_of(cmd: &mut assert_cmd::Command) -> String {
    let out = cmd.output().unwrap();
    String::from_utf8(out.stderr).unwrap()
}

/// A valid `ssh-ed25519` public key, deterministic per `seed`, with no comment.
fn ssh_pubkey(seed: u8) -> String {
    use base64::Engine;
    let point = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let mut blob = Vec::new();
    for field in [b"ssh-ed25519".as_slice(), point.as_slice()] {
        blob.extend((field.len() as u32).to_be_bytes());
        blob.extend(field);
    }
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

fn vault_json(dir: &TempDir) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(dir.path().join("test.murk")).unwrap()).unwrap()
}

// ── circle ──

/// `ssh:` alone reads `~/.ssh/id_ed25519.pub`, and a `~` in an explicit path
/// expands to the same `HOME`.
#[test]
fn authorize_ssh_resolves_default_key_and_tilde_under_home() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let ssh_dir = dir.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::write(
        ssh_dir.join("id_ed25519.pub"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN me@laptop\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["circle", "authorize", "ssh:", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("id_ed25519.pub"));
    let circle = stdout_json(murk(&dir, &key).args(["circle", "--json", "--vault", "test.murk"]));
    assert!(
        circle.as_array().unwrap().iter().any(|e| e["pubkey"]
            == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN"),
        "comment must be stripped from the stored key: {circle}"
    );

    // The tilde path names the same file, so it is the same recipient.
    murk(&dir, &key)
        .args([
            "circle",
            "authorize",
            "ssh:~/.ssh/id_ed25519.pub",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already a recipient"));
}

/// With the vault key, `circle --json` names every recipient and marks only
/// the caller as self. Without it, names live in the encrypted meta and are
/// unavailable, so nobody is named and nobody is self.
#[test]
fn circle_json_names_recipients_and_self_only_with_a_key() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let bob = age_pubkey();
    authorize(&dir, &key, &bob, Some("bob"));

    let with_key = stdout_json(murk(&dir, &key).args(["circle", "--json", "--vault", "test.murk"]));
    let entry = |list: &serde_json::Value, pk: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|e| e["pubkey"] == pk)
            .cloned()
            .unwrap_or_else(|| panic!("{pk} missing from {list}"))
    };
    assert_eq!(
        entry(&with_key, &alice),
        serde_json::json!({"pubkey": alice, "name": "testuser", "is_self": true})
    );
    assert_eq!(
        entry(&with_key, &bob),
        serde_json::json!({"pubkey": bob, "name": "bob", "is_self": false})
    );

    // A HOME with no stored key, and cwd's .env is not a trusted key source.
    let keyless_home = TempDir::new().unwrap();
    let without_key = stdout_json(murk_bin(keyless_home.path()).current_dir(dir.path()).args([
        "circle",
        "--json",
        "--vault",
        "test.murk",
    ]));
    for pk in [&alice, &bob] {
        assert_eq!(
            entry(&without_key, pk),
            serde_json::json!({"pubkey": pk, "name": null, "is_self": false})
        );
    }
}

/// Without a key, plain `circle` prints bare pubkeys, one per line, so the
/// output can be piped straight into another tool.
#[test]
fn circle_without_key_prints_bare_pubkeys() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let bob = age_pubkey();
    authorize(&dir, &key, &bob, Some("bob"));

    let keyless_home = TempDir::new().unwrap();
    let out = murk_bin(keyless_home.path())
        .current_dir(dir.path())
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    let mut expected = vec![alice.as_str(), bob.as_str()];
    expected.sort_unstable();
    assert_eq!(lines, expected);
}

/// Several keys under one name (one person, several machines) collapse into a
/// single line with a key count instead of one line per key.
#[test]
fn circle_consolidates_keys_sharing_a_name() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let (laptop, desktop) = (age_pubkey(), age_pubkey());
    authorize(&dir, &key, &laptop, Some("bob"));
    authorize(&dir, &key, &desktop, Some("bob"));

    let out = murk(&dir, &key)
        .args(["circle", "--vault", "test.murk"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let bob_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("bob")).collect();
    assert_eq!(bob_lines.len(), 1, "{stdout}");
    assert!(bob_lines[0].contains("(2 keys)"), "{stdout}");
}

/// The same SSH key, raw with a comment, via `ssh:` with another comment, or
/// bare, is one recipient: it is stored once as `type base64`, its comment
/// becomes the display name, and adding it again in any form is refused.
#[test]
fn authorize_refuses_the_same_ssh_key_in_another_form() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let bob = ssh_pubkey(1);
    authorize(&dir, &key, &format!("{bob} bob@laptop"), None);

    let circle = stdout_json(murk(&dir, &key).args(["circle", "--json", "--vault", "test.murk"]));
    let stored: Vec<_> = circle
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["pubkey"].as_str().unwrap().starts_with("ssh-"))
        .collect();
    assert_eq!(
        stored,
        [&serde_json::json!({"pubkey": bob, "name": "bob@laptop", "is_self": false})]
    );

    let pub_file = dir.path().join("bob.pub");
    fs::write(&pub_file, format!("{bob} bob@desktop\n")).unwrap();
    for twin in [format!("ssh:{}", pub_file.display()), bob.clone()] {
        murk(&dir, &key)
            .args(["circle", "authorize", &twin, "--vault", "test.murk"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("already a recipient"));
    }
    assert_eq!(vault_json(&dir)["recipients"].as_array().unwrap().len(), 2);
}

/// Revoking your own key (by pubkey in any spelling, or by your display name)
/// is refused before anything is written: the vault stays byte-identical and
/// signed. Revoking someone else still works.
#[test]
fn revoke_refuses_your_own_key() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let bob = age_pubkey();
    authorize(&dir, &key, &bob, Some("bob"));
    let path = dir.path().join("test.murk");
    let before = fs::read(&path).unwrap();

    for spec in [alice.clone(), alice.to_ascii_uppercase(), "testuser".into()] {
        for extra in [&[][..], &["--rotate", "--force"][..]] {
            murk(&dir, &key)
                .args(["circle", "revoke", &spec, "--vault", "test.murk"])
                .args(extra)
                .assert()
                .failure()
                .stderr(predicate::str::contains("you can't revoke your own key"))
                .stderr(predicate::str::contains(format!(
                    "murk circle revoke \"{alice}\""
                )));
            assert_eq!(fs::read(&path).unwrap(), before, "{spec} {extra:?}");
        }
    }

    murk(&dir, &key)
        .args(["circle", "revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success();
    assert_eq!(vault_json(&dir)["recipients"], serde_json::json!([alice]));
}

/// An age key is Bech32, so its uppercase form is the same recipient: it is
/// stored lowercase, the lowercase twin is refused, and revoking it in either
/// case cuts the key's access.
#[test]
fn age_key_case_variants_are_one_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let bob = age_pubkey();
    authorize(&dir, &key, &bob.to_ascii_uppercase(), Some("bob"));
    assert_eq!(
        vault_json(&dir)["recipients"],
        serde_json::json!([alice, bob])
    );

    murk(&dir, &key)
        .args(["circle", "authorize", &bob, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already a recipient"));

    murk(&dir, &key)
        .args([
            "circle",
            "revoke",
            &bob.to_ascii_uppercase(),
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    assert_eq!(vault_json(&dir)["recipients"], serde_json::json!([alice]));
}

/// The five low-order X25519 points as age recipients. age parses each one,
/// and encrypting to any of them panics inside age.
const LOW_ORDER_AGE_RECIPIENTS: [&str; 5] = [
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z",
    "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj7vrya",
    "age1t7wft09r2zxzfvwsk92eeql0tvzyghxytqwgapkcyf8dm5ylz9ts6wm9s8",
    "age1ur4h5lpmgxu2u9jku0a0r87ydtdqnr0tnsetrlvxvgz3vh6fhqqqzyt4v9",
    "age1anlllllllllllllllllllllllllllllllllllllllllllllllals4n2t7m",
];

/// Authorizing a low-order age key is refused with a clear error, not a panic,
/// and the vault is left untouched.
#[test]
fn authorize_refuses_low_order_age_keys() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let path = dir.path().join("test.murk");
    let before = fs::read(&path).unwrap();
    for pk in LOW_ORDER_AGE_RECIPIENTS {
        murk(&dir, &key)
            .args(["circle", "authorize", pk, "--vault", "test.murk"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("invalid public key"))
            .stderr(predicate::str::contains("low-order"))
            .stderr(predicate::str::contains("panicked").not());
        assert_eq!(fs::read(&path).unwrap(), before, "{pk}");
    }
}

/// A vault whose header already lists a low-order key (written by an older
/// murk, or by anyone with repo write access) still loads. `verify` names the
/// bad recipient, a save refuses cleanly instead of panicking, and revoking
/// the bad key repairs the vault.
#[test]
fn vault_with_a_low_order_recipient_loads_flags_and_refuses_to_save() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let path = dir.path().join("test.murk");
    let weak = LOW_ORDER_AGE_RECIPIENTS[0];

    // Header lists the weak key; the meta stays encrypted to alice only (age
    // cannot encrypt to the weak key). A secret-less vault needs no MAC.
    let identity = murk_cli::crypto::parse_identity(&key).unwrap();
    let mut vault = murk_cli::vault::read(&path).unwrap();
    let mut meta = murk_cli::decrypt_meta(&vault, &identity).unwrap().unwrap();
    meta.mac = String::new();
    meta.sig = None;
    vault.recipients.push(weak.into());
    vault.meta = murk_cli::encrypt_value(
        &serde_json::to_vec(&meta).unwrap(),
        &[murk_cli::crypto::parse_recipient(&alice).unwrap()],
    )
    .unwrap();
    murk_cli::vault::write(&path, &vault).unwrap();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsafe recipient"))
        .stderr(predicate::str::contains(weak));

    let before = fs::read(&path).unwrap();
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("v\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to save"))
        .stderr(predicate::str::contains("panicked").not());
    assert_eq!(fs::read(&path).unwrap(), before);

    murk(&dir, &key)
        .args(["circle", "revoke", weak, "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("v\n")
        .assert()
        .success();
}

/// A vault written by an older murk can list one SSH key twice (with and
/// without a comment). `verify` flags it, and revoking the key removes every
/// copy and each copy's scoped override, so the leaver keeps no access.
#[test]
fn revoke_removes_every_stored_copy_of_an_ssh_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("shared\n")
        .assert()
        .success();
    let bob = ssh_pubkey(1);
    authorize(&dir, &key, &bob, Some("bob"));

    // Recreate the legacy state: a commented twin with its own override.
    let path = dir.path().join("test.murk");
    let identity = murk_cli::crypto::parse_identity(&key).unwrap();
    let mut vault = murk_cli::vault::read(&path).unwrap();
    let original = murk_cli::decrypt_vault(&vault, &identity).unwrap();
    let mut current = original.clone();
    let twin = format!("{bob} bob@laptop");
    vault.recipients.push(twin.clone());
    current.recipients.insert(twin.clone(), "bob".into());
    current.private.insert(
        "TOKEN".into(),
        std::collections::HashMap::from([(twin.clone(), "bob's override".to_string().into())]),
    );
    murk_cli::save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();
    assert!(vault_json(&dir)["secrets"]["TOKEN"]["scoped"][&twin].is_string());

    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains("listed 2 times as a recipient"));

    murk(&dir, &key)
        .args(["circle", "revoke", &bob, "--vault", "test.murk"])
        .assert()
        .success();

    let json = vault_json(&dir);
    let blob = bob.split(' ').nth(1).unwrap();
    assert!(
        !json["recipients"].to_string().contains(blob),
        "every copy of the key must go: {}",
        json["recipients"]
    );
    assert!(
        !json["secrets"].to_string().contains(blob),
        "the twin's override must go: {}",
        json["secrets"]
    );
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .stderr(predicate::str::contains("times as a recipient").not());
}

/// A GitHub user's keys all carry `<user>@github`. Revoking that name (or
/// `github:<user>`) lists the keys and, without a TTY to confirm on, needs
/// `--force`; with it, every key goes and other recipients stay.
#[test]
fn revoke_github_user_by_name_removes_every_key() {
    let dir = TempDir::new().unwrap();
    let (key, alice) = init_vault(&dir);
    let (laptop, desktop) = (ssh_pubkey(1), ssh_pubkey(2));
    authorize(&dir, &key, &laptop, Some("octo@github"));
    authorize(&dir, &key, &desktop, Some("octo@github"));
    let carol = age_pubkey();
    authorize(&dir, &key, &carol, Some("carol"));
    let recipients = || vault_json(&dir)["recipients"].clone();
    let before = recipients();

    murk(&dir, &key)
        .args(["circle", "revoke", "octo@github", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(&laptop))
        .stderr(predicate::str::contains(&desktop))
        .stderr(predicate::str::contains("--force"));
    assert_eq!(recipients(), before, "nothing is revoked unconfirmed");

    murk(&dir, &key)
        .args([
            "circle",
            "revoke",
            "github:octo",
            "--force",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    assert_eq!(recipients(), serde_json::json!([alice, carol]));
}

// ── group ──

/// Adding a recipient to a group re-encrypts its secrets to them; a repeat
/// add or a remove of a non-member is a successful no-op; a group that still
/// holds secrets cannot be deleted, an empty one can.
#[test]
fn group_membership_lifecycle() {
    let dir = TempDir::new().unwrap();
    let (alice_key, alice) = init_vault(&dir);
    let bob_dir = TempDir::new().unwrap();
    let (bob_key, bob) = init_vault(&bob_dir);
    authorize(&dir, &alice_key, &bob, Some("bob"));

    // No groups yet: human listing points at `group create`, JSON is empty.
    murk(&dir, &alice_key)
        .args(["group", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("murk group create"));
    assert_eq!(
        stdout_json(murk(&dir, &alice_key).args(["group", "ls", "--json", "--vault", "test.murk"])),
        serde_json::json!({})
    );

    murk(&dir, &alice_key)
        .args(["group", "create", "prod", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["add", "PROD_DB", "--group", "prod", "--vault", "test.murk"])
        .write_stdin("prod_secret\n")
        .assert()
        .success();
    murk(&dir, &bob_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .failure();

    murk(&dir, &alice_key)
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
        .success()
        .stderr(predicate::str::contains("added bob to group prod"));
    murk(&dir, &bob_key)
        .args(["get", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("prod_secret\n");

    // Adding again changes nothing.
    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    murk(&dir, &alice_key)
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
        .success()
        .stderr(predicate::str::contains("bob is already in group prod"));
    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );

    assert_eq!(
        stdout_json(murk(&dir, &alice_key).args(["group", "ls", "--json", "--vault", "test.murk"])),
        serde_json::json!({ "prod": [alice, bob] })
    );
    // Human listing marks the caller.
    murk(&dir, &alice_key)
        .args(["group", "ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("* testuser").and(predicate::str::contains("  bob")));

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
        .success()
        .stderr(predicate::str::contains("bob is not in group prod"));

    // Deleting a group that still holds a secret would orphan it.
    murk(&dir, &alice_key)
        .args(["group", "rm", "prod", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "still has 1 secret(s) assigned (PROD_DB)",
        ));
    murk(&dir, &alice_key)
        .args(["rm", "PROD_DB", "--vault", "test.murk"])
        .assert()
        .success();
    murk(&dir, &alice_key)
        .args(["group", "rm", "prod", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("deleted group prod"));
    assert_eq!(
        stdout_json(murk(&dir, &alice_key).args(["group", "ls", "--json", "--vault", "test.murk"])),
        serde_json::json!({})
    );
}

// ── policy ──

/// `policy show --json` reports `null` (unrestricted) until a policy is set,
/// and clearing an absent policy is a no-op that leaves the vault untouched.
#[test]
fn policy_json_and_clear_without_policy() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    assert_eq!(
        stdout_json(murk(&dir, &key).args(["policy", "show", "--json", "--vault", "test.murk"])),
        serde_json::json!({ "agent_allow_tags": null })
    );

    let before = fs::read_to_string(dir.path().join("test.murk")).unwrap();
    murk(&dir, &key)
        .args(["policy", "clear", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no policy to clear"));
    assert_eq!(
        fs::read_to_string(dir.path().join("test.murk")).unwrap(),
        before
    );

    murk(&dir, &key)
        .args([
            "policy",
            "set",
            "--allow-tag",
            "agents",
            "--allow-tag",
            "ci",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();
    assert_eq!(
        stdout_json(murk(&dir, &key).args(["policy", "show", "--json", "--vault", "test.murk"])),
        serde_json::json!({ "agent_allow_tags": ["agents", "ci"] })
    );
}

// ── shared load / prompt plumbing ──

/// `init` over a `.env` that already holds a key asks before overwriting, and
/// the default answer aborts without touching `.env` or creating a vault.
#[test]
fn init_refuses_to_overwrite_dotenv_key_by_default() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    fs::write(&env_path, "MURK_KEY=AGE-SECRET-KEY-EXISTING\n").unwrap();

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["init", "--vault", "test.murk"])
        .write_stdin("testuser\n\n")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Overwrite? [y/N]").and(predicate::str::contains("Aborted.")),
        );
    assert_eq!(
        fs::read_to_string(&env_path).unwrap(),
        "MURK_KEY=AGE-SECRET-KEY-EXISTING\n"
    );
    assert!(!dir.path().join("test.murk").exists());
}

/// In CI, decrypting with the operator's auto-discovered key prints a hint
/// toward a scoped grant key. An explicit key or agent context stays quiet.
#[test]
fn ci_hint_fires_only_for_the_auto_discovered_personal_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "TOKEN", "--vault", "test.murk"])
        .write_stdin("v\n")
        .assert()
        .success();

    let get = |configure: &dyn Fn(&mut assert_cmd::Command)| {
        let mut cmd = murk_bin(dir.path());
        cmd.current_dir(dir.path()).env("CI", "true").args([
            "get",
            "TOKEN",
            "--vault",
            "test.murk",
        ]);
        configure(&mut cmd);
        let out = cmd.assert().success().stdout("v\n");
        String::from_utf8(out.get_output().stderr.clone()).unwrap()
    };

    let auto = get(&|_| {});
    assert_eq!(
        auto.matches("CI is decrypting with your personal key")
            .count(),
        1,
        "{auto}"
    );
    assert!(auto.contains("murk agent init"), "{auto}");

    let explicit = get(&|cmd| {
        cmd.env("MURK_KEY", &key);
    });
    assert!(!explicit.contains("CI is decrypting"), "{explicit}");
}

/// Sets up a vault whose merge left it unsigned: two branches each add a
/// secret, and the merge driver (which never signs) combines them into
/// `test.murk`. Returns `(dir, key)`.
fn merged_unsigned_vault() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let vault = dir.path().join("test.murk");
    murk(&dir, &key)
        .args(["add", "BASE", "--vault", "test.murk"])
        .write_stdin("b\n")
        .assert()
        .success();
    let base = dir.path().join("base.murk");
    fs::copy(&vault, &base).unwrap();

    murk(&dir, &key)
        .args(["add", "THEIRS", "--vault", "test.murk"])
        .write_stdin("t\n")
        .assert()
        .success();
    let theirs = dir.path().join("theirs.murk");
    fs::copy(&vault, &theirs).unwrap();

    fs::copy(&base, &vault).unwrap();
    murk(&dir, &key)
        .args(["add", "OURS", "--vault", "test.murk"])
        .write_stdin("o\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["merge-driver"])
        .args([&base, &vault, &theirs].map(|p| p.to_str().unwrap()))
        .assert()
        .success();
    (dir, key)
}

/// After a merge strips the signature, every read warns that a vault seen
/// signed is now unsigned, until any write re-signs it.
#[test]
fn signature_downgrade_warns_until_the_next_write() {
    let (dir, key) = merged_unsigned_vault();
    let read = || stderr_of(murk(&dir, &key).args(["get", "OURS", "--vault", "test.murk"]));

    let warned = read();
    assert!(
        warned.contains("was signed before and is now unsigned"),
        "{warned}"
    );
    murk(&dir, &key)
        .args(["get", "THEIRS", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout("t\n");

    murk(&dir, &key)
        .args(["add", "AFTER", "--vault", "test.murk"])
        .write_stdin("a\n")
        .assert()
        .success();
    let clean = read();
    assert!(!clean.contains("unsigned"), "{clean}");
}

/// With signer pinning off, murk cannot tell a downgrade or anchor a
/// signature, and says so: an unsigned vault gets the plain "sign it" nudge,
/// and a signed one is flagged as trust-only.
#[test]
fn signer_pinning_off_reports_what_it_cannot_check() {
    let (dir, key) = merged_unsigned_vault();
    let read = || {
        stderr_of(murk(&dir, &key).env("MURK_NO_SIGNER_PIN", "1").args([
            "get",
            "OURS",
            "--vault",
            "test.murk",
        ]))
    };

    let unsigned = read();
    assert!(
        unsigned.contains("vault is unsigned — run any write command to sign it"),
        "{unsigned}"
    );
    assert!(!unsigned.contains("signed before"), "{unsigned}");

    murk(&dir, &key)
        .env("MURK_NO_SIGNER_PIN", "1")
        .args(["add", "AFTER", "--vault", "test.murk"])
        .write_stdin("a\n")
        .assert()
        .success();
    let signed = read();
    assert!(signed.contains("signer pinning is off"), "{signed}");
    assert!(!signed.contains("unsigned"), "{signed}");
}

// ── rotate --list ──

fn set_schema_field(vault: &Path, key: &str, field: &str, value: Option<&str>) {
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vault).unwrap()).unwrap();
    let entry = json["schema"][key].as_object_mut().unwrap();
    match value {
        Some(v) => entry.insert(field.into(), v.into()),
        None => entry.remove(field),
    };
    fs::write(vault, serde_json::to_string_pretty(&json).unwrap()).unwrap();
}

/// `rotate --list` passes a clean vault, and fails (exit 1) with one finding
/// per problem: an overdue interval, an interval with no baseline, an expiry
/// inside the warning window, and a timestamp it cannot parse.
#[test]
fn rotate_list_reports_each_rotation_problem() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    for name in ["STALE", "UNDATED", "SOON"] {
        murk(&dir, &key)
            .args(["add", name, "--vault", "test.murk"])
            .write_stdin("v\n")
            .assert()
            .success();
    }
    murk(&dir, &key)
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no keys need rotation"));

    for name in ["STALE", "UNDATED"] {
        murk(&dir, &key)
            .args([
                "describe",
                name,
                "d",
                "--rotate-every",
                "30d",
                "--vault",
                "test.murk",
            ])
            .assert()
            .success();
    }
    let soon = (chrono::Utc::now() + chrono::Duration::days(3))
        .format("%Y-%m-%d")
        .to_string();
    murk(&dir, &key)
        .args([
            "describe",
            "SOON",
            "d",
            "--expires",
            &soon,
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Time passing, and an older vault. (A garbled timestamp is refused when
    // the vault loads, so rotate --list never sees one.)
    let vault = dir.path().join("test.murk");
    set_schema_field(&vault, "STALE", "updated", Some("2020-01-01T00:00:00Z"));
    set_schema_field(&vault, "UNDATED", "updated", None);

    let out = murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["rotate", "--list", "--vault", "test.murk"])
        .assert()
        .code(1);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("3 issues in rotation"), "{stderr}");
    assert!(
        stderr.contains("STALE is ")
            && stderr.contains("d overdue for rotation (30d interval, last changed 2020-01-01)")
            && stderr.contains("murk rotate STALE"),
        "{stderr}"
    );
    assert!(
        stderr.contains("UNDATED has a 30d rotation interval but no last-updated timestamp")
            && stderr.contains("murk add UNDATED"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("SOON expires in 2d ({soon})"))
            || stderr.contains(&format!("SOON expires in 3d ({soon})")),
        "{stderr}"
    );
}

// ── agent exec supervision ──

/// `agent exec --only DB_URL -- sh -c <script>` with `DB_URL` in the vault,
/// as a spawnable process for tests that need to drive its pipes.
#[cfg(unix)]
fn agent_exec_sh(script: &str) -> (TempDir, std::process::Command) {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "DB_URL", "--vault", "test.murk"])
        .write_stdin("postgres://prod-sentinel\n")
        .assert()
        .success();
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"));
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("MURK_KEY", &key)
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
    (dir, cmd)
}

/// Wait up to `secs` for `child`, killing it and failing on timeout.
#[cfg(unix)]
fn wait_bounded(
    child: &mut std::process::Child,
    secs: u64,
    what: &str,
) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("{what}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// A signal the child sends to murk itself is not echoed back to the child,
/// and does not stop murk. The child waits before signalling so murk is
/// already supervising it; a signal sent in the instant between spawn and
/// that point takes a different path.
#[cfg(unix)]
#[test]
fn agent_exec_does_not_echo_a_childs_own_signal_back() {
    let (_dir, mut cmd) = agent_exec_sh(
        "trap 'echo echoed; exit 9' TERM; sleep 0.3; kill -TERM $PPID; sleep 0.5; echo done",
    );
    let out = cmd.output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "done\n");
    assert_eq!(out.status.code(), Some(0), "{:?}", out.status);
}

/// When murk's own reader goes away (`murk agent exec ... | head -1`), murk
/// stops copying and closes the child's pipe, so the child sees a write error
/// instead of blocking forever, and murk exits with the child's status.
#[cfg(unix)]
#[test]
fn agent_exec_closes_childs_pipe_when_its_reader_goes_away() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let (_dir, mut cmd) =
        agent_exec_sh("trap '' PIPE; echo ready; while echo line; do :; done; exit 3");
    let mut murk_proc = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(murk_proc.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    drop(lines);

    let status = wait_bounded(
        &mut murk_proc,
        10,
        "child kept writing after the reader left",
    );
    assert_eq!(status.code(), Some(3), "{status:?}");
}
