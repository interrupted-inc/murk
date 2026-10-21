// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk agent connect` / `disconnect`: how the command treats the client
//! configs it edits (symlinks, non-default vaults) and the order of its side
//! effects (no grant is minted for a config that cannot be written).

use std::fs;
use std::path::{Path, PathBuf};

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk, murk_bin};

/// Add `API_KEY` to `vault` so there is something to scope a grant to.
fn add_secret(dir: &TempDir, key: &str, vault: &str) {
    murk(dir, key)
        .args(["add", "API_KEY", "--vault", vault])
        .write_stdin("sk-secret\n")
        .assert()
        .success();
}

/// `murk init` a vault called `vault` in `dir` and return its key. Twin of
/// `common::init_vault`, which is hardwired to `test.murk`.
fn init_named_vault(dir: &TempDir, vault: &str) -> String {
    murk_bin(dir.path())
        .args(["init", "--vault", vault])
        .current_dir(dir.path())
        .write_stdin("testuser\n")
        .assert()
        .success();
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    let key_file = env
        .lines()
        .find_map(|l| {
            l.strip_prefix("export MURK_KEY_FILE=")
                .or_else(|| l.strip_prefix("MURK_KEY_FILE="))
        })
        .expect("init writes MURK_KEY_FILE to .env");
    fs::read_to_string(key_file.trim().trim_matches('\''))
        .unwrap()
        .trim()
        .to_string()
}

/// Every grant key file under the (test-isolated) `$HOME`.
fn agent_key_files(dir: &TempDir) -> Vec<PathBuf> {
    let keys = dir.path().join(".config/murk/agent-keys");
    match fs::read_dir(keys) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

fn assert_no_grant(dir: &TempDir, key: &str, vault: &str) {
    murk(dir, key)
        .args(["agent", "ls", "--vault", vault])
        .assert()
        .success()
        .stderr(predicate::str::contains("no active grants"));
    assert!(
        agent_key_files(dir).is_empty(),
        "no grant key file may exist: {:?}",
        agent_key_files(dir)
    );
}

fn connect(dir: &TempDir, key: &str, client: &str, vault: &str) -> assert_cmd::assert::Assert {
    murk(dir, key)
        .args([
            "agent", "connect", client, "--only", "API_KEY", "--vault", vault,
        ])
        .assert()
}

const FOREIGN_CONFIG: &str = "{\n  \"auths\": { \"ghcr.io\": { \"auth\": \"c2VjcmV0\" } }\n}\n";

const CONFIG_WITH_MURK: &str = "{\n  \"mcpServers\": {\n    \"murk\": { \"command\": \"murk\", \"args\": [\"mcp\"] },\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n";

// ── symlinks ──

#[cfg(unix)]
#[test]
fn connect_refuses_a_symlinked_config_and_leaves_its_target_alone() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    // A repo can commit `.mcp.json` as a link to a file outside the project.
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("config.json");
    fs::write(&target, FOREIGN_CONFIG).unwrap();
    let link = dir.path().join(".mcp.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let vault_before = fs::read(dir.path().join("test.murk")).unwrap();

    connect(&dir, &key, "claude", "test.murk")
        .failure()
        .stderr(predicate::str::contains("symlink").and(predicate::str::contains(".mcp.json")));

    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        FOREIGN_CONFIG,
        "the link target must be untouched"
    );
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        ".mcp.json must still be a symlink, not a copy of the target's content"
    );
    assert_eq!(
        fs::read(dir.path().join("test.murk")).unwrap(),
        vault_before,
        "refused before minting"
    );
    assert_no_grant(&dir, &key, "test.murk");
}

#[cfg(unix)]
#[test]
fn connect_refuses_a_symlinked_client_dir_and_creates_nothing_outside() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    let outside = TempDir::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join(".cursor")).unwrap();

    connect(&dir, &key, "cursor", "test.murk")
        .failure()
        .stderr(predicate::str::contains("symlink").and(predicate::str::contains(".cursor")));

    assert!(
        fs::read_dir(outside.path()).unwrap().next().is_none(),
        "nothing may be created through the link"
    );
    assert_no_grant(&dir, &key, "test.murk");
}

#[cfg(unix)]
#[test]
fn disconnect_refuses_a_symlinked_config_and_leaves_its_target_alone() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let outside = TempDir::new().unwrap();
    let target = outside.path().join("mcp.json");
    fs::write(&target, CONFIG_WITH_MURK).unwrap();
    let link = dir.path().join(".mcp.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    murk(&dir, &key)
        .args(["agent", "disconnect", "claude", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink").and(predicate::str::contains(".mcp.json")));

    assert_eq!(fs::read_to_string(&target).unwrap(), CONFIG_WITH_MURK);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        ".mcp.json must still be a symlink"
    );
}

#[cfg(unix)]
#[test]
fn disconnect_refuses_a_symlinked_client_dir_and_leaves_its_target_alone() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let outside = TempDir::new().unwrap();
    let target = outside.path().join("mcp.json");
    fs::write(&target, CONFIG_WITH_MURK).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join(".cursor")).unwrap();

    murk(&dir, &key)
        .args(["agent", "disconnect", "cursor", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink").and(predicate::str::contains(".cursor")));

    assert_eq!(fs::read_to_string(&target).unwrap(), CONFIG_WITH_MURK);
}

// ── non-default vault ──

#[test]
fn connect_carries_a_non_default_vault_into_the_entry() {
    let dir = TempDir::new().unwrap();
    let key = init_named_vault(&dir, "prod.murk");
    add_secret(&dir, &key, "prod.murk");

    connect(&dir, &key, "claude", "prod.murk").success();

    let body = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entry = &v["mcpServers"]["murk"];
    assert_eq!(
        entry["args"],
        serde_json::json!(["mcp", "--vault", "prod.murk"])
    );

    // The entry must actually find the vault: run it exactly as the editor would,
    // from the project dir. Without `--vault` murk fails "vault file not found";
    // with it, the server starts and only stops because stdin closes before any
    // MCP handshake.
    let mut cmd = murk_bin(dir.path());
    cmd.current_dir(dir.path());
    cmd.args(
        entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap()),
    );
    for (name, value) in entry["env"].as_object().unwrap() {
        cmd.env(name, value.as_str().unwrap());
    }
    cmd.write_stdin("").assert().stderr(
        predicate::str::contains("serving over stdio")
            .and(predicate::str::contains("vault file not found").not()),
    );
}

#[test]
fn connect_keeps_the_default_vault_entry_unchanged() {
    let dir = TempDir::new().unwrap();
    let key = init_named_vault(&dir, ".murk");
    add_secret(&dir, &key, ".murk");

    connect(&dir, &key, "claude", ".murk").success();

    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(v["mcpServers"]["murk"]["args"], serde_json::json!(["mcp"]));
}

#[test]
fn connect_puts_the_vault_before_allow_exec() {
    let dir = TempDir::new().unwrap();
    let key = init_named_vault(&dir, "prod.murk");
    add_secret(&dir, &key, "prod.murk");

    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "codex",
            "--only",
            "API_KEY",
            "--allow-exec",
            "--vault",
            "prod.murk",
        ])
        .assert()
        .success();

    let body = fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert!(
        body.contains("args = [\"mcp\", \"--vault\", \"prod.murk\", \"--allow-exec\"]"),
        "{body}"
    );
}

// ── ordering: validate every config, then mint, then write ──

#[test]
fn connect_with_a_malformed_config_mints_no_grant() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    fs::write(dir.path().join(".mcp.json"), "{not json").unwrap();
    let vault_before = fs::read(dir.path().join("test.murk")).unwrap();

    connect(&dir, &key, "claude", "test.murk")
        .failure()
        .stderr(predicate::str::contains("no grant was minted"));

    assert_eq!(
        fs::read(dir.path().join("test.murk")).unwrap(),
        vault_before,
        "the vault must not be written"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(".mcp.json")).unwrap(),
        "{not json",
        "the bad config must be left as found"
    );
    assert_no_grant(&dir, &key, "test.murk");
}

#[test]
fn connect_writes_no_config_when_any_target_is_bad() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    // Auto-detect picks up both editors; the Claude config is malformed.
    fs::write(dir.path().join(".mcp.json"), "{not json").unwrap();
    fs::create_dir(dir.path().join(".cursor")).unwrap();
    let vault_before = fs::read(dir.path().join("test.murk")).unwrap();

    murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "--only",
            "API_KEY",
            "--vault",
            "test.murk",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no grant was minted"));

    assert!(
        !dir.path().join(".cursor/mcp.json").exists(),
        "a good target must not be written while another is rejected"
    );
    assert_eq!(
        fs::read(dir.path().join("test.murk")).unwrap(),
        vault_before
    );
    assert_no_grant(&dir, &key, "test.murk");
}

/// A write that fails after the grant was minted rolls the whole connect back:
/// configs already written are restored, the new grant is revoked and its key
/// file deleted, so no live grant is left without an editor using it.
#[cfg(unix)]
#[test]
fn connect_rolls_back_when_a_write_fails_after_minting() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    // Auto-detect finds both editors. Claude's config is fine and gets written
    // first; `.cursor` can't take a new file, so that write fails after
    // planning passed.
    fs::write(dir.path().join(".mcp.json"), "{}\n").unwrap();
    let client_dir = dir.path().join(".cursor");
    fs::create_dir(&client_dir).unwrap();
    fs::set_permissions(&client_dir, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::write(client_dir.join("probe"), "").is_ok() {
        // Running as a user that ignores directory modes (root): can't stage it.
        fs::set_permissions(&client_dir, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let assert = murk(&dir, &key)
        .args([
            "agent",
            "connect",
            "--only",
            "API_KEY",
            "--vault",
            "test.murk",
        ])
        .assert();
    fs::set_permissions(&client_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert
        .failure()
        .stderr(predicate::str::contains("rolled back"));

    assert_eq!(
        fs::read_to_string(dir.path().join(".mcp.json")).unwrap(),
        "{}\n"
    );
    assert_no_grant(&dir, &key, "test.murk");
    assert!(agent_key_files(&dir).is_empty());
}

#[test]
fn connect_still_reuses_an_existing_grant() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add_secret(&dir, &key, "test.murk");

    connect(&dir, &key, "claude", "test.murk").success();
    let key_files = agent_key_files(&dir);
    assert_eq!(key_files.len(), 1);
    let key_bytes = fs::read(&key_files[0]).unwrap();

    connect(&dir, &key, "cursor", "test.murk")
        .success()
        .stderr(predicate::str::contains("reusing grant"));
    assert_eq!(fs::read(&key_files[0]).unwrap(), key_bytes);
    assert!(Path::new(&dir.path().join(".cursor/mcp.json")).is_file());
}
