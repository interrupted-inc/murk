// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A vault signed by an agent grant is never a valid author.
//!
//! The grant-signed vault is produced in-process through the library, the way
//! an older binary (or an agent editing `.murk` by hand) would produce it. That
//! needs `MURK_KEY` and `HOME` in this process's environment, so this binary
//! holds exactly one test: nothing else here reads the environment
//! concurrently.

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

#[test]
fn a_grant_signed_vault_is_refused_on_load_and_fails_verify() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "A", "--vault", "test.murk"])
        .write_stdin("aval\n")
        .assert()
        .success();
    let agent_key_path = dir.path().join("agent.key");
    murk(&dir, &key)
        .args(["agent", "grant", "--name", "bot", "--only", "A", "--out"])
        .arg(&agent_key_path)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let agent_key = std::fs::read_to_string(&agent_key_path).unwrap();

    // Hand-edit the schema and re-sign with the grant key. The read-only gate
    // keys off `loaded_by`, which a hand-built state (or an old binary) lacks.
    let vault_path = dir.path().join("test.murk");
    let vault_path = vault_path.to_str().unwrap();
    // SAFETY: the only test in this binary, so no concurrent env access.
    unsafe {
        for var in MURK_CONTEXT_VARS {
            std::env::remove_var(var);
        }
        std::env::set_var("HOME", dir.path());
        std::env::set_var("MURK_KEY", agent_key.trim());
    }
    let (mut vault, mut original, _) = murk_cli::load_vault(vault_path).unwrap();
    original.loaded_by = None;
    let current = original.clone();
    vault.schema.get_mut("A").unwrap().description = "hijacked".into();
    murk_cli::save_vault(vault_path, &mut vault, &original, &current).unwrap();
    unsafe { std::env::remove_var("MURK_KEY") };

    let refused = "vault is signed by agent grant bot";
    murk(&dir, &key)
        .args(["verify", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(refused));
    murk(&dir, &key)
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("aval").not())
        .stderr(predicate::str::contains(refused));
    murk(&dir, &key)
        .env("MURK_STRICT", "1")
        .args(["get", "A", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(refused));
}
