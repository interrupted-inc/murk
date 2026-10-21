// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for integration tests.
//!
//! Every murk invocation in the suite routes through [`murk_bin`], which forces
//! `HOME` (and `XDG_RUNTIME_DIR`) inside the test's temp dir and strips inherited
//! key env. This keeps tests hermetic: they can never read or write the
//! developer's real `~/.config/murk/keys`, and a failure reflects product
//! behavior rather than workstation state.

use std::fs;
use std::path::Path;

/// A syntactically valid age recipient that no test vault was encrypted to
/// (the age README example key). Tamper tests inject it so the vault passes
/// load-time validation and the integrity check is what rejects it.
// Not every integration binary tampers with recipients.
#[allow(dead_code)]
pub const FOREIGN_PK: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

/// `fs::canonicalize` with Windows' `\\?\` verbatim prefix removed.
///
/// The worktree fixtures hand these paths straight to `git`, which on Windows
/// does not accept verbatim paths. Canonicalizing is still necessary: `git
/// worktree` records the real path of a checkout, and on macOS a temp dir
/// reached via `/var` really lives in `/private/var`.
// This module is compiled into every integration binary, and only the worktree
// fixtures in `cli.rs` need this one — unused elsewhere is expected, not a bug.
// Twin of `real_path` in `src/testutil.rs` (unit vs. integration test binaries
// can't share `cfg(test)` code) — mirror any edit there.
#[allow(dead_code)]
pub fn real_path(path: &Path) -> std::path::PathBuf {
    let canonical = fs::canonicalize(path).expect("canonicalize fixture path");
    let text = canonical.to_string_lossy();
    // Only a drive-letter path is safe to unwrap: stripping the prefix from a
    // verbatim UNC path (`\\?\UNC\server\share`) would corrupt it.
    let stripped = text.strip_prefix(r"\\?\").filter(|rest| {
        let bytes = rest.as_bytes();
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\"
    });
    std::path::PathBuf::from(stripped.unwrap_or(&text).to_string())
}

use assert_cmd::Command;

/// Every environment variable that changes murk's behaviour.
///
/// Inherited values would make results depend on the caller's shell (an agent
/// session exports `MURK_AGENT=1`, CI exports `CI=true`), so every spawn strips
/// them and a test that needs one sets it explicitly. Keep in step with the
/// readers in `src/env.rs`, `src/hardening.rs`, `src/pins.rs`, `src/trust.rs`
/// and the `env =` args in `src/cli.rs`.
pub const MURK_CONTEXT_VARS: &[&str] = &[
    "MURK_KEY",
    "MURK_KEY_FILE",
    "MURK_VAULT",
    "MURK_AGENT",
    "MURK_STRICT",
    "MURK_SELF_SCOPE",
    "MURK_NO_SIGNER_PIN",
    "MURK_TRUSTED_SIGNERS",
    "CI",
];

/// Build a `murk` command with `HOME` and `XDG_RUNTIME_DIR` forced into `home`
/// and every inherited murk context variable ([`MURK_CONTEXT_VARS`]) removed.
///
/// murk derives `~/.config/murk/keys` straight from `HOME` (see `env::dirs_path`),
/// and `edit` writes its scratch file under `XDG_RUNTIME_DIR`, so pinning both to
/// a temp dir is what makes a test hermetic. This is the only sanctioned way to
/// spawn murk in tests — callers add `.current_dir(...)`, `.env("MURK_KEY", ...)`,
/// or args on top.
pub fn murk_bin(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("murk").unwrap();
    cmd.env("HOME", home).env("XDG_RUNTIME_DIR", home);
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// Build a murk command rooted at `dir` (both cwd and `HOME`) with `MURK_KEY` set.
///
/// Generic over `AsRef<Path>` so it accepts a `&TempDir` from either `assert_fs`
/// or `tempfile` without callers reaching for `.path()`.
pub fn murk(dir: impl AsRef<Path>, key: &str) -> Command {
    let dir = dir.as_ref();
    let mut cmd = murk_bin(dir);
    cmd.current_dir(dir).env("MURK_KEY", key);
    cmd
}

/// Run `murk init` in `dir` and return `(murk_key, pubkey)`.
///
/// Reads the key from the `MURK_KEY_FILE` path written to `.env` (falling back to
/// a legacy inline `MURK_KEY=` for older fixtures).
pub fn init_vault(dir: impl AsRef<Path>) -> (String, String) {
    let dir = dir.as_ref();
    murk_bin(dir)
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir)
        .write_stdin("testuser\n")
        .assert()
        .success();

    let env_contents = fs::read_to_string(dir.join(".env")).unwrap();

    let murk_key = if let Some(path) = env_contents.lines().find_map(|l| {
        l.strip_prefix("export MURK_KEY_FILE=")
            .or_else(|| l.strip_prefix("MURK_KEY_FILE="))
    }) {
        let path = path.trim().trim_matches('\'');
        fs::read_to_string(path).unwrap().trim().to_string()
    } else if let Some(key) = env_contents.lines().find_map(|l| {
        l.strip_prefix("export MURK_KEY=")
            .or_else(|| l.strip_prefix("MURK_KEY="))
    }) {
        key.to_string()
    } else {
        panic!("no MURK_KEY or MURK_KEY_FILE found in .env");
    };

    assert!(murk_key.starts_with("AGE-SECRET-KEY-"));

    let identity: age::x25519::Identity = murk_key.parse().unwrap();
    let pubkey = identity.to_public().to_string();

    (murk_key, pubkey)
}

pub mod cast;
