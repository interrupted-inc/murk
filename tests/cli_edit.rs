// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk edit` writes decrypted secrets to a scratch file for `$EDITOR`. These
//! tests pin the scratch dir (`XDG_RUNTIME_DIR` and `TMPDIR`) to a directory of
//! its own and check it is empty afterwards on every way out of the command:
//! success, a failing or missing editor, a failed read-back, and a signal.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

const VALUE: &str = "s3cret-value";
/// SIGTERM is 15 on every Unix murk supports.
const SIGTERM: i32 = 15;

struct Fixture {
    dir: TempDir,
    key: String,
    /// The scratch dir `edit` writes its plaintext file into.
    scratch: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (key, _) = init_vault(&dir);
        murk(&dir, &key)
            .args(["add", "SECRET", "--vault", "test.murk"])
            .write_stdin(format!("{VALUE}\n"))
            .assert()
            .success();
        let scratch = dir.path().join("scratch");
        fs::create_dir(&scratch).unwrap();
        Self { dir, key, scratch }
    }

    /// `murk edit SECRET` with the scratch dir pinned and `EDITOR` set.
    fn edit(&self, editor: &str) -> assert_cmd::Command {
        let mut cmd = murk(&self.dir, &self.key);
        cmd.args(["edit", "SECRET", "--vault", "test.murk"])
            .env("XDG_RUNTIME_DIR", &self.scratch)
            .env("TMPDIR", &self.scratch)
            .env("EDITOR", editor)
            .env_remove("VISUAL");
        cmd
    }

    /// Write an executable `sh` script and return its path.
    fn script(&self, name: &str, body: &str) -> String {
        let path = self.dir.path().join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    fn assert_no_leftover(&self) {
        let left: Vec<_> = fs::read_dir(&self.scratch)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(left.is_empty(), "plaintext left in scratch dir: {left:?}");
    }

    fn assert_value(&self, expected: &str) {
        murk(&self.dir, &self.key)
            .args(["get", "SECRET", "--vault", "test.murk"])
            .assert()
            .success()
            .stdout(predicate::str::diff(format!("{expected}\n")));
    }
}

#[test]
fn editor_that_cannot_start_leaves_no_plaintext() {
    let f = Fixture::new();
    let missing = f.dir.path().join("no-such-editor");
    f.edit(missing.to_str().unwrap()).assert().failure();
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

#[test]
fn editor_launch_failure_leaves_no_plaintext() {
    // No program can be found on PATH, so spawning the editor itself fails.
    let f = Fixture::new();
    let empty = f.dir.path().join("empty-bin");
    fs::create_dir(&empty).unwrap();
    f.edit("vi").env("PATH", &empty).assert().failure();
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

#[test]
fn editor_exiting_non_zero_leaves_no_plaintext() {
    let f = Fixture::new();
    f.edit("false")
        .assert()
        .failure()
        .stderr(predicate::str::contains("aborting"));
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

#[test]
fn failed_read_back_leaves_no_plaintext() {
    // Invalid UTF-8 makes reading the edited file back fail.
    let f = Fixture::new();
    let editor = f.script("bad-utf8.sh", r#"printf '\377\376' > "$1""#);
    f.edit(&editor)
        .assert()
        .failure()
        .stderr(predicate::str::contains("reading"));
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

#[test]
fn editor_with_arguments_runs_through_the_shell() {
    let f = Fixture::new();
    let editor = f.script(
        "with-args.sh",
        r#"[ "$1" = "--wait" ] || exit 3
echo new-value > "$2""#,
    );
    f.edit(&format!("{editor} --wait"))
        .assert()
        .success()
        .stderr(predicate::str::contains("updated SECRET"));
    f.assert_no_leftover();
    f.assert_value("new-value");
}

#[test]
fn editor_does_not_inherit_the_key() {
    let f = Fixture::new();
    let seen = f.dir.path().join("editor-env");
    let editor = f.script("dump-env.sh", &format!("env > '{}'", seen.display()));

    // Key passed inline.
    f.edit(&editor).assert().success();
    let env = fs::read_to_string(&seen).unwrap();
    assert!(!env.contains(&f.key), "editor saw MURK_KEY's value");
    assert!(!env.contains("MURK_KEY"), "editor env: {env}");

    // Key passed by file.
    let key_file = f.dir.path().join("key");
    fs::write(&key_file, &f.key).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    f.edit(&editor)
        .env_remove("MURK_KEY")
        .env("MURK_KEY_FILE", &key_file)
        .assert()
        .success();
    let env = fs::read_to_string(&seen).unwrap();
    assert!(!env.contains("MURK_KEY_FILE"), "editor env: {env}");

    f.assert_no_leftover();
}

// ── signals ──

/// An editor that announces itself on `ready`, then waits.
fn waiting_editor(f: &Fixture) -> (String, PathBuf) {
    let ready = f.dir.path().join("ready");
    let editor = f.script(
        "wait.sh",
        &format!(
            "touch '{ready}.tmp' && mv '{ready}.tmp' '{ready}'\nexec sleep 30",
            ready = ready.display()
        ),
    );
    (editor, ready)
}

/// A wrapper that runs the real "editor" as its own child and waits for it.
/// The child saves the file again a second after it starts, and also
/// half a second after a SIGTERM: a descendant that outlives the wrapper
/// must not be able to put the plaintext back after murk's wipe.
fn wrapped_editor(f: &Fixture) -> (String, PathBuf) {
    let ready = f.dir.path().join("ready");
    let child = f.script(
        "child.sh",
        &format!(
            r#"trap 'sleep 0.5; printf leaked > "$1"; exit 0' TERM
touch '{ready}.tmp' && mv '{ready}.tmp' '{ready}'
sleep 1 & wait
printf leaked > "$1""#,
            ready = ready.display()
        ),
    );
    let wrapper = f.script("wrapper.sh", &format!(r#"'{child}' "$1""#));
    (wrapper, ready)
}

/// Start `murk edit` in a process group of its own and return once the
/// editor has written `ready`.
fn spawn_edit(f: &Fixture, (editor, ready): (String, PathBuf)) -> Child {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("murk"));
    for var in MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .args(["edit", "SECRET", "--vault", "test.murk"])
        .current_dir(f.dir.path())
        .env("HOME", f.dir.path())
        .env("XDG_RUNTIME_DIR", &f.scratch)
        .env("TMPDIR", &f.scratch)
        .env("MURK_KEY", &f.key)
        .env("EDITOR", &editor)
        .env_remove("VISUAL")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("murk exited before the editor started: {status:?}");
        }
        assert!(Instant::now() < deadline, "editor never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn kill(target: &str, sig: &str) {
    let ok = std::process::Command::new("kill")
        .args([&format!("-{sig}"), "--", target])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill -{sig} {target} failed");
}

/// Wait for murk to exit.
fn wait_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("murk did not exit after the signal");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kill whatever is left of murk's process group.
fn reap(child: &Child) {
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stderr(Stdio::null())
        .status();
}

fn wait_and_reap(mut child: Child) -> ExitStatus {
    let status = wait_exit(&mut child);
    reap(&child);
    status
}

/// Ctrl-C / Ctrl-\ at the terminal: the whole foreground group gets it.
#[test]
fn interrupt_to_process_group_leaves_no_plaintext() {
    for sig in ["INT", "QUIT"] {
        let f = Fixture::new();
        let child = spawn_edit(&f, waiting_editor(&f));
        kill(&format!("-{}", child.id()), sig);
        let status = wait_and_reap(child);
        assert!(!status.success(), "{sig}: {status:?}");
        f.assert_no_leftover();
        f.assert_value(VALUE);
    }
}

#[test]
fn terminate_to_process_group_leaves_no_plaintext() {
    let f = Fixture::new();
    let child = spawn_edit(&f, waiting_editor(&f));
    kill(&format!("-{}", child.id()), "TERM");
    let status = wait_and_reap(child);
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

/// `kill <murk pid>`: only murk gets the signal; it must reach the editor so
/// murk can clean up and exit instead of dying with the file in place.
#[test]
fn terminate_to_murk_alone_leaves_no_plaintext() {
    let f = Fixture::new();
    let child = spawn_edit(&f, waiting_editor(&f));
    kill(&child.id().to_string(), "TERM");
    let status = wait_and_reap(child);
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
    f.assert_no_leftover();
    f.assert_value(VALUE);
}

/// The editor's whole process tree is gone before murk wipes the file, so a
/// descendant cannot save it again afterwards: checked after a grace period
/// longer than any of the child's delayed saves.
#[test]
fn signal_waits_for_the_whole_editor_tree() {
    for to_group in [false, true] {
        let f = Fixture::new();
        let mut child = spawn_edit(&f, wrapped_editor(&f));
        let target = if to_group {
            format!("-{}", child.id())
        } else {
            child.id().to_string()
        };
        kill(&target, "TERM");
        let status = wait_exit(&mut child);
        // Leave any surviving descendant alone until the grace period is up:
        // reaping it first would hide the late save this test is about.
        std::thread::sleep(Duration::from_millis(2500));
        let left: Vec<_> = fs::read_dir(&f.scratch).unwrap().collect();
        reap(&child);
        assert_eq!(
            status.signal(),
            Some(SIGTERM),
            "group {to_group}: {status:?}"
        );
        assert!(
            left.is_empty(),
            "group {to_group}: plaintext came back: {left:?}"
        );
        f.assert_value(VALUE);
    }
}
