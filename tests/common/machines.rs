// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Several machines sharing one git remote, for tests where each person's
//! trust pin lives in their own `HOME`.
//!
//! A [`Machine`] is a clone of a bare `origin.git` plus a `HOME` of its own,
//! run as one person (their key file is passed as `MURK_KEY_FILE`). git runs
//! with the same `HOME` and key, and with the built `murk` first on `PATH`, so
//! the `.murk` merge driver git starts acts as that person on that machine.

// Each integration binary compiles this module; most use only part of it.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;

/// One clone and its `HOME`, acting as the person whose key is `key_file`.
#[derive(Clone, Debug)]
pub struct Machine {
    pub name: String,
    pub dir: PathBuf,
    pub home: PathBuf,
    pub key_file: PathBuf,
}

impl Machine {
    /// Clone `origin` into `root/<name>` with a `HOME` at `root/<name>-home`.
    pub fn clone(root: &Path, name: &str, key_file: &Path) -> Self {
        let machine = Self {
            name: name.to_string(),
            dir: root.join(name),
            home: root.join(format!("{name}-home")),
            key_file: key_file.to_path_buf(),
        };
        fs::create_dir_all(&machine.home).unwrap();
        let out = git_in(root, &machine.home, None)
            .args(["clone", "-q", "origin.git", name])
            .output()
            .unwrap();
        assert!(out.status.success(), "git clone: {out:?}");
        machine
    }

    /// `murk` run as this machine's person, in its clone.
    pub fn murk(&self) -> Command {
        let mut cmd = super::murk_bin(&self.home);
        cmd.current_dir(&self.dir)
            .env("MURK_KEY_FILE", &self.key_file);
        cmd
    }

    /// `git` run in the clone, as this machine's person.
    pub fn git(&self, args: &[&str]) -> Output {
        git_in(&self.dir, &self.home, Some(&self.key_file))
            .args(args)
            .output()
            .unwrap()
    }

    /// `git` that must succeed; returns its trimmed stdout.
    pub fn git_ok(&self, args: &[&str]) -> String {
        let out = self.git(args);
        assert!(
            out.status.success(),
            "{}: git {args:?}: {}",
            self.name,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Commit the vault if it changed. Returns whether a commit was made.
    pub fn commit(&self, message: &str) -> bool {
        self.git_ok(&["add", "-A", "."]);
        self.git(&["commit", "-q", "-m", message]).status.success()
    }

    /// The working vault's bytes (empty when there is none).
    pub fn vault(&self) -> Vec<u8> {
        fs::read(self.dir.join(".murk")).unwrap_or_default()
    }

    /// The vault at `rev` (empty when git has none there).
    pub fn vault_at(&self, rev: &str) -> Vec<u8> {
        let out = self.git(&["show", &format!("{rev}:.murk")]);
        if out.status.success() {
            out.stdout
        } else {
            Vec::new()
        }
    }

    /// Every commit this clone knows, newest first.
    pub fn revisions(&self) -> Vec<String> {
        self.git_ok(&["rev-list", "--all"])
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// Seconds since the epoch for the next git invocation's commit dates.
static CLOCK: AtomicU64 = AtomicU64::new(1_700_000_000);

/// A hermetic `git`: no system or user config, a fixed author, commits never
/// signed, and the built `murk` first on `PATH` for the merge driver. With a
/// key file, murk commands git starts run as that key. Every invocation gets a
/// later commit date than the one before, so `git rev-list` orders commits the
/// same way on every run, however fast the machine commits.
pub fn git_in(dir: &Path, home: &Path, key_file: Option<&Path>) -> std::process::Command {
    let murk = assert_cmd::cargo::cargo_bin("murk");
    let bin_dir = murk.parent().expect("murk binary has a directory");
    let path = std::env::join_paths(std::iter::once(bin_dir.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();
    let date = format!("@{} +0000", CLOCK.fetch_add(1, Ordering::Relaxed));
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(dir)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ]);
    for var in super::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    if let Some(key) = key_file {
        cmd.env("MURK_KEY_FILE", key);
    }
    cmd
}

/// Copy a directory tree (files and directories only).
pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}
