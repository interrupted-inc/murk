// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk skeleton -o` and `murk agent plan -o`: both are keyless, read-only
//! commands an agent may run unattended, so their output path must never
//! truncate or write through anything that already exists — least of all the
//! vault itself.

use std::fs;
use std::path::Path;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk, murk_bin};

/// The two commands that take `-o`, each as the args up to (not including) the
/// output path.
const OUTPUT_COMMANDS: &[&[&str]] = &[
    &["skeleton", "--vault", "test.murk", "-o"],
    &["agent", "plan", "--vault", "test.murk", "-o"],
];

/// Run `args` + `out` keylessly in `dir` — neither command needs a key.
fn run_to(dir: &Path, args: &[&str], out: &str) -> assert_cmd::assert::Assert {
    murk_bin(dir).current_dir(dir).args(args).arg(out).assert()
}

#[test]
fn output_to_the_vault_is_refused_and_vault_untouched() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let vault = dir.path().join("test.murk");
    let before = fs::read(&vault).unwrap();

    for args in OUTPUT_COMMANDS {
        run_to(dir.path(), args, "test.murk")
            .failure()
            .stderr(predicate::str::contains("test.murk"))
            .stderr(predicate::str::contains("it is the vault"));
        assert_eq!(
            fs::read(&vault).unwrap(),
            before,
            "{args:?} touched the vault"
        );
    }

    // The vault is still a working vault, not a skeleton.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success();
}

#[test]
fn output_to_an_existing_file_is_refused_and_file_untouched() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let existing = dir.path().join("existing.json");
    fs::write(&existing, "precious\n").unwrap();

    for args in OUTPUT_COMMANDS {
        run_to(dir.path(), args, "existing.json")
            .failure()
            .stderr(predicate::str::contains("existing.json"))
            .stderr(predicate::str::contains("already exists"));
        assert_eq!(
            fs::read_to_string(&existing).unwrap(),
            "precious\n",
            "{args:?} overwrote an existing file"
        );
    }
}

#[cfg(unix)]
#[test]
fn output_through_a_symlink_is_refused_and_target_untouched() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let target = dir.path().join("precious.txt");
    fs::write(&target, "precious\n").unwrap();
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();

    for args in OUTPUT_COMMANDS {
        run_to(dir.path(), args, "link.json")
            .failure()
            .stderr(predicate::str::contains("link.json"));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "precious\n",
            "{args:?} wrote through a symlink"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[cfg(unix)]
#[test]
fn output_through_a_symlink_to_the_vault_is_refused() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let vault = dir.path().join("test.murk");
    let before = fs::read(&vault).unwrap();
    symlink(&vault, dir.path().join("alias.json")).unwrap();

    for args in OUTPUT_COMMANDS {
        run_to(dir.path(), args, "alias.json")
            .failure()
            .stderr(predicate::str::contains("it is the vault"));
        assert_eq!(
            fs::read(&vault).unwrap(),
            before,
            "{args:?} touched the vault"
        );
    }
}

#[cfg(unix)]
#[test]
fn output_through_a_dangling_symlink_is_refused_and_creates_nothing() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    init_vault(&dir);
    let missing = dir.path().join("missing.txt");
    symlink(&missing, dir.path().join("dangling.json")).unwrap();

    for args in OUTPUT_COMMANDS {
        run_to(dir.path(), args, "dangling.json")
            .failure()
            .stderr(predicate::str::contains("dangling.json"));
        assert!(!missing.exists(), "{args:?} created the symlink target");
    }
}

#[test]
fn output_to_a_new_path_still_writes() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    run_to(dir.path(), OUTPUT_COMMANDS[0], "skeleton.json")
        .success()
        .stderr(predicate::str::contains("wrote skeleton to"));
    let skeleton: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("skeleton.json")).unwrap())
            .unwrap();
    assert!(skeleton["recipients"].as_array().unwrap().is_empty());

    murk_bin(dir.path())
        .current_dir(dir.path())
        .args([
            "agent",
            "plan",
            "--json",
            "--vault",
            "test.murk",
            "-o",
            "plan.json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote agent plan to"));
    let plan: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("plan.json")).unwrap()).unwrap();
    assert!(plan["entries"].is_array());
}
