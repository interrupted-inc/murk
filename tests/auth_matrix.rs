// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enforce the role × command authorization matrix in `auth_matrix/table.rs`.
//!
//! One fixture vault holds every role (see the table module docs). Each cell
//! copies it into a scratch directory with its own `HOME`, runs the command as
//! the role, and checks:
//!
//! - the exit status matches the expected verdict;
//! - no output carries a fixture value the role may not read;
//! - a refusal leaves the guarded vault file byte-for-byte unchanged;
//! - an allowed read leaves it unchanged, and shows the value the role sees;
//! - an allowed write changes it, and changes the vault's values only as the
//!   row allows: nobody gains access to a value, nobody loses it, plaintexts
//!   stay put, and new keys reach exactly their audience. Values are compared
//!   one by one (shared, group, personal) by decrypting every ciphertext with
//!   every fixture key straight through age.
//!
//! All cells run, then the test fails with the full list of broken cells.
//! Rows that drive `$EDITOR` run on Unix only (see
//! [`table::EDITOR_UNIX_ONLY`]); every other row runs on every platform.

mod common;
#[path = "auth_matrix/table.rs"]
mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::cast::{self, Tier, Who};
use common::{init_vault, murk_bin};
use table::{Audience, Basis, Check, ROWS, Role, Row, Verdict};
use tempfile::TempDir;

// Fixture values. Every one is unique, so a leak check is a substring search.
const SHARED: &str = "val-shared-cur";
const SHARED_OLD: &str = "val-shared-old";
const OVERRIDE: &str = "val-o-override";
const PRIV: &str = "val-o-private";
const OPS: &str = "val-ops-cur";
const OPS_OLD: &str = "val-ops-old";
const AGENT_OK: &str = "val-agent-ok";
const THEIRS: &str = "val-theirs";

const ALL_VALUES: &[&str] = &[
    SHARED, SHARED_OLD, OVERRIDE, PRIV, OPS, OPS_OLD, AGENT_OK, THEIRS,
];

/// The fixture values a role may see in any output.
fn readable(role: Role) -> &'static [&'static str] {
    match role {
        Role::Owner | Role::GroupMember => &[SHARED, SHARED_OLD, OPS, OPS_OLD, AGENT_OK, THEIRS],
        Role::Member | Role::NonMember => &[SHARED, SHARED_OLD, AGENT_OK, THEIRS],
        Role::OverrideOwner => &[SHARED, SHARED_OLD, OVERRIDE, PRIV, AGENT_OK, THEIRS],
        Role::Grant | Role::GrantAgent => &[AGENT_OK],
        Role::GrantExpired | Role::Revoked | Role::Outsider => &[],
    }
}

/// The value of `key` that `get` returns for a role.
fn visible(role: Role, key: &str) -> &'static str {
    match (role, key) {
        (Role::OverrideOwner, "SHARED") => OVERRIDE,
        (_, "SHARED") => SHARED,
        (_, "OPS") => OPS,
        (_, "PRIV") => PRIV,
        (_, "AGENT_OK") => AGENT_OK,
        _ => panic!("no fixture value for {key}"),
    }
}

struct Fixture {
    _dir: TempDir,
    repo: PathBuf,
    /// Grant key files, copied into each cell's HOME.
    grant_key: PathBuf,
    expired_key: PathBuf,
    ids: BTreeMap<&'static str, Who>,
}

fn git(repo: &Path, home: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=matrix",
            "-c",
            "user.email=matrix@example.com",
        ])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Fixture {
    fn build() -> Self {
        let dir = TempDir::new().unwrap();
        let repo = dir.path().join("repo");
        let home = dir.path().join("home");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();

        // `init_vault` roots HOME at the repo; drop what it leaves there so the
        // cells find no stored key and no `.env`.
        let (owner_secret, _) = init_vault(&repo);
        fs::remove_dir_all(repo.join(".config")).unwrap();
        fs::remove_file(repo.join(".env")).unwrap();

        let mut ids = BTreeMap::new();
        ids.insert("owner", Who::from_secret("owner", &owner_secret));
        for label in [
            "member",
            "gmember",
            "nonmember",
            "override",
            "spare",
            "revoked",
            "outsider",
            "x",
        ] {
            ids.insert(label, Who::generate(label));
        }

        let run = |who: &str, args: &[&str], stdin: &str| {
            let out = murk_bin(&home)
                .current_dir(&repo)
                .env("MURK_KEY", &ids[who].secret)
                .env("MURK_VAULT", "test.murk")
                .args(args)
                .write_stdin(stdin)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "fixture: {who} murk {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };

        // Display names match the labels, so rows can name recipients.
        for label in [
            "member",
            "gmember",
            "nonmember",
            "override",
            "spare",
            "revoked",
        ] {
            run(
                "owner",
                &["circle", "authorize", &ids[label].pubkey, "--name", label],
                "",
            );
        }
        run("owner", &["group", "create", "ops"], "");
        run("owner", &["group", "add", "ops", "--member", "gmember"], "");
        run("owner", &["group", "add", "ops", "--member", "spare"], "");
        run("owner", &["group", "create", "idle"], "");
        run(
            "owner",
            &["group", "add", "idle", "--member", "gmember"],
            "",
        );
        run("owner", &["add", "SHARED"], &format!("{SHARED_OLD}\n"));
        run("owner", &["add", "AGENT_OK"], &format!("{AGENT_OK}\n"));
        run(
            "owner",
            &["add", "OPS", "--group", "ops"],
            &format!("{OPS_OLD}\n"),
        );
        run(
            "override",
            &["add", "SHARED", "--group", "me"],
            &format!("{OVERRIDE}\n"),
        );
        run(
            "override",
            &["add", "PRIV", "--group", "me"],
            &format!("{PRIV}\n"),
        );
        for key in ["SHARED", "OPS", "PRIV", "AGENT_OK"] {
            run(
                "owner",
                &["describe", key, "fixture", "--tag", "agents"],
                "",
            );
        }
        run("owner", &["policy", "set", "--allow-tag", "agents"], "");

        let grant_key = home.join("bot.key");
        let expired_key = home.join("old.key");
        let grant_path = grant_key.to_str().unwrap();
        let expired_path = expired_key.to_str().unwrap();
        run(
            "owner",
            &[
                "agent", "grant", "--name", "bot", "--only", "AGENT_OK", "--ttl", "7d", "--out",
                grant_path,
            ],
            "",
        );
        // A vault write after a grant's TTL drops the grant, so the TTL must
        // outlast the fixture's remaining writes; checked below.
        run(
            "owner",
            &[
                "agent",
                "grant",
                "--name",
                "old",
                "--only",
                "AGENT_OK",
                "--ttl",
                "5s",
                "--out",
                expired_path,
            ],
            "",
        );
        let expired_at = Instant::now() + Duration::from_millis(5100);
        run("owner", &["circle", "revoke", "revoked"], "");

        // Commit, then change the shared and group values so `diff` has
        // something to show.
        git(&repo, &home, &["init", "-q"]);
        git(&repo, &home, &["add", "-A"]);
        git(&repo, &home, &["commit", "-q", "-m", "fixture"]);
        let base = fs::read(repo.join("test.murk")).unwrap();
        run(
            "owner",
            &["add", "SHARED", "--group", "everyone"],
            &format!("{SHARED}\n"),
        );
        run(
            "owner",
            &["add", "OPS", "--group", "ops"],
            &format!("{OPS}\n"),
        );

        // Merge-driver inputs: base is the commit, ours the working vault,
        // theirs the commit plus a new key.
        let merge = repo.join(".merge");
        fs::create_dir_all(&merge).unwrap();
        fs::write(merge.join("base.murk"), &base).unwrap();
        fs::write(merge.join("theirs.murk"), &base).unwrap();
        fs::copy(repo.join("test.murk"), merge.join("ours.murk")).unwrap();
        run(
            "owner",
            &["add", "THEIRS", "--vault", ".merge/theirs.murk"],
            &format!("{THEIRS}\n"),
        );

        let read = |path: &Path| fs::read_to_string(path).unwrap();
        ids.insert("grant", Who::from_secret("grant", &read(&grant_key)));
        ids.insert("expired", Who::from_secret("expired", &read(&expired_key)));
        assert!(
            Instant::now() < expired_at,
            "the fixture took longer than the expiring grant's TTL, so a later write may have dropped it"
        );
        for vault in ["test.murk", ".merge/ours.murk", ".merge/theirs.murk"] {
            assert!(
                read(&repo.join(vault)).contains(&ids["expired"].pubkey),
                "the expiring grant is missing from {vault}"
            );
        }
        if let Some(wait) = expired_at.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }

        Fixture {
            _dir: dir,
            repo,
            grant_key,
            expired_key,
            ids,
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// Labels of the fixture keys that are agent grants.
const GRANT_LABELS: &[&str] = &["grant", "expired", "newgrant"];

/// The command that prints the environment, for `{PRINTENV}` in a row.
#[cfg(unix)]
const PRINTENV: &[&str] = &["env"];
#[cfg(windows)]
const PRINTENV: &[&str] = &["cmd", "/C", "set"];

fn matches(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

/// Run one cell. `Ok` when it behaves as the table says; `Err` explains how
/// it didn't. The observed verdict is returned either way.
fn run_cell(fx: &Fixture, row: &Row, role: Role) -> (Verdict, Result<(), String>) {
    let cell = TempDir::new().unwrap();
    let repo = cell.path().join("repo");
    let home = cell.path().join("home");
    copy_dir(&fx.repo, &repo);
    fs::create_dir_all(&home).unwrap();
    for (name, contents) in row.files {
        fs::write(repo.join(name), contents).unwrap();
    }

    let guard = repo.join(row.guard);
    let before = fs::read(&guard).unwrap();

    let mut cmd = murk_bin(&home);
    cmd.current_dir(&repo).env("MURK_VAULT", "test.murk");
    match role {
        Role::Grant | Role::GrantAgent | Role::GrantExpired => {
            let src = if role == Role::GrantExpired {
                &fx.expired_key
            } else {
                &fx.grant_key
            };
            let key = home.join("grant.key");
            fs::copy(src, &key).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            cmd.env("MURK_KEY_FILE", &key);
            if role == Role::GrantAgent {
                cmd.env("MURK_AGENT", "1");
            }
        }
        _ => {
            cmd.env("MURK_KEY", &fx.ids[label(role)].secret);
        }
    }
    #[cfg(unix)]
    if row.editor {
        let script = cell.path().join("editor.sh");
        fs::write(&script, "#!/bin/sh\necho val-edited > \"$1\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        cmd.env("EDITOR", &script).env_remove("VISUAL");
    }
    let args: Vec<String> = row
        .args
        .iter()
        .flat_map(|a| match *a {
            "{PRINTENV}" => PRINTENV.iter().map(|s| s.to_string()).collect(),
            _ => vec![a.replace("{X}", &fx.ids["x"].pubkey)],
        })
        .collect();
    let out = cmd
        .args(&args)
        .write_stdin(row.stdin)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A conflict is only a verdict for rows that expect one (the merge driver):
    // anywhere else a non-zero exit is a refusal.
    let conflict_row = row.cells.iter().any(|c| c.verdict == Verdict::Conflict);
    let observed = if out.status.success() {
        Verdict::Allow
    } else if conflict_row && stderr.contains("conflict") {
        Verdict::Conflict
    } else {
        Verdict::Refuse
    };
    let expected = row.cells[role.index()].verdict;
    let after = fs::read(&guard).unwrap_or_default();
    let changed = after != before;
    // The line that says why: the first error line, else the last line.
    let reason = |s: &str| {
        s.lines()
            .find(|l| l.contains("error"))
            .or_else(|| s.lines().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let result = (|| {
        let allowed = readable(role);
        let leaked: Vec<&str> = ALL_VALUES
            .iter()
            .copied()
            .filter(|v| !allowed.contains(v) && (stdout.contains(v) || stderr.contains(v)))
            .collect();
        if !leaked.is_empty() {
            return Err(format!("output leaks {leaked:?}"));
        }
        if observed != expected {
            return Err(match observed {
                Verdict::Allow => format!(
                    "allowed (exit 0{})",
                    if changed { ", vault changed" } else { "" }
                ),
                Verdict::Refuse => format!("refused: {}", reason(&stderr)),
                Verdict::Conflict => format!("conflict: {}", reason(&stderr)),
            });
        }
        match observed {
            Verdict::Refuse if changed => return Err("refused but changed the vault".into()),
            // Git keeps whatever a conflicting driver wrote as the conflicted
            // result, and commits nothing, so the scratch copy may change.
            Verdict::Refuse | Verdict::Conflict => return Ok(()),
            Verdict::Allow => {}
        }
        match row.check {
            Check::Read { reveals } => {
                if changed {
                    return Err("a read changed the vault".into());
                }
                if let Some(key) = reveals {
                    let want = visible(role, key);
                    if !stdout.contains(want) {
                        return Err(format!("output lacks {want}"));
                    }
                }
                Ok(())
            }
            Check::Write {
                touches,
                gains,
                losses,
                creates,
            } => {
                if !changed {
                    return Err("allowed but wrote nothing".into());
                }
                // The result must still load: a write that leaves a vault
                // failing its integrity check is not an allowed write. Load as
                // the owner, or the group member when the row removes the owner.
                let loader = if losses.contains(&("*", "owner")) {
                    "gmember"
                } else {
                    "owner"
                };
                let load = murk_bin(&home)
                    .current_dir(&repo)
                    .env("MURK_KEY", &fx.ids[loader].secret)
                    .args(["export", "--vault", row.guard])
                    .output()
                    .unwrap();
                if !load.status.success() {
                    return Err(format!(
                        "{loader} can't load the result: {}",
                        reason(&String::from_utf8_lossy(&load.stderr))
                    ));
                }
                let mut ids: Vec<Who> = fx.ids.values().cloned().collect();
                for path in [repo.join("newgrant.key")]
                    .into_iter()
                    .chain(agent_key_files(&home, "-newgrant"))
                {
                    if path.exists() {
                        ids.push(Who::from_secret(
                            "newgrant",
                            &fs::read_to_string(&path).unwrap(),
                        ));
                    }
                }
                let pre_vault = cell.path().join("pre.murk");
                fs::write(&pre_vault, &before).unwrap();
                let problems = value_problems(
                    &cast::cells(&pre_vault, &ids),
                    &cast::cells(&guard, &ids),
                    &ids,
                    label(role),
                    Expect {
                        touches,
                        gains,
                        losses,
                        creates,
                    },
                );
                if problems.is_empty() {
                    Ok(())
                } else {
                    Err(problems.join("; "))
                }
            }
        }
    })();
    (observed, result)
}

/// What a row allows a write to do to the vault's values.
struct Expect {
    touches: &'static [&'static str],
    gains: &'static [(&'static str, &'static str)],
    losses: &'static [(&'static str, &'static str)],
    creates: &'static [(&'static str, Audience)],
}

/// Compare every value before and after a write (see [`Check::Write`]).
/// `caller` is the label of the identity that ran the command.
fn value_problems(
    pre: &cast::Cells,
    post: &cast::Cells,
    ids: &[Who],
    caller: &str,
    expect: Expect,
) -> Vec<String> {
    let label_of: BTreeMap<&str, &str> = ids
        .iter()
        .map(|w| (w.pubkey.as_str(), w.label.as_str()))
        .collect();
    let is_grant = |pk: &str| label_of.get(pk).is_some_and(|l| GRANT_LABELS.contains(l));
    // A personal value that belongs to a recipient other than the caller.
    let others_private = |tier: &Tier| match tier {
        Tier::Private(pk) => !is_grant(pk) && label_of.get(pk.as_str()) != Some(&caller),
        _ => false,
    };
    let describe = |key: &str, tier: &Tier| match tier {
        Tier::Shared => format!("{key} (shared)"),
        Tier::Group(g) => format!("{key} (group {g})"),
        Tier::Private(pk) => format!(
            "{key} (personal value of {})",
            label_of.get(pk.as_str()).unwrap_or(&"an unknown key")
        ),
    };
    let gained = |key: &str, who: &str| {
        expect
            .gains
            .iter()
            .any(|(k, w)| matches(k, key) && matches(w, who))
    };
    // A write may drop an expired grant: it can't read anything anyway.
    let lost_ok = |key: &str, who: &str| {
        who == "expired"
            || expect
                .losses
                .iter()
                .any(|(k, w)| matches(k, key) && matches(w, who))
    };
    // Who could read a key's value before: its shared and group values, and
    // grants' copies of them (a recipient's own override is their own value).
    let readers_of = |cells: &cast::Cells, key: &str| -> BTreeSet<String> {
        cells
            .iter()
            .filter(|((k, tier), _)| {
                k == key && !matches!(tier, Tier::Private(pk) if !is_grant(pk))
            })
            .flat_map(|(_, by)| by.keys().cloned())
            .collect()
    };
    let pre_keys: BTreeSet<&str> = pre.keys().map(|(k, _)| k.as_str()).collect();
    let post_keys: BTreeSet<&str> = post.keys().map(|(k, _)| k.as_str()).collect();
    let mut problems = Vec::new();

    // Nobody gains access, and personal values appear only for the caller.
    for ((key, tier), by) in post {
        if !pre_keys.contains(key.as_str()) {
            continue;
        }
        let before: BTreeSet<String> = match pre.get(&(key.clone(), tier.clone())) {
            Some(was) => was.keys().cloned().collect(),
            None if others_private(tier) => {
                problems.push(format!("{} appeared", describe(key, tier)));
                continue;
            }
            None if matches!(tier, Tier::Private(pk) if !is_grant(pk)) => continue,
            None => readers_of(pre, key),
        };
        for who in by.keys().filter(|w| !before.contains(*w)) {
            if !gained(key, who) {
                problems.push(format!("{who} can now read {}", describe(key, tier)));
            }
        }
    }

    // Every value keeps its readers and plaintext unless the command names
    // its key; other recipients' personal values are kept even then.
    for ((key, tier), was) in pre {
        if expect.touches.contains(&key.as_str()) && !others_private(tier) {
            continue;
        }
        let now = post.get(&(key.clone(), tier.clone()));
        for (who, value) in was {
            match now.and_then(|m| m.get(who)) {
                None if !lost_ok(key, who) => {
                    problems.push(format!("{who} lost {}", describe(key, tier)));
                }
                Some(v) if v != value => {
                    problems.push(format!("{} changed for {who}", describe(key, tier)));
                }
                _ => {}
            }
        }
    }

    // New keys: only the listed ones, each encrypted to exactly its audience.
    for key in post_keys.difference(&pre_keys) {
        let Some((_, audience)) = expect.creates.iter().find(|(k, _)| k == key) else {
            problems.push(format!("unexpected new key {key}"));
            continue;
        };
        let cells: Vec<(&Tier, BTreeSet<String>)> = post
            .iter()
            .filter(|((k, _), _)| k == key)
            .map(|((_, tier), by)| (tier, by.keys().cloned().collect()))
            .collect();
        // The audience's readers, taken from an existing value of that tier.
        let audience_readers = |want: &dyn Fn(&Tier) -> bool| -> BTreeSet<String> {
            pre.iter()
                .filter(|((_, tier), _)| want(tier))
                .flat_map(|(_, by)| by.keys().cloned())
                .collect()
        };
        let ok = match (audience, cells.as_slice()) {
            (Audience::Everyone, [(Tier::Shared, by)]) => {
                *by == audience_readers(&|t| matches!(t, Tier::Shared))
            }
            (Audience::Group(g), [(Tier::Group(name), by)]) if name == g => {
                *by == audience_readers(&|t| matches!(t, Tier::Group(n) if n == g))
            }
            (Audience::Me, [(Tier::Private(pk), by)]) => {
                label_of.get(pk.as_str()) == Some(&caller)
                    && by.iter().map(String::as_str).eq([caller])
            }
            _ => false,
        };
        if !ok {
            let got: Vec<String> = cells
                .iter()
                .map(|(tier, by)| format!("{} read by {by:?}", describe(key, tier)))
                .collect();
            problems.push(format!(
                "{key} should be {audience:?}, got {}",
                got.join(", ")
            ));
        }
    }
    for (key, _) in expect.creates {
        if !post_keys.contains(key) {
            problems.push(format!("{key} was not created"));
        }
    }
    problems
}

/// The fixture label of a role's identity.
fn label(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Member => "member",
        Role::GroupMember => "gmember",
        Role::NonMember => "nonmember",
        Role::OverrideOwner => "override",
        Role::Grant | Role::GrantAgent => "grant",
        Role::GrantExpired => "expired",
        Role::Revoked => "revoked",
        Role::Outsider => "outsider",
    }
}

/// Agent key files `murk agent connect` wrote under `home`.
fn agent_key_files(home: &Path, suffix: &str) -> Vec<PathBuf> {
    let dir = home.join(".config/murk/agent-keys");
    fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().ends_with(suffix))
                .collect()
        })
        .unwrap_or_default()
}

fn mark(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "yes",
        Verdict::Refuse => "no",
        Verdict::Conflict => "conflict",
    }
}

#[test]
fn every_role_gets_exactly_the_access_the_matrix_grants() {
    let fx = Fixture::build();
    // Rows that drive `$EDITOR` run on Unix only (see `EDITOR_UNIX_ONLY`).
    let runs = |row: &Row| cfg!(unix) || !row.editor;
    let cells: Vec<(usize, Role)> = (0..ROWS.len())
        .filter(|r| runs(&ROWS[*r]))
        .flat_map(|r| Role::ALL.iter().map(move |role| (r, *role)))
        .collect();
    let results = Mutex::new(BTreeMap::new());
    let next = Mutex::new(cells.into_iter());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let Some((r, role)) = next.lock().unwrap().next() else {
                        break;
                    };
                    let outcome = run_cell(&fx, &ROWS[r], role);
                    results.lock().unwrap().insert((r, role.index()), outcome);
                }
            });
        }
    });
    let results = results.into_inner().unwrap();

    // The observed matrix, failing cells marked `!`, for the test log.
    let mut report = String::from("observed (! = differs from the table):\n");
    let mut failures = Vec::new();
    for (r, row) in ROWS.iter().enumerate().filter(|(_, row)| runs(row)) {
        let mut line = format!("{:<50}", row.command);
        for role in Role::ALL {
            let (observed, result) = &results[&(r, role.index())];
            let flag = if result.is_ok() { " " } else { "!" };
            line.push_str(&format!(" {:>8}{flag}", mark(*observed)));
            if let Err(why) = result {
                let cell = row.cells[role.index()];
                let expected = match cell.basis {
                    Basis::UnderReview => {
                        format!("{} (current behaviour, under review)", mark(cell.verdict))
                    }
                    _ => mark(cell.verdict).to_string(),
                };
                failures.push(format!(
                    "{} as {}: expected {expected}, {why}",
                    row.command,
                    role.heading(),
                ));
            }
        }
        report.push_str(&line);
        report.push('\n');
    }
    eprintln!("{report}");
    assert!(
        failures.is_empty(),
        "{} of {} cells broke the matrix:\n{}",
        failures.len(),
        results.len(),
        failures.join("\n")
    );
}
