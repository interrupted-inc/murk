//! Git integration helpers (merge driver setup).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// The `.gitattributes` line that enables the merge driver.
const GITATTRIBUTES_LINE: &str = "*.murk merge=murk";

/// Git config keys for the merge driver.
const GIT_CONFIG_MERGE_NAME: &str = "merge.murk.name";
const GIT_CONFIG_MERGE_DRIVER: &str = "merge.murk.driver";

/// A step completed during merge driver setup.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeDriverSetupStep {
    /// `.gitattributes` already contained the merge driver entry.
    GitattributesAlreadyExists,
    /// Appended the merge driver entry to an existing `.gitattributes`.
    GitattributesAppended,
    /// Created a new `.gitattributes` file with the merge driver entry.
    GitattributesCreated,
    /// Configured `git config merge.murk.*`.
    GitConfigured,
}

/// Configure git to use murk's custom merge driver for `.murk` files.
///
/// 1. Ensures `.gitattributes` contains `*.murk merge=murk`.
/// 2. Runs `git config merge.murk.name` and `git config merge.murk.driver`.
///
/// Returns the steps that were performed.
pub fn setup_merge_driver() -> Result<Vec<MergeDriverSetupStep>, String> {
    let mut steps = Vec::new();

    // 1. Write .gitattributes entry.
    let gitattributes = Path::new(".gitattributes");
    let merge_line = GITATTRIBUTES_LINE;

    crate::env::reject_symlink(gitattributes, ".gitattributes")?;

    if gitattributes.exists() {
        let contents = fs::read_to_string(gitattributes)
            .map_err(|e| format!("reading .gitattributes: {e}"))?;
        if contents.contains(merge_line) {
            steps.push(MergeDriverSetupStep::GitattributesAlreadyExists);
        } else {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(gitattributes)
                .map_err(|e| format!("writing .gitattributes: {e}"))?;
            writeln!(file, "{merge_line}").map_err(|e| format!("writing .gitattributes: {e}"))?;
            steps.push(MergeDriverSetupStep::GitattributesAppended);
        }
    } else {
        fs::write(gitattributes, format!("{merge_line}\n"))
            .map_err(|e| format!("writing .gitattributes: {e}"))?;
        steps.push(MergeDriverSetupStep::GitattributesCreated);
    }

    // 2. Configure git merge driver.
    let configs = [
        (GIT_CONFIG_MERGE_NAME, "murk vault merge"),
        (GIT_CONFIG_MERGE_DRIVER, "murk merge-driver %O %A %B"),
    ];
    for (key, value) in &configs {
        let status = Command::new("git")
            .args(["config", key, value])
            .status()
            .map_err(|e| format!("running git config: {e}"))?;
        if !status.success() {
            return Err(format!("git config {key} failed (are you in a git repo?)"));
        }
    }
    steps.push(MergeDriverSetupStep::GitConfigured);

    Ok(steps)
}

/// Signature status of the most recent commit that modified `path`.
///
/// The vault signature authenticates *content*; a signed commit authenticates
/// *who landed it* — together they anchor integrity in git (see `THREAT_MODEL`).
/// `murk verify` surfaces this so a team can confirm the vault's history is
/// signed, not just its bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitSignature {
    /// A good, verified signature.
    Good,
    /// A signature is present but git could not validate it (unknown/expired key).
    Unverified,
    /// A bad signature — the commit was altered or the signature doesn't match.
    Bad,
    /// The commit carries no signature.
    Unsigned,
}

/// Return the signature status of the last commit touching `path`, or `None`
/// when git is unavailable, the repo has no such commit, or the path is
/// untracked — i.e. there is no git anchor to check.
pub fn last_commit_signature(path: &str) -> Option<CommitSignature> {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%G?", "--", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    match String::from_utf8(output.stdout).ok()?.trim() {
        "G" => Some(CommitSignature::Good),
        // U (good, unknown validity), X (expired), Y (expired key), E (cannot
        // check) all mean "a signature exists but we can't fully vouch for it".
        "U" | "X" | "Y" | "E" => Some(CommitSignature::Unverified),
        "B" | "R" => Some(CommitSignature::Bad),
        "N" => Some(CommitSignature::Unsigned),
        // Empty: no commit for this path (untracked / no history) — no anchor.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::CWD_LOCK;

    #[test]
    fn setup_merge_driver_creates_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_setup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Init a git repo so git config works.
        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesCreated));
        assert!(steps.contains(&MergeDriverSetupStep::GitConfigured));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_appends_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.txt text\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAppended));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.txt text"));
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_already_exists() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_exists");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.murk merge=murk\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap();
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAlreadyExists));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn last_commit_signature_unsigned_commit() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(dir.join("vault.murk"), "data\n").unwrap();
        Command::new("git")
            .args(["add", "vault.murk"])
            .current_dir(dir)
            .output()
            .unwrap();
        // Explicit identity + gpgsign=false so the commit lands unsigned
        // regardless of the runner's global git config.
        Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "add vault",
            ])
            .current_dir(dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("vault.murk");
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, Some(CommitSignature::Unsigned));
    }

    #[test]
    fn last_commit_signature_untracked_path_is_none() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        // A commit exists, but for a *different* file — so `git log` succeeds
        // with empty output for the queried path: the "no anchor" branch.
        std::fs::write(dir.join("other.txt"), "x\n").unwrap();
        Command::new("git")
            .args(["add", "other.txt"])
            .current_dir(dir)
            .output()
            .unwrap();
        let commit = Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "seed",
            ])
            .current_dir(dir)
            .output()
            .unwrap();
        // If the seed commit fails, `git log` would error (not return empty) and
        // the None below would come from the wrong branch — assert it landed.
        assert!(
            commit.status.success(),
            "seed commit must succeed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("never-committed.murk");
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, None);
    }

    #[test]
    fn setup_merge_driver_outside_repo_errors() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // No `git init`: `git config` has no repo to write to and must fail,
        // surfacing the "are you in a git repo?" guidance rather than silently
        // claiming the merge driver was configured.
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = setup_merge_driver();
        std::env::set_current_dir(original_dir).unwrap();

        let err = result.unwrap_err();
        assert!(
            err.contains("git config") && err.contains("failed"),
            "expected git-config failure guidance, got: {err}"
        );
    }
}
