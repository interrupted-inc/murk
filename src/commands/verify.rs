use super::*;
use colored::Colorize;
use murk_cli::types;
use std::path::Path;

/// Human label for a signer pubkey: its recipient display name, or a truncated
/// key. Tolerates ssh-ed25519 comment mismatches — the name map may be keyed by
/// `ssh-ed25519 <blob> comment` while the signer is the comment-stripped form.
pub(crate) fn signer_display_name(murk: &types::Murk, signer: &str) -> String {
    if let Some(name) = murk.recipients.get(signer) {
        return name.clone();
    }
    if signer.starts_with("ssh-ed25519 ")
        && let Some((_, name)) = murk
            .recipients
            .iter()
            .find(|(pk, _)| murk_cli::signing::ssh_ed25519_key_eq(pk, signer))
    {
        return name.clone();
    }
    murk_cli::truncate_pubkey(signer)
}

pub(crate) fn cmd_verify(vault_path: &str) {
    // Load the vault first — MAC/integrity failure short-circuits the rest
    // of the checks with the hard error from the loader.
    let (vault, murk, _identity) = load_vault(vault_path);

    let mut findings: Vec<Finding> = Vec::new();

    if murk.legacy_mac {
        findings.push(Finding {
            category: "mac",
            message: "vault uses legacy unkeyed MAC".into(),
            fix: Some("run any write command (e.g. `murk describe`) to upgrade to BLAKE3".into()),
        });
    }

    // Signature status — the real content-integrity anchor. A valid signature
    // proves a recipient authored the current vault; the MAC alone can't (a
    // repo-writer can forge it). An invalid signature would already have failed
    // the load above, so here it is only Signed or Unsigned.
    match &murk.signature {
        types::SignatureState::Signed {
            signer,
            anchored: true,
        } => {
            eprintln!(
                "{} signature  signed by {}",
                "ok".green().bold(),
                signer_display_name(&murk, signer).dimmed()
            );
        }
        // Age signer whose key isn't pinned yet (fresh clone): the signature is
        // trust-on-first-use, not authenticated authorship. Don't present it as a
        // clean "signed by" — warn and point at the real anchor. Not a hard
        // finding: for the vault's own author this is the normal first load, and
        // the key is pinned now, so later tampering is caught.
        types::SignatureState::Signed {
            signer,
            anchored: false,
        } => {
            eprintln!(
                "{} signature  signed by {} — {}",
                "warn".yellow().bold(),
                signer_display_name(&murk, signer).dimmed(),
                "trust-on-first-use (key not yet anchored on this machine); anchor authorship with signed git commits, or use an ssh-ed25519 key".dimmed()
            );
        }
        types::SignatureState::Unsigned
            if !vault.secrets.is_empty() && !murk.signature_downgraded =>
        {
            findings.push(Finding {
                category: "signature",
                message: "vault is unsigned — content integrity relies on git".into(),
                fix: Some(
                    "run any write command with an age or ssh-ed25519 key to sign it; ssh-rsa and hardware/plugin keys cannot sign".into(),
                ),
            });
        }
        types::SignatureState::Unsigned => {}
    }

    // A vault signed before and unsigned now — the sharper signal. Fail the check
    // (report_findings exits non-zero) so `verify` asserts, not just warns.
    if murk.signature_downgraded {
        findings.push(Finding {
            category: "signature",
            message: "vault was signed before and is now unsigned — signature stripped, or a merge left it unsigned".into(),
            fix: Some(
                "re-sign with any write command after reviewing `murk diff`; if the downgrade is unexpected, inspect `git log -p`".into(),
            ),
        });
    }

    // Git anchor — is the vault's latest commit signed? The vault signature
    // covers content; a signed commit covers who landed it. Only surfaced when
    // there is a git history to check.
    match murk_cli::last_commit_signature(vault_path) {
        Some(murk_cli::CommitSignature::Good | murk_cli::CommitSignature::Unverified) => {
            eprintln!(
                "{} commit  last .murk commit is signed",
                "ok".green().bold()
            );
        }
        Some(murk_cli::CommitSignature::Bad) => {
            findings.push(Finding {
                category: "commit",
                message: "last .murk commit has a bad signature".into(),
                fix: Some(
                    "inspect `git log --show-signature -- .murk` — history may be tampered".into(),
                ),
            });
        }
        Some(murk_cli::CommitSignature::Unsigned) => {
            findings.push(Finding {
                category: "commit",
                message: "last .murk commit is unsigned".into(),
                fix: Some(
                    "enable commit signing and protect the branch so vault history is attributable"
                        .into(),
                ),
            });
        }
        None => {}
    }

    // The vault file itself is public-by-design, so we don't care about read
    // perms. We do care about *write* perms: a group-writable vault is an
    // easy way for a local attacker to tamper with ciphertext.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(vault_path) {
            let mode = meta.mode() & 0o777;
            if mode & 0o022 != 0 {
                findings.push(Finding {
                    category: "perms",
                    message: format!("vault file is group/world writable (mode {mode:o})"),
                    fix: Some(format!("chmod 644 {vault_path}")),
                });
            }
        }
    }

    // After the .env kill, every valid key source is safe. Re-resolve
    // explicitly so verify can surface where the key came from — transparency
    // about key provenance is the point.
    match murk_cli::resolve_key_with_source(vault_path) {
        Ok((_, source)) => {
            eprintln!(
                "{} key  {}",
                "ok".green().bold(),
                source.describe().dimmed()
            );
        }
        Err(msg) => {
            findings.push(Finding {
                category: "key",
                message: format!("cannot resolve a key: {msg}"),
                fix: None,
            });
        }
    }

    let rsa_recipients: Vec<&String> = vault
        .recipients
        .iter()
        .filter(|r| r.starts_with("ssh-rsa "))
        .collect();
    if !rsa_recipients.is_empty() {
        findings.push(Finding {
            category: "recipients",
            message: format!(
                "{} ssh-rsa recipient{} present",
                rsa_recipients.len(),
                if rsa_recipients.len() == 1 { "" } else { "s" }
            ),
            fix: Some("rotate to ed25519 keys and `murk revoke` the old ssh-rsa recipients".into()),
        });
    }

    if findings.is_empty() {
        eprintln!("{} vault integrity verified", "ok".green().bold());
        eprintln!("{} no safety issues found", "ok".green().bold());
        return;
    }

    eprintln!("{} vault integrity verified", "ok".green().bold());
    report_findings(&findings, "vault");
}

pub(crate) fn cmd_doctor(vault_path: &str) {
    // doctor is repo-level hygiene — most checks are about the working tree:
    // env files, key files sitting next to the vault, obvious commit-would-be-bad
    // state. It also reads the vault's plaintext schema (no key needed) to flag
    // rotation/expiry drift.
    let mut findings: Vec<Finding> = Vec::new();

    let cwd = std::env::current_dir().unwrap_or_else(|e| die(&e, 1));

    // ── .env contains an inline MURK_KEY ──
    // After the .env kill this is dead config AND a historical footgun.
    // Previously-committed .env files with inline keys are still out there.
    let env_path = cwd.join(".env");
    if env_path.exists()
        && let Ok(contents) = std::fs::read_to_string(&env_path)
    {
        let has_inline = contents.lines().any(|l| {
            let t = l.trim_start();
            (t.starts_with("MURK_KEY=") || t.starts_with("export MURK_KEY="))
                && !t.starts_with("MURK_KEY_FILE=")
                && !t.starts_with("export MURK_KEY_FILE=")
        });
        if has_inline {
            findings.push(Finding {
                category: "dotenv",
                message: "inline MURK_KEY in .env (dead config, risk of commit)".into(),
                fix: Some("remove the MURK_KEY= line and re-run `murk init`".into()),
            });
        }
    }

    // ── .env is not in .gitignore ──
    // Soft guardrail: an untracked .env is fine for local dev, but a .env
    // that isn't excluded from git has probably slipped into a commit
    // somewhere. Ask git directly via `check-ignore` so we respect nested
    // .gitignore files, global excludes, and negated rules.
    if env_path.exists()
        && cwd.join(".git").exists()
        && let Ok(output) = std::process::Command::new("git")
            .args(["check-ignore", "--quiet", ".env"])
            .current_dir(&cwd)
            .status()
        && !output.success()
    {
        findings.push(Finding {
            category: "gitignore",
            message: ".env is not excluded from git".into(),
            fix: Some("add `.env` to .gitignore so it cannot be committed".into()),
        });
    }

    // ── Key file is inside the working tree ──
    // `murk init` puts the key file under ~/.config/murk/keys by default,
    // which is outside any repo. But MURK_KEY_FILE can be set to anywhere,
    // and a user who put it next to the vault has just opted in to
    // committing their private key. Fail loudly.
    if let Ok((_, source)) = murk_cli::resolve_key_with_source(".murk")
        && let murk_cli::KeySource::EnvFile(path) | murk_cli::KeySource::Auto(path) = source
        && let Ok(abs) = std::fs::canonicalize(&path)
        && let Ok(repo) = std::fs::canonicalize(&cwd)
        && abs.starts_with(&repo)
    {
        findings.push(Finding {
            category: "keyfile",
            message: format!("key file {} is inside the working tree", abs.display()),
            fix: Some(
                "move it out of the repo (e.g. ~/.config/murk/keys/) and update MURK_KEY_FILE"
                    .into(),
            ),
        });
    }

    // ── Rotation / expiry drift ──
    // Read-only over the plaintext schema (no decryption). Skipped silently when
    // there's no readable vault — doctor still reports the repo-hygiene findings.
    if let Ok((vault, _raw)) = murk_cli::vault::read_with_raw(Path::new(vault_path)) {
        for issue in murk_cli::rotation_health(&vault, chrono::Utc::now()) {
            findings.push(rotation_finding(&issue));
        }
    }

    if findings.is_empty() {
        eprintln!("{} repo hygiene looks clean", "ok".green().bold());
        return;
    }

    report_findings(&findings, "repo");
}
