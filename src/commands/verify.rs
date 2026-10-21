// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use murk_cli::types;
use std::path::Path;

pub(crate) fn cmd_verify(vault_path: &str) {
    // Decrypt and check integrity — a MAC or signature failure short-circuits
    // with the hard error. Trust is reported as a finding rather than refused,
    // so `verify` explains why other commands would refuse the vault.
    let inspected = try_or_die(murk_cli::inspect_vault(vault_path));
    let vault = &inspected.vault;
    let murk = &inspected.murk;

    let mut findings: Vec<Finding> = Vec::new();

    if murk.legacy_mac {
        findings.push(Finding {
            category: "mac",
            message: "vault uses legacy unkeyed MAC".into(),
            fix: Some("run any write command (e.g. `murk describe`) to upgrade to BLAKE3".into()),
        });
    }

    // Signature and trust — the content-integrity anchor. A valid signature by
    // a signer this machine trusts is authenticated authorship; anything else
    // is a finding, with the same explanation the loader refuses with.
    match &inspected.assessment.verdict {
        murk_cli::trust::Verdict::Trusted => {
            if let types::SignatureState::Signed { signer, .. } = &murk.signature {
                eprintln!(
                    "{} signature  signed by trusted signer {}",
                    "ok".green().bold(),
                    murk_cli::trust::label(&murk.recipients, signer).dimmed()
                );
            }
        }
        murk_cli::trust::Verdict::UnsignedAllowed => {
            findings.push(Finding {
                category: "signature",
                message: "vault is unsigned — content integrity relies on signed git commits".into(),
                fix: Some(
                    "have a recipient with an age or ssh-ed25519 key review it and run `murk trust`; ssh-rsa and hardware/plugin keys cannot sign".into(),
                ),
            });
        }
        murk_cli::trust::Verdict::Refused(_) => {
            let msg = inspected.refusal_message(vault_path).unwrap_or_default();
            let mut lines = msg.lines();
            findings.push(Finding {
                category: "trust",
                message: lines.next().unwrap_or_default().to_string(),
                fix: Some(lines.collect::<Vec<_>>().join("; ")).filter(|s| !s.is_empty()),
            });
        }
    }

    // Git anchor — is the vault's latest commit signed, and by someone this
    // vault trusts? The vault signature covers content; a signed commit covers
    // who landed it. A signature by a key the vault does not trust is no
    // anchor: git accepts any key it is told about. Only surfaced when there
    // is a git history to check.
    let trusted_ssh = inspected.assessment.trusted_ssh_signers(&murk.grants);
    match murk_cli::last_commit_signature(vault_path, &trusted_ssh) {
        Some(murk_cli::CommitSignature::Verified(signer)) => {
            // git checked the signature; whose key it is, is for the vault to say.
            let id = signer.id();
            let trusted = id.and_then(|id| Some((id, key_with_fingerprint(&trusted_ssh, id)?)));
            if let Some((id, key)) = trusted {
                eprintln!(
                    "{} commit  last .murk commit signed by {} with key {id}, a trusted signer of this vault",
                    "ok".green().bold(),
                    murk_cli::trust::label(&murk.recipients, key).dimmed(),
                );
            } else {
                let by = id.map_or_else(|| "an unidentified key".into(), |id| format!("key {id}"));
                let recipient = id
                    .and_then(|id| key_with_fingerprint(&vault.recipients, id))
                    .map(|r| {
                        format!(
                            ", recipient {}",
                            murk_cli::trust::label(&murk.recipients, r)
                        )
                    })
                    .unwrap_or_default();
                findings.push(Finding {
                    category: "commit",
                    message: format!(
                        "last .murk commit is signed by {by}{recipient}, which is not a trusted signer of this vault"
                    ),
                    fix: Some(if trusted_ssh.is_empty() {
                        "no signer this machine trusts for this vault has an ssh-ed25519 key, the only kind murk matches a commit's signer to; sign vault commits with a trusted signer's ssh key once one does".into()
                    } else {
                        "sign vault commits with the ssh-ed25519 key of a trusted signer (`git config gpg.format ssh`, `git config user.signingkey`); murk checks the commit's key against the vault's signers, not git's own list".into()
                    }),
                });
            }
        }
        Some(murk_cli::CommitSignature::Unverified { status, signer }) => {
            let key = signer
                .id()
                .map(|id| format!(" (key {id})"))
                .unwrap_or_default();
            let message = match status {
                'X' => format!("the signature on the last .murk commit has expired{key}"),
                'Y' => format!("the last .murk commit is signed with an expired key{key}"),
                _ => format!("git could not check the signature on the last .murk commit{key}"),
            };
            findings.push(Finding {
                category: "commit",
                message,
                fix: Some(format!(
                    "inspect `git log --show-signature -1 -- {vault_path}` to see why git does not vouch for it"
                )),
            });
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

/// The ssh-ed25519 key among `keys` whose `ssh-keygen -l` fingerprint is
/// `fingerprint`, the form git reports a commit's ssh signer in.
fn key_with_fingerprint<'a>(
    keys: impl IntoIterator<Item = &'a String>,
    fingerprint: &str,
) -> Option<&'a String> {
    keys.into_iter().find(|key| {
        murk_cli::signing::ssh_ed25519_fingerprint(key).is_some_and(|fp| fp == fingerprint)
    })
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
        && let Ok(output) = murk_cli::git_command()
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

    // ── Key file is inside the working tree / readable by others ──
    // `murk init` puts the key file under ~/.config/murk/keys by default,
    // which is outside any repo. But MURK_KEY_FILE can be set to anywhere,
    // and a user who put it next to the vault has just opted in to
    // committing their private key. Fail loudly. Locate the key without
    // reading it: a key file murk refuses to load (loose permissions) is
    // exactly the one these checks must still see.
    // Both key variables set is a resolution error (no key loads), so it is a
    // finding of its own. Its message is a summary line followed by hint
    // lines, the last of which is the fix.
    let located = match murk_cli::locate_key(vault_path) {
        Ok(source) => source,
        Err(msg) => {
            let mut lines = msg.lines();
            findings.push(Finding {
                category: "key",
                message: lines.next().unwrap_or_default().to_string(),
                fix: lines.last().map(str::to_string),
            });
            None
        }
    };
    if let Some(murk_cli::KeySource::EnvFile(path) | murk_cli::KeySource::Auto(path)) = located {
        if let Ok(abs) = std::fs::canonicalize(&path)
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
        if let Some(mode) = murk_cli::secret_file_loose_mode(&path) {
            findings.push(Finding {
                category: "perms",
                message: format!(
                    "key file {} is readable by others (mode {mode:o})",
                    path.display()
                ),
                fix: Some(format!("chmod 600 {}", path.display())),
            });
        }
    }

    // ── Rotation / expiry drift ──
    // Read-only over the plaintext schema (no decryption). Skipped silently when
    // there's no readable vault — doctor still reports the repo-hygiene findings.
    // With no key nothing checks that schema, so say so: a stripped expiry or
    // revoke marker would otherwise read as a clean bill of health.
    if let Ok((vault, _raw)) = murk_cli::vault::read_with_raw(Path::new(vault_path)) {
        warn_if_keyless(vault_path);
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
