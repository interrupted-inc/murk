// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use colored::Colorize;
use std::process;

pub(crate) fn cmd_scan(paths: &[String], vault_path: &str) {
    let scan_paths: Vec<&str> = if paths.is_empty() {
        vec!["."]
    } else {
        paths.iter().map(String::as_str).collect()
    };
    // A path that doesn't exist or can't be read is a bad argument: checked
    // before anything else, so a mistyped pre-commit path never reports "ok".
    for path in &scan_paths {
        if let Err(e) = murk_cli::scan::check_scan_path(path) {
            die(&e, 2);
        }
    }

    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, &[]);

    if secrets.is_empty() {
        eprintln!("{} no secrets to scan for", "ok".green().bold());
        return;
    }

    let report = murk_cli::scan::scan_for_leaks(&scan_paths, &secrets, 8);

    for (path, reason) in &report.unreadable {
        eprintln!("{} cannot read {path}: {reason}", "warn".yellow().bold());
    }
    for f in &report.findings {
        eprintln!(
            "{} {} leaked in {}",
            "warn".yellow().bold(),
            f.key.bold(),
            f.path
        );
    }

    let findings = &report.findings;
    if !findings.is_empty() {
        eprintln!(
            "{} {} leaked secret{} found",
            "error".red().bold(),
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        );
        process::exit(1);
    }
    if !report.unreadable.is_empty() {
        let n = report.unreadable.len();
        eprintln!(
            "{} scan incomplete: {n} path{} could not be read",
            "error".red().bold(),
            if n == 1 { "" } else { "s" }
        );
        process::exit(1);
    }
    eprintln!("{} no leaked secrets found", "ok".green().bold());
}
