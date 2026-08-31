use super::*;
use colored::Colorize;
use std::process;

pub(crate) fn cmd_scan(paths: &[String], vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, &[]);

    if secrets.is_empty() {
        eprintln!("{} no secrets to scan for", "ok".green().bold());
        return;
    }

    let scan_paths: Vec<&str> = if paths.is_empty() {
        vec!["."]
    } else {
        paths.iter().map(String::as_str).collect()
    };

    let findings = murk_cli::scan::scan_for_leaks(&scan_paths, &secrets, 8);

    for f in &findings {
        eprintln!(
            "{} {} leaked in {}",
            "warn".yellow().bold(),
            f.key.bold(),
            f.path
        );
    }

    if findings.is_empty() {
        eprintln!("{} no leaked secrets found", "ok".green().bold());
    } else {
        eprintln!(
            "{} {} leaked secret{} found",
            "error".red().bold(),
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        );
        process::exit(1);
    }
}
