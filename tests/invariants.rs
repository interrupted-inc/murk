//! Source-level invariants that generic lints (clippy, fmt, cargo-deny) can't
//! express. These scan the crate source as text — cheap, deterministic, and they
//! fail fast when an agent or human violates a secret-handling rule that code
//! review might miss.
//!
//! Adding a rule here is the cheapest way to make a murk-specific invariant
//! self-enforcing. Keep each rule precise: a false positive trains people to
//! ignore the check.

use std::fs;
use std::path::Path;

/// Every `.rs` file under `src/`, paired with its contents. Paths are
/// `/`-normalized and relative to the crate root so comparisons are portable.
fn source_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect(Path::new("src"), &mut out);
    assert!(!out.is_empty(), "no source files found under src/");
    out
}

fn collect(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let body = fs::read_to_string(&path).expect("read source file");
            out.push((rel(&path), body));
        }
    }
}

/// Normalize a path to forward slashes relative to the crate root.
fn rel(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Non-comment lines of a file, as (1-based line number, trimmed text).
fn code_lines(body: &str) -> impl Iterator<Item = (usize, &str)> {
    body.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.starts_with("//"))
}

/// True if a line reads from the process environment — `var`, `var_os`, `vars`,
/// or `vars_os` — as opposed to writing it (`set_var` / `remove_var` /
/// `env_remove`), which all contain `var` as a substring. We strip the write
/// accessors first so they don't masquerade as reads.
fn reads_env(line: &str) -> bool {
    let cleaned = line
        .replace("set_var", "")
        .replace("remove_var", "")
        .replace("env_remove", "")
        .replace("env_set", "");
    cleaned.contains("var(")
        || cleaned.contains("var_os(")
        || cleaned.contains("vars(")
        || cleaned.contains("vars_os(")
}

/// Secret material must be read from the environment in one place: the `env`
/// module. A second reader is a spot where a key can bypass the strict-mode and
/// auto-discovery rules that `env` centralizes (see `env::resolve_key` /
/// `env::key_from_env_only`), or leak through a path nobody audited.
///
/// This flags, outside `env.rs`, either: a use of the canonical `ENV_MURK_KEY*`
/// consts (the internal handle for these vars — currently env-only), or a read
/// accessor on the same line as a `MURK_KEY*` literal. It is a guardrail against
/// accidental regressions, not a soundness proof: a determined bypass (building
/// the var name dynamically, or scanning `env::vars()` across several lines)
/// would slip past — that needs a semantic lint, tracked separately.
#[test]
fn murk_key_is_read_only_in_the_env_module() {
    const ALLOWED: &str = "src/env.rs";

    let offenders: Vec<String> = source_files()
        .iter()
        .filter(|(path, _)| path != ALLOWED)
        .flat_map(|(path, body)| {
            code_lines(body)
                .filter(|(_, line)| {
                    // The canonical consts are the internal handle for these env
                    // vars; outside env.rs they have no business appearing.
                    let uses_const = line.contains("ENV_MURK_KEY");
                    // Or a literal var name read through any std accessor.
                    let reads_literal = reads_env(line)
                        && (line.contains("\"MURK_KEY\"") || line.contains("\"MURK_KEY_FILE\""));
                    uses_const || reads_literal
                })
                .map(move |(n, line)| format!("  {path}:{n}: {line}"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "MURK_KEY / MURK_KEY_FILE may only be read in {ALLOWED} (the single auth \
         read path). Route new reads through env::resolve_key / env::key_from_env_only.\n{}",
        offenders.join("\n"),
    );
}

/// The library crate (`murk_cli`) returns data; the binary owns all
/// user-facing output. Library code must not write to stdout — that is exactly
/// where a decrypted secret would leak into a pipe or `$(...)`. Warnings on
/// stderr (`eprintln!`) are fine; the binary's UI layer — `main.rs` and its
/// `commands/` handler modules — is exempt.
#[test]
fn library_modules_do_not_print_to_stdout() {
    // The binary crate's UI code: the entrypoint plus its command handlers.
    // These modules are compiled into the `murk` binary (via `mod commands;`),
    // not the `murk_cli` library, so printing to stdout is their job.
    let is_ui_layer = |path: &str| path == "src/main.rs" || path.starts_with("src/commands/");

    let offenders: Vec<String> = source_files()
        .iter()
        .filter(|(path, _)| !is_ui_layer(path))
        .flat_map(|(path, body)| {
            code_lines(body)
                .filter(|(_, line)| {
                    // `print!`/`println!`, but not their `eprint!`/`eprintln!`
                    // (stderr) cousins, which `contains` would otherwise match.
                    (line.contains("println!") || line.contains("print!"))
                        && !line.contains("eprintln!")
                        && !line.contains("eprint!")
                })
                .map(move |(n, line)| format!("  {path}:{n}: {line}"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "library modules must not write to stdout — stdout belongs to the binary. \
         Return the value and let main.rs print it, or use eprintln! for a warning.\n{}",
        offenders.join("\n"),
    );
}
