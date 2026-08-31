// Command handlers thread many CLI flags straight into the library's
// multi-field secret calls, which the library already allows crate-wide
// (see lib.rs). Apply the same policy to the binary crate.
#![allow(clippy::too_many_arguments)]

use murk_cli::cli::{AgentCommand, CircleCommand, Cli, Command, CompletionAction};

use std::process;

use clap::Parser;

mod mcp;

mod commands;

use commands::completion::*;
use commands::exec::*;
use commands::git::*;
use commands::grants::*;
use commands::info::*;
use commands::init::*;
use commands::recipients::*;
use commands::recover::*;
use commands::resolve_value;
use commands::scan::*;
use commands::secrets::*;
use commands::verify::*;

fn main() {
    // clap's derive-generated parser uses large stack frames, and the command
    // tree here is big. On Windows the default 1 MiB main-thread stack can
    // overflow during argument parsing, so run everything on a thread with a
    // generous stack. (Other platforms default to ~8 MiB and are unaffected, but
    // running uniformly keeps behavior consistent.)
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawn main thread");
    // Propagate a panic in `run` as a non-zero exit, same as a normal main.
    if handle.join().is_err() {
        process::exit(1);
    }
}

fn run() {
    murk_cli::hardening::disable_core_dumps();
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore { vault } => cmd_restore(&vault),
        Command::Import {
            file,
            force,
            group,
            example,
            vault,
        } => {
            cmd_import(
                &file,
                force,
                group.as_deref(),
                example.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            );
        }
        Command::Add {
            key,
            desc,
            example,
            group,
            scoped,
            tag,
            vault,
        } => {
            let vault = murk_cli::resolve_vault_path(&vault);
            let resolved = resolve_value(&key);
            cmd_add(
                &key,
                &resolved,
                desc.as_deref(),
                example.as_deref(),
                group.as_deref(),
                scoped,
                &tag,
                &vault,
            );
        }
        Command::Generate {
            key,
            length,
            hex,
            desc,
            example,
            group,
            tag,
            vault,
        } => cmd_generate(
            &key,
            length,
            hex,
            desc.as_deref(),
            example.as_deref(),
            group.as_deref(),
            &tag,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Rotate {
            key,
            all,
            generate,
            length,
            hex,
            list,
            json,
            vault,
        } => {
            let vault_path = murk_cli::resolve_vault_path(&vault);
            if list {
                cmd_rotate_list(json, &vault_path);
            } else {
                cmd_rotate(key.as_deref(), all, generate, length, hex, &vault_path);
            }
        }
        Command::Rm { key, vault } => cmd_rm(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Get { key, vault } => cmd_get(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Ls { tag, json, vault } => {
            cmd_ls(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Describe {
            key,
            description,
            example,
            tag,
            rotate_every,
            expires,
            vault,
        } => cmd_describe(
            &key,
            &description,
            example.as_deref(),
            &tag,
            rotate_every.as_deref(),
            expires.as_deref(),
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Info { tag, json, vault } => {
            cmd_info(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Export { tag, json, vault } => {
            cmd_export(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Edit {
            key,
            scoped,
            group,
            vault,
        } => {
            cmd_edit(
                key.as_deref(),
                scoped,
                group.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            );
        }
        Command::Exec {
            only,
            tag,
            clean_env,
            vault,
            command,
        } => cmd_exec(
            &command,
            &only,
            &tag,
            clean_env,
            /* agent_mode */ false,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Authorize {
            pubkey,
            name,
            force,
            allow_ssh_rsa,
            vault,
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            None,
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Revoke {
            recipient,
            rotate,
            vault,
        } => {
            cmd_revoke(&recipient, rotate, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Circle {
            sub: None,
            json,
            vault,
        } => cmd_recipients(json, &murk_cli::resolve_vault_path(&vault)),
        Command::Circle {
            sub:
                Some(CircleCommand::Authorize {
                    pubkey,
                    name,
                    group,
                    force,
                    allow_ssh_rsa,
                    vault,
                }),
            ..
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            group.as_deref(),
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Circle {
            sub:
                Some(CircleCommand::Revoke {
                    recipient,
                    rotate,
                    vault,
                }),
            ..
        } => cmd_revoke(&recipient, rotate, &murk_cli::resolve_vault_path(&vault)),
        Command::Group { sub } => cmd_group(sub),
        Command::Policy { sub } => cmd_policy(sub),
        Command::Env { vault } => cmd_env(&vault),
        Command::Diff {
            git_ref,
            show_values,
            json,
            vault,
        } => cmd_diff(
            &git_ref,
            show_values,
            json,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::MergeDriver { base, ours, theirs } => cmd_merge_driver(&base, &ours, &theirs),
        Command::SetupMergeDriver => cmd_setup_merge_driver(),
        Command::Verify { vault } => cmd_verify(&murk_cli::resolve_vault_path(&vault)),
        Command::Doctor { vault } => cmd_doctor(&murk_cli::resolve_vault_path(&vault)),
        Command::Skeleton { output, vault } => {
            cmd_skeleton(output.as_deref(), &murk_cli::resolve_vault_path(&vault));
        }
        Command::Agent { sub } => match sub {
            AgentCommand::Plan {
                tag,
                json,
                output,
                vault,
            } => cmd_agent_plan(
                &tag,
                json,
                output.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Exec {
                only,
                vault,
                command,
            } => cmd_agent_exec(&command, &only, &murk_cli::resolve_vault_path(&vault)),
            AgentCommand::Grant {
                name,
                only,
                ttl,
                renew,
                out,
                vault,
            } => cmd_agent_grant(
                &name,
                &only,
                &ttl,
                renew,
                out.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Init {
                name,
                only,
                allow_tag,
                ttl,
                out,
                vault,
            } => cmd_agent_init(
                &name,
                &only,
                &allow_tag,
                &ttl,
                out.as_deref(),
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Ls { json, vault } => {
                cmd_agent_ls(json, &murk_cli::resolve_vault_path(&vault));
            }
            AgentCommand::Revoke {
                name,
                rotate,
                vault,
            } => cmd_agent_revoke(&name, rotate, &murk_cli::resolve_vault_path(&vault)),
            AgentCommand::Connect {
                client,
                only,
                allow_tag,
                allow_exec,
                ttl,
                name,
                vault,
            } => cmd_agent_connect(
                client.as_deref(),
                &only,
                &allow_tag,
                allow_exec,
                &ttl,
                &name,
                &murk_cli::resolve_vault_path(&vault),
            ),
            AgentCommand::Disconnect {
                client,
                rotate,
                name,
                vault,
            } => cmd_agent_disconnect(
                client.as_deref(),
                rotate,
                &name,
                &murk_cli::resolve_vault_path(&vault),
            ),
        },
        Command::Scan { paths, vault } => {
            cmd_scan(&paths, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Mcp { vault, allow_exec } => {
            cmd_mcp(&murk_cli::resolve_vault_path(&vault), allow_exec)
        }
        Command::Completion { action } => match action {
            CompletionAction::Generate { shell } => cmd_completion_generate(shell),
            CompletionAction::Install { shell } => cmd_completion_install(shell),
        },
    }
}

#[cfg(test)]
mod cli_structure {
    //! Structural guards over the clap command tree.
    //!
    //! murk keeps each command's handler in a flat `cmd_<name>` function
    //! dispatched from the exhaustive `match` in [`run`], so "every subcommand
    //! has a handler" is already enforced by the compiler — a missing arm won't
    //! build. What the compiler does *not* catch is a subcommand shipped without
    //! help text, or one that no integration test ever exercises. These tests
    //! close both gaps so the CLI surface stays coherent as it grows.

    use clap::CommandFactory;

    use super::Cli;

    /// Collect `(path, has_about)` for every subcommand at any depth, where
    /// `path` is the space-joined invocation (e.g. `"circle authorize"`).
    fn collect(cmd: &clap::Command, prefix: &str, out: &mut Vec<(String, bool)>) {
        for sub in cmd.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            out.push((path.clone(), sub.get_about().is_some()));
            collect(sub, &path, out);
        }
    }

    #[test]
    fn every_subcommand_has_help() {
        let mut subs = Vec::new();
        collect(&Cli::command(), "", &mut subs);

        // Guard against the walk silently finding an empty tree.
        assert!(
            subs.len() >= 25,
            "expected the full command surface, only found {}: {:?}",
            subs.len(),
            subs.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );

        let missing: Vec<&String> = subs
            .iter()
            .filter(|(_, has_about)| !has_about)
            .map(|(path, _)| path)
            .collect();
        assert!(
            missing.is_empty(),
            "these subcommands ship without an about/help string: {missing:?}"
        );
    }

    #[test]
    fn every_top_level_subcommand_has_an_integration_test() {
        // Nested subcommands (e.g. `circle authorize`) are covered transitively
        // through their parent and by `every_subcommand_has_help`; here we only
        // assert each top-level command is actually invoked somewhere in the
        // integration suite, so a new command cannot ship untested.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let sources: String = ["tests/cli.rs", "tests/adversarial.rs"]
            .iter()
            .map(|rel| {
                std::fs::read_to_string(format!("{manifest}/{rel}"))
                    .unwrap_or_else(|e| panic!("reading {rel}: {e}"))
            })
            .collect();

        let untested: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .filter(|name| !sources.contains(&format!("\"{name}\"")))
            .collect();
        assert!(
            untested.is_empty(),
            "these top-level subcommands are never invoked by an integration test: {untested:?}"
        );
    }
}
