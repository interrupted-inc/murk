use super::*;
use clap::CommandFactory;
use colored::Colorize;
use murk_cli::cli::Cli;
use std::fs;
use std::io::{self};

pub(crate) fn cmd_completion_generate(shell: clap_complete::Shell) {
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut io::stdout());
}

pub(crate) fn cmd_completion_install(shell: clap_complete::Shell) {
    use clap_complete::Shell;

    let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));

    let (dir, filename) = match shell {
        Shell::Zsh => {
            let dir = format!("{home}/.zfunc");
            (dir, "_murk".to_string())
        }
        Shell::Bash => {
            let dir = format!("{home}/.local/share/bash-completion/completions");
            (dir, "murk".to_string())
        }
        Shell::Fish => {
            let dir = format!("{home}/.config/fish/completions");
            (dir, "murk.fish".to_string())
        }
        Shell::Elvish => {
            let dir = format!("{home}/.config/elvish/lib");
            (dir, "murk.elv".to_string())
        }
        Shell::PowerShell => {
            let dir = format!("{home}/.config/powershell");
            (dir, "_murk.ps1".to_string())
        }
        _ => die(&format!("unsupported shell: {shell}"), 1),
    };

    fs::create_dir_all(&dir).unwrap_or_else(|e| die(&format!("failed to create {dir}: {e}"), 1));

    let path = format!("{dir}/{filename}");
    let mut file =
        fs::File::create(&path).unwrap_or_else(|e| die(&format!("failed to write {path}: {e}"), 1));
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut file);

    eprintln!("{} wrote {}", "ok".green().bold(), path);

    match shell {
        Shell::Zsh => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.zshrc".bold()
            );
            eprintln!("  fpath+=~/.zfunc");
            eprintln!("  autoload -Uz compinit && compinit");
        }
        Shell::Bash => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.bashrc".bold()
            );
            eprintln!(
                "  [[ -r ~/.local/share/bash-completion/completions/murk ]] && \
                 source ~/.local/share/bash-completion/completions/murk"
            );
        }
        Shell::Fish => {
            eprintln!(
                "\n{} completions are loaded automatically by fish",
                "hint".cyan().bold()
            );
        }
        _ => {}
    }
}
