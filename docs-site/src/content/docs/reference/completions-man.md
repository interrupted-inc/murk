---
title: Completions & man pages
description: Shell completion scripts and man pages for murk, and how they are generated.
sidebar:
  order: 3
---

murk ships shell completions and man pages generated directly from its command
model, so they never drift from the binary.

## Shell completions

The quickest path is to let murk install completions for your shell (name the
shell: bash, zsh, fish, elvish, or powershell):

```bash
murk completion install zsh
```

To print a completion script to stdout instead (for a custom location or a
system package), use `generate`:

```bash
murk completion generate zsh > ~/.zfunc/_murk
```

Both are documented in the [CLI reference](/reference/cli/#murk-completion).
Pre-generated scripts for every supported shell (bash, zsh, fish, elvish,
PowerShell) are committed under
[`docs/completions/`](https://github.com/interrupted-inc/murk/tree/main/docs/completions)
for packagers who want to ship them without running murk.

## Man pages

Man pages for the root command and every subcommand are committed under
[`docs/man/`](https://github.com/interrupted-inc/murk/tree/main/docs/man) in roff format
(`murk.1`, `murk-init.1`, `murk-agent-plan.1`, …). Install them where your
`MANPATH` can find them, or read one directly:

```bash
man ./docs/man/murk.1
```

## How they stay in sync

murk's dev-only doc generator produces the completions, man pages, the
[CLI reference](/reference/cli/), and the [environment variables reference](/reference/env/):

```bash
cargo run --features doc-gen --bin gen-docs
```

CI runs the same generator with `--check` and fails if any committed artifact is
stale, so a change to the CLI surface can't merge without regenerating them.
