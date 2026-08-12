---
title: Environment variables
description: The environment variables murk reads and writes, and how they interact.
sidebar:
  order: 5
---

murk is configured almost entirely through environment variables, so it composes cleanly with direnv, CI, and subprocess wrapping without needing flags on every invocation. This page documents the variables the binary actually reads and writes. Run `murk <command> --help` for the equivalent CLI flags where one exists (`--vault` mirrors `MURK_VAULT`, for example).

## Identity and vault selection

| Variable | Description |
| --- | --- |
| `MURK_KEY` | Your raw age private key (`AGE-SECRET-KEY-1...`), inline. Convenient for scripts and CI, but the key sits in plaintext wherever this variable is set: an env file, a CI secret store, a process environment. Rejected if set to a hardware-plugin identity string (`AGE-PLUGIN-...`). Use `MURK_KEY_FILE` for those. |
| `MURK_KEY_FILE` | Path to a file holding your private key: a raw age key, an SSH PEM key, or an age plugin identity file (with a `# Recipient:` or `# public key:` header). `murk init` writes this to `.env` for direnv to pick up. |
| `MURK_VAULT` | Vault filename, defaulting to `.murk`. Equivalent to passing `--vault` on every command. |

murk resolves your identity in order: an explicit `MURK_KEY`, then `MURK_KEY_FILE`, then an automatic lookup at `~/.config/murk/keys/<vault-hash>` (the file `murk init` writes). That last, automatic step is disabled whenever strict mode is active (see below), so an agent context always needs an explicit key of its own.

`.env` itself is a write-only convenience: `murk init` populates it with a `MURK_KEY_FILE` reference so direnv (or `source .env`) can export it, but murk never reads `.env` directly at runtime. Reading it at runtime would let a vault copied into another repo silently borrow whatever key that directory's `.env` happened to reference. murk avoids that by trusting only the process environment and the vault-keyed automatic lookup.

## Safety and agent context

| Variable | Description |
| --- | --- |
| `MURK_STRICT` | Truthy (`1`/`true`/`yes`) fails closed rather than let a secret touch disk: `murk edit`'s scratch file must live on a RAM-backed filesystem (aborting before launching the editor otherwise), `export`/`get` refuse to run with stdout pointed at a regular file, and the automatic key lookup in `~/.config/murk/keys` is disabled. |
| `MURK_AGENT` | Marks the process as running on behalf of an AI agent. Forces strict mode unconditionally: there's no way to turn strict back off from inside an agent context, even by setting `MURK_STRICT=0`. `murk agent exec` sets it (alongside `MURK_STRICT=1`) on its child process automatically. |
| `MURK_SELF_SCOPE` | Truthy holds *your own* key to the vault's agent allow-tag policy, as if you were an agent: `get`, `exec`/`agent exec`, and single-key `edit KEY` fail closed on a non-allowed key, `export` withholds forbidden keys, and bulk `edit` is refused. Implied automatically inside an agent context. A no-op on a vault with no policy set. See [Grants](/concepts/grants/). |
| `MURK_NO_SIGNER_PIN` | Opts out of signer-registry pinning (TOFU) on load: an escape hatch for a deliberate signer-key change, not something to leave set. See [Recipients & signatures](/concepts/recipients-signatures/). |

## Also honored

A few standard variables shape specific commands, without being murk-specific configuration:

| Variable | Description |
| --- | --- |
| `CI` | If truthy (the conventional CI-runner convention), murk prints a one-line nudge in its output toward the scoped-agent path when it sees a pipeline decrypting with a personal key. Advisory only: unlike `MURK_AGENT`, it doesn't change behavior on its own. |
| `EDITOR`, `VISUAL` | `murk edit` opens this editor for interactive edits, checking `EDITOR` then `VISUAL`, falling back to `vi` if neither is set. |
| `XDG_RUNTIME_DIR` | Preferred over `/tmp` as the scratch location for `murk edit`'s temporary file, when it exists and is a directory. It's typically tmpfs, so the plaintext buffer never touches persistent storage. |
| `HOME` (`USERPROFILE` on Windows) | Base directory for murk's own state: `~/.config/murk/keys`, `~/.config/murk/agent-keys`, and `~/.config/murk/signer-pins`. |

## Where these come together

[How murk works](/concepts/how-it-works/) covers the identity and layering model these variables configure. [Grants](/concepts/grants/) shows `MURK_AGENT` and a grant key in a real invocation. [Hardware-backed keys](/guides/hardware-keys/) covers pointing `MURK_KEY_FILE` at a plugin identity. [direnv integration](/guides/direnv/) covers the `.env` / `MURK_KEY_FILE` handoff for automatic shell loading. For a terse, generated table of every variable, see the [environment variables reference](/reference/env/).
