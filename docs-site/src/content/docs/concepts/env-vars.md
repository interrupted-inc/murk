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

murk resolves your identity from `MURK_KEY` or `MURK_KEY_FILE`, then from an automatic lookup at `~/.config/murk/keys/<vault-hash>` (the file `murk init` writes). Set one of the two variables, not both: murk refuses to run when both are non-empty rather than guess which key you meant, and an empty value counts as unset. The automatic step is disabled whenever strict mode is active (see below), so an agent context always needs an explicit key of its own.

`.env` itself is a write-only convenience: `murk init` populates it with a `MURK_KEY_FILE` reference so direnv (or `source .env`) can export it, but murk never reads `.env` directly at runtime. Reading it at runtime would let a vault copied into another repo silently borrow whatever key that directory's `.env` happened to reference. murk avoids that by trusting only the process environment and the vault-keyed automatic lookup.

The automatic lookup is keyed on the vault's absolute path, and a git worktree puts the same committed vault at a different one. So murk also accepts the key stored for that vault in a sibling worktree of the same repository — the main checkout first, then linked worktrees. A fresh worktree needs no key provisioning: check it out and `murk get` works, with no `.env` to copy and nothing to re-run. Only checkouts git itself records as part of the repository count, verified in both directions against git's own metadata, so a copied vault in a directory that merely *claims* to be a worktree still gets nothing. Strict mode and agent context skip the automatic lookup entirely, worktree or not.

## Safety and agent context

| Variable | Description |
| --- | --- |
| `MURK_STRICT` | Truthy (`1`/`true`/`yes`) fails closed rather than let a secret touch disk: `murk edit`'s scratch file must live on a RAM-backed filesystem (aborting before launching the editor otherwise), `export`, `get` and `diff --show-values` refuse to run with stdout pointed at a regular file, and the automatic key lookup in `~/.config/murk/keys` is disabled. |
| `MURK_AGENT` | Marks the process as running on behalf of an AI agent. Forces strict mode unconditionally: there's no way to turn strict back off from inside an agent context, even by setting `MURK_STRICT=0`. `murk agent exec` sets it (alongside `MURK_STRICT=1`) on its child process automatically. |
| `MURK_SELF_SCOPE` | Truthy holds *your own* key to the vault's agent allow-tag policy, as if you were an agent: `get`, `exec`/`agent exec`, and single-key `edit KEY` fail closed on a non-allowed key, `export` withholds forbidden keys, and bulk `edit` is refused. Implied automatically inside an agent context. A no-op on a vault with no policy set. See [Grants](/concepts/grants/). |
| `MURK_TRUSTED_SIGNERS` | Signers trusted to sign the vault, separated by commas or newlines. An age signer is `age1...:<verifying key>` (the recipient, a colon, the base64 Ed25519 verifying key); an `ssh-ed25519` signer is its public key line. `murk trust --print-key` prints the entry for your own key. For CI runners and other machines with no [trust pin](/concepts/recipients-signatures/#trusting-a-signer): set it from a CI secret next to `MURK_KEY`. When set, it replaces the pin's trusted set, an age signer's signature has to verify under the verifying key given here, and it makes an unsigned vault an error even for a key that can't sign. Trust that comes from this variable is not written into the pin, so it never widens what the machine trusts once the variable is gone. Agent grant keys listed here still never count, and an entry in neither form, including a bare `age1...` key without its verifying key, is an error. |
| `MURK_NO_SIGNER_PIN` | murk neither reads nor writes the local trust pin, so trust comes only from `MURK_TRUSTED_SIGNERS`. It doesn't switch the trust check off: without `MURK_TRUSTED_SIGNERS`, every signed vault is refused, and rollback and stripped-signature detection are off. A machine with no home directory behaves the same way. |

## Also honored

A few standard variables shape specific commands, without being murk-specific configuration:

| Variable | Description |
| --- | --- |
| `CI` | If truthy (the conventional CI-runner convention), murk prints a nudge in its output toward the scoped-agent path when it sees a pipeline decrypting with a personal key. Advisory only: unlike `MURK_AGENT`, it doesn't change behavior on its own. |
| `EDITOR`, `VISUAL` | `murk edit` opens this editor for interactive edits, checking `EDITOR` then `VISUAL`, falling back to `vi` if neither is set. On Unix the value runs through `sh`, as git does, so it can carry arguments (`code --wait`). The editor doesn't inherit `MURK_KEY` or `MURK_KEY_FILE`. |
| `XDG_RUNTIME_DIR` | Preferred over `/tmp` as the scratch location for `murk edit`'s temporary file, when it exists and is a directory. It's typically tmpfs, so the plaintext buffer never touches persistent storage. |
| `HOME` (`USERPROFILE` on Windows) | Base directory for murk's own state: `~/.config/murk/keys`, `~/.config/murk/agent-keys`, and the trust pins in `~/.config/murk/signer-pins`. |

## Variable names a vault may not set

`murk export` (shell and `--json`), `murk exec` and `murk agent exec` put the vault's key names into an environment. Whoever last wrote the vault chooses those names, so murk refuses to set a variable that changes how a program, its loader or its shell runs, or how murk itself behaves. A vault can't hand its writer control of `PATH` or your trusted signers that way. The command stops and names the keys. Review who added them (`murk diff`, `git log -p`), then pass `--allow-reserved` if you mean it.

Names are matched case-insensitively. The reserved set is:

- **Prefixes:** `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `NPM_CONFIG_`, `MURK_`, and the interpreter and build-tool families `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `_JAVA_`, `JDK_`, `DOTNET_`, `CARGO_`, `RUSTC`, `SSL_`, `PIP_`, `GEM_`, `BUNDLE_`. These catch names such as `PYTHONPATH`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `SSL_CERT_FILE` and `CARGO_HOME`.
- **Suffix:** `_PROXY` (`HTTPS_PROXY`, `ALL_PROXY` and the like). A proxy the vault writer chose would route the child's traffic, and the secrets in its environment, through their host.
- **Search paths and interpreter hooks:** `PATH`, `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `CLASSPATH`, `GCONV_PATH`, `GLIBC_TUNABLES`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `GOFLAGS`, `MAVEN_OPTS`, `GRADLE_OPTS`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`.
- **Shell start-up and prompt hooks:** `BASH_ENV`, `ENV`, `ZDOTDIR`, `SHELLOPTS`, `BASHOPTS`, `IFS`, `SHELL`, `PS0` to `PS4`, `PROMPT_COMMAND`, `CDPATH`.
- **Tool configuration and the commands tools run:** `HOME`, `XDG_CONFIG_HOME`, `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `BROWSER`, `SSH_ASKPASS`, `SUDO_ASKPASS`.

`NODE_ENV` is not reserved: it is an ordinary application setting, and `NODE_` is not a prefix.

The MCP server's `murk_exec` tool always refuses these names, with no override. `murk add`, `murk import` and `murk generate` warn when a key has one of these names.

## Where these come together

[How murk works](/concepts/how-it-works/) covers the identity and layering model these variables configure. [Grants](/concepts/grants/) shows `MURK_AGENT` and a grant key in a real invocation. [Hardware-backed keys](/guides/hardware-keys/) covers pointing `MURK_KEY_FILE` at a plugin identity. [direnv integration](/guides/direnv/) covers the `.env` / `MURK_KEY_FILE` handoff for automatic shell loading. For a terse, generated table of every variable, see the [environment variables reference](/reference/env/).
