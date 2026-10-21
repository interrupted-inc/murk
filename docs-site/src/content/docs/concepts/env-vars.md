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
| `MURK_KEY_FILE` | Path to a file holding your private key: a raw age key, an SSH PEM key, or an age plugin identity file (with a `# Recipient:` or `# public key:` header). `murk init` writes this variable into `.env`. |
| `MURK_VAULT` | Vault filename, defaulting to `.murk`. Equivalent to passing `--vault` on every command. |

murk resolves your identity from `MURK_KEY` or `MURK_KEY_FILE`, then from an automatic lookup at `~/.config/murk/keys/<vault-hash>` (the file `murk init` writes). Set one of the two variables, not both: murk refuses to run when both are non-empty rather than guess which key you meant, and an empty value counts as unset. The automatic step is disabled whenever strict mode is active (see below), so an agent context always needs an explicit key of its own.

`.env` is a write-only convenience. `murk init` puts a `MURK_KEY_FILE` reference in it so you can `source .env`, or load it with direnv's `dotenv` command. The `.envrc` that `murk env` writes does not load it, because direnv finds the key through the stored-key lookup. murk never reads `.env` to find a key. Otherwise a vault copied into another repo could borrow whatever key that directory's `.env` points to. murk uses only the process environment and the stored-key lookup. (`murk doctor` and `murk init` read `.env` to check it for an inline `MURK_KEY`, and `murk import` imports from it.)

The automatic lookup is keyed on the vault's absolute path, and a git worktree puts the same committed vault at a different one. So murk also accepts the key stored for that vault in a sibling worktree of the same repository — the main checkout first, then linked worktrees. A fresh worktree needs no key provisioning: check it out and `murk get` works, with no `.env` to copy and nothing to re-run. Only checkouts git itself records as part of the repository count, verified in both directions against git's own metadata, so a copied vault in a directory that merely *claims* to be a worktree still gets nothing. Strict mode and agent context skip the automatic lookup entirely, worktree or not.

## Safety and agent context

:::caution[Experimental]
Strict mode (`MURK_STRICT`, and the strict mode that `MURK_AGENT` forces) is experimental. It is four specific checks, listed below, not a guarantee that no plaintext touches disk.
:::

| Variable | Description |
| --- | --- |
| `MURK_STRICT` | Experimental. Any value except unset, empty, `0`, `false`, `no` and `off` (any letter case; a typo turns it on) fails closed rather than let a secret touch disk. `murk edit` aborts before it starts the editor unless its scratch file is on a RAM-backed filesystem. `export`, `get` and `diff --show-values` refuse to run when stdout is a regular file. murk skips the stored-key lookup in `~/.config/murk/keys`. It also refuses a result that no key checked, such as `murk rotate --list` run without a key. |
| `MURK_AGENT` | Marks the process as running on behalf of an AI agent. Forces strict mode unconditionally: there's no way to turn strict back off from inside an agent context, even by setting `MURK_STRICT=0`. `murk agent exec` sets it (alongside `MURK_STRICT=1`) on its child process automatically. |
| `MURK_SELF_SCOPE` | Read like `MURK_STRICT` (any value except unset, empty, `0`, `false`, `no` and `off`). Holds *your own* key to the vault's agent allow-tag policy, as if you were an agent: `get`, `exec`/`agent exec`, and single-key `edit KEY` fail closed on a non-allowed key, `export` withholds forbidden keys, and bulk `edit` is refused. Implied automatically inside an agent context. A no-op on a vault with no policy set. See [Grants](/concepts/grants/). |
| `MURK_TRUSTED_SIGNERS` | Signers trusted to sign the vault, separated by commas or newlines. An age signer is `age1...:<verifying key>` (the recipient, a colon, the base64 Ed25519 verifying key); an `ssh-ed25519` signer is its public key line. `murk trust --print-key` prints the entry for your own key. For CI runners and other machines with no [trust pin](/concepts/recipients-signatures/#trusting-a-signer): set it from a CI secret next to `MURK_KEY`. When set, it replaces the pin's trusted set, an age signer's signature has to verify under the verifying key given here, and it makes an unsigned vault an error even for a key that can't sign. Trust that comes from this variable is not written into the pin, so it never widens what the machine trusts once the variable is gone. Agent grant keys listed here still never count, and an entry in neither form, including a bare `age1...` key without its verifying key, is an error. |
| `MURK_NO_SIGNER_PIN` | Any value counts, including `0` and an empty string, so unset the variable to turn it off. murk neither reads nor writes the local trust pin, so trust comes only from `MURK_TRUSTED_SIGNERS`. It doesn't switch the trust check off: without `MURK_TRUSTED_SIGNERS`, every signed vault is refused, and rollback and stripped-signature detection are off. A machine with no home directory behaves the same way. |

## Also honored

A few standard variables shape specific commands, without being murk-specific configuration:

| Variable | Description |
| --- | --- |
| `CI` | Truthy value (`1`, `true`, `yes`). When murk decrypts with the stored key from `~/.config/murk/keys`, it prints a hint to use a scoped grant key instead. It does not change behaviour, and it stays quiet with an explicit key, in agent context and in strict mode. |
| `EDITOR`, `VISUAL` | `murk edit` opens this editor for interactive edits, checking `EDITOR` then `VISUAL`, falling back to `vi` if neither is set. On Unix the value runs through `sh`, as git does, so it can carry arguments (`code --wait`). The editor doesn't inherit `MURK_KEY` or `MURK_KEY_FILE`. |
| `XDG_RUNTIME_DIR` | Where `murk edit` puts its scratch file when the directory exists. It is usually a tmpfs, so the plaintext stays off persistent storage. Otherwise murk uses `/dev/shm` on Unix when it is RAM-backed, and then the system temporary directory (`$TMPDIR`, or `/tmp`). murk warns when the scratch file is not on a RAM-backed filesystem. |
| `HOME` (`USERPROFILE` on Windows) | Base for murk's state under `~/.config/murk`: `keys`, `agent-keys` and `signer-pins` (the trust pins). murk does not use `XDG_CONFIG_HOME`. |

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

[How murk works](/concepts/how-it-works/) covers the identity and layering model these variables configure. [Grants](/concepts/grants/) shows `MURK_AGENT` and a grant key in a real invocation. [Hardware-backed keys](/guides/hardware-keys/) covers pointing `MURK_KEY_FILE` at a plugin identity. [direnv integration](/guides/direnv/) covers how the key reaches murk under direnv. For a terse, generated table of every variable, see the [environment variables reference](/reference/env/).
