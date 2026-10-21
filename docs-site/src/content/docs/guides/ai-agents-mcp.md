---
title: AI agents & MCP
description: Grant AI agents scoped access to secrets over MCP.
sidebar:
  order: 10
---

:::caution[Experimental]
Agent grants, `murk agent exec`, `murk mcp`, `murk agent connect`/`disconnect` and the agent policy are experimental. They are new and their access rules changed in 0.13.1. A running `murk mcp` server does not see a revocation or policy change until it restarts, so restart it after you revoke. Treat them as a guardrail, not a security boundary.
:::

AI coding agents need secrets to do real work: an API key to call a service, a
database URL to run a migration. The usual way to hand them over is to paste a
value into a prompt or point the agent at a `.env` file. Both can leak. Prompts
are often logged, and sometimes sent to third-party APIs. `.env` files get
committed by accident. And once a value is in a log or a prompt, you can't pull
it back.

murk splits this into two steps.

To understand a project, an agent doesn't need values, it needs to know what
secrets exist. `murk agent plan` prints the schema — key names, descriptions,
and tags — with no decryption and no key involved. The agent writes code and
config against those names without seeing a value.

To run a command, you mint a grant: an ephemeral key that decrypts only the
secrets you name. The agent runs against that grant, never your own key, and
you can revoke it. If a task only needs `STRIPE_KEY`, that's the only thing
the grant can read.

This narrows where secrets are exposed. It doesn't make a leak impossible: a
command the agent runs can still print a value to its own output, and
anything running as your user can read a grant key stored on disk. murk
refuses an expired grant on every read, but the key
itself can't expire and still reads old vault versions with raw age, so
revoke and rotate to close it. murk gives you least-privilege, revocable
access, not a sandbox. For real isolation, run the agent as a separate user
or in a container.

## Rules

1. **Never paste secrets into prompts.** Agent conversations are logged,
   cached, and sometimes sent to third-party APIs. Once a secret is in a
   prompt, assume it's leaked.

2. **Never give agents your `MURK_KEY`.** The key is your identity. If an
   agent has it, it can decrypt everything in the vault, and you can't
   revoke it without re-keying.

3. **Use `murk exec` to inject secrets.** Instead of exporting secrets to the
   shell, run agent commands through `murk exec` so secrets exist only in the
   subprocess environment:

   ```bash
   murk exec -- python deploy.py
   murk exec -- npm run migrate
   ```

   When the agent itself is invoking the command, use `murk agent exec`. It
   requires explicit `--only` keys, clears the inherited environment, strips
   `MURK_KEY`, marks the child as an agent context (`MURK_AGENT=1`), and
   masks the injected values in the command's output. So the run can only see
   the secrets you named and a nested `murk` won't fall back to your stored
   key.

   `agent exec` needs a key handed to it: `MURK_KEY` or `MURK_KEY_FILE`,
   normally pointing at a scoped [grant](/concepts/grants/) key. It refuses to
   decrypt with your personal key that murk would otherwise find on its own in
   `~/.config/murk/keys`, because an agent shell with no `MURK_*` set would
   get it silently. When you are the one running it and mean to use your own
   key, say so with `--allow-operator-key`. murk then prints a one-line
   warning on every run that uses the auto-discovered key. An explicit
   `MURK_KEY` or `MURK_KEY_FILE` is accepted without the flag and without a
   warning:

   ```bash
   MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex murk agent exec --only DATABASE_URL -- npm test
   murk agent exec --allow-operator-key --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   ```

4. **Use `murk agent plan` for schema prompting.** Agents don't need secret
   values to understand what's available. `agent plan` emits key names,
   descriptions, examples, and tags as text or JSON: no decryption, no
   `MURK_KEY`, no recipient metadata:

   ```bash
   murk agent plan            # human-readable
   murk agent plan --json     # machine-readable
   murk agent plan --tag db   # filter by tag
   ```

   It needs no key at all, so it works anywhere the vault file is: the agent
   can run it itself, or you can drop the output into a system prompt. A
   configured MCP server also offers the `murk_plan` tool, filtered to that
   server's grant and policy. Starting that server needs a grant key. However
   it arrives, the agent learns what env vars exist and how to reference them
   without ever seeing a value.

   Reach for `murk info` when you want a fuller picture (recipients, your key
   source, private overrides). Reach for `murk skeleton` when you want a
   distributable vault file shaped like the real one but with `recipients` /
   `secrets` / `meta` blanked.

   Full flags for every command here are in the [CLI reference](/reference/cli/).


![murk agent plan, then a scoped grant the agent runs against: the schema has no values, and every key outside the grant is refused](/demos/agent.gif)

## Agent context

Set `MURK_AGENT=1` to tell murk it's running for an agent. In an agent
context, murk **forces strict mode**. It won't fall back to your stored key
in `~/.config/murk/keys` (the agent must present its own
`MURK_KEY`/`MURK_KEY_FILE`, e.g. a [grant](/concepts/grants/) key, or fail
closed). `murk get`, `murk export` and `murk diff --show-values` refuse to write to a
stdout that is a regular file. `murk edit` requires a RAM-backed tmpdir, and
`murk edit` itself is experimental: its lifecycle is new and its process
handling is Unix-only. Strict mode does not stop a process from writing values
elsewhere: a program that receives them can save them anywhere.

`murk agent exec` sets `MURK_AGENT=1` and `MURK_STRICT=1` for the child, so a
nested `murk` stays strict and won't fall back to your stored key on the
normal path. This is a safe default, **not a sandbox**: a child controls its
own environment, so it can unset those vars or read `~/.config/murk/keys`
directly. For real containment, run agents under a separate user or in a
container (see below). If you want a non-strict shell yourself, just don't
set `MURK_AGENT`. In CI, murk stays out of the way but prints a short hint
toward a scoped grant key when it sees a pipeline decrypting with your
personal key. `murk agent exec` does not wait for CI to object: it refuses a
personal key it discovers on its own unless you pass `--allow-operator-key`,
and then it prints a warning, in CI or not. It accepts any identity you
supply through `MURK_KEY` or `MURK_KEY_FILE`, so supply a scoped grant key,
not your personal key.

**Self-scoping your own key.** The allow-tag policy (see [Restricting which
secrets agents can touch](#restricting-which-secrets-agents-can-touch),
below) normally binds only agent grant keys. `murk get`/`export`/`edit`
with your *own* key ignore it. Set `MURK_SELF_SCOPE=1` (agent context implies
it) to hold your own reads to the policy too: `get`, `exec` (and `agent
exec`), and single-key `edit KEY` fail closed on a non-allowed key. `export`
withholds forbidden keys, with a note on stderr, and murk refuses bulk
`murk edit`. Reach for it when you run an agent in your own shell and want the
guardrail to actually bite. It's still the murk binary enforcing it, not a
sandbox.


![murk agent exec: run a command with only the named secret injected, and no key](/demos/agent-exec.gif)

## Scoped agent grants

`murk agent exec` with a grant key is the safest pattern: the agent's command
gets secret *values* in its environment and never sees a key, and the grant
bounds which values it can reach. The same [grant](/concepts/grants/) key
covers an agent that has to run `murk` itself over a session, for example a
long-running agent that calls `murk get` as it works.

### One-shot setup: `murk agent init`

`murk agent init` does the whole safe-path setup in one command: it
(optionally) sets the allow-list, mints a scoped grant, and (when it writes
a key file) prints the exact run command plus an isolation recipe.

```bash
murk agent init --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent init --name codex --only DATABASE_URL --allow-tag agents --ttl 30m
```

`--allow-tag` sets the vault's agent allow-list before granting: a single
vault write covers both, and a forbidden scope fails closed before anything
is saved. The manual building blocks are below.

`murk agent grant` mints a fresh ephemeral age identity and gives it read
access to exactly the keys you name, never your `MURK_KEY`:

```bash
murk agent grant --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent grant --name codex --only DATABASE_URL --only PG_PASSWORD --ttl 30m
```

It writes the agent key to `~/.config/murk/agent-keys/<vault-hash>-<name>`
(or `--out PATH`, which refuses an existing file unless you pass `--force`, or
`--out -` to stream it to stdout) and prints how to use it. Run the agent with that key and `MURK_AGENT=1` (agent context, strict is
forced) so it won't fall back to your stored key:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The granted key reads only its own keys. Anything else fails closed.
`murk get` reports `KEY is outside this grant's scope`, and `agent exec`
reports `key not found: KEY`. That is a decryption boundary rather
than a check: the grant is excluded from the shared layer entirely, so the
other values were never encrypted to it in the first place.

List and revoke grants:

```bash
murk agent ls                       # name, scope, TTL status
murk agent grant --name codex --only STRIPE_SECRET_KEY --renew   # fresh key, old one revoked
murk agent revoke codex --rotate    # remove the grant and rotate its keys
```

A running `murk mcp` server keeps serving a revoked grant until it restarts,
so restart it (restart the editor) after you revoke.

Three things to keep in mind:

- **murk enforces the TTL at read time. Cryptography does not.** Past its
  expiry a grant fails closed on every read (`murk get`, `agent exec`,
  `murk_get`, `murk_exec`, the bindings), and `agent ls` flags it.
  `murk_plan` still lists the schema of the grant's keys. A running
  `murk mcp` server checks expiry on every `murk_get` and `murk_exec` call,
  but it does not see a revocation or a policy change until it restarts. Age
  keys can't self-destruct, and old vault versions stay readable in git, so a
  leaked grant key still decrypts history with raw age. Revoke the grant and
  rotate its secrets to close the exposure.
- **The key is a bearer credential.** Whoever holds the key file has the
  access. Treat it like the secret it unlocks.
- **Real isolation is the OS's job.** An agent running as you, with read
  access to your home directory, can read `~/.config/murk/keys` directly and
  bypass murk. `MURK_STRICT` stops murk from *handing over* your key, but
  for true containment run the agent in a sandbox, container, or under a
  separate user that can't read your key directory.

## Vault trust and reserved names

**Agents never sign, and never decide what to trust.** An agent grant key is
read-only: a vault signed by a grant key is refused, and `murk trust`
refuses to run under a grant identity. `murk trust` is the human review
step. Don't hand an agent `murk trust --yes`.

**A fresh environment needs `MURK_TRUSTED_SIGNERS`.** murk checks every
vault against the trust pin of the machine it runs on. An agent in a
container, a CI job or any other place with no pin gets "not trusted on this
machine yet", and a grant can't run `murk trust` to fix that. Set
`MURK_TRUSTED_SIGNERS` to the entries of the people who write the vault
(`murk trust --print-key` prints one, as `age1...:<verifying key>` or an
`ssh-ed25519` public key line), from outside the repo. See
[CI/CD](/guides/cicd/#telling-ci-who-may-sign-the-vault).

**The vault can't pick the agent's environment.** Whoever last wrote the
vault chose its key names, so `murk agent exec` refuses to inject a key
named like `PATH`, `HOME`, `NODE_OPTIONS`, `BASH_ENV`, `RUSTFLAGS`, anything
ending in `_PROXY`, or anything starting with `LD_`, `DYLD_`, `GIT_`,
`BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `DOTNET_`, `CARGO_`, `SSL_`,
`PIP_`, `GEM_`, `BUNDLE_`, `NPM_CONFIG_` or `MURK_`, unless you pass
`--allow-reserved`. The MCP `murk_exec` tool always refuses them, with no
override. See [Variable names a vault may not
set](/concepts/env-vars/#variable-names-a-vault-may-not-set) for the full
list.

## Output masking

`murk agent exec` and the MCP `murk_exec` tool replace every injected value
in the command's stdout and stderr with a `***KEY***` placeholder, so an
`env` dump or a debug line doesn't drop a secret into an agent's transcript.
It is on by default, with no flag to turn it off.

:::caution[An accident guard, not a security boundary]
This is the same idea as GitHub Actions' `::add-mask::`. Its limits:

- It matches a value byte for byte. A value that is encoded (base64,
  URL-encoding, hex), transformed, printed only in part, or split between
  stdout and stderr gets through.
- It covers stdout and stderr only. A value the command writes to a file, a
  socket, or another process is not touched.
- Values shorter than **4 bytes** are not masked. Masking `1`, `on`, or `dev`
  would rewrite unrelated output and still not hide a value that short.
- When one value contains another, the longer one wins: the output shows the
  longer key's placeholder.

A command that wants to leak a value it was handed can do so. Masking only
stops the accidental case.
:::

**What changes for the command under `agent exec`.** To see the output,
`agent exec` supervises the command instead of replacing itself with it
(plain `murk exec` still does the latter):

- The command's stdout and stderr are pipes, not your terminal. A program
  that checks for a terminal may drop colour or progress bars, or buffer its
  output differently. stdin is still your terminal.
- murk holds back only the tail of a chunk that could still be the start of
  a value (at most one byte shorter than your longest masked value).
  Everything else is written at once. Each stream is matched on its own.
- murk exits with the command's exit code. If a signal killed the command,
  murk re-raises the same signal.
- Ctrl-C reaches the command once, straight from the terminal. SIGINT,
  SIGTERM, SIGHUP and SIGQUIT sent to murk alone (for example by a harness
  timeout) are forwarded.
- murk waits until both streams close, so a background process that
  inherits them keeps `agent exec` running.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list, and murk will refuse to inject or
grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the agent-usable ones
murk policy set --allow-tag agents              # default-deny everything else
```

Now `agent exec` and `agent grant` only work for keys tagged `agents`. Asking
for an untagged or production key fails closed with a clear error. There is
no override flag, so an agent can't talk its way past the policy.
`agents` is just an example tag. Use whatever tags fit your vault (`dev`,
`ci`, ...). The policy lives in the vault header (MAC-covered, readable with
`murk policy show` even without a key) so it travels with the repo and
applies in CI. The murk binary enforces the policy as a guardrail, not as
access control (see the [threat model](/security/threat-model/)).

A granted agent is held to the policy no matter how it reads: `murk get`,
`murk agent exec`, or the Python/Node bindings (`murk-secrets`). `get()` and
`export()` from the bindings refuse a forbidden key just like the CLI, so the
allow-list is enforced from every entry point. Tightening the policy takes
effect on the next murk process that reads the vault. Drop a tag and the
agent's next `murk get` (run with `MURK_AGENT=1`) or `agent exec` refuses
that key, even though its grant key still exists. A running `murk mcp` server and a loaded binding
object keep the vault state from their last load. Restart the server
(restart the editor) and reload the binding object after you change a
policy or revoke a grant. Grant expiry is the exception: it is checked again
on every value read.

## Serving secrets over MCP (`murk mcp`)

Agent harnesses that speak the
[Model Context Protocol](https://modelcontextprotocol.io) (Claude Code,
Cursor, omp, and others) can reach murk secrets directly through
`murk mcp`, a stdio MCP server built into the binary. It calls murk
in-process (no subprocess, no Node runtime), and the same grant
and policy machinery as everything above binds it.

It runs **only** as a scoped agent: it fails closed unless it is launched
with a grant key **and** `MURK_AGENT=1`. Started with your stored key, a
plain recipient, or no grant, it refuses to start, so an MCP client can
never be handed your full read scope.

```bash
# Mint a scoped grant first (see above), then run the server with it:
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 murk mcp
```

The server loads the vault once, at startup. Restart it after you revoke a
grant or change the policy. Grant expiry is checked on every `murk_get` and
`murk_exec` call.

### One-command wiring: `murk agent connect`

Rather than hand-edit each editor's MCP config, let murk do it — minting the
grant and writing the config in one step:

```bash
# Auto-detect the editors this repo uses and wire them all:
murk agent connect --only STRIPE_SECRET_KEY --only DATABASE_URL --ttl 2h

# ...or target one (claude, cursor, vscode, zed, gemini, omp, codex):
murk agent connect cursor --only STRIPE_SECRET_KEY
```

`connect` mints one scoped grant for the vault and writes each editor's
project-local config, pointing at `murk mcp` with `MURK_KEY_FILE`,
`MURK_AGENT=1`, and an empty `MURK_KEY` (murk refuses to run with both key
variables set, so the entry masks one the editor passes down from your shell):

| Editor | Config file | Format |
| --- | --- | --- |
| Claude Code | `.mcp.json` | JSON |
| Cursor | `.cursor/mcp.json` | JSON |
| VS Code | `.vscode/mcp.json` | JSON |
| Zed | `.zed/settings.json` | JSON |
| Gemini CLI | `.gemini/settings.json` | JSON |
| omp | `.omp/mcp.json` | JSON |
| Codex | `.codex/config.toml` | TOML |

It writes only a key-file **path**, never key material, and preserves any
other servers and comments already in the file. Add `--allow-exec` to also
expose the exec tool. Because these files are often committed, murk warns and
offers to add the path to `.gitignore`.

`murk agent disconnect [CLIENT]` removes only murk's entry, leaving other
servers untouched. It leaves the grant live. Add `--rotate` to revoke the
grant and rotate the keys it could read.

`--only` is required and repeatable. The grant is named `mcp` (change it
with `--name`) and expires after 2 hours (change it with `--ttl`). Running
`connect` again reuses an existing grant with the same scope, and fails with
a fix to run if the scope differs. When the grant expires, the editor's murk
tools fail with `grant mcp expired`. Renew it with
`murk agent grant --name mcp --only STRIPE_SECRET_KEY --renew`, which
rewrites the same key file, then restart the editor.

![murk agent connect mints a scoped grant and writes the editor's MCP entry with a key-file path; a read outside the grant fails closed, and disconnect --rotate revokes and rotates](/demos/agent-connect.gif)

The server speaks JSON-RPC over stdout and logs only to stderr, so point
your MCP client at that command with `MURK_KEY_FILE` and `MURK_AGENT=1` in
its environment. It exposes two always-on read tools bounded to the grant,
plus an opt-in exec tool:

- **`murk_plan`**: lists the key names, descriptions, examples and tags of
  the secrets *this grant may read*, as JSON. It returns no values and omits
  keys outside the grant or the agent policy. That limits the tool only. The
  schema is plaintext in `.murk`, so an agent that can read the file or run
  `murk agent plan` still sees every key name. Takes an optional `tags`
  filter.
- **`murk_get { key }`**: returns one secret value if the grant may read
  it. The value lands in the model's context, so it ends up in the agent's
  transcript. Prefer `murk_exec` (or `murk agent exec`) when the command can
  take the secret from its environment. A key outside the grant or forbidden
  by the agent policy returns an error result, never the value.
- **`murk_exec { only, command }`**: off unless you start the server with
  `murk mcp --allow-exec`. Runs `command` (an argv array, no shell) with the
  secrets named in `only` injected into its environment. It returns
  `exit_code`, `stdout`, `stderr` and `truncated` as JSON, with the injected
  values masked (see [Output masking](#output-masking), above). Every key in
  `only` must be in the grant's scope and allowed by the policy, or nothing
  runs. The command gets a clean environment (`PATH`, `HOME` and `TERM` on
  Unix, plus `MURK_AGENT=1` and `MURK_STRICT=1`), no stdin, a 120-second
  timeout and 1 MiB per output stream. murk kills it past either limit. A
  non-zero exit or a truncated stream returns an error result. `only` limits
  the injected secrets, not the command. The command runs as your user with
  your filesystem and network access, so `murk_exec` is **not a sandbox**.
  Enable it only where the server already runs under OS-level isolation.

You can verify it end to end without a client by driving the handshake over
a pipe:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | MURK_KEY_FILE=<grant> MURK_AGENT=1 murk mcp
```

The transport is a local stdio pipe, not a network listener. The grant
bounds which secret *values* reach the agent (the capability-not-credential
model). But `murk_exec` (when enabled) runs real commands as your user, so
treat it like `murk agent exec`: a safe default, not a sandbox, with
OS-level isolation the real boundary (see
[Scoped agent grants](#scoped-agent-grants), above).
For an editor murk doesn't wire automatically yet, add the same `murk mcp`
entry (with `MURK_KEY_FILE`, `MURK_AGENT=1`, and an empty `MURK_KEY`) to that
harness's MCP config by hand.

## Check the code an agent wrote

Agents can hardcode a secret they were handed. After an agent edits code,
run `murk scan`. It reports any value your key can read, 8 bytes or longer,
that appears verbatim in a text file in your working tree. It skips hidden
directories, `target/`, `node_modules/`, `.murk` and `.lock` files, and
binary files. It exits with status 1 on a finding. It can't see an encoded
or partial copy, or a value your key can't read.

![murk scan flags a vault value hardcoded into a file, then reports clean after the fix](/demos/agent-scan.gif)

## Auditing agent activity

murk keeps no separate agent log. Commit each vault change and git becomes
the record:

```bash
git log -p .murk        # who changed the vault and when
murk diff HEAD~1        # which secrets changed in the last commit
```

`git log -p .murk` attributes each change to its commit author (and to the
commit signature, if you sign commits). The diff shows policy edits and
added or removed recipient keys in plaintext. A new grant shows up as a new
recipient key and new `scoped` ciphertexts under the secrets it can read, so
the diff shows which secrets that key can read. Its name, TTL and issuer are
encrypted and appear only as a changed `meta` blob. `murk diff` also lists recipients added and removed, signer changes, and policy, grant and group-member changes, and it verifies the old revision's MAC and signature before it shows anything from it. Git can't show
secret reads on a developer's machine, because murk never sees them. Don't
treat the absence of a read trail as proof a secret wasn't used. See the
[threat model](/security/threat-model/) for the full audit boundary.
