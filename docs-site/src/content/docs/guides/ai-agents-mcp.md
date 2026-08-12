---
title: AI agents & MCP
description: Grant AI agents scoped access to secrets over MCP.
sidebar:
  order: 9
---

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
anything running as your user can read a grant key stored on disk. A grant's
TTL is a reminder to revoke rather than an expiry — nothing stops an old
grant key from working until you revoke and rotate. murk gives you
least-privilege, revocable access, not a sandbox. For real isolation, run the
agent as a separate user or in a container.

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
   `MURK_KEY`, and marks the child as an agent context (`MURK_AGENT=1`). So
   the run can only see the secrets you named and a nested `murk` won't fall
   back to your stored key:

   ```bash
   murk agent exec --only DATABASE_URL -- npm test
   murk agent exec --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
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
   can run it itself, a harness can call the `murk_plan` MCP tool, or you can
   drop the output into a system prompt. However it arrives, the agent learns
   what env vars exist and how to reference them without ever seeing a value.

   Reach for `murk info` when you want a fuller picture (recipients, your key
   source, private overrides). Reach for `murk skeleton` when you want a
   distributable vault file shaped like the real one but with `recipients` /
   `secrets` / `meta` blanked.

   Full flags for every command here are in the [CLI reference](/reference/cli/).


![murk agent plan, then a scoped grant the agent runs against: the schema has no values, and every key outside the grant is refused](/demos/agent.gif)

## Agent context

Set `MURK_AGENT=1` to tell murk it's running for an agent. In an agent
context, murk **forces strict mode**: it won't fall back to your stored key
in `~/.config/murk/keys` (the agent must present its own
`MURK_KEY`/`MURK_KEY_FILE`, e.g. a [grant](/concepts/grants/) key, or fail
closed), won't write plaintext secrets to a file, and requires a RAM-backed
tmpdir for `murk edit`.

`murk agent exec` sets `MURK_AGENT=1` and `MURK_STRICT=1` for the child, so a
nested `murk` stays strict and won't fall back to your stored key on the
normal path. This is a safe default, **not a sandbox**: a child controls its
own environment, so it can unset those vars or read `~/.config/murk/keys`
directly. For real containment, run agents under a separate user or in a
container (see below). If you want a non-strict shell yourself, just don't
set `MURK_AGENT`. In CI, murk stays out of the way but prints a one-line
nudge toward the scoped path when it sees a pipeline decrypting with your
personal key.

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

`murk agent exec` is the safest pattern: the agent's command gets secret
*values* in its environment and never sees a key. Reach for a
[grant](/concepts/grants/) when the agent has to run `murk` itself over a
session, for example a long-running agent that calls `murk get` as it
works.

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
(or `--out PATH`, or `--out -` to stream it to stdout) and prints how to use
it. Run the agent with that key and `MURK_AGENT=1` (agent context, strict is
forced) so it won't fall back to your stored key:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The granted key reads only its keys. Anything else fails closed with
`KEY is outside this grant's scope`. That is a decryption boundary rather
than a check: the grant is excluded from the shared layer entirely, so the
other values were never encrypted to it in the first place.

List and revoke grants:

```bash
murk agent ls                       # name, scope, TTL status
murk agent revoke codex --rotate    # remove the grant and rotate its keys
```

Three things to keep in mind:

- **The TTL is advisory.** age keys can't self-destruct, and old vault
  versions stay readable in git, so a leaked grant key works until you
  `agent revoke` and rotate. The TTL tells you *when* to revoke. `agent ls`
  flags expired grants. Revoke + rotate is the real close.
- **The key is a bearer credential.** Whoever holds the key file has the
  access. Treat it like the secret it unlocks.
- **Real isolation is the OS's job.** An agent running as you, with read
  access to your home directory, can read `~/.config/murk/keys` directly and
  bypass murk. `MURK_STRICT` stops murk from *handing over* your key, but
  for true containment run the agent in a sandbox, container, or under a
  separate user that can't read your key directory.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list, and murk will refuse to inject or
grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the agent-usable ones
murk policy set --allow-tag agents              # default-deny everything else
```

Now `agent exec` and `agent grant` only work for keys tagged `agents`. Asking
for an untagged or production key fails closed with a clear error. There's
no override flag, so a misbehaving agent can't talk its way past it.
`agents` is just an example tag. Use whatever tags fit your vault (`dev`,
`ci`, ...). The policy lives in the vault header (MAC-covered, readable with
`murk policy show` even without a key) so it travels with the repo and
applies in CI. Note this is a guardrail enforced by the murk binary, not
access control: see the [threat model](/security/threat-model/).

A granted agent is held to the policy no matter how it reads: `murk get`,
`murk agent exec`, or the Python/Node bindings (`murk-secrets`). `get()` and
`export()` from the bindings refuse a forbidden key just like the CLI, so the
allow-list is enforced from every entry point. Tightening the policy applies
retroactively: drop a tag and the agent loses access on its next read, even
though its old grant key still exists.

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
project-local config, pointing at `murk mcp` with `MURK_KEY_FILE` and
`MURK_AGENT=1`:

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
servers untouched. Add `--rotate` to revoke the grant and rotate the keys it
could read.

The server speaks JSON-RPC over stdout and logs only to stderr, so point
your MCP client at that command with `MURK_KEY_FILE` and `MURK_AGENT=1` in
its environment. It exposes two always-on read tools bounded to the grant,
plus an opt-in exec tool:

- **`murk_plan`**: the schema (key names, descriptions, examples, tags) of
  the secrets *this grant may read*, as JSON. No values, and no keys outside
  the grant's scope or the vault's agent policy: a narrowly-scoped agent
  can't even enumerate what else the vault holds. Takes an optional `tags`
  filter.
- **`murk_get { key }`**: one secret value, if the grant may read it. A key
  outside the grant's scope or forbidden by the agent policy returns an
  error result and never the value: fail-closed, like every other agent
  path.
- **`murk_exec { only, command }`**: *opt-in*, enabled with
  `murk mcp --allow-exec`. Runs a command with the named secrets injected
  into its environment (no shell), returning captured stdout, stderr, and
  the exit code. Every key in `only` must be in the grant's scope and
  policy-allowed, or it fails closed before running anything. Output and
  runtime are bounded. The caveat: `only` scopes the injected *secrets*, not
  the command: it runs as your user with your filesystem and network
  access, so it is **not a sandbox**. Enable it only where the server
  already runs under OS-level isolation.

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
entry (with `MURK_KEY_FILE` and `MURK_AGENT=1`) to that harness's MCP config
by hand.

## Check the code an agent wrote

Agents can accidentally hardcode a secret they were handed. `murk scan` compares files in your working tree against the vault's decrypted values and flags any leak. Run it after an agent edits code.

![murk scan flags a vault value hardcoded into a file, then reports clean after the fix](/demos/agent-scan.gif)

## Auditing agent activity

There's no separate agent log to consult. **git is the record.** Every
admin change to a grant or policy is a commit, so:

```bash
git log -p .murk        # who created/revoked grants, changed policy, rotated values
murk diff               # the same changes for the latest revision, decoded
```

Each shows the change attributed to its commit author (and signed, if you
use git commit signing). What git *can't* show is secret reads on a
developer's machine (murk never sees those). So don't treat the absence of
a read trail as proof a secret wasn't used. See the
[threat model](/security/threat-model/) for the full audit boundary.
