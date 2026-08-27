# Using murk with AI agents

AI coding agents need secrets — API keys, database URLs, service tokens. The common pattern is pasting them into `.env` files or chat prompts. Both are bad: prompts get logged, `.env` files get committed, and there's no way to revoke access when the session ends.

murk gives agents access to secrets without exposing them in plaintext.

## Rules

1. **Never paste secrets into prompts.** Agent conversations are logged, cached, and sometimes sent to third-party APIs. Once a secret is in a prompt, assume it's leaked.

2. **Never give agents your `MURK_KEY`.** The key is your identity. If an agent has it, it can decrypt everything in the vault — and you can't revoke it without re-keying.

3. **Use `murk exec` to inject secrets.** Instead of exporting secrets to the shell, run agent commands through `murk exec` so secrets exist only in the subprocess environment:

   ```bash
   murk exec -- python deploy.py
   murk exec -- npm run migrate
   ```

   When the agent itself is invoking the command, use `murk agent exec`. It requires explicit `--only` keys, clears the inherited environment, strips `MURK_KEY`, and marks the child as an agent context (`MURK_AGENT=1`) — so the run can only see the secrets you named and a nested `murk` won't fall back to your stored key:

   ```bash
   murk agent exec --only DATABASE_URL -- npm test
   murk agent exec --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
   ```

4. **Use `murk agent plan` for schema prompting.** Agents don't need secret values to understand what's available. `agent plan` emits key names, descriptions, examples, and tags as text or JSON — no decryption, no `MURK_KEY`, no recipient metadata:

   ```bash
   murk agent plan            # human-readable
   murk agent plan --json     # machine-readable
   murk agent plan --tag db   # filter by tag
   ```

   It needs no key at all, so it works anywhere the vault file is: the agent can run it itself, a harness can call the `murk_plan` MCP tool (see below), or you can drop the output into a system prompt. However it arrives, the agent learns what env vars exist and how to reference them without ever seeing a value.

   Reach for `murk info` when you want a fuller picture (recipients, your key source, private overrides). Reach for `murk skeleton` when you want a distributable vault file shaped like the real one but with `recipients` / `secrets` / `meta` blanked.

## Agent context

Set `MURK_AGENT=1` to tell murk it's running for an agent. In an agent context, **strict mode is forced**: murk won't fall back to your stored key in `~/.config/murk/keys` (the agent must present its own `MURK_KEY`/`MURK_KEY_FILE` — e.g. a grant key — or fail closed), won't write plaintext secrets to a file, and requires a RAM-backed tmpdir for `murk edit`.

`murk agent exec` sets `MURK_AGENT=1` and `MURK_STRICT=1` for the child, so a nested `murk` stays strict and won't fall back to your stored key on the normal path. This is a safe default, **not a sandbox**: a child controls its own environment, so it can unset those vars or read `~/.config/murk/keys` directly — for real containment, run agents under a separate user or in a container (see below). If you want a non-strict shell yourself, just don't set `MURK_AGENT`. In CI, murk stays out of the way but prints a nudge toward the scoped path when it sees a pipeline decrypting with your personal key.

**Self-scoping your own key.** The allow-tag policy (see _Restricting which secrets agents can touch_, below) normally binds only agent grant keys — `murk get`/`export`/`edit` with your _own_ key ignore it. Set `MURK_SELF_SCOPE=1` (agent context implies it) to hold your own reads to the policy too: `get`, `exec` (and `agent exec`), and single-key `edit KEY` fail closed on a non-allowed key; `export` withholds forbidden keys (with a note on stderr); and bulk `murk edit` is refused. Reach for it when you run an agent in your own shell and want the guardrail to actually bite — it's still the murk binary enforcing it, not a sandbox.

## Scoped agent grants

`murk agent exec` is the safest pattern: the agent's command gets secret _values_ in its environment and never sees a key. Reach for a **grant** when the agent has to run `murk` itself over a session — for example a long-running agent that calls `murk get` as it works.

### One-shot setup: `murk agent init`

`murk agent init` does the whole safe-path setup in one command: it (optionally) sets the allow-list, mints a scoped grant, and — when it writes a key file — prints the exact run command plus an isolation recipe.

```bash
murk agent init --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent init --name codex --only DATABASE_URL --allow-tag agents --ttl 30m
```

`--allow-tag` sets the vault's agent allow-list before granting — a single vault write covers both, and a forbidden scope fails closed before anything is saved. The manual building blocks are below.

`murk agent grant` mints a fresh ephemeral age identity and gives it read access to exactly the keys you name — never your `MURK_KEY`:

```bash
murk agent grant --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent grant --name codex --only DATABASE_URL --only PG_PASSWORD --ttl 30m --renew
```

A grant name stays unique: re-minting a live name is refused unless you pass `--renew`, which revokes the old key and mints a fresh one under the same name in a single vault write — handy when a short TTL lapses mid-session.

It writes the agent key to `~/.config/murk/agent-keys/<vault-hash>-<name>` (or `--out PATH`, or `--out -` to stream it to stdout) and prints how to use it. Run the agent with that key and `MURK_AGENT=1` (agent context — strict is forced) so it won't fall back to your stored key:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The granted key reads only its keys — anything else fails closed with `KEY is outside this grant's scope`. That is a decryption boundary rather than a check: the grant is excluded from the shared layer entirely, so the other values were never encrypted to it in the first place.

List and revoke grants:

```bash
murk agent ls                       # name, scope, TTL status
murk agent revoke codex --rotate    # remove the grant and rotate its keys
```

Three things to keep in mind:

- **The TTL is enforced at read time — by murk, not cryptography.** Past its expiry a grant fails closed at every entry point (`murk get`, `agent exec`, MCP, the bindings), and `agent ls` flags it. But age keys can't self-destruct, and old vault versions stay readable in git, so a leaked grant key still decrypts history with raw age. Revoke + rotate is the real close.
- **The key is a bearer credential.** Whoever holds the key file has the access. Treat it like the secret it unlocks.
- **Real isolation is the OS's job.** An agent running as you, with read access to your home directory, can read `~/.config/murk/keys` directly and bypass murk. `MURK_STRICT` stops murk from _handing over_ your key, but for true containment run the agent in a sandbox, container, or under a separate user that can't read your key directory.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list, and murk will refuse to inject or grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the agent-usable ones
murk policy set --allow-tag agents              # default-deny everything else
```

Now `agent exec` and `agent grant` only work for keys tagged `agents`; asking for an untagged or production key fails closed with a clear error — there's no override flag, so a misbehaving agent can't talk its way past it. `agents` is just an example tag; use whatever tags fit your vault (`dev`, `ci`, ...). The policy lives in the vault header (MAC-covered, readable with `murk policy show` even without a key) so it travels with the repo and applies in CI. Note this is a guardrail enforced by the murk binary, not access control — see THREAT_MODEL.md.

A granted agent is held to the policy no matter how it reads — `murk get`, `murk agent exec`, or the Python/Node bindings (`murk-secrets`). `get()` and `export()` from the bindings refuse a forbidden key just like the CLI, so the allow-list is enforced from every entry point. Tightening the policy applies retroactively: drop a tag and the agent loses access on its next read, even though its old grant key still exists.

## Serving secrets over MCP (`murk mcp`)

Agent harnesses that speak the [Model Context Protocol](https://modelcontextprotocol.io) — Claude Code, Cursor, omp, and others — can reach murk secrets directly through `murk mcp`, a stdio MCP server built into the binary. It calls murk in-process (no subprocess, no Node runtime) and is bound by the same grant and policy machinery as everything above.

It runs **only** as a scoped agent: it fails closed unless it is launched with a grant key **and** `MURK_AGENT=1`. Started with your stored key, a plain recipient, or no grant, it refuses to start — so an MCP client can never be handed your full read scope.

```bash
# Mint a scoped grant first (see above), then run the server with it:
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 murk mcp
```

The server speaks JSON-RPC over stdout and logs only to stderr, so point your MCP client at that command with `MURK_KEY_FILE` and `MURK_AGENT=1` in its environment. It exposes two always-on read tools bounded to the grant, plus an opt-in exec tool:

- **`murk_plan`** — the schema (key names, descriptions, examples, tags) of the secrets _this grant may read_, as JSON. No values, and no keys outside the grant's scope or the vault's agent policy — a narrowly-scoped agent can't even enumerate what else the vault holds. Takes an optional `tags` filter.
- **`murk_get { key }`** — one secret value, if the grant may read it. A key outside the grant's scope or forbidden by the agent policy returns an error result and never the value: fail-closed, like every other agent path.
- **`murk_exec { only, command }`** — _opt-in_, enabled with `murk mcp --allow-exec`. Runs a command with the named secrets injected into its environment (no shell), returning captured stdout, stderr, and the exit code. Every key in `only` must be in the grant's scope and policy-allowed, or it fails closed before running anything; output and runtime are bounded. The caveat: `only` scopes the injected _secrets_, not the command — it runs as your user with your filesystem and network access, so it is **not a sandbox**. Enable it only where the server already runs under OS-level isolation.

You can verify it end to end without a client by driving the handshake over a pipe:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | MURK_KEY_FILE=<grant> MURK_AGENT=1 murk mcp
```

The transport is a local stdio pipe, not a network listener. The grant bounds which secret _values_ reach the agent — the capability-not-credential model — but `murk_exec` (when enabled) runs real commands as your user, so treat it like `murk agent exec`: a safe default, not a sandbox, with OS-level isolation the real boundary (see _Scoped agent grants_ above).

### Where the MCP entry goes

`murk agent connect` writes the wiring for you, but only for hosts that manage their own MCP servers. There are two shapes, and getting them confused fails silently.

**The editor manages its own MCP servers.** Claude Code, Cursor, VS Code, Zed, Gemini CLI, omp, and Codex each read a project-local config file (`.mcp.json`, `.codex/config.toml`, and so on). `murk agent connect` writes the `murk` entry there — the command, its args, and an `env` block carrying `MURK_KEY_FILE` (a path, never the key) and `MURK_AGENT=1`. The editor launches `murk mcp` with that env, so the grant and agent context reach the server. Run `murk agent connect <editor>`, or let it auto-detect from the config files and marker directories already in the repo.

**The host delegates MCP to a provider CLI it wraps.** Some agentic IDEs don't manage MCP servers themselves — they run one of the provider CLIs above on your behalf and only render its MCP tool-call events. bb is one: it shows MCP activity but exposes no MCP config surface of its own. Here the `murk` entry belongs in the _provider's_ config, not the IDE's — Claude Code's `.mcp.json` or Codex's `.codex/config.toml` — and `MURK_KEY_FILE`/`MURK_AGENT` must reach the provider process that launches `murk mcp`, not the IDE process around it. So connect the provider, not the wrapper: `murk agent connect claude` (or `codex`) writes the entry to the file the provider actually reads, with the env in that entry's own block.

To tell which case you're in: if your IDE is one of the editors above and has its own MCP settings, connect it directly. If it isn't — and it works by driving Claude Code, Codex, or another provider CLI underneath — you're in the delegating case, so connect that provider instead. The failure mode is quiet: wire the wrong layer and the agent gets a config it never reads, or a grant key the provider never sees, with no error to point at.

## Configuring your agent harness

An agent harness — Claude Code, Cursor, and the like — can auto-approve some murk commands and prompt for confirmation on the rest. The split is mechanical, not a judgement call. Commands that read only the vault header and the plaintext schema need no key and expose no values. Commands that decrypt, mutate the vault, or change who can decrypt do. Auto-approve the first set; require confirmation for the second.

**Allow — no key, no decryption, no mutation.**

| Command                                     | Why it's safe                                                                          |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| `murk info`, `murk info --json`             | Reads the header — recipients, key source, counts. No values, and the key is optional. |
| `murk agent plan`, `murk agent plan --json` | Emits the schema (key names, descriptions, tags). No values.                           |
| `murk skeleton`                             | Writes a copy of the vault shape with recipients, secrets, and meta blanked.           |
| `murk circle`                               | Lists recipients from the header. The key is optional.                                 |
| `murk doctor`                               | Repo-hygiene checks over the working tree and the plaintext schema. No key.            |

**Ask — decrypts, mutates, or changes trust.**

| Command                                               | Why it needs confirmation                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `murk add`, `murk rm`, `murk describe`, `murk import` | Write to the vault.                                                                                      |
| `murk get`, `murk export`                             | Decrypt secret values and return them.                                                                   |
| `murk diff`, `murk diff --show-values`                | Decrypt the old and current values to compute the diff; `--show-values` also prints them.                |
| `murk verify`                                         | Loads and decrypts the whole vault to check integrity — reveals no values, but needs the key.            |
| `murk scan`                                           | Decrypts every secret to search the working tree for leaked values.                                      |
| `murk env`                                            | Writes an `.envrc` that runs `murk export` — sets up ambient decryption of your full scope in the shell. |
| `murk authorize`, `murk revoke`                       | Change who can decrypt the vault.                                                                        |
| `murk init`, `murk recover`, `murk restore`           | Create or rewrite vault or key material.                                                                 |
| `murk exec -- CMD`                                    | Decrypts your full scope into a subprocess; use `murk agent exec` instead.                               |

**Special case: `murk agent exec --only KEY -- CMD`.** The wrapper is safe by design — it clears the inherited environment, strips `MURK_KEY`, injects only the named secrets, and marks the child as an agent context. It needs no confirmation. But the inner `CMD` still runs as your user with your filesystem and network access, so it must pass the harness's normal command rules like any other command it would run.

**Why the split holds.** Under `murk agent exec` the subprocess has no `MURK_KEY`, so every command that needs decryption fails closed. The allow list is exactly the set that still works in that state — the commands that read the header and schema and nothing more. That is what makes it safe to auto-approve: stripped of a key, nothing on the list can produce a secret value even if asked to.

## Auditing agent activity

There's no separate agent log to consult — **git is the record.** Every admin change to a grant or policy is a commit, so:

```bash
git log -p .murk        # who created/revoked grants, changed policy, rotated values
murk diff               # the same changes for the latest revision, decoded
```

Each shows the change attributed to its commit author (and signed, if you use git commit signing). What git _can't_ show is secret reads on a developer's machine — murk never sees those — so don't treat the absence of a read trail as proof a secret wasn't used. See THREAT_MODEL.md for the full audit boundary.
