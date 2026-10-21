# Using murk with AI agents

AI coding agents need secrets: API keys, database URLs, service tokens. The usual ways to hand them over are chat prompts and `.env` files. Prompts get logged and `.env` files get committed. Neither lets you revoke access when the session ends.

murk gives an agent only the secrets a task needs, for a limited time, without handing over your key. The values still reach the agent's command (or the agent itself) in plaintext. Use a scoped grant, and keep values out of prompts and transcripts.

## Rules

1. **Never paste secrets into prompts.** Agent conversations are logged, cached, and sometimes sent to third-party APIs. Once a secret is in a prompt, assume it's leaked.

2. **Never give agents your `MURK_KEY`.** The key is your identity. If an agent has it, it can decrypt everything in the vault — and you can't revoke it without re-keying.

3. **Use `murk exec` to inject secrets.** Instead of exporting secrets to the shell, run agent commands through `murk exec` so secrets exist only in the subprocess environment:

   ```bash
   murk exec -- python deploy.py
   murk exec -- npm run migrate
   ```

   When the agent itself is invoking the command, use `murk agent exec`. It requires explicit `--only` keys, clears the inherited environment, strips `MURK_KEY`, marks the child as an agent context (`MURK_AGENT=1`), and masks the injected values in the command's output — so the run can only see the secrets you named and a nested `murk` won't fall back to your stored key.

   `agent exec` needs a key handed to it: `MURK_KEY` or `MURK_KEY_FILE`, normally pointing at a scoped grant key (see _Scoped agent grants_, below). It refuses to decrypt with your personal key that murk would otherwise find on its own in `~/.config/murk/keys`, because an agent shell with no `MURK_*` set would get it silently. When you are the one running it and mean to use your own key, say so with `--allow-operator-key`. murk then prints a one-line warning on every run that uses the auto-discovered key. An explicit `MURK_KEY` or `MURK_KEY_FILE` is accepted without the flag and without a warning:

   ```bash
   MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex murk agent exec --only DATABASE_URL -- npm test
   murk agent exec --allow-operator-key --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   ```

4. **Use `murk agent plan` for schema prompting.** Agents don't need secret values to understand what's available. `agent plan` emits key names, descriptions, examples, and tags as text or JSON — no decryption, no `MURK_KEY`, no recipient metadata:

   ```bash
   murk agent plan            # human-readable
   murk agent plan --json     # machine-readable
   murk agent plan --tag db   # filter by tag
   ```

   It needs no key at all, so it works anywhere the vault file is: the agent can run it itself, or you can drop the output into a system prompt. A configured MCP server also offers the `murk_plan` tool (see below), filtered to that server's grant and policy. Starting that server needs a grant key. However it arrives, the agent learns what env vars exist and how to reference them without ever seeing a value.

   Reach for `murk info` when you want a fuller picture (recipients, your key source, private overrides). Reach for `murk skeleton` when you want a distributable vault file shaped like the real one but with `recipients` / `secrets` / `meta` blanked.

## Agent context

Set `MURK_AGENT=1` to tell murk it's running for an agent. In an agent context, **strict mode is forced**. murk won't fall back to your stored key in `~/.config/murk/keys` (the agent must present its own `MURK_KEY`/`MURK_KEY_FILE`, e.g. a grant key, or fail closed). `murk get` and `murk export` refuse to write to a stdout that is a regular file. `murk edit` requires a RAM-backed tmpdir. murk refuses a vault that was signed before and is now unsigned. Strict mode does not stop a process from writing values elsewhere: `murk diff --json` and `murk diff --show-values` print values, even into a file.

`murk agent exec` sets `MURK_AGENT=1` and `MURK_STRICT=1` for the child, so a nested `murk` stays strict and won't fall back to your stored key on the normal path. This is a safe default, **not a sandbox**: a child controls its own environment, so it can unset those vars or read `~/.config/murk/keys` directly — for real containment, run agents under a separate user or in a container (see below). If you want a non-strict shell yourself, just don't set `MURK_AGENT`. In CI, murk stays out of the way but prints a short hint toward a scoped grant key when it sees a pipeline decrypting with your personal key. `murk agent exec` does not wait for CI to object: it refuses a personal key it discovers on its own unless you pass `--allow-operator-key`, and then it prints a warning, in CI or not. It accepts any identity you supply through `MURK_KEY` or `MURK_KEY_FILE`, so supply a scoped grant key, not your personal key.

**Self-scoping your own key.** The allow-tag policy (see _Restricting which secrets agents can touch_, below) normally binds only agent grant keys — `murk get`/`export`/`edit` with your _own_ key ignore it. Set `MURK_SELF_SCOPE=1` (agent context implies it) to hold your own reads to the policy too: `get`, `exec` (and `agent exec`), and single-key `edit KEY` fail closed on a non-allowed key; `export` withholds forbidden keys (with a note on stderr); and bulk `murk edit` is refused. Reach for it when you run an agent in your own shell and want the guardrail to actually bite — it's still the murk binary enforcing it, not a sandbox.

## Scoped agent grants

`murk agent exec` with a grant key is the safest pattern: the agent's command gets secret _values_ in its environment and never sees a key, and the grant bounds which values it can reach. The same grant key covers an agent that has to run `murk` itself over a session — for example a long-running agent that calls `murk get` as it works.

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

A grant name stays unique: re-minting an existing name, even an expired one, is refused unless you pass `--renew`, which revokes the old key and mints a fresh one under the same name in a single vault write — handy when a short TTL lapses mid-session.

It writes the agent key to `~/.config/murk/agent-keys/<vault-hash>-<name>` (or `--out PATH`, which refuses an existing file unless you pass `--force`, or `--out -` to stream it to stdout) and prints how to use it. Run the agent with that key and `MURK_AGENT=1` (agent context — strict is forced) so it won't fall back to your stored key:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The granted key reads only its own keys. Anything else fails closed (`murk get` reports `KEY is outside this grant's scope`, and `agent exec` reports `key not found: KEY`). That is a decryption boundary rather than a check: the grant is excluded from the shared layer entirely, so the other values were never encrypted to it in the first place.

List and revoke grants:

```bash
murk agent ls                       # name, scope, TTL status
murk agent revoke codex --rotate    # remove the grant and rotate its keys
```

A running `murk mcp` server keeps serving a revoked grant until it restarts, so restart it (restart the editor) after you revoke.

Three things to keep in mind:

- **murk enforces the TTL at read time. Cryptography does not.** Past its expiry a grant fails closed on every read (`murk get`, `agent exec`, `murk_get`, `murk_exec`, the bindings), and `agent ls` flags it. `murk_plan` still lists the schema of the grant's keys. A running `murk mcp` server checks expiry on every `murk_get` and `murk_exec` call, but it does not see a revocation or a policy change until it restarts. Age keys can't self-destruct, and old vault versions stay readable in git, so a leaked grant key still decrypts history with raw age. Revoke the grant and rotate its secrets to close the exposure.
- **The key is a bearer credential.** Whoever holds the key file has the access. Treat it like the secret it unlocks.
- **Real isolation is the OS's job.** An agent running as you, with read access to your home directory, can read `~/.config/murk/keys` directly and bypass murk. `MURK_STRICT` stops murk from _handing over_ your key, but for true containment run the agent in a sandbox, container, or under a separate user that can't read your key directory.

## Vault trust and reserved names

**Agents never sign, and never decide what to trust.** An agent grant key is read-only: a vault signed by a grant key is refused, and `murk trust` refuses to run under a grant identity. `murk trust` is the human review step. Don't hand an agent `murk trust --yes`.

**A fresh environment needs `MURK_TRUSTED_SIGNERS`.** murk checks every vault against the trust pin of the machine it runs on. An agent in a container, a CI job or any other place with no pin gets "not trusted on this machine yet", and a grant can't run `murk trust` to fix that. Set `MURK_TRUSTED_SIGNERS` to the entries of the people who write the vault (`murk trust --print-key` prints one, as `age1...:<verifying key>` or an `ssh-ed25519` public key line), from outside the repo. See [CI/CD](https://murk.interrupted.sh/guides/cicd/#telling-ci-who-may-sign-the-vault).

**The vault can't pick the agent's environment.** Whoever last wrote the vault chose its key names, so `murk agent exec` refuses to inject a key named like `PATH`, `HOME`, `NODE_OPTIONS`, `BASH_ENV`, `RUSTFLAGS`, anything ending in `_PROXY`, or anything starting with `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `DOTNET_`, `CARGO_`, `SSL_`, `PIP_`, `GEM_`, `BUNDLE_`, `NPM_CONFIG_` or `MURK_`, unless you pass `--allow-reserved`. The MCP `murk_exec` tool always refuses them, with no override.

## Output masking

`murk agent exec` and the MCP `murk_exec` tool replace every injected value in the command's stdout and stderr with a `***KEY***` placeholder, so an `env` dump or a debug line doesn't drop a secret into an agent's transcript. It is on by default, with no flag to turn it off.

This is an **accident guard, not a security boundary** — the same idea as GitHub Actions' `::add-mask::`. Its limits:

- It matches a value byte for byte. A value that is encoded (base64, URL-encoding, hex), transformed, printed only in part, or split between stdout and stderr gets through.
- It covers stdout and stderr only. A value the command writes to a file, a socket, or another process is not touched.
- Values shorter than **4 bytes** are not masked. Masking `1`, `on`, or `dev` would rewrite unrelated output and still not hide a value that short.
- When one value contains another, the longer one wins: the output shows the longer key's placeholder.

A command that wants to leak a value it was handed can do so. Masking only stops the accidental case.

**What changes for the command under `agent exec`.** To see the output, `agent exec` supervises the command instead of replacing itself with it (plain `murk exec` still does the latter):

- The command's stdout and stderr are pipes, not your terminal. A program that checks for a terminal may drop colour or progress bars, or buffer its output differently. stdin is still your terminal.
- murk holds back only the tail of a chunk that could still be the start of a value (at most one byte shorter than your longest masked value). Everything else is written at once. Each stream is matched on its own.
- murk exits with the command's exit code. If a signal killed the command, murk re-raises the same signal.
- Ctrl-C reaches the command once, straight from the terminal. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to murk alone (for example by a harness timeout) are forwarded.
- murk waits until both streams close, so a background process that inherits them keeps `agent exec` running.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list, and murk will refuse to inject or grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the agent-usable ones
murk policy set --allow-tag agents              # default-deny everything else
```

Now `agent exec` and `agent grant` only work for keys tagged `agents`; asking for an untagged or production key fails closed with a clear error. There is no override flag, so an agent can't talk its way past the policy. `agents` is just an example tag; use whatever tags fit your vault (`dev`, `ci`, ...). The policy lives in the vault header (MAC-covered, readable with `murk policy show` even without a key) so it travels with the repo and applies in CI. The murk binary enforces the policy as a guardrail, not as access control (see THREAT_MODEL.md).

A granted agent is held to the policy no matter how it reads — `murk get`, `murk agent exec`, or the Python/Node bindings (`murk-secrets`). `get()` and `export()` from the bindings refuse a forbidden key just like the CLI, so the allow-list is enforced from every entry point. Tightening the policy takes effect on the next murk process that reads the vault. Drop a tag and the agent's next `murk get` (run with `MURK_AGENT=1`) or `agent exec` refuses that key, even though its grant key still exists. A running `murk mcp` server and a loaded binding object keep the vault state from their last load. Restart the server (restart the editor) and reload the binding object after you change a policy or revoke a grant. Grant expiry is the exception: it is checked again on every value read.

## Serving secrets over MCP (`murk mcp`)

Agent harnesses that speak the [Model Context Protocol](https://modelcontextprotocol.io) — Claude Code, Cursor, omp, and others — can reach murk secrets directly through `murk mcp`, a stdio MCP server built into the binary. It calls murk in-process (no subprocess, no Node runtime) and is bound by the same grant and policy machinery as everything above.

It runs **only** as a scoped agent: it fails closed unless it is launched with a grant key **and** `MURK_AGENT=1`. Started with your stored key, a plain recipient, or no grant, it refuses to start — so an MCP client can never be handed your full read scope.

```bash
# Mint a scoped grant first (see above), then run the server with it:
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 murk mcp
```

The server loads the vault once, at startup. Restart it after you revoke a grant or change the policy. Grant expiry is checked on every `murk_get` and `murk_exec` call.

The server speaks JSON-RPC over stdout and logs only to stderr, so point your MCP client at that command with `MURK_KEY_FILE` and `MURK_AGENT=1` in its environment. It exposes two always-on read tools bounded to the grant, plus an opt-in exec tool:

- **`murk_plan`** — lists the key names, descriptions, examples and tags of the secrets _this grant may read_, as JSON. It returns no values and omits keys outside the grant or the agent policy. That limits the tool only. The schema is plaintext in `.murk`, so an agent that can read the file or run `murk agent plan` still sees every key name. Takes an optional `tags` filter.
- **`murk_get { key }`** — returns one secret value if the grant may read it. The value lands in the model's context, so it ends up in the agent's transcript. Prefer `murk_exec` (or `murk agent exec`) when the command can take the secret from its environment. A key outside the grant or forbidden by the agent policy returns an error result, never the value.
- **`murk_exec { only, command }`** — off unless you start the server with `murk mcp --allow-exec`. Runs `command` (an argv array, no shell) with the secrets named in `only` injected into its environment. It returns `exit_code`, `stdout`, `stderr` and `truncated` as JSON, with the injected values masked (see _Output masking_, above). Every key in `only` must be in the grant's scope and allowed by the policy, or nothing runs. The command gets a clean environment (`PATH`, `HOME` and `TERM` on Unix, plus `MURK_AGENT=1` and `MURK_STRICT=1`), no stdin, a 120-second timeout and 1 MiB per output stream. murk kills it past either limit. A non-zero exit or a truncated stream returns an error result. `only` limits the injected secrets, not the command. The command runs as your user with your filesystem and network access, so `murk_exec` is **not a sandbox**. Enable it only where the server already runs under OS-level isolation.

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

**The editor manages its own MCP servers.** Claude Code, Cursor, VS Code, Zed, Gemini CLI, omp, and Codex each read a project-local config file (`.mcp.json`, `.codex/config.toml`, and so on). `murk agent connect` writes the `murk` entry there — the command, its args, and an `env` block carrying `MURK_KEY_FILE` (a path, never the key), `MURK_AGENT=1`, and an empty `MURK_KEY`. The empty `MURK_KEY` masks one the editor may pass down from your shell: murk refuses to run with both variables set. The editor launches `murk mcp` with that env, so the grant and agent context reach the server.

Run `murk agent connect claude --only STRIPE_SECRET_KEY`, or leave the editor off to auto-detect from the config files and marker directories already in the repo. `--only` is required and repeatable. The grant is named `mcp` (change it with `--name`) and expires after 2 hours (change it with `--ttl`). Running `connect` again reuses an existing grant with the same scope, and fails with a fix to run if the scope differs. When the grant expires, the editor's murk tools fail with `grant mcp expired`. Renew it with `murk agent grant --name mcp --only STRIPE_SECRET_KEY --renew`, which rewrites the same key file, then restart the editor. `murk agent disconnect [editor]` removes the entry but leaves the grant live. Add `--rotate` to revoke it and rotate the keys.

**The host delegates MCP to a provider CLI it wraps.** Some agentic IDEs don't manage MCP servers themselves — they run one of the provider CLIs above on your behalf and only render its MCP tool-call events. bb is one: it shows MCP activity but exposes no MCP config surface of its own. Here the `murk` entry belongs in the _provider's_ config, not the IDE's — Claude Code's `.mcp.json` or Codex's `.codex/config.toml` — and `MURK_KEY_FILE`/`MURK_AGENT` must reach the provider process that launches `murk mcp`, not the IDE process around it. So connect the provider, not the wrapper: `murk agent connect claude --only KEY` (or `codex`) writes the entry to the file the provider actually reads, with the env in that entry's own block.

To tell which case you're in: if your IDE is one of the editors above and has its own MCP settings, connect it directly. If it isn't — and it works by driving Claude Code, Codex, or another provider CLI underneath — you're in the delegating case, so connect that provider instead. The failure mode is quiet: wire the wrong layer and the agent gets a config it never reads, or a grant key the provider never sees, with no error to point at.

## Configuring your agent harness

An agent harness — Claude Code, Cursor, and the like — can auto-approve some murk commands and prompt for confirmation on the rest. The split is mechanical, not a judgement call. Commands that read only the vault header and the plaintext schema return no secret values. The rest decrypt values, mutate the vault, or change who can decrypt. Auto-approve the first set; require confirmation for the second.

**Allow: no secret value can come out.**

| Command                                                 | Why it's safe                                                                                 |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `murk info`, `murk info --json`                         | Reads the header. With a key it also shows recipient names and your key source. Never values. |
| `murk agent plan`, `murk agent plan --json` (to stdout) | Emits the schema (key names, descriptions, tags). No values.                                  |
| `murk skeleton` (to stdout)                             | Prints a copy of the vault shape with recipients, secrets, and meta blanked.                  |
| `murk circle`                                           | Lists recipients from the header. With a key it also shows recipient names. Never values.     |
| `murk doctor`                                           | Repo-hygiene checks over the working tree and the plaintext schema. No key.                   |

**Ask — decrypts, mutates, or changes trust.**

| Command                                               | Why it needs confirmation                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `murk add`, `murk rm`, `murk describe`, `murk import` | Write to the vault.                                                                                      |
| `murk get`, `murk export`                             | Decrypt secret values and return them.                                                                   |
| `murk diff`, `murk diff --show-values`, `murk diff --json` | Decrypt the old and current values to compute the diff. `--show-values` and `--json` print them. |
| `murk verify`                                         | Loads and decrypts the whole vault to check integrity — reveals no values, but needs the key.            |
| `murk scan`                                           | Decrypts every secret to search the working tree for leaked values.                                      |
| `murk env`                                            | Writes an `.envrc` that runs `murk export` — sets up ambient decryption of your full scope in the shell. |
| `murk authorize`, `murk revoke`                       | Change who can decrypt the vault.                                                                        |
| `murk trust`                                          | Records a vault as trusted on this machine and can re-sign it. That decision is yours, never `--yes`.   |
| `murk init`, `murk recover`, `murk restore`           | Create a key, or print your recovery phrase or secret key.                                               |
| `murk skeleton -o PATH`, `murk agent plan -o PATH`    | Overwrites `PATH` without asking.                                                                        |
| `murk exec -- CMD`                                    | Decrypts your full scope into a subprocess; use `murk agent exec` instead.                               |

**Special case: `murk agent exec --only KEY -- CMD`.** The wrapper is safe by default — it clears the inherited environment, strips `MURK_KEY`, injects only the named secrets, marks the child as an agent context, masks the injected values in the output, and refuses your auto-discovered personal key. Auto-approve it only when the harness itself supplies the grant key through its own environment. The command text can't prove which key a run uses. `agent exec` refuses only a key it finds on its own, so a command that sets `MURK_KEY` or `MURK_KEY_FILE` itself can point it at your personal key without any warning. These still need confirmation:

- **Any command that sets `MURK_KEY` or `MURK_KEY_FILE`.**
- **`--allow-operator-key`** tells `agent exec` to decrypt with _your_ stored key. That is your call, never the agent's: require confirmation for any command that carries it.
- **The inner `CMD`** still runs as your user with your filesystem and network access, so it must pass the harness's normal command rules like any other command it would run. Deny environment dumps (`env`, `printenv`, `set`, `export -p`) under `agent exec` or any other wrapper that injects secrets: masking catches a verbatim value, not an encoded or partial one.

**Why the split holds.** Under `murk agent exec` the subprocess has no `MURK_KEY`, so every command that needs decryption fails closed. The allow list is exactly the set that still works in that state — the commands that read the header and schema and nothing more. That is what makes it safe to auto-approve: stripped of a key, nothing on the list can produce a secret value even if asked to.

## Auditing agent activity

murk keeps no separate agent log. Commit each vault change and git becomes the record:

```bash
git log -p .murk        # who changed the vault and when
murk diff HEAD~1        # which secrets changed in the last commit
```

`git log -p .murk` attributes each change to its commit author (and to the commit signature, if you sign commits). The diff shows policy edits and added or removed recipient keys in plaintext. A new grant shows up as a new recipient key and new `scoped` ciphertexts under the secrets it can read, so the diff shows which secrets that key can read. Its name, TTL and issuer are encrypted and appear only as a changed `meta` blob. `murk diff` compares secret values only. It does not show grant, policy or recipient changes, and it does not verify the integrity of the old revision it reads. Git can't show secret reads on a developer's machine, because murk never sees them. Don't treat the absence of a read trail as proof a secret wasn't used. See THREAT_MODEL.md for the full audit boundary.
