---
name: murk
description: Read project secrets from the murk vault through grant-scoped tools. Use when a task needs an API key, database URL, token, or other secret — never ask the user to paste one.
---

# murk secrets in bb threads

This project keeps secrets in an encrypted murk vault (`.murk`). You never get
the vault key. You get **grants**: ephemeral identities the user mints for
exactly the keys a task needs, with a TTL. Everything outside a grant fails
closed — the other values were never encrypted to your identity.

## Rules

1. **Never ask the user to paste a secret into chat.** Prompts are logged and
   cached. Point them at `bb murk grant mint` instead.
2. **Never echo, log, or commit secret values.** That includes values you can
   read from a delivered env file and values a reveal grant returns inline.
   Do not write them into code, config, commit messages, or tool output.
3. **Never commit the delivered env file** (`.murk-<threadId>.env`, the exact
   path is in every murk_get result). It is mode 0600 and deleted automatically
   when this thread goes idle. If it shows up in `git status`, leave it out of
   the commit (it is ephemeral either way).

## Discovering what exists: murk_plan

`murk_plan` returns the vault schema — key names and tags only. It never
returns values, descriptions, or grant state. Call it before asking the user
for access, so you can name the exact keys; whether a key is granted shows up
when murk_get either delivers it or fails closed.

## Reading secrets: murk_get

`murk_get` reads keys covered by an active grant:

- **Default (file delivery):** values are written to `.murk-<threadId>.env` in
  this worktree (mode 0600) and the tool returns only key names + the exact
  file path. Source that path — `set -a; source <path>; set +a` — or hand it
  to dotenv-aware tools without printing its contents. The file disappears
  when the thread idles; call murk_get again in a later turn instead of
  caching values. murk_get never touches bytes it did not write: if something
  else already sits at the delivery path, or the file changed after delivery,
  it fails closed and asks you to move that file aside.
- **Reveal grants:** only when the user minted the grant with `--reveal` do
  values come back inline, and only for that grant's keys. Treat them as
  radioactive: use them, never repeat them.

A key outside your grants fails closed. Do not retry with variations — ask the
user to mint access:

```
bb murk grant mint --keys STRIPE_SECRET_KEY --ttl 2h
bb murk grant mint --keys DATABASE_URL,PG_PASSWORD --thread <threadId>
bb murk grant mint --keys TEST_TOKEN --reveal        # inline values, if allowed
```

`bb murk grant list` shows scope, keys, expiry, and reveal status;
`bb murk grant revoke <id>` closes access early.

## Running commands that need secrets

Prefer wiring the delivered file into the command's environment over exporting
values into your shell session:

```bash
set -a; source .murk-<threadId>.env; set +a; ./migrate.sh   # path from the murk_get result
```

`murk agent exec --only KEY -- CMD` also injects secrets into a subprocess
without a file — but only in environments that hold their own `MURK_KEY` or
`MURK_KEY_FILE` (an operator's shell, a CI job with its own identity). A bb
thread never holds key material — grants live only as 0600 identity files
under the plugin's data dir — so that command always fails here. Use the
delivered dotenv file instead.
