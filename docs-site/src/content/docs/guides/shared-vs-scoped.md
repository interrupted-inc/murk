---
title: Shared vs scoped secrets
description: When to use shared secrets versus per-user scoped overrides.
sidebar:
  order: 1
---

Every `.murk` vault has two layers of encryption for a given key. Picking the
right one is the main decision you make when adding a secret.

## Shared secrets (the murk)

Shared secrets are encrypted to every recipient except agent grants (see
[Grants](/concepts/grants/)). When you add a new key with `murk add KEY`,
every authorized team member can decrypt it. Updating an existing key without
`--group` keeps it in its tier. This is where
production credentials, third-party API keys, and other team-wide secrets
live.

```bash
# Everyone sees this (prompts for value, hidden input)
murk add DATABASE_URL
```

## Scoped secrets (motes)

Scoped secrets are encrypted to only your key: they live in a reserved
personal group named `me`. When you run `murk add KEY --group me`, the value
is encrypted so that only you can decrypt
it: no other recipient, even one with full vault access, can read it. During
`murk export`, `murk exec`, and `murk get`, a scoped value overrides the
shared value for the same key. That lets you point `DATABASE_URL` at a local
database while the rest of the team uses the shared production value, without
anyone's export clobbering anyone else's.

```bash
# Only you see this; it overrides the shared value during export
murk add DATABASE_URL --group me
```

You can also pipe a value in for scripting. Just use a command that doesn't
leak to shell history:

```bash
pbpaste | murk add DATABASE_URL
```

## Choosing between them

- **Shared**: anything the whole team (or CI) needs the same value for:
  production API keys, shared database URLs, third-party service credentials.
- **Scoped**: anything that should differ per developer or stay private to
  you: a local database URL, a personal API token, a value you don't want
  even other recipients to read.

Scoped secrets don't affect who's authorized on the vault: that's the
recipient list, managed with `murk circle` (see [working in
teams](/guides/teams/)). They're a second layer of encryption *within* the
vault, on top of the recipient list. See [how murk's vault format
works](/concepts/vault-format/) for the on-disk details, and the [`murk
add`](/reference/cli/#murk-add) reference for the full flag list.

Every recipient except an agent grant can decrypt every shared secret. Tags
and descriptions in the schema do not restrict anyone. To limit a secret to
part of the team, put it in a group (`--group NAME`). To keep it to yourself,
use `--group me`.
