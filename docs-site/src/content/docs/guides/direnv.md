---
title: direnv integration
description: Load secrets automatically when you cd into a project.
sidebar:
  order: 7
---

[direnv](https://direnv.net/) loads and unloads environment variables based
on your current directory. murk has built-in support for it, so secrets can
load automatically the moment you `cd` into a project: no manual `export`
or wrapper script.

![Secrets loading automatically on cd via direnv](https://raw.githubusercontent.com/interrupted-sh/murk/demo/direnv.gif)

## Setting it up

```bash
murk env
direnv allow
```

`murk env` writes a `.envrc` for direnv integration, wired to your vault.
`direnv allow` tells direnv it's safe to execute that `.envrc` (direnv
requires this explicit opt-in per directory, as a safety measure against
untrusted repos setting arbitrary environment variables on `cd`).

From then on, direnv exports every secret you can read (shared, group, and
your own `me` overrides) when you enter the project and unsets them when you
leave.

## Keeping up with vault changes

direnv reloads when `.envrc` changes, not when `.murk` does. After `git pull`
or `murk rotate`, run `direnv reload`. To make direnv watch the vault, add
this line above the `eval` line in `.envrc`:

```bash
watch_file .murk
```

## Where the key lives

Your private key is stored in `~/.config/murk/keys/` with restricted
permissions, outside the repository, and the CLI auto-discovers it based
on the vault's absolute path. So under direnv nothing about the key needs to
live in the repo at all. The `.envrc` just runs `murk export`. (For shells that
don't use direnv, `murk init` also writes a `.env` holding a `MURK_KEY_FILE`
*reference* to that path, never the key itself, so `source .env` works too.)
Either way, no secret material lands in the repo directory.

## Without direnv

If you'd rather not use direnv, `murk exec` gives you the same result for a
single command instead of an ambient shell environment:

```bash
murk exec ./deploy.sh    # runs with all secrets in the environment
```

This is also the pattern to reach for in non-interactive contexts like CI
(see [CI/CD](/guides/cicd/)) where there's no shell session for direnv to
hook into.

## Related

- [Quick start](/quick-start/) covers `murk init`, getting authorized, and
  `murk env`.
- [Environment variables](/concepts/env-vars/) documents every variable murk
  reads and writes, including `MURK_KEY_FILE`, `MURK_VAULT`, and `MURK_KEY`.
- [Shared vs scoped secrets](/guides/shared-vs-scoped/) covers how scoped
  overrides interact with what gets exported.
