---
title: Offboarding a teammate
description: Revoke access and rotate secrets when someone leaves.
sidebar:
  order: 3
---

When someone leaves the team, revoke their access and rotate whatever they
could read.

![Revoking a teammate and rotating the secrets they could read](https://raw.githubusercontent.com/interrupted-inc/murk/demo/offboard.gif)

## Revoke and rotate in one step

```bash
murk circle revoke carol --rotate
```

This removes carol as a recipient and re-encrypts the shared secrets she
had access to without her key. With `--rotate`, it also prompts you for a
new value for each of them in the same session. Commit and push the result:

```bash
git commit -am "revoke carol, rotate secrets" && git push
```

Without `--rotate` on an interactive terminal, `murk circle revoke` offers to
rotate anyway. When it runs non-interactively (e.g. in a script), it just
prints a hint instead.

## Import rotated values from a file

If you already have replacement values staged in a file, revoke first and
bulk-import instead of answering prompts one at a time:

```bash
murk circle revoke carol
murk import .env.rotated
```

## Why rotation matters

Revocation re-encrypts the vault **going forward**: it drops carol's key
from future shared-secret ciphertexts. It does not touch git history:

:::caution
Revocation doesn't erase git history. The revoked user can still decrypt any
version of the vault they previously had access to, straight from old git
commits. Rotation, giving the secret a new value, is the only way to
actually close the exposure. Revocation alone just stops *future* changes
from being readable to them.
:::

So always rotate after revoking someone whose access mattered. `murk circle
revoke --rotate` does both in one motion; if you skip `--rotate`, follow up
with `murk rotate KEY` (or `murk rotate --all`) for anything sensitive they
could read.

## Checking what needs rotating

```bash
murk rotate --list         # keys needing rotation: overdue, expiring, post-revoke
murk rotate --list --json
```

This flags secrets that are overdue for rotation, approaching an expiry, or
still outstanding after a past revoke (useful as a periodic hygiene check
independent of any single offboarding event). See `murk doctor` for broader
repo hygiene scanning, and the [CLI reference](/reference/cli/#murk-circle-revoke)
for the full flag surface on `circle revoke` and `rotate`.

For adding and authorizing teammates in the first place, see [working in
teams](/guides/teams/).
