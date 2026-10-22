---
title: Offboarding a teammate
description: Revoke access and rotate secrets when someone leaves.
sidebar:
  order: 3
---

When someone leaves the team, revoke their access and rotate whatever they
could read.

![Revoking a teammate and rotating the secrets they could read](https://raw.githubusercontent.com/interrupted-sh/murk/demo/offboard.gif)

## Revoke and rotate in one step

murk cannot change a credential at its provider. Rotating here means storing
a replacement value in the vault. Create the new credential at each service
first. Invalidate the old one after you push the new vault (in an urgent case,
invalidate it first).

```bash
murk circle revoke carol --rotate
```

`carol` can be a display name, a public key or `github:carol`. A display name
that matches several different keys is rejected (`ambiguous name "carol"
matches 2 recipients`). List the full keys with `murk circle --json`, then
revoke each one by public key. A teammate added with `github:` has one
recipient per key on their account, all named `carol@github`. Revoking
`carol@github` or `github:carol` removes all of those keys. With more than
one key, murk lists them and asks you to confirm. Without a terminal it
refuses unless you pass `--force`.

Another recipient runs this command. murk refuses to revoke your own key, so
a member who is leaving cannot remove themselves: ask a teammate to run `murk
circle revoke <you>`.

This removes carol as a recipient and re-encrypts the shared secrets she
had access to without her key. With `--rotate`, it also prompts you for a
new value for each secret she could read, in the same session. That covers
shared secrets and secrets in her groups. A group secret gets its new value
in the same group. Commit and push the result:

```bash
git commit -am "revoke carol, rotate secrets" && git push
```

Without `--rotate` on an interactive terminal, `murk circle revoke` offers to
rotate anyway. When it runs non-interactively (e.g. in a script), it just
prints a hint instead.

## Rotate from a file

If you already have the new values in a file, pass it with `--values-from`
instead of answering prompts:

```bash
murk circle revoke carol --rotate --values-from .env.rotated
rm .env.rotated
```

The file holds `KEY=value` lines, in the same format as `murk import` (`-`
reads them from stdin). Values are matched by name, and each one stays in its
tier. If the file names a key that cannot be rotated here (not in the vault,
in a group you are not in, or not one carol could read), murk refuses the whole
batch and writes nothing, so carol is not revoked either. Keys the file leaves
out are not rotated: murk reports them and `murk rotate --list` keeps listing
them. Delete the file afterwards: it holds plaintext secrets.

## Why rotation matters

Revocation re-encrypts the vault **going forward**: it drops carol's key
from future shared-secret ciphertexts. It does not touch git history:

:::caution
Revocation doesn't erase git history. The revoked user can still decrypt any
version of the vault they previously had access to, straight from old git
commits. Rotation (a new credential at the provider, stored as the new value)
is the only way to close the exposure. Revocation alone just stops *future*
changes from being readable to them.
:::

So always rotate after revoking someone whose access mattered. `murk circle
revoke --rotate` does both in one motion; if you skip `--rotate`, follow up
with `murk rotate KEY` (or `murk rotate --all`) for anything sensitive they
could read.

## What stops a revoked teammate coming back

`murk circle revoke` removes every spelling of the key, and murk refuses an
`age1...` key with a non-canonical encoding, so an alias form of
it can't survive the revocation. Once a machine has accepted the revoking
vault, it refuses any vault the revoked key signs, on every branch. The only
exception is their own history from before the revoke, at an older commit
(see [the removal rule](/concepts/recipients-signatures/#trusting-a-signer)),
and it never makes them trusted again. An older
revision that still lists them, replayed to re-enrol them or put back rotated
values, is refused as a rollback wherever the revoke has reached: the branch
it was made on, and the branches it was merged or pulled into.

Revoke on the main branch. A revoke on an unmerged branch doesn't stop main's
vaults from listing them until you merge it, and that merge is a
[conflict](/guides/git-merge-ssh/#conflicts) to resolve by hand. Until then
they are still a recipient on main and on every other branch the revoke hasn't
reached, so they can read any secret added or rotated there. If you revoked on
a branch, merge it into main before you add or rotate secrets anywhere else. A
`--rotate` on that branch protects only the values rotated there. If you really
do need to go back to an older vault, see [rollback and deliberate
reverts](/concepts/recipients-signatures/#rollback-and-deliberate-reverts).

## Agent grants that trusted them

Revoking a teammate also revokes every agent grant whose key file trusts
them as a signer, and murk deletes the grant key files it keeps itself. It
can't reach any other copy: a key file written with `--out`, handed to the
agent host, or made on another operator's machine. Such a copy still trusts
the revoked teammate. If they sign a vault built from a copy from before the
revoke, the agent reads the values they chose, until the expiry written into
the key file. A key file without that line (minted by an older murk, or the
bare key line that murk-action takes) has no such limit, because they can
write a later expiry into the vault.

So delete every other copy of each revoked grant's key file, including the
one on the agent host, then re-mint the grant (`murk agent grant --name NAME
--only KEY --renew`). The revoke lists the grants and prints the commands.
Also remove the revoked teammate's entry from `MURK_TRUSTED_SIGNERS` wherever
it's set.

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

Human output exits 1 when anything needs rotating, so it works as a CI gate.
With a key, `rotate --list` verifies the vault first, so deleting a `revoked_at`
or `expires_at` marker from the header fails the command instead of turning the
gate green. Without a key it can only read the header as written: it prints
`warn unverified header`, `--json` reports `"verified": false`, and under
`MURK_STRICT` it exits 1. `--json` prints `{"verified": ..., "issues": [...]}`.

For adding and authorizing teammates in the first place, see [working in
teams](/guides/teams/).
