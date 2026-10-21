---
title: Git merge driver & SSH
description: Set up the merge driver and SSH-key authorization.
sidebar:
  order: 9
---

`.murk` is a single JSON-ish file with encrypted values, which means a naive
git merge on it doesn't work the way it would for plaintext. git has no
idea two different encrypted blobs might represent non-conflicting changes
to different keys. murk ships its own merge driver to handle this correctly,
plus first-class support for SSH keys as recipients so you don't need a
separate age key at all.

![Using an SSH key as a murk recipient](https://raw.githubusercontent.com/interrupted-sh/murk/demo/ssh.gif)

## Setting up the merge driver

```bash
murk setup-merge-driver
```

This configures git to use `murk merge-driver` for `.murk` files by writing
the driver definition to `.git/config` and pointing `.murk` at it via
`.gitattributes`. Run it once per clone (it's local git config, not
something that travels with the repo automatically — everyone who works on
the vault needs to run it in their own checkout).

Once configured, git invokes `murk merge-driver ANCESTOR OURS THEIRS PATH`
automatically during a merge or rebase that touches `.murk`, instead of
falling back to a text-based three-way merge on the raw file. `PATH` is the
vault's path (git's `%P`), so the driver reads the right trust pin. It
merges non-conflicting secret changes (different keys added or changed on
each side) automatically.

Run it with your key available (`MURK_KEY`, `MURK_KEY_FILE`, or the stored
key for a vault named `.murk`; for a vault with another name, set
`MURK_KEY_FILE`). With a key, it checks **both sides** the way a load does: MAC, a
valid signature, a signer this machine trusts, not an agent grant, the same
vault id, and, for a side that changed the vault, a save counter above the
common ancestor's. It authenticates the **common ancestor** too, because the
ancestor decides what counts as a change and which group memberships the
sides are judged against. A parent an attacker chose (a cherry-pick, a
`git apply --3way`) could otherwise shape the merge. An ancestor your key
can't read is merged conservatively: any difference in the encrypted meta is
a conflict. An ancestor that fails its checks is refused.

If the ancestor or a side fails, the merge is a conflict that names it, and
nothing is merged, re-MACed, or signed. Otherwise the driver writes the
merged vault with a fresh MAC and signs it with your key (it stays unsigned
only if your key can't sign), numbered above both sides and everything this
machine has accepted. Without a key it can't verify or sign, so it refuses
any merge that would need new integrity data.

Because the merged vault is signed by your key, it has to pass the group
rule a load applies: a change to a group's membership needs a signature from
a member of that group. A merge that changes a group's membership, when your
key isn't in that group, is a conflict that says so. A member of the group
has to do that merge.

Because the result is signed in your name, check what you merged:

```bash
git diff HEAD@{1} -- .murk   # recipients, schema, policy and ciphertext entries
murk diff HEAD@{1}           # secret values
```

`murk diff [REF]` shows which secrets changed relative to a git ref
(defaults to `HEAD`) without printing values, unless you pass
`--show-values`. It also lists recipient additions and removals and signer
changes, and it runs on a vault this machine doesn't trust yet (with a
warning), since it's the review step before `murk trust`.

### Upgrading an older driver config

Before 0.14, `murk setup-merge-driver` wrote `murk merge-driver %O %A %B`
with no path. A driver configured that way still runs, but it falls back to
`.murk` and can't find the pin for a vault with another name. Re-run
`murk setup-merge-driver` in each clone to add `%P`.

### Merges that never run the driver

Server-side merges (the GitHub web UI, merge queues) don't run the driver.
The textual merge either conflicts or produces a vault that fails
verification on the next load. murk never serves a vault it can't verify,
so a bad server-side merge shows up as a refusal, not as wrong values. Run
the merge locally if a vault changed on both sides.

## Conflicts

The driver reports a conflict, and git stops the merge, when:

- both sides added or changed the same key,
- one side removed a key that the other side kept or changed,
- only one side added or removed a recipient (authorize and revoke teammates
  on the main branch, not on a side branch that also changes secrets),
- one side changed a secret while the other side changed recipients,
- both sides changed the agent policy differently,
- a side, or the common ancestor, fails the checks above (MAC, signature,
  trusted signer, grant key, vault id, save counter),
- the merge changes a group's membership and your key is not in that group.

The driver lists each conflicting field and leaves `.murk` unmerged. The file
keeps our side's metadata, so it verifies only where it still equals ours.
Take one side (`git checkout --ours .murk` or `--theirs`) and redo the other
side's changes with murk (`murk add KEY`, `murk circle authorize` or
`murk circle revoke`, checking the result with `murk circle`). Then
`git add .murk` and commit.

## SSH keys as recipients

You can use an SSH key instead of a separate age keypair. murk accepts SSH
public keys directly as recipients, right alongside `age1...` keys in the same
recipient list:

```bash
murk circle authorize ssh:~/.ssh/id_ed25519.pub --name you@example.com
```

To decrypt with the matching private key, point `MURK_KEY_FILE` at it:

```bash
export MURK_KEY_FILE=~/.ssh/id_ed25519
```

murk does not search `~/.ssh` on its own. It needs an unencrypted, supported
SSH private key that only you can read (mode `600`). It cannot read a
passphrase-protected key (`encrypted SSH keys are not yet supported`). Use an
unencrypted key, for example one kept only for murk, or use an age key.

`circle authorize` also accepts bare `ssh:` (defaulting to
`~/.ssh/id_ed25519.pub`), or `github:username` to pull SSH keys straight
from a GitHub account. See [working in teams](/guides/teams/) for the
GitHub-based flow and its pinning behavior.

murk accepts `ssh-ed25519` keys by default. It refuses to authorize an
`ssh-rsa` key unless you pass `--allow-ssh-rsa`, because ed25519 is strongly
recommended (see RUSTSEC-2023-0071). With `github:username`, murk skips RSA
keys with a warning instead, and fails only if every key is RSA.

### Signing behavior differs by key type

- **`ssh-ed25519`** keys are themselves Ed25519 signing keys, so murk signs
  directly with them. The verifying key is embedded in the recipient string
  itself, so the signature is self-authenticating: no separate registry
  entry needed.
- **`ssh-rsa`** keys cannot sign (age exposes no signing scalar for RSA).
  Writes made with an `ssh-rsa` identity leave the vault unsigned. A machine
  whose own key can sign refuses that vault until a signing teammate reviews
  it and runs `murk trust`, which re-signs it. The `ssh-rsa` holder's own
  machine loads an unsigned vault with a warning, and `murk verify` reports it
  as a finding. This is the same "sign when
  capable" behavior hardware-backed identities have. See [hardware
  keys](/guides/hardware-keys/#mixed-teams) and the [threat
  model](/security/threat-model/) for the full signing story.

## Related

- [CLI reference: `murk setup-merge-driver`](/reference/cli/#murk-setup-merge-driver)
  and [`murk circle authorize`](/reference/cli/#murk-circle-authorize) for
  the full flag surface.
- [Recipients & signatures](/concepts/recipients-signatures/) for how the
  recipient list, signatures and the trust pin fit together.
