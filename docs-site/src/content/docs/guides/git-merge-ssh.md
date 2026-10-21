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

Once configured, git runs `murk merge-driver ANCESTOR OURS THEIRS` during a
merge or rebase that touches `.murk`, instead of falling back to a text-based
three-way merge on the raw file. It merges non-conflicting secret changes
(different keys added or changed on each side) automatically.

The driver needs your key at merge time. It decrypts the metadata of both
sides to rebuild it, so run merges with a key available (`MURK_KEY`,
`MURK_KEY_FILE`, or your stored key). The driver takes no `--vault` flag and
looks up the stored key for a vault named `.murk`. If your vault has another
name, set `MURK_KEY_FILE`.

Without a key, the driver keeps our side's metadata, MAC and signature. That
is safe only when the merged secrets, recipients, schema and policy equal
ours, and then the merge completes with a warning. Otherwise the driver exits
with an error and git reports a conflict on `.murk`. Run `git merge --abort`,
make your key available, and merge again.

Merge `.murk` locally, with your key. Server-side merges (the GitHub merge
button, merge queues, bot merges) run a plain text merge and never invoke
the murk merge driver. Do not let them merge branches that change `.murk`,
and do not resolve `.murk` conflicts in the GitHub web editor. A plain text
merge of `.murk` either conflicts or produces a vault that murk 0.14.0 and
later refuse to load.

When the driver rebuilds the metadata with your key, it does not sign the
result. It runs without a human and must not vouch for content nobody has
reviewed. The merged vault has no signature, and it carries the signer
registry forward. If the vault was signed before, each command then warns
`vault was signed before and is now unsigned`, and `murk verify` fails until
someone re-signs it. To re-sign, review what changed, then run any write
command (for example `murk add` or `murk describe`) with an age or
`ssh-ed25519` key:

```bash
git diff HEAD@{1} -- .murk   # recipients, schema, policy and ciphertext entries
murk diff HEAD@{1}           # secret values
```

Use whatever ref makes sense for your merge. `murk diff [REF]` shows which
secrets changed relative to a git ref (defaults to `HEAD`). It prints no
values unless you pass `--show-values` or `--json`. It decrypts the old
revision without verifying its MAC or signature, so it does not prove the old
side is authentic.

## Conflicts

The driver reports a conflict, and git stops the merge, when:

- both sides added or changed the same key,
- one side removed a key that the other side kept or changed,
- only one side added or removed a recipient (authorize and revoke teammates
  on the main branch, not on a side branch that also changes secrets),
- one side changed a secret while the other side changed recipients,
- both sides changed the agent policy differently.

The driver lists each conflicting field. `.murk` is left unmerged and keeps
our side's value for each conflicting field. A recipient that only one side
added or removed stays in the list. Set the value you want with
`murk add KEY`, or fix recipients with `murk circle authorize` or
`murk circle revoke` (check the result with `murk circle`). Then
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
  Writes made with an `ssh-rsa` identity leave the vault unsigned. Ordinary
  commands warn about this only when the vault was signed before, or when the
  person loading it has a key that can sign. `murk verify` reports an
  unsigned vault with secrets as a failure. Hardware-backed identities behave
  the same way. See [hardware keys](/guides/hardware-keys/) and the [threat
  model](/security/threat-model/) for the full signing story.

## Related

- [CLI reference: `murk setup-merge-driver`](/reference/cli/#murk-setup-merge-driver)
  and [`murk circle authorize`](/reference/cli/#murk-circle-authorize) for
  the full flag surface.
- [Recipients & signatures](/concepts/recipients-signatures/) for how the
  recipient list and signer registry fit together.
