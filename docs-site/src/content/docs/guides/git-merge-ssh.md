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

![Using an SSH key as a murk recipient](https://raw.githubusercontent.com/interrupted-inc/murk/demo/ssh.gif)

## Setting up the merge driver

```bash
murk setup-merge-driver
```

This configures git to use `murk merge-driver` for `.murk` files by writing
the driver definition to `.git/config` and pointing `.murk` at it via
`.gitattributes`. Run it once per clone (it's local git config, not
something that travels with the repo automatically — everyone who works on
the vault needs to run it in their own checkout).

Once configured, git invokes `murk merge-driver ANCESTOR OURS THEIRS`
automatically during a merge or rebase that touches `.murk`, instead of
falling back to a text-based three-way merge on the raw file. It merges
non-conflicting secret changes (different keys added or changed on each
side) automatically. It does not decide to vouch for the merged content:
it leaves the result **unsigned** (`sig: null`), carrying the existing signer
registry forward. Re-sign it by running any write command (e.g. `murk add`,
`murk rotate`) with a signing-capable key after reviewing what actually
changed:

```bash
murk diff HEAD@{1}   # or whatever ref makes sense for your merge
```

`murk diff [REF]` shows which secrets changed relative to a git ref
(defaults to `HEAD`) without printing values, unless you pass
`--show-values`. Use it to sanity-check a merge before you trust it.

## SSH keys as recipients

You don't need a separate age keypair if you already have an SSH key. murk
accepts SSH public keys directly as recipients, right alongside `age1...`
keys in the same recipient list:

```bash
murk circle authorize ssh:~/.ssh/id_ed25519.pub --name you@example.com
```

`circle authorize` also accepts bare `ssh:` (defaulting to
`~/.ssh/id_ed25519.pub`), or `github:username` to pull SSH keys straight
from a GitHub account. See [working in teams](/guides/teams/) for the
GitHub-based flow and its pinning behavior.

murk accepts `ssh-ed25519` keys by default. murk rejects `ssh-rsa` keys
unless you pass `--allow-ssh-rsa`: ed25519 is recommended, and this default
nudges teams away from the weaker key type.

### Signing behavior differs by key type

- **`ssh-ed25519`** keys are themselves Ed25519 signing keys, so murk signs
  directly with them. The verifying key is embedded in the recipient string
  itself, so the signature is self-authenticating: no separate registry
  entry needed.
- **`ssh-rsa`** keys cannot sign (age exposes no signing scalar for RSA).
  Writes made with an `ssh-rsa` identity leave the vault unsigned: a
  warning on next load, not a hard failure. This is the same "sign when
  capable" behavior hardware-backed identities have. See [hardware
  keys](/guides/hardware-keys/) and the [threat
  model](/security/threat-model/) for the full signing story.

## Related

- [CLI reference: `murk setup-merge-driver`](/reference/cli/#murk-setup-merge-driver)
  and [`murk circle authorize`](/reference/cli/#murk-circle-authorize) for
  the full flag surface.
- [Recipients & signatures](/concepts/recipients-signatures/) for how the
  recipient list and signer registry fit together.
