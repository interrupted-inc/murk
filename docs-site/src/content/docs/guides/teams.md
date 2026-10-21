---
title: Working in teams
description: Authorize teammates and manage a shared vault.
sidebar:
  order: 2
---

murk's vault is per-recipient: every teammate has their own key, and adding
or removing someone is a normal git-tracked change to the vault file: no
shared password to rotate, no separate secrets server to run.

![Alice authorizes Bob as a recipient, then Bob decrypts the shared vault](https://raw.githubusercontent.com/interrupted-sh/murk/demo/team.gif)

## Adding a teammate

Each person has their own key. The handoff takes four steps:

1. Alice creates the vault and commits it:

   ```bash
   murk init
   murk add DATABASE_URL
   git add .murk && git commit -m "add vault" && git push
   ```

2. Bob clones the repository and runs `murk init` once in his clone. It
   creates his key (or reuses the one he already has for this vault) and,
   because he is not authorized yet, prints his public key. He sends that
   key to Alice.

   ```bash
   murk init
   ```

3. Alice authorizes the key, then commits and pushes. This re-encrypts the
   shared secrets to include Bob's key.

   ```bash
   murk circle authorize age1bob... --name bob@example.com
   git commit -am "authorize bob" && git push
   ```

4. Bob pulls. He can now read the shared secrets:

   ```bash
   git pull
   murk get DATABASE_URL
   ```

Bob can still keep his own local overrides on top of the shared secrets. See
[shared vs scoped secrets](/guides/shared-vs-scoped/):

```bash
murk add DATABASE_URL --group me
```

## Authorizing via GitHub

Instead of exchanging age keys, you can authorize by GitHub username:

```bash
murk circle authorize github:bob
```

This fetches Bob's SSH public keys from `https://github.com/bob.keys` (no
authentication required) and authorizes every `ssh-ed25519` key on his
account. It skips `ssh-rsa` keys with a warning unless you pass
`--allow-ssh-rsa`, and fails if every key is RSA.

Bob decrypts with the matching private key by setting `MURK_KEY_FILE` to it
(for example `~/.ssh/id_ed25519`). murk does not search `~/.ssh` on its own.
It needs an unencrypted SSH private key that only Bob can read, and it cannot
read a passphrase-protected one. If Bob has no such key, use the age key
exchange above.

### Recipient pinning

The first successful `murk circle authorize github:bob` records the SHA-256
fingerprints of the fetched keys in the encrypted vault metadata. If Bob's
GitHub keys change later, the next `authorize github:bob` refuses to proceed
silently: it flags the diff and requires `--force` to accept the new keys.
This catches both benign key rotation and a compromised GitHub account adding
an attacker's key. It turns either into something a human has to actively
confirm rather than something that happens invisibly.

This pinning trusts GitHub as a key directory and trusts that the
username belongs to who you think it does. Treat `authorize github:user` with
the same care you'd give any access grant: verify identity out of band for
sensitive vaults. See the [threat model](/security/threat-model/) for the
full trust analysis.

## Listing and managing recipients

```bash
murk circle                    # list recipients
murk circle revoke RECIPIENT   # RECIPIENT is a public key or a display name (see offboarding)
```

To share a secret with only part of the team, use a group:

```bash
murk group create ops
murk group add ops --member bob@example.com
murk add STRIPE_KEY --group ops
```

`murk group ls` lists groups, and `murk group rm ops --member bob@example.com`
removes a member. `murk circle authorize ... --group ops` adds a new
recipient to a group in the same step. See [shared vs scoped
secrets](/guides/shared-vs-scoped/) and the [CLI
reference](/reference/cli/#murk-group) for the full flag surface.

When someone leaves the team, don't just stop there. See
[offboarding a teammate](/guides/offboarding/) for revocation and rotation.
