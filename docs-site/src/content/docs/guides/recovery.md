---
title: Key recovery
description: Recover a lost key from your 24-word phrase.
sidebar:
  order: 5
---

Your murk key is derived from a BIP39 mnemonic, the same scheme used by
most crypto wallets. `murk init` generates 256 bits of entropy, prints it as
24 recovery words, and derives your age keypair directly from those bytes
(no intermediate hashing step: same bytes, same key every time).

![Recovering a lost key from the 24-word BIP39 phrase](https://raw.githubusercontent.com/interrupted-sh/murk/demo/recovery.gif)

## Write the words down when you run `murk init`

```bash
murk init
```

The 24 words print once, at key-generation time. **Store them in a secure
password manager or keep a physical copy offline**, as your threat model
calls for. Anyone with your 24 words has your key: treat the
phrase exactly like the key itself. Don't paste it into chat, don't commit
it, don't screenshot it into a note-taking app synced to the cloud without
thinking about who else can read that account.

## Recovering a lost key

If the key file is gone (new machine, wiped disk) and you still have the 24
words, run `murk restore` in the project directory. It asks for the phrase
(input is hidden) and prints the key. It does not save it, so write it to a
file that only you can read and point `MURK_KEY_FILE` at it:

```bash
mkdir -p -m 700 ~/.config/murk
(umask 077 && murk restore > ~/.config/murk/restored.key)
export MURK_KEY_FILE=~/.config/murk/restored.key
```

Add the `export` line to your shell profile. Running the command in the
project directory lets murk warn you if the restored key is not a recipient
of the vault, which means the phrase was wrong.

The key is derived directly from the words, so it is identical to the one
`murk init` generated: the same public key, still a recipient of every vault
that authorized it. Nothing changes on the vault side.

## Displaying your phrase again

```bash
murk recover
```

This prints the 24 words for the key murk uses for the vault in the current
directory (`MURK_KEY`, `MURK_KEY_FILE`, or the stored key). Use it if you did
not record the phrase at `murk init`. It works only for age keys. SSH keys
and hardware identities have no phrase, and `murk recover` fails on them.
Anyone who can read your key file can derive the phrase, so treat both as one
secret.

## What recovery does and doesn't cover

Recovery restores *your key*, not the vault. It's local to your machine and
has nothing to do with git. Losing the `.murk` file itself isn't a
recovery-phrase problem, since the file lives in your repo and git already
keeps history for it.

Recovery phrases apply only to age keys. SSH keys and hardware-backed
identities (YubiKey, Secure Enclave, FIDO2) have none. See [hardware
keys](/guides/hardware-keys/) for how recovery works differently there.

## If your key was stolen

Restoring from the phrase gives back the same key, so it does not remove the
attacker's access. Replace the key instead:

1. If no teammate can authorize a new key for you (for example, you are the
   only recipient), restore the old key as shown above. Only a current
   recipient can change the recipient list.
2. On a trusted machine, in a clean clone, unset `MURK_KEY` and
   `MURK_KEY_FILE` and run `murk init`. With no stored key for this vault, it
   creates a new key and prints its public key.
3. Authorize the new key with `murk circle authorize <new-public-key>`, and
   add it to each group the old key belonged to with `murk group add NAME
   --member <new-public-key>`. Without this, the new key cannot read or
   rotate those groups' secrets. Run these with the old key
   (`MURK_KEY_FILE=~/.config/murk/restored.key`), or ask a teammate who is a
   member of those groups.
4. Switch to the new key. Run `unset MURK_KEY MURK_KEY_FILE` so murk uses the
   key from step 2. murk refuses to revoke the key it runs as, so this step
   fails with the old key. In a terminal, revoke the old key and enter a new
   value for each secret: `murk circle revoke <old-public-key> --rotate` (see
   [offboarding a teammate](/guides/offboarding/)).
5. Delete the restored key file and remove its `export` line.
6. Replace the real credentials at their providers. Distribute the new ones,
   then invalidate the old ones (in an urgent case, invalidate them first).

See the [CLI reference](/reference/cli/#murk-restore) for the full command
surface.
