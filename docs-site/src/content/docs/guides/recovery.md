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

The 24 words print once, at key-generation time. **Write them down somewhere
durable and offline**: a password manager, a physical safe, whatever your
threat model calls for. Anyone with your 24 words has your key: treat the
phrase exactly like the key itself. Don't paste it into chat, don't commit
it, don't screenshot it into a note-taking app synced to the cloud without
thinking about who else can read that account.

## Recovering a lost key

If you lose the key file itself (new machine, wiped disk, whatever) but
still have the recovery phrase, restore it:

```bash
murk restore
```

This prompts for your 24-word phrase with hidden input and re-derives your
original keypair. Because the derivation is deterministic, the restored key
is identical to the one `murk init` generated: same public key, so you're
still a valid recipient on any vault that already authorized you. Nothing on
the vault side needs to change.

## Displaying your phrase again

If you still have your key but want to re-display (or re-back-up) its
recovery phrase:

```bash
murk recover
```

This re-derives the 24-word phrase from your current `MURK_KEY` (useful if
you generated a key and didn't securely record the phrase the first time).

## What recovery does and doesn't cover

Recovery restores *your key*, not the vault. It's local to your machine and
has nothing to do with git. Losing the `.murk` file itself isn't a
recovery-phrase problem, since the file lives in your repo and git already
keeps history for it.

Recovery phrases also only apply to raw age keys. If you're using a
hardware-backed identity (YubiKey, Secure Enclave, FIDO2), there is no BIP39
phrase to write down. See [hardware keys](/guides/hardware-keys/) for how
recovery works differently there.

If you're recovering because your machine (and therefore your key) was
compromised, don't stop at `murk restore`: rotate the secrets that key could
read once you're back in, the same as you would for any other exposed
credential. See [offboarding a teammate](/guides/offboarding/) for the
revoke-and-rotate pattern, and the [CLI reference](/reference/cli/#murk-restore)
for the full command surface.
