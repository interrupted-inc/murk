---
title: Hardware keys (YubiKey)
description: Back murk with a hardware security key.
sidebar:
  order: 6
---

By default, `murk init` generates a raw age key and stores it under
`~/.config/murk/keys/`. That's fine for development, but the private key
exists as plaintext bytes on disk. Anyone with read access to the file can
decrypt everything the key is authorized for.

murk doesn't have a first-class "yubikey" flag or subcommand. Instead it
supports **age plugin identities**: point `MURK_KEY_FILE` at a plugin
identity file. The private key material lives in tamper-resistant
hardware and never exists as raw bytes murk (or anything else) can read
directly. This is the same [age plugin
mechanism](https://github.com/FiloSottile/age#plugins) the wider age
ecosystem uses, so any plugin that speaks it works with murk.

| Hardware | Plugin |
| --- | --- |
| YubiKey, Nitrokey, any PIV-capable smart card | [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) |
| Apple Secure Enclave (Touch ID) | [`age-plugin-se`](https://github.com/remko/age-plugin-se) |
| Any FIDO2 security key | [`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) |
| OpenPGP Card | [`age-plugin-openpgp-card`](https://crates.io/crates/age-plugin-openpgp-card) |

## Example: setting up a YubiKey

```bash
# Install the plugin; it must be on $PATH, murk shells out to it on decrypt
brew install age-plugin-yubikey

# Generate an identity bound to the YubiKey. Prompts for the PIV PIN
# (default 123456) and a touch. --touch-policy always requires a physical
# tap for every decrypt; --pin-policy once caches the PIN per session.
age-plugin-yubikey --generate --touch-policy always --pin-policy once \
  > ~/.config/murk/yubikey.txt

# murk refuses identity files readable by others
chmod 600 ~/.config/murk/yubikey.txt

# Point murk at the identity file
echo 'export MURK_KEY_FILE=~/.config/murk/yubikey.txt' >> .env

# Authorize the YubiKey's public key on your vault
murk circle authorize $(grep -i recipient ~/.config/murk/yubikey.txt | awk '{print $NF}')

# Read a secret: the YubiKey blinks; tap it to decrypt
murk get SOME_KEY
```

The identity file contains a `#    Recipient: age1yubikey1...` header
followed by an `AGE-PLUGIN-YUBIKEY-1...` pointer. murk reads the public key
straight from that header (no plugin call needed just to look up a scoped
secret). It only invokes the plugin binary when actually decrypting, which
is when the YubiKey prompts you to tap it.

The same pattern applies to the other plugins in the table: generate an
identity file with the plugin's own CLI, point `MURK_KEY_FILE` at it, and
authorize the pubkey it prints.

## Failure modes to expect

If the plugin binary isn't on `$PATH`, murk fails with an
`age-plugin-<name> unavailable` error. Install it and retry.

`MURK_KEY` (the inline environment variable, as opposed to `MURK_KEY_FILE`)
rejects `AGE-PLUGIN-...` strings outright. A bare plugin pointer doesn't
carry the recipient public key murk needs, so hardware identities only work
via `MURK_KEY_FILE` pointing at the identity file.

## No BIP39 recovery for hardware identities

The entire point of a hardware-backed key is that the raw key bytes never
leave the device, so there are no bytes to encode as a recovery phrase.
`murk restore` and `murk recover` are age-key-only. Running them against a
plugin identity is a hard error, not a silent no-op.

The recovery strategy for a hardware key is different: **enroll a second
hardware device at setup and add both public keys as recipients**
(`murk circle authorize <backup-pubkey>`). If you lose one device, the
backup still decrypts. Treat this the same way you'd treat a backup SSH key
or a spare hardware security key for any other account: set it up before
you need it, not after you've lost the primary.

## Signing implications

age keys and `ssh-ed25519` keys can produce a vault signature on write.
Hardware/plugin identities and `ssh-rsa` keys cannot (age exposes no signing
scalar for them). Writes from a hardware-only identity leave the vault
unsigned.

What happens next depends on the key that loads it. A hardware or `ssh-rsa`
key loads an unsigned vault with a warning, since it has nothing to check
against: a team entirely on hardware keys relies on signed git commits as
the integrity anchor. A machine whose own key can sign (age or
`ssh-ed25519`) refuses an unsigned vault, because an unsigned file could
come from anyone with write access to the repo. So does any machine that sets
`MURK_TRUSTED_SIGNERS`, whatever its key: once you name the signers you
require, an unsigned vault is refused. A team entirely on hardware keys never
produces a signature, so don't set that variable there. See the [threat
model](/security/threat-model/) for the full signing story.

### Mixed teams

If some teammates sign and some don't, their writes arrive unsigned, and
the signing teammates' machines refuse them. To bring a hardware-key
teammate's change in, a signing teammate reviews it (`git log -p -- .murk`,
`murk diff`) and runs:

```bash
murk trust
```

`murk trust` re-signs the vault with their key. That is a save, so they
commit and push the result. After that, the signing teammates' machines
load the vault again. Keep the review honest: the re-signature vouches for
the whole file, including recipient changes.

A hardware or `ssh-rsa` machine that last accepted this vault signed gets
one refusal when it turns unsigned ("signed when this machine last accepted
it"). Review it the same way. `murk trust` on that machine can't sign, so it
accepts the vault and forgets that a signed version was seen, and later
unsigned loads give only the warning.

## Choosing `MURK_KEY` vs `MURK_KEY_FILE`

Setting `MURK_KEY` to a raw `AGE-SECRET-KEY-1...` string works, but the key
is then plaintext in your environment/`.env`. Prefer `MURK_KEY_FILE`
pointing at either a file under `~/.config/murk/keys/` (the `murk init`
default, fine for development) or a hardware-backed plugin identity file
(recommended for production use). Set one or the other: murk refuses to run
when both are non-empty, and treats an empty value as unset. See [environment
variables](/concepts/env-vars/) for the full list murk reads.
