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
unsigned: a warning on next load, not a hard failure. A team entirely on
hardware keys relies on git as the integrity anchor. A mixed team is signed
whenever a signing-capable holder last wrote. See the [threat
model](/security/threat-model/) for the full signing story.

## Choosing `MURK_KEY` vs `MURK_KEY_FILE`

Setting `MURK_KEY` to a raw `AGE-SECRET-KEY-1...` string works, but the key
is then plaintext in your environment/`.env`. Prefer `MURK_KEY_FILE`
pointing at either a file under `~/.config/murk/keys/` (the `murk init`
default, fine for development) or a hardware-backed plugin identity file
(recommended for production use). See [environment
variables](/concepts/env-vars/) for the full list murk reads.
