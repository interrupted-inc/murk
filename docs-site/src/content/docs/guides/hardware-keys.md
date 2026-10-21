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
identity file. With the YubiKey, Secure Enclave and OpenPGP card plugins, the
private key stays on the device. This is the same [age plugin
mechanism](https://github.com/FiloSottile/age#plugins) the wider age
ecosystem uses, so any plugin that speaks it works with murk.

| Hardware | Plugin |
| --- | --- |
| YubiKey 4 and 5 | [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) |
| Apple Secure Enclave (Touch ID) | [`age-plugin-se`](https://github.com/remko/age-plugin-se) |
| OpenPGP card (YubiKey, Nitrokey) | [`age-plugin-openpgp-card`](https://crates.io/crates/age-plugin-openpgp-card) |
| FIDO2 key with `hmac-secret` (experimental; the identity is held in memory while decrypting) | [`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) |

## Example: setting up a YubiKey

```bash
# 1. Install the plugin. murk runs it to encrypt and to decrypt, so it must
#    be on $PATH.
brew install age-plugin-yubikey

# 2. Generate an identity bound to the YubiKey. Prompts for the PIV PIN
#    (default 123456) and a touch. --touch-policy always asks for a tap on
#    every decrypt. --pin-policy once asks for the PIN once per session.
age-plugin-yubikey --generate --touch-policy always --pin-policy once \
  > ~/.config/murk/yubikey.txt

# murk refuses identity files readable by others
chmod 600 ~/.config/murk/yubikey.txt

# 3. With your current key, authorize the YubiKey's public key.
murk circle authorize "$(grep -i recipient ~/.config/murk/yubikey.txt | awk '{print $NF}')" --name yubikey

# 4. Switch to the YubiKey. Add this line to your shell profile or .envrc.
export MURK_KEY_FILE=~/.config/murk/yubikey.txt

# 5. Read a secret. The YubiKey blinks; tap it to decrypt.
murk get SOME_KEY
```

Authorize first, then switch. Once `MURK_KEY_FILE` points at the YubiKey,
murk uses only that identity. It is not a recipient yet, so
`murk circle authorize` would fail. murk does not read `.env`, so the export
has to reach your shell.

The identity file has a `#    Recipient: age1yubikey1...` header followed by
an `AGE-PLUGIN-YUBIKEY-1...` line. murk reads your public key from the header
without calling the plugin. It runs the plugin whenever it encrypts to a
plugin recipient or decrypts with a plugin identity. Every write re-encrypts
the vault metadata to all recipients, so every teammate who writes to a vault
with a hardware recipient needs the plugin installed, whatever kind of key
they use. Teammates with software keys can read without it.

Each command decrypts the vault metadata and each secret you can read as
separate operations, and each one runs the plugin. With
`--touch-policy always`, a single command can therefore ask for more than one
tap. The exact number of taps and how long the PIN stays cached depend on the
plugin and the device, and this guide has not measured them. Try a few
commands with your own key before you rely on it.

Adding the YubiKey does not remove your software key. It is still a
recipient, its file is still in `~/.config/murk/keys/`, and its recovery
words still recreate it. Anyone who can read that file can still decrypt the
vault. To finish the move, first enroll and test a backup device (see below).
Then revoke the old key with `murk circle revoke <name> --rotate` (`murk
circle` lists the names) and delete its key file. The old key can still
decrypt every earlier version of `.murk` in git history, so change the
secrets at their provider as well.

The same pattern applies to the other plugins in the table: generate an
identity file with the plugin's own CLI, authorize the public key it prints
with your current key, then point `MURK_KEY_FILE` at it.

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
`murk recover` fails on plugin identities (and on SSH keys). `murk restore`
does not look at your current identity. It turns a phrase back into the age
key that phrase encodes, which has nothing to do with your hardware key.

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
the integrity anchor, and `murk verify` reports the unsigned vault as a
finding. A machine whose own key can sign (age or
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
