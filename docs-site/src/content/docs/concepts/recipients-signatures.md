---
title: Recipients & signatures
description: How recipients are authorized and pinned, and how the MAC and signature protect the vault.
sidebar:
  order: 3
---

Two separate mechanisms protect a `.murk` file: the **recipient list** controls who can decrypt it, and the **integrity MAC and signature** detect whether it's been tampered with.

## Adding and removing recipients

`murk circle authorize PUBKEY --name NAME` adds a recipient and re-encrypts every shared secret so the new key can read it. PUBKEY can be an `age1...` key, an `ssh-ed25519 ...` key, `ssh:PATH` (a public key file; `ssh:` alone reads `~/.ssh/id_ed25519.pub`) or `github:USERNAME`. murk refuses `ssh-rsa` keys unless you pass `--allow-ssh-rsa`. For `github:USERNAME`, it skips them with a warning instead. murk fetches that user's keys from `https://github.com/USERNAME.keys` and records their fingerprints in `github_pins` in the encrypted meta. If the account's keys change later, the next `authorize github:USERNAME` stops and shows what was added or removed. Pass `--force` to accept the change. Pass `--group NAME` to add the recipient to a group in the same step.

Display names are stored only inside the encrypted `meta` blob, never in the plaintext `recipients` list, so the pubkey-to-person mapping is itself protected, even though the existence of a pubkey isn't.

`murk circle revoke RECIPIENT [--rotate]` removes a recipient's pubkey, re-encrypts shared secrets without it, and drops that recipient's private entries. You can't revoke yourself. Ask another recipient to run `murk circle revoke <you>`. **Revocation doesn't erase git history**: the revoked recipient can still decrypt any vault version they previously had access to. Rotation is the only way to close the exposure. With `--rotate`, or if you answer yes at the prompt, murk asks you for a new value for each shared or group value the recipient could read, and keeps each value in its tier. If you decline, murk marks those keys with `revoked_at`. `murk doctor` and `murk rotate --list` report them until their values change.

## The integrity MAC

On every save, murk computes a BLAKE3 keyed hash over the key names, the per-key ciphertexts, the recipient list, the schema, the group and grant definitions, the policy and any `revoked_at` markers. It stores the digest as `mac`, with its key `mac_key`, in the encrypted meta. On load, murk recomputes the hash and refuses the vault if it differs. This catches corruption and edits made without rebuilding the meta.

It is **not** a defense against a malicious recipient or anyone else with write access to the repo. age only needs recipients' *public* keys (which sit in the plaintext header) to re-encrypt content, so a repo-writer can mint a fresh `mac_key`, recompute a valid MAC over tampered content, and re-encrypt `meta` to match. Authorship integrity comes from the signature below, not the MAC.

## Signatures

murk signs the vault with Ed25519 on every save when the writer's identity can sign. A repo-writer who is not a recipient cannot produce a valid signature for an `ssh-ed25519` signer, or for an age signer whose key this machine has already pinned (see [Signer-registry pinning](#signer-registry-pinning-tofu) below). On a first load with no pin, murk trusts an age signer's key as the meta states it. The MAC alone cannot give this guarantee. A recipient can still sign their own changes. The signature makes those changes attributable, like a signed git commit, but it does not make them impossible.

Two identity types can sign: an **age** key (an Ed25519 key derived from the raw age key bytes via a domain-separated KDF, so the same BIP39 phrase recovers both), and an **ssh-ed25519** key (which signs directly, since the key itself is already Ed25519). `ssh-rsa` keys and hardware/plugin identities can't sign, so vaults saved with those identities are written unsigned.

On load, if a signature is present, murk requires the signer to be a current recipient and the signature to match the vault's content: **a present-but-invalid signature fails the load as tampering**, not a warning. If there is no signature, the vault loads and integrity rests on git. murk warns about an unsigned vault with secrets only when your own key can sign. murk also remembers that a vault was signed before on this machine. If that vault later loads unsigned, murk warns, `murk verify` reports a finding, and strict mode (`MURK_STRICT`) refuses the load. When the merge driver has a key and regenerates the meta, it deliberately leaves the merged vault unsigned, since resolving a merge automatically isn't the same as vouching for the result. The next person to write the vault re-signs it. Before that write, review `git diff -- .murk` for recipients, schema, policy and ciphertext entries, and `murk diff` for secret values. `murk diff` does not check the MAC or signature of the old revision it compares against.

## Signer-registry pinning (TOFU)

The registry mapping a recipient's pubkey to their verifying key lives inside the re-encryptable `meta` blob, which on its own would let a repo-writer register a rogue verifying key under an existing recipient's pubkey and forge that recipient's signature. To close that gap, murk pins each pubkey → verifying-key mapping locally on first sight, in `~/.config/murk/signer-pins/<vault-hash>.json`, and enforces it on every subsequent load: a *changed* verifying key for an already-pinned pubkey is never legitimate, since the mapping is a fixed derivation, so the load fails as an integrity error. New pubkeys are trusted on first use. The `MURK_NO_SIGNER_PIN` variable opts out of this check. See [Environment variables](/concepts/env-vars/).

## Where this fits

The [threat model](/security/threat-model/) covers the full malicious-recipient boundary and what signatures do and don't close. [Vault format](/concepts/vault-format/) shows where the MAC, signer registry, and signature live on disk. [Hardware-backed keys](/guides/hardware-keys/) covers plugin identities, which authorize and decrypt normally but can't sign. [SSH keys & git merge](/guides/git-merge-ssh/) covers `ssh-ed25519` signing and the merge driver's unsigned-then-resign flow in practice.
