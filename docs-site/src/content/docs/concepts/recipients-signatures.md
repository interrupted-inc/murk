---
title: Recipients & signatures
description: How recipients are authorized and pinned, and how the MAC and signature protect the vault.
sidebar:
  order: 3
---

Two separate mechanisms protect a `.murk` file: the **recipient list** controls who can decrypt it, and the **integrity MAC and signature** detect whether it's been tampered with.

## Adding and removing recipients

`murk circle authorize PUBKEY --name NAME` adds a new recipient and re-encrypts every shared secret so the new key can read it. It accepts three formats: a raw `age1...` key, an `ssh-ed25519 ...` key, or `github:username`, which fetches that user's SSH public keys from `https://github.com/<username>.keys`. GitHub-sourced keys are pinned by fingerprint on first authorize (in the encrypted meta's `github_pins`), so if the account's keys change later, the next `authorize github:<user>` flags the diff instead of silently trusting new keys. Pass `--group` to add the recipient to a named group in the same step.

Display names are stored only inside the encrypted `meta` blob, never in the plaintext `recipients` list, so the pubkey-to-person mapping is itself protected, even though the existence of a pubkey isn't.

`murk circle revoke RECIPIENT [--rotate]` removes a recipient's pubkey, re-encrypts shared secrets without it, and drops that recipient's private entries. **Revocation doesn't erase git history**: the revoked recipient can still decrypt any vault version they previously had access to. `--rotate` (or the interactive prompt) walks through generating new values for everything they could read. That's the only way to actually close the exposure.

## The integrity MAC

Every save computes a BLAKE3 keyed hash over the vault's key names, per-key ciphertexts, recipient list, schema, group and grant definitions, policy, and any pending-rotation markers, storing the digest as `mac` alongside its key (`hmac_key`) in the encrypted meta. On load, murk recomputes and checks it, catching accidental corruption or a non-recipient's tampering immediately.

It is **not** a defense against a malicious recipient or anyone else with write access to the repo. age only needs recipients' *public* keys (which sit in the plaintext header) to re-encrypt content, so a repo-writer can mint a fresh `hmac_key`, recompute a valid MAC over tampered content, and re-encrypt `meta` to match. Authorship integrity comes from the signature below, not the MAC.

## Signatures

murk signs the vault with Ed25519 on every save where the writer holds a signing-capable identity, so tampering by someone who can write to the repo (but isn't a legitimate recipient acting honestly) is detectable, which the MAC alone can't provide.

Two identity types can sign: an **age** key (an Ed25519 key derived from the raw age key bytes via a domain-separated KDF, so the same BIP39 phrase recovers both), and an **ssh-ed25519** key (which signs directly, since the key itself is already Ed25519). `ssh-rsa` keys and hardware/plugin identities can't sign, so vaults saved with those identities are written unsigned.

On load, if a signature is present, murk requires the signer to be a current recipient and the signature to match the vault's content: **a present-but-invalid signature fails the load as tampering**, not a warning. An absent signature loads with an "unsigned" warning instead. Integrity then rests entirely on git. The merge driver deliberately leaves merged vaults unsigned, since resolving a merge automatically isn't the same as vouching for the result. The next person to write the vault re-signs it after reviewing `murk diff`.

## Signer-registry pinning (TOFU)

The registry mapping a recipient's pubkey to their verifying key lives inside the re-encryptable `meta` blob, which on its own would let a repo-writer register a rogue verifying key under an existing recipient's pubkey and forge that recipient's signature. To close that gap, murk pins each pubkey → verifying-key mapping locally on first sight, in `~/.config/murk/signer-pins/<vault-hash>.json`, and enforces it on every subsequent load: a *changed* verifying key for an already-pinned pubkey is never legitimate, since the mapping is a fixed derivation, so the load fails as an integrity error. New pubkeys are trusted on first use. The `MURK_NO_SIGNER_PIN` variable opts out of this check. See [Environment variables](/concepts/env-vars/).

## Where this fits

The [threat model](/security/threat-model/) covers the full malicious-recipient boundary and what signatures do and don't close. [Vault format](/concepts/vault-format/) shows where the MAC, signer registry, and signature live on disk. [Hardware-backed keys](/guides/hardware-keys/) covers plugin identities, which authorize and decrypt normally but can't sign. [SSH keys & git merge](/guides/git-merge-ssh/) covers `ssh-ed25519` signing and the merge driver's unsigned-then-resign flow in practice.
