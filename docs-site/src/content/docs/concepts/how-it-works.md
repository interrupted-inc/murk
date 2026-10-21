---
title: How murk works
description: "The single-file vault model behind murk: what's public, what's encrypted, and how layered access works."
sidebar:
  order: 1
---

murk stores secrets in a single `.murk` file that's safe to commit to git. One key unlocks everything you're authorized to read. There's no server and no runtime dependency, and murk implements no custom cryptographic *primitives*. [age](https://age-encryption.org/) does the encryption, with standard BLAKE3 (keyed integrity) and Ed25519 (signatures) on top. What murk adds is the vault format, how those primitives are composed, and the command-line UX around them.

## Your key is your identity

murk derives your public key from `MURK_KEY` (an inline age secret key) or `MURK_KEY_FILE` (a path to one: a raw age key, an SSH key, or a hardware-backed plugin identity). That public key is what determines which private secrets are yours and which entry in the vault's recipient list is you. See [Environment variables](/concepts/env-vars/) for how murk resolves it, and [Recipients & signatures](/concepts/recipients-signatures/) for how a key gets added to a vault in the first place.

Losing the key means losing access. That's exactly why `murk init` prints a BIP39 recovery phrase.

## The header is public, the values aren't

A `.murk` file is one JSON document. Everything in it is plaintext *except* the secret values and one encrypted metadata blob:

- **Recipients**: the public keys authorized to decrypt the vault. No names, just keys.
- **Schema**: key names, descriptions, examples, and tags for every secret. This is what `murk info` and `murk ls` show, and it works without a key at all.
- **Policy**: an optional allow-list constraining what agents can touch (see [Grants](/concepts/grants/)).
- **Secrets**: age ciphertext, one entry per key.
- **Meta**: a single age blob holding recipient display names, group membership, agent grants, and the integrity/signature data. Encrypted so none of it leaks to a non-recipient.

Anyone with read access to the repo can see what secrets exist and why (`murk info`, `murk ls`), which makes vaults easy to audit and diff in git. Only recipients with a valid key can see the *values*. The full byte-level layout lives in [Vault format](/concepts/vault-format/).

## Three layers for one secret

Every secret has a base tier: either **shared** (encrypted to every recipient, the implicit `everyone` group) or a single **named group** (encrypted only to that group's members), plus an optional personal **private override** (a "mote", the `me` tier, encrypted to just your key).

When you `murk get` or `murk export`, resolution goes in order:

1. Your private override, if you've set one for that key.
2. A named-group value, if you're a member of the group holding it.
3. The shared value.

That layering is what lets a team share most config while keeping per-developer or per-environment values (a personal API key, a `prod`-only credential) out of everyone's hands. [Shared vs scoped secrets](/guides/shared-vs-scoped/) covers the day-to-day workflow for choosing between them.

## Agents get a narrower layer still

Recipients and groups are for people. AI agents and automation get a separate mechanism: a **grant** is an ephemeral, time-boxed identity scoped to a fixed set of keys, excluded from the shared layer entirely. It's never your own key. See [Grants](/concepts/grants/) for how that works.

## What this model does and doesn't buy you

Because every recipient except agent grants can decrypt every shared secret by design, murk's access control is a convenience and audit boundary, not a hard security perimeter against an insider: a malicious recipient, or an old murk binary, can always read what their key is authorized for. Git is the audit trail once you commit each recipient change, rotation and grant (murk does not commit for you). The [threat model](/security/threat-model/) spells out exactly what murk protects against and what it doesn't.

For the authoritative, byte-level specification (including the exact JSON schema and the integrity hash algorithm), see [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md) on GitHub.
