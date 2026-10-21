---
title: Vault format
description: "The on-disk structure of the .murk file: header, secrets, and encrypted meta."
sidebar:
  order: 2
---

A `.murk` file is a single JSON document. Every field is plaintext except the per-key encrypted values and one encrypted `meta` blob. This page walks through the structure conceptually. See [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#file-format) on GitHub for the exact field-by-field schema.

## The plaintext header

- **`version`**: semver. murk validates the major version on load (rejecting a vault with a different major version). It accepts minor bumps transparently.
- **`created`, `vault_name`, `repo`**: informational metadata about the vault.
- **`vault_id`, `generation`**: the vault's identity and a save counter. `vault_id` is 32 lowercase hex characters, random for a vault made by `murk init`. A vault written by 0.13 has none, and the first 0.14 save derives one from its `created` timestamp and name, so teammates who upgrade separately agree on it. `generation` goes up on every save. Both are covered by the signature, and each machine checks them against its trust pin, so another vault's file or an older revision is refused. See [Trusting a signer](/concepts/recipients-signatures/#trusting-a-signer).
- **`recipients`**: the list of authorized public keys (age, SSH, or hardware-plugin), and nothing else. No names or emails live here. See [Recipients & signatures](/concepts/recipients-signatures/) for where those go and why.
- **`schema`**: one entry per key name, with a `description` and optional `example` and `tags`, plus optional lifecycle fields (`created`, `updated`, `rotation_interval_days`, `expires_at`, `revoked_at`) that `murk doctor` and `murk rotate --list` use to flag overdue or expiring credentials. This is public and readable without a key: it's what `murk info` and `murk ls` show. Without a key nothing checks it, so those commands print a `warn unverified header` line. Key names must be valid shell identifiers.
- **`policy`** *(optional)*: an agent allow-tag list. It lives in the plaintext header, at the same trust level as the recipient list, specifically so it's readable without a key. See [Grants](/concepts/grants/).
- **`sig`** *(optional)*: the signature over the rest of the file: the signer, the signed-view version, and a base64 Ed25519 signature. It covers every other field, the encrypted meta included, and makes tampering by a repo-writer attributable. It is omitted when the last writer couldn't sign. Vaults written before 3.0 carried a view-1 signature inside the meta instead.

## Encrypted secret values

Each key in `secrets` carries up to three ciphertext fields, one age blob per tier:

- **`shared`**: encrypted to every recipient (the `everyone` group).
- **`scoped`**: a map of recipient pubkey → ciphertext, one entry per recipient with a private override (the `me` tier — the field is still named `scoped` on disk for backward compatibility with vaults written before that tier was renamed).
- **`grouped`**: a map of group name → ciphertext, for secrets whose base tier is a named group rather than `everyone`.

A secret's base tier is exactly one of `shared` or a single `grouped` entry: assigning it to a named group drops any existing shared value. The private (`me`) override layers on top of whichever base tier is active. Because age determines readability from the ciphertext's recipients, a non-member of a group can't decrypt its `grouped` entry. There's no separate access check.

## The encrypted meta blob

`meta` is a single age blob, encrypted to every recipient, holding everything that shouldn't be visible in the plaintext header:

- **`recipients`**: the only place public keys are mapped to display names.
- **`groups`**: group name → member pubkeys, kept out of the header so org structure (who's in which group) doesn't leak to a non-recipient.
- **`grants`**: the agent grant registry (ephemeral pubkey, scope, TTL, issuer), kept out of the header so an agent's existence and scope don't leak either. See [Grants](/concepts/grants/).
- **`mac` / `mac_key`**: the keyed integrity hash covering the vault's contents, and the key used to compute it.
- **`signers`** *(age keys only)*: the signer registry, mapping each age signer's recipient to the base64 Ed25519 verifying key it signs with. That key can't be computed from the `age1...` recipient, so the writer records it on every save, and a loader believes an entry only as [Recipients & signatures](/concepts/recipients-signatures/#a-new-teammates-first-write) describes. `ssh-ed25519` keys are never listed: the recipient string is the verifying key.

The mechanics of the MAC and signatures (what they protect against and what they don't) are covered in [Recipients & signatures](/concepts/recipients-signatures/).

## Illustrative skeleton

```json
{
  "version": "2.0",
  "vault_id": "3f1c0d7a9b2e4c6d8e0f1a2b3c4d5e6f",
  "generation": 12,
  "recipients": ["age1abc...", "age1xyz..."],
  "schema": {
    "DATABASE_URL": { "description": "postgres connection string" }
  },
  "policy": { "agent_allow_tags": ["agents"] },
  "secrets": {
    "DATABASE_URL": {
      "shared": "<age ciphertext>",
      "scoped": { "age1xyz...": "<age ciphertext>" }
    }
  },
  "meta": "<age ciphertext: recipients, groups, grants, signers, mac>",
  "sig": { "signer": "age1abc...", "v": 2, "sig": "<base64 Ed25519 signature>" }
}
```

All ciphertext is base64-encoded age output. `policy`, `scoped`, and `grouped` are only present when the vault actually uses them, so a vault that never touches groups, grants, or policy carries none of those fields.
