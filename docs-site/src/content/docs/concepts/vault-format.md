---
title: Vault format
description: "The on-disk structure of the .murk file: header, secrets, and encrypted meta."
sidebar:
  order: 2
---

A `.murk` file is a single JSON document. Every field is plaintext except the per-key encrypted values and one encrypted `meta` blob. This page walks through the structure conceptually. See [SPEC.md](https://github.com/interrupted-inc/murk/blob/main/SPEC.md#file-format) on GitHub for the exact field-by-field schema.

## The plaintext header

- **`version`**: semver. murk validates the major version on load (rejecting a vault with a different major version). It accepts minor bumps transparently.
- **`created`, `vault_name`, `repo`**: informational metadata about the vault.
- **`recipients`**: the list of authorized public keys (age, SSH, or hardware-plugin), and nothing else. No names or emails live here. See [Recipients & signatures](/concepts/recipients-signatures/) for where those go and why.
- **`schema`**: one entry per key name, with a `description` and optional `example` and `tags`, plus optional lifecycle fields (`created`, `updated`, `rotation_interval_days`, `expires_at`, `revoked_at`) that `murk doctor` and `murk rotate --list` use to flag overdue or expiring credentials. This is public and readable without a key: it's what `murk info` and `murk ls` show. Key names must be valid shell identifiers.
- **`policy`** *(optional)*: an agent allow-tag list. It lives in the plaintext header, at the same trust level as the recipient list, specifically so it's readable without a key. See [Grants](/concepts/grants/).

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
- **`signers` / `sig`**: the Ed25519 verifying-key registry and the current signature, which make tampering by a repo-writer attributable.

The mechanics of the MAC and signatures (what they protect against and what they don't) are covered in [Recipients & signatures](/concepts/recipients-signatures/).

## Illustrative skeleton

```json
{
  "version": "2.0",
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
  "meta": "<age ciphertext: recipients, groups, grants, mac, signers>"
}
```

All ciphertext is base64-encoded age output. `policy`, `scoped`, and `grouped` are only present when the vault actually uses them, so a vault that never touches groups, grants, or policy stays byte-identical to one written by an older murk version.
