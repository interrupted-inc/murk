---
title: Vault format
description: "The on-disk structure of the .murk file: header, secrets, and encrypted meta."
sidebar:
  order: 2
---

A `.murk` file is a single JSON document. Every field is plaintext except the encrypted values and one encrypted `meta` blob. This page walks through the structure conceptually. See [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#file-format) on GitHub for the exact field-by-field schema.

## The plaintext header

- **`version`**: `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` in decimal with no leading zeros, with major `2` or `3`. murk writes `3.0`. It rejects any other major version on load and accepts newer minor versions. A `2.x` vault still loads and becomes `3.0` on its next save. murk 0.13 and older refuse a `3.x` vault as an unsupported version.
- **`created`, `vault_name`, `repo`**: descriptive metadata about the vault. In a `3.x` vault the MAC and the signature cover them.
- **`vault_id`, `generation`** *(optional)*: the vault's identity and a save counter. `vault_id` is 32 lowercase hex characters, random for a vault made by `murk init`. A vault written by 0.13 has none, and the first 0.14 save derives one from its `created` timestamp and name, so teammates who upgrade separately agree on it. `generation` goes up on every save. Both are covered by the MAC and the signature, and each machine checks them against its trust pin, so another vault's file or an older revision is refused. They are omitted when unset. See [Trusting a signer](/concepts/recipients-signatures/#trusting-a-signer).
- **`recipients`**: the list of authorized public keys (age, SSH, or hardware-plugin), and nothing else. No names or emails live here. See [Recipients & signatures](/concepts/recipients-signatures/) for where those go and why.
- **`schema`**: one entry per key name, with a `description` and optional `example` and `tags`, plus optional lifecycle fields (`created`, `updated`, `rotation_interval_days`, `expires_at`, `revoked_at`) that `murk doctor` and `murk rotate --list` use to flag overdue or expiring credentials. This is public and readable without a key: it's what `murk info` and `murk ls` show. Without a key nothing checks it, so those commands print a `warn unverified header` line. Key names must be valid shell identifiers.
- **`policy`** *(optional)*: an agent allow-tag list. It lives in the plaintext header, at the same trust level as the recipient list, specifically so it's readable without a key. See [Grants](/concepts/grants/).
- **`sig`** *(optional)*: the signature over the rest of the file: the signer, the signed-view version, and a base64 Ed25519 signature. It covers every other field, the encrypted meta included, and makes tampering by a repo-writer attributable. It is omitted when the last writer couldn't sign. Vaults written before 3.0 carried a view-1 signature inside the meta instead.

## Encrypted secret values

Each key in `secrets` carries up to three ciphertext fields, one age blob per tier:

- **`shared`**: encrypted to every recipient except agent grants (the `everyone` group). Empty (`""`) when the secret has no shared value, because its base tier is a named group or it has only private values.
- **`scoped`**: a map of recipient pubkey → ciphertext, one entry per recipient with a private override (the `me` tier). The field kept its old name for compatibility with vaults written before the tier was renamed. Each agent grant also has its entries here.
- **`grouped`**: a map of group name → ciphertext, for secrets whose base tier is a named group rather than `everyone`.

A secret has at most one base tier: `shared` or a single `grouped` entry. Assigning it to a named group drops any existing shared value. A secret can also have only private (`me`) values, with an empty `shared` and no `grouped` entry. The private (`me`) override layers on top of any base tier. Because age determines readability from the ciphertext's recipients, a non-member of a group can't decrypt its `grouped` entry. There's no separate access check.

A top-level **`agents`** map *(optional)* maps each grant pubkey to an age blob encrypted to that grant only. The blob holds the grant's own record: its name, scope, issue and expiry times, and issuer. It holds no values and nothing else from the meta. It is omitted when the vault has no grants.

## The encrypted meta blob

`meta` is a single age blob, encrypted to every recipient except agent grants, holding everything that shouldn't be visible in the plaintext header:

- **`recipients`**: the only place public keys are mapped to display names.
- **`groups`**: group name → member pubkeys, kept out of the header so org structure (who's in which group) doesn't leak to a non-recipient.
- **`grants`**: the agent grant registry (ephemeral pubkey, scope, TTL, issuer), kept out of the header so grant names, TTLs and issuers don't leak. The agent's pubkey is still a plaintext recipient, and its `scoped` entries on the secrets show which secrets it can read. See [Grants](/concepts/grants/).
- **`mac` / `mac_key`**: the keyed integrity hash covering the vault's contents, including the header identity fields (`vault_name`, `repo`, `created`, `vault_id` and `generation`), and the key used to compute it.
- **`signers`** *(age keys only)*: the signer registry, mapping each age signer's recipient to the base64 Ed25519 verifying key it signs with. That key can't be computed from the `age1...` recipient, so the writer records it on every save, and a loader believes an entry only as [Recipients & signatures](/concepts/recipients-signatures/#a-new-teammates-first-write) describes. `ssh-ed25519` keys are never listed: the recipient string is the verifying key.
- **`github_pins`**: GitHub username to the SHA-256 fingerprints of the keys fetched when you authorized `github:USER`, used to detect changed keys.

The mechanics of the MAC and signatures (what they protect against and what they don't) are covered in [Recipients & signatures](/concepts/recipients-signatures/).

## The signature

`sig` is a top-level field, outside the meta, so the file alone can be verified. It holds the signer's pubkey, the signed-view version (`2`) and an Ed25519 signature over the whole file with `sig` left out: every header field, the `agents` and `secrets` ciphertexts, and the `meta` ciphertext. It is omitted when the last writer's identity can't sign.

## Validation on load

A `.murk` file arrives through git, so murk treats it as untrusted input. Before it uses a vault, murk rejects files over 64 MiB and checks every field against an allowlist: the version, RFC 3339 timestamps, key and group names, public keys, base64 ciphertexts, and free text without control characters. After it decrypts `meta`, it checks the meta fields the same way. The first failure rejects the whole vault, and the error names the field. murk runs the same checks before it writes a vault. [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#load-time-validation) lists the rules.

## Illustrative skeleton

```json
{
  "version": "3.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "vault_id": "0123456789abcdef0123456789abcdef",
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
  "meta": "<age ciphertext: recipients, groups, grants, mac, signers, github_pins>",
  "sig": { "signer": "age1abc...", "v": 2, "sig": "<base64 Ed25519 signature>" }
}
```

All ciphertext is base64-encoded age output. `policy`, `agents`, `scoped` and `grouped` appear only when the vault uses them. murk writes the newest MAC version on every save, so an older vault upgrades on its next write. The bytes change on every save, because murk generates a fresh `mac_key` and re-encrypts the meta.
