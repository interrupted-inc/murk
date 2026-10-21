---
title: Grants
description: Scoped, time-boxed vault access for AI agents and automation.
sidebar:
  order: 4
---

A grant gives an agent or tool read access to a fixed set of secrets, for a limited time, through a key that is deliberately not yours.

## A grant key isn't your key

`murk agent grant --name NAME --only KEY [--ttl DUR]` mints a fresh, ephemeral age identity: never your `MURK_KEY`. The grant is a recipient, but it can't read the encrypted `meta` blob, and it's excluded from the `everyone` layer entirely. It gets its own record (name, scope, issue and expiry times, issuer), encrypted to its key alone in the vault's top-level `agents` map. Its actual access is the set of `--only` keys, each re-encrypted as a private ciphertext addressed to the grant's own pubkey. Nothing else in the vault decrypts for it, shared or otherwise. You can grant only keys that have a shared value. murk refuses a key whose base tier is a named group, or that has only private values.

A grant can't check the MAC, because the MAC key lives in the meta. It trusts a vault only by its signature, checked against signers named outside the vault: the `# murk-trusted-signer:` lines murk writes into the grant's key file when it mints or renews the grant, plus any in `MURK_TRUSTED_SIGNERS`. With neither, murk refuses the load and tells you to re-mint the grant. murk checks the signature first, then the grant's own record, then its values.

The key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, which refuses an existing file unless you pass `--force`, or `--out -` to stream it instead of writing a file). It's a bearer credential: whoever holds it has the access it grants, so treat the file like the secrets it unlocks.

## Running with a grant

Point the agent at the grant key and mark it as an agent context:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<vault-hash>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

`MURK_AGENT=1` forces strict mode for that process, so it can never fall back to your stored key in `~/.config/murk/keys` even if `MURK_STRICT` isn't otherwise set: it must present the grant key or fail closed. `murk agent init` does the whole safe-path setup (optionally setting the allow-list, minting the grant, and printing the exact run command) in one step. See [Environment variables](/concepts/env-vars/) for what each variable does, and [AI agents & MCP](/guides/ai-agents-mcp/) for the full walkthrough, including serving a grant over MCP with `murk mcp`.

## What constrains a grant

Scope is a hard, cryptographic boundary: a grant cannot decrypt a key it wasn't given, because no ciphertext exists for its pubkey. On top of that, the vault's optional **agent policy** (`murk policy set --allow-tag TAG`) is a second, binary-enforced guardrail: once set, a secret can only be granted or injected in agent mode if its schema carries an allowed tag, with no override flag. That's a guardrail enforced by the murk binary at its agent entry points, not a sandbox or an access-control system: a compromised agent process, or a human with `age` and the raw key, is outside what any of this stops. See the [threat model](/security/threat-model/) for the full boundary.

## TTL and revocation

`--ttl` (default `2h`) is recorded in the grant's metadata alongside its scope and issuer. **The TTL is enforced at read time**: past `expires_at`, the murk binary refuses the grant on every read (CLI, MCP, the bindings). The MCP `murk_plan` tool still lists the schema of the grant's keys. Like the allow-tag policy, that is a binary-level guardrail, not cryptographic access control — age keys can't self-destruct, and old vault versions stay decryptable from git history with raw age — so revocation is still what closes the exposure. `murk agent ls` lists active grants with their scope and TTL status (time remaining, or how long expired) and works offline.

To renew a grant past (or nearing) its TTL, pass `--renew` to `murk agent grant`: it revokes the existing key and mints a fresh one under the same name, in a single vault write. Without `--renew`, murk refuses a name that already exists, even if the grant has expired.

`murk agent revoke NAME [--rotate]` removes the grant and its ephemeral recipient, clearing its private ciphertexts so it can no longer read current values. Because the key could still decrypt old `.murk` versions from git history, **revocation doesn't erase git history**: `--rotate` re-prompts for new values across the grant's scope, which is the step that actually closes the exposure.

Revocation and policy changes apply when a process loads the vault. A running `murk mcp` server and a loaded binding object keep the vault state from their last load, so they still serve a revoked grant. Restart the server and reload the binding object after you change access. Grant expiry is checked again on every value read.

## Grants never sign or trust

A grant is read-only. murk refuses a vault signed by a grant key, and refuses a former grant key that shows up in the recipients without its grant. `murk trust` won't accept either, and it won't run under a grant identity. So a grant can't decide what a machine trusts: a runner or container that uses a grant key has no pin to lean on and needs `MURK_TRUSTED_SIGNERS` (see [CI/CD](/guides/cicd/#telling-ci-who-may-sign-the-vault)).

## Where grant state lives

The full `grants` registry lives inside the encrypted `meta` blob, not the plaintext header. Each grant also has its own record in the top-level `agents` map, encrypted to that grant only. Grant names, timestamps, issuers and the recorded scope list are encrypted in both places. The ephemeral recipient key and the `scoped` ciphertexts under each secret it can read are plaintext, so which secrets that key can read is visible without decryption. See [Vault format](/concepts/vault-format/) for the full on-disk layout, and [Recipients & signatures](/concepts/recipients-signatures/) for how that meta blob is protected against tampering.
