---
title: Grants
description: Scoped, time-boxed vault access for AI agents and automation.
sidebar:
  order: 4
---

A grant gives an agent or tool read access to a fixed set of secrets, for a limited time, through a key that is deliberately not yours.

## A grant key isn't your key

`murk agent grant --name NAME --only KEY [--ttl DUR]` mints a fresh, ephemeral age identity: never your `MURK_KEY`. The grant becomes a recipient of the encrypted `meta` blob, so it can verify vault integrity and read group/grant state, but it's excluded from the `everyone` layer entirely. Its actual access is the set of `--only` keys, each re-encrypted as a private ciphertext addressed to the grant's own pubkey. Nothing else in the vault decrypts for it, shared or otherwise.

The key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, or `--out -` to stream it instead of writing a file). It's a bearer credential: whoever holds it has the access it grants, so treat the file like the secrets it unlocks.

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

`--ttl` (default `2h`) is recorded in the grant's metadata alongside its scope and issuer. **The TTL is advisory** (age keys can't self-destruct, and old vault versions stay decryptable from git history), so it tells you *when* to act, not a guarantee that access stops on its own. `murk agent ls` lists active grants with their scope and TTL status (time remaining, or how long expired) and works offline.

`murk agent revoke NAME [--rotate]` removes the grant and its ephemeral recipient, clearing its private ciphertexts so it can no longer read current values. Because the key could still decrypt old `.murk` versions from git history, **revocation doesn't erase git history**: `--rotate` re-prompts for new values across the grant's scope, which is the step that actually closes the exposure.

## Where grant state lives

The `grants` map lives inside the encrypted `meta` blob, not the plaintext header, so an agent's existence and its scope don't leak to anyone without a key. See [Vault format](/concepts/vault-format/) for the full on-disk layout, and [Recipients & signatures](/concepts/recipients-signatures/) for how that meta blob is protected against tampering.
