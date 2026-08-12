---
title: Library bindings
description: Read murk secrets at runtime from Python and Node.js with the murk-secrets bindings.
sidebar:
  order: 4
---

murk ships language bindings so a program can read its secrets directly
instead of shelling out to the CLI. They're published as
[`murk-secrets`](https://pypi.org/project/murk-secrets/) on PyPI and
[`@interrupted/murk-secrets`](https://www.npmjs.com/package/@interrupted/murk-secrets) on
npm.

The bindings only read: they load and decrypt an existing vault. You still
create and manage vaults with the [CLI](/reference/cli/) — `murk init`,
`murk add`, `murk circle`, and so on. Reach for a binding when a program wants
its secrets in memory instead of through `source .env`.

## Prerequisites

The bindings read a vault the CLI made, so first you need:

- the [murk CLI](/install/) installed, and a `.murk` vault created with
  `murk init` and populated with `murk add`.
- your key available in the environment as `MURK_KEY` or `MURK_KEY_FILE`.
  `murk init` writes a `.env` that references your key file, so `source .env`
  in the project directory is the usual setup. See
  [Environment variables](/concepts/env-vars/) for what each one does.

Both packages ship prebuilt native binaries with release provenance. See
[Verifying releases](/security/verifying/) to check it.

## Python

Requires Python ≥ 3.9.

```bash
pip install murk-secrets
```

```python
import murk

# Load the vault (reads MURK_KEY / MURK_KEY_FILE from the environment)
vault = murk.load()

db_url = vault.get("DATABASE_URL")   # str | None
secrets = vault.export()             # dict[str, str] of everything you can read
api_key = vault["API_KEY"]           # dict-style access; raises RuntimeError if absent

if "STRIPE_SECRET" in vault:
    charge(vault["STRIPE_SECRET"])
```

The module is imported as `murk` even though the package is `murk-secrets`.

### API

> Every decrypted value murk returns is a plain host-language string. See [Decrypted values in memory](#decrypted-values-in-memory) for the lifetime caveat.

#### Functions

| Function | Returns | Description |
|---|---|---|
| `murk.load(vault_path=".murk")` | `Vault` | Load and decrypt a vault |
| `murk.get(key, vault_path=".murk")` | `str \| None` | One-liner: load, then read one key |
| `murk.export_all(vault_path=".murk")` | `dict[str, str]` | One-liner: load, then export everything |
| `murk.has_identity()` | `bool` | Whether a decryption identity is available (can `load` decrypt?) |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `str \| None` | Decrypted value, or `None` if the key is absent |
| `vault.export()` | `dict[str, str]` | All readable secrets |
| `vault.keys()` | `list[str]` | Key names |
| `vault[key]` | `str` | Dict-style access. Raises `RuntimeError` if absent |
| `key in vault` | `bool` | Membership test |
| `len(vault)` | `int` | Number of secrets |

## Node.js

Requires Node.js ≥ 16. TypeScript types are bundled.

```bash
npm install @interrupted/murk-secrets
```

```typescript
import { load, get, exportAll } from "@interrupted/murk-secrets";

// Load the vault (reads MURK_KEY / MURK_KEY_FILE from the environment)
const vault = load();

const dbUrl = vault.get("DATABASE_URL");   // string | null
const secrets = vault.export();            // Record<string, string>

if (vault.has("STRIPE_SECRET")) {
  charge(vault.get("STRIPE_SECRET")!);
}

// One-liners load the vault on each call
get("DATABASE_URL");
exportAll();
```

### API

> Every decrypted value murk returns is a plain host-language string. See [Decrypted values in memory](#decrypted-values-in-memory) for the lifetime caveat.

#### Functions

| Function | Returns | Description |
|---|---|---|
| `load(vaultPath?)` | `Vault` | Load and decrypt a vault |
| `get(key, vaultPath?)` | `string \| null` | One-liner: load, then read one key |
| `exportAll(vaultPath?)` | `Record<string, string>` | One-liner: load, then export everything |
| `hasIdentity()` | `boolean` | Whether a decryption identity is available (can `load` decrypt?) |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `string \| null` | Decrypted value, or `null` if the key is absent |
| `vault.export()` | `Record<string, string>` | All readable secrets |
| `vault.keys()` | `string[]` | Key names |
| `vault.has(key)` | `boolean` | Membership test |
| `vault.length` | `number` | Number of secrets |

## How reads resolve

Both bindings resolve a key the way the CLI does: a personal
[scoped](/guides/shared-vs-scoped/) override first, then a group value you can
read, then the shared value. `export()` merges the same way. You only ever see
keys your identity is a recipient of.

## Agent policy is enforced on read

When the loaded key is an [agent grant](/concepts/grants/) (from
`murk agent grant`), the vault's agent policy is enforced on every read — the
same gate as `murk agent exec`:

- `get()` rejects a forbidden key.
- `export()` checks the whole readable set first and rejects the call outright
  if any key is out of policy — no partial results.

Python raises `RuntimeError`. Node throws. Operator keys skip the check. A
grant can't decrypt out-of-scope secrets in the first place — its ephemeral
key isn't a recipient of them — so this is a backstop, not the only guard. See
[AI agents & MCP](/guides/ai-agents-mcp/) for the full model.

## Decrypted values in memory

murk zeroes plaintext from its own memory when a value is dropped, but that
stops at the FFI boundary. `get()` and `export()` return native values — a
Python `str`/`dict`, a JavaScript `string`/object — and once a value is in
your program the runtime owns it. murk can't wipe it. That's unavoidable when
you read secrets into a process, and it's noted in the
[threat model](/security/threat-model/). It doesn't touch the vault on disk,
only how long values linger in memory — so don't hold them longer than needed.
