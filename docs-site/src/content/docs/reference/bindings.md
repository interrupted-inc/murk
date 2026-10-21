---
title: Library bindings
description: Read murk secrets from Python and Node.js, and write them from Node.js.
sidebar:
  order: 4
---

murk ships Python and Node.js bindings so a program can read its secrets
without shelling out to the CLI. They are published as
[`murk-secrets`](https://pypi.org/project/murk-secrets/) on PyPI and
[`@interrupted/murk-secrets`](https://www.npmjs.com/package/@interrupted/murk-secrets) on
npm.

Both bindings load and decrypt an existing vault. The Node binding can also
store secrets and key descriptions, like `murk add` and `murk describe`.
The Python binding is read-only. Rotation, recipient and group changes, and
agent grants stay in the [CLI](/reference/cli/). Use a binding when a program
needs secrets in memory. If it only needs them as environment variables, use
`murk exec`.

## Prerequisites

The bindings work on a vault the CLI made, so first you need:

1. The [murk CLI](/install/).
2. A `.murk` vault: run `murk init`, then `murk add KEY` for each secret.
3. A key the bindings can find. They look in this order:
   - `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (a key file path).
     Set one, not both: murk refuses to load when both are set.
   - The key file `murk init` stored under `~/.config/murk/keys/`.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On
the machine where you ran it, you do not need to source it. Set the variable
yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is
set, because both turn off the stored-key lookup. See
[Environment variables](/concepts/env-vars/).

Both packages ship prebuilt native binaries with release provenance. See
[Verifying releases](/security/verifying/) to check it.

## Python

Requires Python ≥ 3.9. The Python binding is read-only.

```bash
pip install murk-secrets
```

```python
import murk

# Load the vault (finds your key as described above)
vault = murk.load()

db_url = vault.get("DATABASE_URL")   # str | None
secrets = vault.export()             # dict[str, str] of everything you can read
api_key = vault["API_KEY"]           # dict-style access; raises RuntimeError if the key is not readable

stripe = vault.get("STRIPE_SECRET")
if stripe is not None:
    charge(stripe)
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
| `murk.has_identity()` | `bool` | `True` if murk can find a key for `./.murk` (`MURK_KEY`, `MURK_KEY_FILE` or the stored key file). It does not read the vault, so it does not guarantee that `load` succeeds |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `str \| None` | Decrypted value, or `None` if no value is readable for the key |
| `vault.export()` | `dict[str, str]` | All readable secrets |
| `vault.keys()` | `list[str]` | Key names in the vault schema, including keys you cannot read |
| `vault[key]` | `str` | Like `get`, but raises `RuntimeError` (not `KeyError`) if no value is readable |
| `key in vault` | `bool` | `True` if the key is in the schema, even if you cannot read its value |
| `len(vault)` | `int` | Number of keys in the schema |

## Node.js

Requires Node.js 18.17 or later on Node 18, or 20.3 or later. Node 19 is not
supported. The addon uses Node-API version 9. TypeScript types are bundled.
The Node binding reads
and writes: it can store secrets and descriptions as well as decrypt them.

```bash
npm install @interrupted/murk-secrets
```

```typescript
import { load, get, exportAll, add } from "@interrupted/murk-secrets";

// Load the vault (finds your key as described above)
const vault = load();

const dbUrl = vault.get("DATABASE_URL");   // string | null
const secrets = vault.export();            // Record<string, string>

const stripe = vault.get("STRIPE_SECRET");
if (stripe !== null) {
  charge(stripe);
}

// Store a secret (encrypted to everyone by default)
vault.add("NEW_TOKEN", "value");
vault.add("MY_TOKEN", "value", { tier: "me" });        // personal, scoped to you
vault.add("TEAM_TOKEN", "value", { tier: "backend" }); // to a named group

// One-liners load the vault on each call
get("DATABASE_URL");
exportAll();
add("NEW_TOKEN", "value");
```

### API

> Every decrypted value murk returns is a plain host-language string. See [Decrypted values in memory](#decrypted-values-in-memory) for the lifetime caveat.

#### Functions

| Function | Returns | Description |
|---|---|---|
| `load(vaultPath?)` | `Vault` | Load and decrypt a vault |
| `get(key, vaultPath?)` | `string \| null` | One-liner: load, then read one key |
| `exportAll(vaultPath?)` | `Record<string, string>` | One-liner: load, then export everything |
| `add(key, value, options?, vaultPath?)` | `void` | One-liner: load, then store a secret |
| `hasIdentity()` | `boolean` | `true` if murk can find a key for `./.murk` (`MURK_KEY`, `MURK_KEY_FILE` or the stored key file). It does not read the vault, so it does not guarantee that `load` succeeds |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `string \| null` | Decrypted value, or `null` if no value is readable for the key |
| `vault.export()` | `Record<string, string>` | All readable secrets |
| `vault.keys()` | `string[]` | Key names in the vault schema, including keys you cannot read |
| `vault.has(key)` | `boolean` | `true` if the key is in the schema, even if you cannot read its value |
| `vault.add(key, value, options?)` | `void` | Store a secret (see [Writing secrets](#writing-secrets-node)) |
| `vault.describe(key, description, options?)` | `void` | Set a key's description, tags, or example |
| `vault.length` | `number` | Number of keys in the schema |

### Writing secrets (Node)

`vault.add(key, value, options?)` works like `murk add`. It encrypts the value,
re-signs the vault and writes it back to disk under an exclusive lock, so
concurrent writers are safe. The loaded `Vault` refreshes, so later reads on
the same handle see the write. Key names must start with a letter or
underscore and contain only `A-Z`, `a-z`, `0-9` and `_`.

All options are optional:

| Option | Type | Description |
|---|---|---|
| `tier` | `string` | Where the value lives: `"everyone"` (default, encrypted to every recipient except agent grants), `"me"` (a personal value encrypted to you only), or a group name (encrypted to that group's members — you must be a member) |
| `desc` | `string` | Human-readable description recorded in the vault schema |
| `tags` | `string[]` | Tags recorded on the key. Tags are the unit the agent allow-tag policy gates on |

`tier` accepts aliases: `"all"` and `"shared"` mean `"everyone"`, and
`"self"` and `"mine"` mean `"me"`. These six names are reserved and cannot
name a group. Matching is case-sensitive, so `"Everyone"` names a group. Any
other string names a group, so a misspelled tier fails with `group not found`
unless a group with that name exists.

An `everyone` or group write replaces the key's base value. A group write
removes the shared value, and a shared write removes the group assignment. A
`me` write leaves the shared value alone. `add` adds `tags` to the key's
existing tags. It never removes one.

`vault.describe(key, description, options?)` works like `murk describe`,
without `--rotate-every` and `--expires`. It never touches the value. It
always replaces the description. `options.tags` replaces the existing tags
when it is non-empty. `options.example` sets the example value (for
`.env.example`-style docs), and leaving it out clears the current one. If the
key does not exist yet, `describe` creates a documented entry with no value.

## How reads resolve

Both bindings resolve a key the way the CLI does: a personal
[scoped](/guides/shared-vs-scoped/) value first, then a group value you can
read, then the shared value. `export()` merges the same way and returns only
values you can decrypt.

`keys()`, `len()` (`length` in Node) and `in` (`has()` in Node) read the vault
schema, which is plaintext. They list every key in the vault, including keys
you cannot decrypt and keys documented without a value.

## Agent policy is enforced on read and write

When the loaded key is an [agent grant](/concepts/grants/) (from
`murk agent grant`), the bindings enforce the vault's agent policy on every
read and write, the same gate as `murk agent exec`:

- `get()` raises or throws if the grant can read the key but the policy
  forbids it. For a key the grant cannot read, it returns `None` or `null`.
- `export()` checks the whole readable set first and rejects the call if any
  key is out of policy. It never returns partial results.
- `add()` and `describe()` (Node) check the resulting key before saving. A
  forbidden write fails and leaves the vault on disk unchanged.
- Once the grant's TTL has passed, `export()`, `add()`, `describe()` and
  `get()` of a readable key fail. `keys()`, `len()`/`length` and `in`/`has()`
  read only the schema and never check the policy.

Python raises `RuntimeError`. Node throws. A plain operator key skips the
check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set, which holds your own
key to the policy the same way (see
[Environment variables](/concepts/env-vars/)). A grant also cannot decrypt
out-of-scope secrets, because its ephemeral key is not a recipient of them.
The policy check is a backstop, not the only guard. See
[AI agents & MCP](/guides/ai-agents-mcp/) for the full model.

A loaded `Vault` keeps the decrypted values and policy from its last load.
`get()` and `export()` use that snapshot, so policy changes and revocations
reach them only when the program calls `load()` again. In Node, `add()` and
`describe()` reload the vault from disk first, so they always check the
current policy. They then refresh the handle, so later reads see the new
state too. Grant expiry is checked again on each value read.

## Decrypted values in memory

murk zeroes plaintext from its own memory when a value is dropped, but that
stops at the FFI boundary. `get()` and `export()` return native values — a
Python `str`/`dict`, a JavaScript `string`/object — and once a value is in
your program the runtime owns it. murk can't wipe it. That's unavoidable when
you read secrets into a process, and it's noted in the
[threat model](/security/threat-model/). It doesn't touch the vault on disk,
only how long values linger in memory — so don't hold them longer than needed.

The Node write path makes this sharper. To call `vault.add(key, value)` you
already hold the plaintext as a JavaScript string before the call. It lives in
V8's heap, is copied across the FFI boundary, and is zeroized on neither side.
Build the value as late as possible, pass it straight into `add()`, and don't
keep it around.
