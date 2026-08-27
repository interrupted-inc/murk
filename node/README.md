# @interrupted/murk-secrets

[![npm](https://img.shields.io/npm/v/@interrupted/murk-secrets)](https://www.npmjs.com/package/@interrupted/murk-secrets)

Node.js/TypeScript bindings for [murk](https://github.com/interrupted-inc/murk) — an encrypted secrets manager for developers.

## Prerequisites

You need the [murk CLI](https://github.com/interrupted-inc/murk) to create and manage vaults. This package can read them and store secrets into them; trust-changing operations (rotation, recipient/group changes, agent grants) stay CLI-only.

```bash
# Install the CLI first
brew tap interrupted-inc/murk && brew install murk

# Initialize a vault and add secrets
murk init
murk add DATABASE_URL
murk add API_KEY
```

Then add the Node package to your project:

```bash
npm install @interrupted/murk-secrets
```

## Quick start

```bash
# Load your key (created by murk init)
source .env
```

```typescript
import { load, get, exportAll } from '@interrupted/murk-secrets'

// Load the vault (reads MURK_KEY from environment)
const vault = load()

// Get a single secret
const dbUrl = vault.get('DATABASE_URL')

// Get all secrets as an object
const secrets = vault.export()

// One-liners
get('DATABASE_URL')
exportAll()

// Store a secret (encrypted to everyone by default)
vault.add('NEW_TOKEN', 'value')
vault.add('MY_TOKEN', 'value', { tier: 'me' })        // personal, scoped to you
vault.add('TEAM_TOKEN', 'value', { tier: 'backend' }) // to a named group
add('NEW_TOKEN', 'value')                             // one-liner
```

## API

### `load(vaultPath?: string): Vault`

Load and decrypt a murk vault. Reads `MURK_KEY` or `MURK_KEY_FILE` from the environment.

### `get(key: string, vaultPath?: string): string | null`

One-liner: load the vault and get a single value.

### `exportAll(vaultPath?: string): Record<string, string>`

One-liner: load the vault and export all secrets as an object.

### `add(key, value, options?, vaultPath?): void`

One-liner: load the vault and store a secret. See `vault.add` below.

### `hasIdentity(): boolean`

Whether a decryption identity (`MURK_KEY` / `MURK_KEY_FILE`) is available — i.e. whether `load()` can decrypt. This is not a check for whether a secret exists; use `vault.has(key)` / `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `string \| null` | Get a single decrypted value |
| `vault.export()` | `Record<string, string>` | All secrets as an object |
| `vault.keys()` | `string[]` | List of key names |
| `vault.has(key)` | `boolean` | Check if a key exists |
| `vault.length` | `number` | Number of secrets |
| `vault.add(key, value, options?)` | `void` | Store a secret (see below) |
| `vault.describe(key, description, options?)` | `void` | Set a key's description/tags/example |

Scoped (per-user) overrides are applied automatically — if you have a scoped value for a key, it takes priority over the shared value.

### Writing secrets

`vault.add(key, value, options?)` mirrors `murk add`: it encrypts the value, re-signs the vault, and writes it back to disk under an exclusive lock (safe against concurrent writers). An existing key is overwritten in place. Options:

- `tier` — where the value lives: `'everyone'` (default, shared to all recipients), `'me'` (a personal value encrypted to you only), or a **group name** (encrypted to that group's members; you must be a member).
- `desc` — a human-readable description recorded in the schema.
- `tags` — tags recorded on the key; tags are the unit the agent allow-tag policy gates on.

`vault.describe(key, description, options?)` updates a key's schema metadata (`tags`, `example`) without touching its value. A key with no value becomes a documented-but-unset entry, the same as `murk describe`.

Trust-changing operations — rotation, adding/removing recipients or group members, and minting agent grants — are deliberately **not** exposed here; use the CLI for those.

## Memory hygiene

Every decrypted value murk returns is a plain host-language string. murk zeroes plaintext
from its own memory when a value is dropped, but that guarantee ends at the FFI
boundary: once a value crosses into JavaScript the runtime owns it, and its
garbage collector — not murk — controls its lifetime. This is inherent to
reading secrets into a process (see the
[threat model](https://github.com/interrupted-inc/murk/blob/main/THREAT_MODEL.md)); avoid
holding decrypted values longer than you need them.

The write path makes this sharper. To call `vault.add(key, value)` you already hold
the plaintext as a JavaScript `String` *before* the call — it lives in V8's heap, is
copied across the FFI boundary into a Rust `String`, and is zeroized on neither side.
Reads only ever expose plaintext murk itself produced during decryption; a write means
the plaintext originated in your process and lingers there under the GC's control. Build
the value as late as possible, pass it straight into `add`, and don't keep it around.

## Agent policy

When the loaded key is an agent grant (minted with `murk agent grant`), the vault's agent policy is enforced on read, the same way the CLI enforces it at `murk agent exec`: `get()` and `export()` throw if the policy forbids a key. Operator keys are unaffected. This makes a policy vault strict from every entry point — though an agent already cannot decrypt out-of-scope secrets at all, since its ephemeral key is not a recipient of them.

## Requirements

- Node.js >= 16
- [murk CLI](https://github.com/interrupted-inc/murk) installed (to create and manage vaults)
- A `.murk` vault file in your project (created with `murk init`)
- `MURK_KEY` or `MURK_KEY_FILE` in the environment (created by `murk init`, loaded via `source .env`)

## License

MIT OR Apache-2.0
