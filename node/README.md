# @interrupted/murk-secrets

[![npm](https://img.shields.io/npm/v/@interrupted/murk-secrets)](https://www.npmjs.com/package/@interrupted/murk-secrets)

> **Experimental writes.** Reading secrets (`load`, `get`, `exportAll`) is stable. Writing (`add`, `describe`) is experimental: the write API is new and may change. See [Feature status](https://murk.interrupted.sh/reference/feature-status/).

Node.js/TypeScript bindings for [murk](https://github.com/interrupted-sh/murk) — an encrypted secrets manager for developers.

## Prerequisites

You need the [murk CLI](https://github.com/interrupted-sh/murk) to create and manage vaults. This package can read them and store secrets into them; trust-changing operations (rotation, recipient/group changes, agent grants) stay CLI-only.

```bash
# Install the CLI first
brew install interrupted-sh/tap/murk

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
# Optional on the machine that ran murk init (see "Key lookup").
# POSIX shell syntax.
source .env
```

```typescript
import { load, get, exportAll, add } from '@interrupted/murk-secrets'

// Load the vault (finds your key; see "Key lookup")
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

Load and decrypt a murk vault. Finds your key as described in [Key lookup](#key-lookup).

### `get(key: string, vaultPath?: string): string | null`

One-liner: load the vault and get a single value.

### `exportAll(vaultPath?: string): Record<string, string>`

One-liner: load the vault and export all secrets as an object.

### `add(key, value, options?, vaultPath?): void`

One-liner: load the vault and store a secret. See `vault.add` below.

### `hasIdentity(): boolean`

Returns `true` if murk can find a key for `./.murk`: `MURK_KEY`, `MURK_KEY_FILE` or the key file `murk init` stored. Returns `false` if no key is found, if both variables are set, or if the key file cannot be read. It does not read the vault, so `true` does not guarantee that `load()` succeeds. It does not check whether a secret exists. Use `vault.has(key)` or `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `string \| null` | Decrypted value, or `null` if no value is readable for the key |
| `vault.export()` | `Record<string, string>` | All secrets as an object |
| `vault.keys()` | `string[]` | Key names in the vault schema, including keys you cannot read |
| `vault.has(key)` | `boolean` | `true` if the key is in the schema, even if you cannot read its value |
| `vault.length` | `number` | Number of keys in the schema |
| `vault.add(key, value, options?)` | `void` | Store a secret (see below) |
| `vault.describe(key, description, options?)` | `void` | Set a key's description/tags/example |
| `vault.warnings` | `string[]` | Warnings about an accepted vault, the ones the CLI prints as `warn …` (empty for a clean load) |

Scoped (per-user) overrides are applied automatically — if you have a scoped value for a key, it takes priority over the shared value.

### Trust

Every call that reads the vault (`load`, `get`, `exportAll`, `add`, `vault.add`, `vault.describe`) applies the same trust check as the CLI. A vault this machine does not trust — unsigned when your key could have signed it, signed by a key this machine hasn't accepted, rolled back, or tampered with — throws an `Error` whose `code` is `'MURK_TRUST'`, with the CLI's message. Nothing in the binding skips the check. Run `murk trust` once from a shell to accept a vault, or set `MURK_TRUSTED_SIGNERS` in CI. An agent grant key reads only through the trusted signers in its key file or `MURK_TRUSTED_SIGNERS`.

### Writing secrets

`vault.add(key, value, options?)` mirrors `murk add`: it encrypts the value, re-signs the vault, and writes it back to disk under an exclusive lock (safe against concurrent writers). An `everyone` or group write replaces the key's base value. A group write removes the shared value, and a shared write removes the group assignment. A `me` write leaves the shared value alone. `tags` are added to the key's existing tags. Options:

- `tier` — where the value lives: `'everyone'` (encrypted to every recipient except agent grants), `'me'` (a personal value encrypted to you only), or a **group name** (encrypted to that group's members; you must be a member). Omit it to keep an existing key in its tier (a new key is shared). A key held by a group you are not a member of can't be updated, except with `'me'`, and a key holding only other recipients' overrides needs an explicit `tier`.
- `desc` — a human-readable description recorded in the schema.
- `tags` — tags recorded on the key; tags are the unit the agent allow-tag policy gates on.

`vault.describe(key, description, options?)` works like `murk describe`, without `--rotate-every` and `--expires`. It never touches the value and always replaces the description. `options.tags` replaces the existing tags when it is non-empty. Leaving out `options.example` clears the current example. If the key does not exist yet, `describe` creates a documented entry with no value.

Trust-changing operations — rotation, adding/removing recipients or group members, and minting agent grants — are deliberately **not** exposed here; use the CLI for those.

## Memory hygiene

Every decrypted value murk returns is a plain host-language string. murk zeroes plaintext
from its own memory when a value is dropped, but that guarantee ends at the FFI
boundary: once a value crosses into JavaScript the runtime owns it, and its
garbage collector — not murk — controls its lifetime. This is inherent to
reading secrets into a process (see the
[threat model](https://github.com/interrupted-sh/murk/blob/main/THREAT_MODEL.md)); avoid
holding decrypted values longer than you need them.

The write path makes this sharper. To call `vault.add(key, value)` you already hold
the plaintext as a JavaScript `String` *before* the call — it lives in V8's heap, is
copied across the FFI boundary into a Rust `String`, and is zeroized on neither side.
Reads only ever expose plaintext murk itself produced during decryption; a write means
the plaintext originated in your process and lingers there under the GC's control. Build
the value as late as possible, pass it straight into `add`, and don't keep it around.

## Agent policy

If the loaded key is an agent grant (from `murk agent grant`), the bindings enforce the vault's agent policy on reads and writes, as `murk agent exec` does. `get()` and `export()` throw when the policy forbids a key they can read. `add()` and `describe()` check the key before saving and throw without changing the vault. Once the grant's TTL has passed, `export()`, `add()`, `describe()` and `get()` of a readable key throw too. `keys()`, `has()` and `length` read only the schema and never check the policy. A plain operator key skips the check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set. A grant also cannot decrypt out-of-scope secrets, because its key is not a recipient of them, so the policy check is a second guard.

`get()` and `export()` use the values and policy from the vault's last load. Policy changes and revocations reach them only after you call `load()` again or write through the handle. `add()` and `describe()` reload the vault from disk first, so they always check the current policy, and they refresh the handle afterwards. Grant expiry is checked again on each value read.

## Key lookup

`load()` finds your key the same way the CLI does:

1. `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (the path to a key file). Set one, not both. murk refuses to load when both are set.
2. The key file that `murk init` stored under `~/.config/murk/keys/`.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On the machine where you ran `murk init`, you do not need to source it. Set the variable yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is set, because both turn off step 2.

## Requirements

Node.js 18.17 or later on Node 18, or 20.3 or later (not Node 19), the murk CLI, a `.murk` vault in your project and a key (see [Key lookup](#key-lookup)). The addon needs Node-API version 9.

## License

MIT OR Apache-2.0
