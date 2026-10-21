# murk-secrets

[![PyPI](https://img.shields.io/pypi/v/murk-secrets)](https://pypi.org/project/murk-secrets/)

Python bindings for [murk](https://github.com/interrupted-sh/murk) — an encrypted secrets manager for developers.

murk stores encrypted secrets in a single `.murk` file safe to commit to git. This package lets Python apps read those secrets at runtime.

## Prerequisites

You need the [murk CLI](https://github.com/interrupted-sh/murk) to create and manage vaults. This package only reads them.

```bash
# Install the CLI first
brew install interrupted-sh/tap/murk

# Initialize a vault and add secrets
murk init
murk add DATABASE_URL
murk add API_KEY
```

Then add the Python package to your project:

```bash
pip install murk-secrets
```

## Quick start

```bash
# Optional on the machine that ran murk init (see "Key lookup").
# POSIX shell syntax.
source .env
```

```python
import murk

# Load the vault (finds your key; see "Key lookup")
vault = murk.load()

# Get a single secret
db_url = vault.get("DATABASE_URL")

# Get all secrets as a dict
secrets = vault.export()

# Dict-style access
api_key = vault["API_KEY"]
```

## API

### `murk.load(vault_path=".murk") -> Vault`

Load and decrypt a murk vault. Finds your key as described in [Key lookup](#key-lookup).

### `murk.get(key, vault_path=".murk") -> str | None`

One-liner: load the vault and get a single value.

### `murk.export_all(vault_path=".murk") -> dict[str, str]`

One-liner: load the vault and export all secrets as a dict.

### `murk.has_identity() -> bool`

Returns `True` if murk can find a key for `./.murk`: `MURK_KEY`, `MURK_KEY_FILE` or the key file `murk init` stored. Returns `False` if no key is found, if both variables are set, or if the key file cannot be read. It does not read the vault, so `True` does not guarantee that `load()` succeeds. It does not check whether a secret exists. Use `key in vault` or `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `str \| None` | Decrypted value, or `None` if no value is readable for the key |
| `vault.export()` | `dict[str, str]` | Every secret you can read |
| `vault.keys()` | `list[str]` | Key names in the vault schema, including keys you cannot read |
| `vault[key]` | `str` | Like `get`, but raises `RuntimeError` (not `KeyError`) if no value is readable |
| `key in vault` | `bool` | `True` if the key is in the schema, even if you cannot read its value |
| `len(vault)` | `int` | Number of keys in the schema |
| `vault.warnings` | `list[str]` | Warnings about an accepted vault, the ones the CLI prints as `warn …` (empty for a clean load) |

Scoped (per-user) overrides are applied automatically — if you have a scoped value for a key, it takes priority over the shared value.

## Trust

`load()`, `get()` and `export_all()` apply the same trust check as the CLI. A vault this machine does not trust — unsigned when your key could have signed it, signed by a key this machine hasn't accepted, rolled back, or tampered with — raises `murk.TrustError` (a subclass of `RuntimeError`) with the CLI's message. Nothing in the binding skips the check. Run `murk trust` once from a shell to accept a vault, or set `MURK_TRUSTED_SIGNERS` in CI. An agent grant key reads only through the trusted signers in its key file or `MURK_TRUSTED_SIGNERS`.

## Memory hygiene

Every decrypted value murk returns is a plain Python string. murk zeroes plaintext from
its own memory when a value is dropped, but that guarantee ends at the FFI
boundary: once a value crosses into Python the interpreter owns it, and its
garbage collector — not murk — controls its lifetime. This is inherent to
reading secrets into a process (see the
[threat model](https://github.com/interrupted-sh/murk/blob/main/THREAT_MODEL.md)); avoid
holding decrypted values longer than you need them.

## Agent policy

If the loaded key is an agent grant (from `murk agent grant`), the bindings enforce the vault's agent policy on every read, as `murk agent exec` does. `get()` and `export()` raise `RuntimeError` when the policy forbids a key they can read. Once the grant's TTL has passed, `export()` and `get()` of a readable key raise too. `keys()`, `len()` and `in` read only the schema and never check the policy. A plain operator key skips the check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set. A grant also cannot decrypt out-of-scope secrets, because its key is not a recipient of them, so the policy check is a second guard.

A loaded `Vault` keeps the values and policy from its last load. Policy changes and revocations apply only after you call `load()` again. Grant expiry is checked again on each value read.

## Key lookup

`load()` finds your key the same way the CLI does:

1. `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (the path to a key file). Set one, not both. murk refuses to load when both are set.
2. The key file that `murk init` stored under `~/.config/murk/keys/`.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On the machine where you ran `murk init`, you do not need to source it. Set the variable yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is set, because both turn off step 2.

## Requirements

Python 3.9 or later, the murk CLI, a `.murk` vault in your project and a key (see [Key lookup](#key-lookup)).

## License

MIT OR Apache-2.0
