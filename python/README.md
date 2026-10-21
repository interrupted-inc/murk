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
# Load your key (created by murk init)
source .env
```

```python
import murk

# Load the vault (reads MURK_KEY from environment)
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

Load and decrypt a murk vault. Reads `MURK_KEY` or `MURK_KEY_FILE` from the environment.

### `murk.get(key, vault_path=".murk") -> str | None`

One-liner: load the vault and get a single value.

### `murk.export_all(vault_path=".murk") -> dict[str, str]`

One-liner: load the vault and export all secrets as a dict.

### `murk.has_identity() -> bool`

Whether a decryption identity (`MURK_KEY` / `MURK_KEY_FILE`) is available — i.e. whether `load()` can decrypt. This is not a check for whether a secret exists; use `key in vault` / `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `str \| None` | Get a single decrypted value |
| `vault.export()` | `dict[str, str]` | All secrets as a dict |
| `vault.keys()` | `list[str]` | List of key names |
| `vault[key]` | `str` | Dict-style access (raises on missing key) |
| `key in vault` | `bool` | Check if a key exists |
| `len(vault)` | `int` | Number of secrets |
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

When the loaded key is an agent grant (minted with `murk agent grant`), the vault's agent policy is enforced on read, the same way the CLI enforces it at `murk agent exec`: `get()` and `export()` raise `RuntimeError` if the policy forbids a key. Operator keys are unaffected. This makes a policy vault strict from every entry point — though an agent already cannot decrypt out-of-scope secrets at all, since its ephemeral key is not a recipient of them.

## Environment

Set one of:
- `MURK_KEY` — your age secret key directly
- `MURK_KEY_FILE` — path to your key file (created by `murk init`)

The easiest setup is `source .env` in your project directory after running `murk init`.

## Requirements

- Python >= 3.9
- [murk CLI](https://github.com/interrupted-sh/murk) installed (to create and manage vaults)
- A `.murk` vault file in your project (created with `murk init`)
- `MURK_KEY` or `MURK_KEY_FILE` in the environment (created by `murk init`, loaded via `source .env`)

## License

MIT OR Apache-2.0
