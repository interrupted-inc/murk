# <img src="logo.svg" height="28"> murk

[![CI](https://github.com/interrupted-inc/murk/actions/workflows/ci.yaml/badge.svg)](https://github.com/interrupted-inc/murk/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/interrupted-inc/murk/graph/badge.svg)](https://codecov.io/gh/interrupted-inc/murk)
[![Crates.io](https://img.shields.io/crates/v/murk-cli)](https://crates.io/crates/murk-cli)
[![docs.rs](https://img.shields.io/docsrs/murk-cli)](https://docs.rs/murk-cli)
[![License](https://img.shields.io/crates/l/murk-cli)](LICENSE-MIT)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12291/badge)](https://www.bestpractices.dev/projects/12291)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)

Encrypted secrets manager for developers.

murk stores encrypted secrets in a single `.murk` file designed to be committed to git. Values are encrypted with [age](https://age-encryption.org/), key names remain readable. It works with [direnv](https://direnv.net/) and supports teams — one binary, no runtime dependencies.

> murk is pre-1.0 and has not been independently audited. Use good judgment with production secrets.

<p align="center">
  <img src="https://raw.githubusercontent.com/interrupted-inc/murk/demo/hero.gif" alt="murk demo" width="900">
</p>

## Why

Most teams share `.env` files over Slack. That's bad. Tools like SOPS and Vault exist but they're complex, require cloud setup, or pull in runtimes you don't want.

murk is simple: one key on your machine, one encrypted file in your repo. See [THREAT_MODEL.md](THREAT_MODEL.md) for what it protects and what it doesn't.

## How murk compares

| | murk | SOPS | Vault | dotenvx | git-crypt |
|---|---|---|---|---|---|
| Encrypted values, readable keys | Yes | Yes | N/A | Yes | No (whole file) |
| Per-recipient encryption | Yes | Yes | ACL-based | No (shared key) | Yes (GPG) |
| Scoped per-user overrides | Yes | No | No | No | No |
| Requires a server | No | No | Yes | No | No |
| Cloud KMS required | No | Optional | Typically | No | No |
| Single binary, no runtime | Yes | Yes | No | Yes | Yes |
| Built-in direnv integration | Yes | No | No | Yes | No |
| Recovery phrase | Yes (BIP39) | No | No | No | No |

**SOPS** is the closest alternative. Both encrypt values in-place and support age. murk differs in having scoped (per-user) secrets, a single-file vault model, built-in team management (`murk circle`), and BIP39 key recovery. SOPS has broader KMS backend support and a larger ecosystem.

**Vault** solves a different problem — it's centralized infrastructure for secret storage, rotation, and dynamic credentials. If you need a secrets server, use Vault. murk is scoped to encrypted secrets in a repo.

**dotenvx** encrypts `.env` files but uses a single shared key for the whole team. There's no per-recipient encryption — if someone leaves, everyone needs a new key.

**git-crypt** encrypts entire files via git filters. Diffs are opaque, and revoking a team member is effectively impractical without re-encrypting git history.

## Install

```bash
brew tap interrupted-inc/murk && brew install murk
```

Or via Cargo (requires [Rust toolchain](https://rustup.rs)):

```bash
cargo install murk-cli
```

Or download a pre-built binary:

```bash
curl -fsSL https://raw.githubusercontent.com/interrupted-inc/murk/main/install.sh | sh
```

Pre-built binaries are available for Linux (x86_64, aarch64, armhf), macOS (x86_64, Apple Silicon), and Windows on the [releases page](https://github.com/interrupted-inc/murk/releases). Binary releases are [attested](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) and can be verified with `gh attestation verify murk-* --owner interrupted-inc`. See [VERIFYING.md](VERIFYING.md) for verifying the npm, PyPI, and crates.io releases too.

## Quick start

```bash
# Initialize — generates your key, recovery phrase, and a vault
murk init

# Add secrets (prompts for value, hidden input)
murk add DATABASE_URL
murk add OPENAI_KEY

# Wire up direnv so secrets load automatically on cd
murk env
direnv allow
```

Your key is stored in `~/.config/murk/keys/` with restricted permissions and is auto-discovered by the CLI based on the vault's absolute path. The `.env` file in your project contains a `MURK_KEY_FILE` reference for shells that don't use direnv — no secrets in the repo directory.

Without direnv, use `murk exec`:

```bash
murk exec ./deploy.sh    # runs with all secrets in the environment
```

## How it works

Your `.murk` file has a plaintext header (key names, descriptions — no values) and encrypted values. Anyone can see what secrets exist via `murk info`. Only recipients with a valid `MURK_KEY` can see values.

```bash
murk info           # Public schema — works without a key
murk ls             # List key names
murk get KEY        # Print a single value
murk export         # Shell export statements
```

## Shared secrets vs scoped secrets

murk has two layers of encryption inside the `.murk` file:

**Shared secrets** (the murk) are encrypted to all recipients. When you run `murk add KEY`, every authorized team member can decrypt it. This is where production credentials, API keys, and other team-wide secrets live.

**Scoped secrets** (motes) are encrypted to only your key. When you run `murk add KEY --group me`, the value is encrypted to only your key in the vault. During `murk export`, scoped values override shared ones — so you can use a local database URL while the rest of the team uses production.

```bash
# Shared — everyone sees this (prompts for value, hidden input)
murk add DATABASE_URL

# Scoped — only you see this, overrides the shared value during export
murk add DATABASE_URL --group me

# Or pipe for scripting (use a command that doesn't leak to shell history)
pbpaste | murk add DATABASE_URL
```

## Teams

```bash
# Alice sets up the vault
murk init
murk add DATABASE_URL

# Bob generates his own key
murk init

# Alice adds Bob as a recipient
murk circle authorize age1bob... --name bob@example.com

# Bob can now decrypt
murk export

# Bob overrides a value for local dev
murk add DATABASE_URL --group me
```

<p align="center">
  <img src="https://raw.githubusercontent.com/interrupted-inc/murk/demo/team.gif" alt="murk team demo" width="900">
</p>

## Offboarding

When someone leaves, revoke their access and rotate the secrets:

```bash
murk circle revoke carol --rotate   # remove carol, then rotate what she could read
git commit -am "revoke carol, rotate secrets" && git push
```

Revocation re-encrypts the vault going forward, but old versions remain in git history. The revoked user can still decrypt any version they previously had access to. Always rotate secrets after revocation.

If you already have new values in a file, import them directly:

```bash
murk circle revoke carol
murk import .env.rotated  # bulk-update from a file
```

<p align="center">
  <img src="https://raw.githubusercontent.com/interrupted-inc/murk/demo/offboard.gif" alt="murk offboarding demo" width="900">
</p>

## CI/CD

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-murk--action-2ea44f?logo=github&logoColor=white)](https://github.com/marketplace/actions/murk-action)

Use [murk-action](https://github.com/interrupted-inc/murk-action) to decrypt secrets in GitHub Actions workflows:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-inc/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # all vault secrets are now in the environment
```

Store your `MURK_KEY` as a GitHub Actions secret. Decrypted values are registered with GitHub's log masking, but masking depends on GitHub's runner behavior and is not a hard security boundary.

## Recovery

Your key is a BIP39 mnemonic. `murk init` prints 24 recovery words — write them down.

```bash
# Lost your key? Recover it (prompts for phrase, hidden input)
murk restore
```

## Commands

**Setup & recovery**

| Command | Description |
|---------|-------------|
| `murk init` | Generate keypair and create vault |
| `murk env` | Write a `.envrc` for direnv integration |
| `murk restore` | Recover key from BIP39 phrase |
| `murk recover` | Show recovery phrase for current key |

**Secrets**

| Command | Description |
|---------|-------------|
| `murk add KEY [--group me]` | Add or update a secret (prompts for value) |
| `murk generate KEY [--hex] [--length N]` | Generate a random secret and store it |
| `murk rotate KEY [--generate]` | Rotate a secret with a new value |
| `murk rotate --all` | Rotate all secrets (prompts for each) |
| `murk rotate --list [--json]` | List keys needing rotation (overdue, expiring, post-revoke) |
| `murk rm KEY` | Remove a secret |
| `murk get KEY` | Print a single decrypted value |
| `murk edit [KEY] [--group me]` | Edit secrets in `$EDITOR` |
| `murk ls` | List key names |
| `murk export` | Print all secrets as shell exports |
| `murk import [FILE]` | Import secrets from a .env file |

**Metadata**

| Command | Description |
|---------|-------------|
| `murk describe KEY "..."` | Set description for a key |
| `murk info` | Show public schema (no key required) |
| `murk skeleton` | Export schema-only vault with no secrets or recipients |

**Run**

| Command | Description |
|---------|-------------|
| `murk exec CMD...` | Run a command with secrets in the environment (`--only`, `--clean-env`) |

**Agents**

| Command | Description |
|---------|-------------|
| `murk agent plan` | Emit schema-only context for AI agent prompts (no key required) |
| `murk agent exec --only KEY -- CMD...` | Run a command with strict agent-safe defaults (clean env, no `MURK_KEY`) |
| `murk agent grant --name NAME --only KEY --ttl DUR` | Mint a scoped key that reads only the named secrets (the TTL is advisory — revoke to close it) |
| `murk agent ls` | List active agent grants and their TTLs |
| `murk agent revoke NAME [--rotate]` | Revoke a grant and rotate the keys it could read |
| `murk mcp [--allow-exec]` | Run a stdio MCP server exposing scoped secrets to AI agents (needs a grant + `MURK_AGENT`) |
| `murk policy show\|set\|clear` | Manage the agent allow-list (tags agents may receive) |

**Recipients & groups**

| Command | Description |
|---------|-------------|
| `murk circle` | List recipients |
| `murk circle authorize PUBKEY [--name NAME] [--allow-ssh-rsa]` | Add a recipient (age key, `ssh:path`, or `github:user`) |
| `murk circle revoke RECIPIENT` | Remove a recipient |
| `murk group create\|ls\|add\|rm NAME` | Manage named recipient groups (encrypt a secret to a subset) |

**Checks**

| Command | Description |
|---------|-------------|
| `murk verify` | Check MAC, recipients, and key access without decrypting secrets |
| `murk doctor` | Scan the surrounding repo for hygiene issues |
| `murk scan [PATHS...]` | Scan files for leaked secret values |

**Git**

| Command | Description |
|---------|-------------|
| `murk diff [REF]` | Show secret changes since a git ref |
| `murk setup-merge-driver` | Configure git to merge `.murk` vaults without decrypting |

**Shell**

| Command | Description |
|---------|-------------|
| `murk completion generate\|install SHELL` | Generate or install shell completions |

Every vault command accepts `--vault NAME` (or `MURK_VAULT`). `ls`, `export`, `info`, `exec`, and `agent plan` filter by `--tag`; `ls`, `export`, `info`, `diff`, and `agent plan` support `--json`. See `murk <command> --help` for the full flag list, or [docs/cli-reference.md](docs/cli-reference.md) for the complete reference (auto-generated, kept in sync with the binary).

## Design

- **age for encryption, Ed25519 signatures for integrity** — no custom cryptographic primitives; a BLAKE3 MAC binds ciphertexts and an Ed25519 signature (derived from your age key, or your ssh-ed25519 key directly) authenticates the writer, so tampering with a *signed* vault is detectable. An attacker with repo write access can still strip the signature — that loads as an unsigned warning, not a hard failure — so git commit signing is the anchor. See [THREAT_MODEL.md](THREAT_MODEL.md)
- **Git is the audit trail** — murk doesn't replicate what git does
- **Header is public, values are private** — key names are visible, values are not
- **Explicit over magic** — never silently overwrites or destroys data

The `.murk` file is designed to be committed — key names are readable, values are individually encrypted:

```json
{
  "version": "2.0",
  "recipients": ["age1abc..."],
  "schema": {
    "DATABASE_URL": { "description": "Production database" },
    "STRIPE_SECRET": { "description": "Stripe secret key" }
  },
  "secrets": {
    "DATABASE_URL": { "shared": "age-encryption.org/v1\n..." },
    "STRIPE_SECRET": { "shared": "age-encryption.org/v1\n..." }
  },
  "meta": "age-encryption.org/v1\n..."
}
```

See [SPEC.md](SPEC.md) for the full specification.

## Security notes

**Shell history** — `murk add` and `murk restore` prompt interactively with hidden input. Prefer these over passing secrets as arguments or via `echo`, which can leak to shell history. When piping from scripts, use commands that don't record to history (e.g. `pbpaste | murk add KEY` or reading from a file).

**Command output** — `murk get KEY` prints the decrypted value to stdout; run interactively, that means it lands in your terminal and its scrollback. Strict mode blocks plaintext to a redirected file, but not to a TTY. Prefer piping into the consumer over reading secrets on screen.

**Key names are plaintext** — the `.murk` header exposes key names (e.g. `STRIPE_SECRET_KEY`, `DATABASE_URL`) so that `murk info` works without a key and git diffs stay readable. Only values are encrypted. If your threat model requires hiding what services you use, this is a trade-off to be aware of.

**Key storage** — your secret key lives in `~/.config/murk/keys/` with `chmod 600` permissions, outside your repository. The `.env` file in your project contains only a `MURK_KEY_FILE` reference to this path, not the key itself. Similar to SSH keys in `~/.ssh`, but murk also exposes secrets via `export` and `exec` into subprocess environments. If a machine is compromised, rotate your key and re-authorize with a new one.

**Hardware-backed keys** — for stronger protection, point `MURK_KEY_FILE` at an age plugin identity file (YubiKey, Apple Secure Enclave, FIDO2, etc.) so the private key lives in hardware and never exists as bytes on disk. See [hardware identities](#hardware-identities) below.

**Access control is advisory** — any authorized recipient can decrypt all shared secrets. Per-key access metadata in the schema is cosmetic and not enforced cryptographically. If a recipient has `MURK_KEY` and is in the recipient list, they can read everything in the shared layer. Use scoped secrets (motes) for values that should stay private to one recipient.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model.

**AI agents** — if you're using murk with AI coding agents, see [docs/ai-agents.md](docs/ai-agents.md) for safe patterns.

## Hardware identities

By default `murk init` generates a raw age key and stores it under `~/.config/murk/keys/`. That's fine for development, but the key lives on disk as plaintext — anyone with read access to the file can decrypt everything.

For production use, point `MURK_KEY_FILE` at an [age plugin identity file](https://github.com/FiloSottile/age#plugins) so the private key lives in tamper-resistant hardware and only consents to decrypt with a physical action (touch, Touch ID, PIN):

| Hardware | Plugin |
| --- | --- |
| YubiKey, Nitrokey, any PIV-capable smart card | [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) |
| Apple Secure Enclave (Touch ID) | [`age-plugin-se`](https://github.com/remko/age-plugin-se) |
| Any FIDO2 security key | [`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) |
| OpenPGP Card | [`age-plugin-openpgp-card`](https://crates.io/crates/age-plugin-openpgp-card) |

Example setup with a YubiKey:

```bash
# Install the plugin (must be on $PATH — murk shells out to it on decrypt)
brew install age-plugin-yubikey

# Generate an identity bound to the YubiKey. Prompts for the PIV PIN
# (default 123456) and a touch. --touch-policy always requires a physical
# tap for every decrypt; --pin-policy once caches the PIN per session.
age-plugin-yubikey --generate --touch-policy always --pin-policy once \
  > ~/.config/murk/yubikey.txt

# murk refuses identity files readable by others
chmod 600 ~/.config/murk/yubikey.txt

# Point murk at the identity file
echo 'export MURK_KEY_FILE=~/.config/murk/yubikey.txt' >> .env

# Authorize the YubiKey's public key on your vault
murk circle authorize $(grep -i recipient ~/.config/murk/yubikey.txt | awk '{print $NF}')

# Read a secret — the YubiKey blinks; tap it to decrypt
murk get SOME_KEY
```

The identity file contains a `#    Recipient: age1yubikey1...` header followed by an `AGE-PLUGIN-YUBIKEY-1...` pointer. murk reads the pubkey from the header (no plugin call needed for scoped secret lookup) and invokes the plugin only when actually decrypting — at which point the YubiKey prompts you to tap it.

If the plugin binary isn't on `$PATH`, murk fails with `age-plugin-yubikey unavailable` — install it and retry. `MURK_KEY` (the inline env var) rejects `AGE-PLUGIN-...` strings: a bare plugin identity doesn't carry the recipient pubkey, so use `MURK_KEY_FILE` pointing at the identity file.

**No BIP39 recovery for hardware identities.** The whole point of hardware-backed keys is that the raw key bytes never leave the device, so there are no bytes to encode as a recovery phrase. Instead, enroll a second hardware device at setup and add both pubkeys as recipients (`murk circle authorize <backup-pubkey>`) — if you lose one, the backup still decrypts.

**`MURK_KEY` vs `MURK_KEY_FILE`.** Setting `MURK_KEY` to a raw `AGE-SECRET-KEY-1...` string in `.env` works, but the key is then plaintext on disk. Prefer `MURK_KEY_FILE` pointing at either a file under `~/.config/murk/keys/` (convenience) or a hardware-backed plugin identity file (strongly recommended for production).

## License

MIT OR Apache-2.0
