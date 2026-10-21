# <img src="logo.svg" height="28"> murk

[![CI](https://github.com/interrupted-sh/murk/actions/workflows/ci.yaml/badge.svg)](https://github.com/interrupted-sh/murk/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/interrupted-sh/murk/graph/badge.svg)](https://codecov.io/gh/interrupted-sh/murk)
[![Crates.io](https://img.shields.io/crates/v/murk-cli)](https://crates.io/crates/murk-cli)
[![docs.rs](https://img.shields.io/docsrs/murk-cli)](https://docs.rs/murk-cli)
[![License](https://img.shields.io/crates/l/murk-cli)](LICENSE-MIT)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12291/badge)](https://www.bestpractices.dev/projects/12291)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)

Encrypted secrets manager for developers.

murk stores encrypted secrets in a single `.murk` file designed to be committed to git. Values are encrypted with [age](https://age-encryption.org/), key names remain readable. It works with [direnv](https://direnv.net/) and supports teams — one binary, no runtime dependencies.

> murk is pre-1.0 and has not been independently audited. Use good judgment with production secrets.
>
> Deciding whether to adopt it? See [Is murk right for you?](https://murk.interrupted.sh/suitability/) for a suitability matrix and the 0.x release contract.

<p align="center">
  <img src="https://raw.githubusercontent.com/interrupted-sh/murk/demo/hero.gif" alt="murk demo" width="900">
</p>

## Why

Teams often share `.env` files over chat, which leaves secrets in message history. Vault needs a server. SOPS supports more key backends than murk and has more to configure.

murk is simple: one key on your machine, one encrypted file in your repo. See [THREAT_MODEL.md](THREAT_MODEL.md) for what it protects and what it doesn't.

## How murk compares

| | murk | SOPS | Vault | dotenvx | git-crypt |
|---|---|---|---|---|---|
| Encrypted values, readable keys | Yes | Yes | N/A | Yes | No (whole file) |
| Per-recipient encryption | Yes | Yes | ACL-based | No (shared key) | Yes (GPG) |
| Scoped per-user overrides | Yes | No | No | No | No |
| Requires a server | No | No | Yes | No | No |
| Cloud KMS required | No | Optional | Typically | No | No |
| Single binary, no runtime | Yes | Yes | Yes (needs a server) | Yes | Yes |
| Built-in direnv integration | Yes | No | No | Not documented | No |
| Recovery phrase | Yes (BIP39) | No | No | No | No |

Compared against each project's documentation as of murk v0.13.0. Other tools change, so check their current docs.

**SOPS** is the closest alternative. Both encrypt values in-place and support age. murk differs in having scoped (per-user) secrets, a single-file vault model, built-in team management (`murk circle`), and BIP39 key recovery. SOPS has broader KMS backend support and a larger ecosystem.

**Vault** solves a different problem — it's centralized infrastructure for secret storage, rotation, and dynamic credentials. If you need a secrets server, use Vault. murk is scoped to encrypted secrets in a repo.

**dotenvx** encrypts `.env` files but uses a single shared key for the whole team. There's no per-recipient encryption — if someone leaves, everyone needs a new key.

**git-crypt** encrypts entire files via git filters. Diffs are opaque, and revoking a team member is effectively impractical without re-encrypting git history.

## Install

```bash
brew install interrupted-sh/tap/murk
```

Or via Cargo (requires [Rust toolchain](https://rustup.rs)):

```bash
cargo install murk-cli
```

Or download a pre-built binary (Linux and macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/interrupted-sh/murk/main/install.sh | sh
```

The script checks the archive against the release's `SHA256SUMS`, which catches a corrupt download but not a tampered release. It then checks the release's build provenance with the [GitHub CLI](https://cli.github.com) (`gh`, logged in with `gh auth login` or `GH_TOKEN`). A check that fails stops the install. If `gh` is missing or not logged in, it asks whether to install anyway (default no). Without a terminal, as in CI or a docker build, it stops unless `MURK_SKIP_ATTESTATION=1` is set on the `sh` side. Set `MURK_TAG=v0.14.0` to install a specific release.

It installs to `/usr/local/bin` by default. Set `PREFIX` (binary goes to `$PREFIX/bin`), `DESTDIR` (staging root prepended to the path), or `MURK_INSTALL_DIR` (exact bin directory, overrides `PREFIX`) on the `sh` side of the pipe, e.g. `... | PREFIX="$HOME/.local" sh`.

Pre-built binaries are available for Linux (x86_64, aarch64, armhf), macOS (x86_64, Apple Silicon), and Windows on the [releases page](https://github.com/interrupted-sh/murk/releases). On Windows, download the `.zip` from that page. Binary releases are [attested](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds). Verify one downloaded file at a time with `gh attestation verify murk-v0.13.0-aarch64-apple-darwin.tar.gz --repo interrupted-sh/murk --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml` (needs `gh auth login`; 0.12.0 and later; releases up to 0.11.0 were signed as `interrupted-inc/murk`). See [VERIFYING.md](VERIFYING.md) for verifying older releases and the npm, PyPI, and crates.io releases too.

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

Your key is stored in `~/.config/murk/keys/` with restricted permissions. murk finds it itself, based on the vault's absolute path, including from a git worktree of the same repo, so a fresh worktree needs no setup. `murk init` also writes a `.env` file with a `MURK_KEY_FILE` line that points at the key (the key itself is not in the repo). murk does not read `.env`. Use `source .env` if you want the variable in your shell.

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

**Shared secrets** (the murk) are encrypted to every recipient except agent grants. When you run `murk add KEY`, every authorized team member can decrypt it. This is where production credentials, API keys, and other team-wide secrets live.

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
  <img src="https://raw.githubusercontent.com/interrupted-sh/murk/demo/team.gif" alt="murk team demo" width="900">
</p>

## Offboarding

When someone leaves, revoke their access and rotate the secrets:

```bash
murk circle revoke carol --rotate   # remove carol, then rotate what she could read
git commit -am "revoke carol, rotate secrets" && git push
```

Revocation re-encrypts the vault going forward, but old versions remain in git history. The revoked user can still decrypt any version they previously had access to. Always rotate secrets after revocation. murk only stores the replacement values: create new credentials at each provider and invalidate the old ones there.

If you already have the new values in a file, rotate from it in the same step:

```bash
murk circle revoke carol --rotate --values-from .env.rotated
rm .env.rotated               # it holds plaintext secrets
```

Values are matched by name and each stays in its tier. If the file names a key that cannot be rotated, nothing is written and carol is not revoked. Keys it leaves out stay listed by `murk rotate --list`.

<p align="center">
  <img src="https://raw.githubusercontent.com/interrupted-sh/murk/demo/offboard.gif" alt="murk offboarding demo" width="900">
</p>

## Git worktrees

A fresh worktree checks out tracked files and nothing else, so every gitignored `.env` you depend on is missing — the reason worktree setups usually involve copying or symlinking one in. murk needs neither: the vault is committed, so it arrives with the checkout, and the key was never in the repo. murk resolves it from a sibling checkout of the same repository.

```bash
git worktree add ../murk-feature-x
cd ../murk-feature-x
murk exec ./deploy.sh   # works immediately — nothing to provision
```

Only real worktrees of the repo count, verified against git's own metadata; a copy of the vault elsewhere on disk still gets nothing. Key discovery stays disabled under `MURK_STRICT` and in agent context, so an agent in a worktree still needs its own scoped grant.

## Trusting a vault

A `.murk` file lists its own recipients, so a valid signature alone doesn't say the signer is someone you trust. murk checks every vault against a trust pin on your machine (`~/.config/murk/signer-pins/`, outside the repo, shared by every git worktree of the repo). The first load on each machine is refused until you review the vault and accept it:

```bash
git log -p -- .murk   # who changed the vault
murk diff             # what changed, and who signed it
murk trust            # shows the signer, its signing-key fingerprint and every recipient, then asks (--yes for scripts)
```

murk refuses a vault that is unsigned (when your key can sign, or when `MURK_TRUSTED_SIGNERS` is set), was signed when you last accepted it and now isn't, is signed by a key this machine doesn't trust or by an agent grant, is another vault's file, is older than one already accepted on that branch, or changes a group without a member's signature. The message says what it saw. After a refusal you've reviewed, `murk trust` accepts it again. To revert a branch on purpose, restore the old file, run `murk trust`, then make any write. If murk can't write its pin (a read-only home), it warns and carries on.

Hardware, plugin and `ssh-rsa` keys can't sign, so their writes are unsigned. A signing teammate reviews them and runs `murk trust`, which re-signs the vault.

**A new teammate with an age key** is confirmed once on every other machine. Their first signed write carries a signing key your machine has never seen, so murk refuses it once ("a trusted recipient whose signing key this machine has not confirmed yet") and shows the key's fingerprint. They run `murk trust --print-key` to see their own fingerprint (`murk init` prints it too, before they're authorized), you compare the two over a channel other than the repo, and you run `murk trust`. That is trust on first use: the key comes from the vault, so the fingerprint check is what makes it trustworthy. Once a machine that confirmed the key writes, its signed vault carries the key, and machines that load that vault learn it without another prompt. A different key for a signer whose key is already pinned is refused as a forgery, and `murk trust` won't accept it. `ssh-ed25519` teammates (for example `murk circle authorize github:user`) need no confirmation: their recipient string is their verifying key.

**Upgrading to 0.14.** Every teammate and CI runner needs 0.14: a 0.14 save is written in a signature format 0.13 refuses. The first load of an existing vault on each machine is refused once. Review it and run `murk trust`, then make the first 0.14 save. Once a machine has seen a vault saved by 0.14, a vault signed by 0.13 is refused as rolled back. A vault written by 0.13 gets an id derived from its creation time and name, so teammates who upgrade on different days agree on it. CI sets `MURK_TRUSTED_SIGNERS` (below). Re-run `murk setup-merge-driver` in each clone so the merge driver gets the vault path.

## CI/CD

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-murk--action-2ea44f?logo=github&logoColor=white)](https://github.com/marketplace/actions/murk-action)

Use [murk-action](https://github.com/interrupted-sh/murk-action) to decrypt secrets in GitHub Actions workflows:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
    env:
      MURK_TRUSTED_SIGNERS: ${{ secrets.MURK_TRUSTED_SIGNERS }}
  - run: ./deploy.sh  # all vault secrets are now in the environment
```

A CI runner has no trust pin and nobody to run `murk trust`. `MURK_TRUSTED_SIGNERS` lists the people who write the vault, separated by commas or newlines. An age signer is `age1...:<verifying key>` and an `ssh-ed25519` signer is its public key line; each signer runs `murk trust --print-key` to get their entry (it goes to stdout, the fingerprint to stderr). A bare `age1...` key without its verifying key is an error. Store it as a secret next to `MURK_KEY`. With it set, an unsigned vault is refused even for a key that can't sign, and the variable never adds to what the machine's own pin trusts. The action has to pass the variable through to `murk`; if yours doesn't, run `murk exec` yourself with both variables in the step's `env:`.

The organization was renamed from `interrupted-inc` to `interrupted-sh`. Change any workflow that still uses `interrupted-inc/murk-action` to `interrupted-sh/murk-action`.

Store your `MURK_KEY` as a GitHub Actions secret. Decrypted values are registered with GitHub's log masking, but masking depends on GitHub's runner behavior and is not a hard security boundary.

## Recovery

When `murk init` generates a key, it prints a 24-word recovery phrase that encodes that key. Write it down.

```bash
# Lost your key? Print it from the phrase (prompts, hidden input) and save it
mkdir -p -m 700 ~/.config/murk
(umask 077 && murk restore > ~/.config/murk/restored.key)
export MURK_KEY_FILE=~/.config/murk/restored.key
```

`murk restore` only prints the key. It writes no file. Save the output to a file with mode 600 and point `MURK_KEY_FILE` at it. The phrase covers age keys only, not SSH or hardware keys.

## Commands

**Setup & recovery**

| Command | Description |
|---------|-------------|
| `murk init` | Create a vault and key, or reuse your existing key |
| `murk env` | Write a `.envrc` for direnv integration |
| `murk restore` | Print the key encoded by a BIP39 phrase |
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
| `murk exec CMD...` | Run a command with secrets in the environment (`--only`, `--clean-env`). Refuses keys named like loader, shell, proxy or murk variables (`PATH`, `LD_*`, `GIT_*`, `*_PROXY`, `MURK_*`, ...) unless `--allow-reserved` |

**Agents**

| Command | Description |
|---------|-------------|
| `murk agent plan` | Emit schema-only context for AI agent prompts (no key required) |
| `murk agent exec --only KEY -- CMD...` | Run a command with strict agent-safe defaults (clean env, no `MURK_KEY`, injected values masked in the output; refuses an auto-discovered personal key unless you pass `--allow-operator-key`, so supply a grant key) |
| `murk agent grant --name NAME --only KEY [--ttl DUR]` | Mint a short-lived scoped key that reads only the named secrets (`--ttl` defaults to 2h; reads fail closed after the TTL — revoke to close it for good) |
| `murk agent init --name NAME --only KEY` | Set the agent allow-list, mint a grant and print how to run the agent |
| `murk agent connect [CLIENT] --only KEY` | Wire `murk mcp` into an AI editor's MCP config with a scoped grant |
| `murk agent disconnect [CLIENT] [--rotate]` | Remove murk from an AI editor's MCP config (`--rotate` also revokes the grant and rotates its keys) |
| `murk agent ls` | List active agent grants and their TTLs |
| `murk agent revoke NAME [--rotate]` | Revoke a grant (`--rotate` also rotates the secrets it could read) |
| `murk mcp [--allow-exec]` | Run a stdio MCP server exposing scoped secrets to AI agents (needs a grant + `MURK_AGENT`) |
| `murk policy show\|set\|clear` | Manage the agent allow-list (tags agents may receive) |

**Recipients & groups**

| Command | Description |
|---------|-------------|
| `murk circle` | List recipients |
| `murk circle authorize PUBKEY [--name NAME] [--allow-ssh-rsa]` | Add a recipient (age key, `ssh:path`, or `github:user`) |
| `murk circle revoke RECIPIENT` | Remove a recipient |
| `murk group create NAME` | Create a named recipient group (encrypt a secret to a subset) |
| `murk group ls` | List groups and their members |
| `murk group add NAME --member M` | Add a member to a group (you must be a member of it) |
| `murk group rm NAME [--member M]` | Remove a member, or delete the group (you must be a member of it) |

**Checks**

| Command | Description |
|---------|-------------|
| `murk verify` | Check vault integrity, signature, trust, recipients and key access (needs a key; prints no secret values) |
| `murk trust [--yes]` | Show who signed the vault and what changed, then trust it on this machine (re-signs an unsigned vault with your key). `murk trust --print-key` prints your own signing-key fingerprint and your `MURK_TRUSTED_SIGNERS` entry |
| `murk doctor` | Scan the surrounding repo for hygiene issues |
| `murk scan [PATHS...]` | Scan files for leaked secret values |

**Git**

| Command | Description |
|---------|-------------|
| `murk diff [REF] [--show-values] [--json]` | Show secret, recipient and signer changes since a git ref. Prints key names only, unless you pass `--show-values`. The old revision is verified before anything in it is shown |
| `murk setup-merge-driver` | Configure git to merge `.murk` vaults: the driver verifies both sides and signs the result |

**Shell**

| Command | Description |
|---------|-------------|
| `murk completion generate\|install SHELL` | Generate or install shell completions |

Every vault command accepts `--vault FILE` (or `MURK_VAULT`; default `.murk`). `ls`, `export`, `info`, `exec`, and `agent plan` filter by `--tag`; `ls`, `export`, `info`, `diff`, and `agent plan` support `--json`. See `murk <command> --help` for the full flag list, or [docs/cli-reference.md](docs/cli-reference.md) for the complete reference (auto-generated, kept in sync with the binary).

## Pre-commit hooks

murk provides a [pre-commit](https://pre-commit.com/) hook to scan staged files for leaked secret values. Add it to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/interrupted-sh/murk
    rev: v0.13.0  # run 'pre-commit autoupdate' to move to a newer tag
    hooks:
      - id: murk-scan
```

Then install the hook:

```bash
# Install pre-commit if needed
pip install pre-commit

# Install the hook into your repository
pre-commit install
```

The hook runs `murk scan` on staged files before each commit, failing the commit if any leaked secret values are detected. **Requires:** murk installed on PATH, and a `.murk` vault file in your repository.

To manually run on specific files:

```bash
pre-commit run murk-scan --files <file1> <file2>
```

To run on all files:

```bash
pre-commit run murk-scan --all-files
```

## Design

- **age for encryption, Ed25519 signatures for integrity** — no custom cryptographic primitives; a BLAKE3 MAC binds ciphertexts and an Ed25519 signature authenticates the writer (age keys sign with an Ed25519 key derived from the age secret, its verifying key published in the vault's signer registry; ssh-ed25519 keys sign directly). Each machine accepts a vault only from signers it trusts and pins each signer's verifying key, recorded locally by `murk trust` or given in `MURK_TRUSTED_SIGNERS`, so a vault an attacker wrote or replayed is refused. A trusted signer can still change values and recipients — that is authorized by design — and a vault written by a key that cannot sign (hardware, ssh-rsa) is unsigned, so git commit signing remains the anchor for those teams. See [THREAT_MODEL.md](THREAT_MODEL.md)
- **Git is the audit trail** — murk doesn't replicate what git does
- **Header is public, values are private** — key names are visible, values are not
- **Explicit over magic** — never silently overwrites or destroys data

The `.murk` file is designed to be committed. Key names are readable and each value is encrypted on its own. This abridged illustration is not a loadable vault (see [SPEC.md](SPEC.md) for the full format):

```json
{
  "version": "3.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1abc..."],
  "schema": {
    "DATABASE_URL": { "description": "Production database" },
    "STRIPE_SECRET": { "description": "Stripe secret key" }
  },
  "secrets": {
    "DATABASE_URL": { "shared": "<base64 age ciphertext>" },
    "STRIPE_SECRET": { "shared": "<base64 age ciphertext>" }
  },
  "meta": "<base64 age ciphertext>",
  "sig": { "signer": "age1abc...", "v": 2, "sig": "<base64 ed25519 signature>" }
}
```

See [SPEC.md](SPEC.md) for the full specification.

## Security notes

**Shell history** — `murk add` and `murk restore` prompt interactively with hidden input. Prefer these over passing secrets as arguments or via `echo`, which can leak to shell history. When piping from scripts, use commands that don't record to history (e.g. `pbpaste | murk add KEY` or reading from a file).

**Command output** — `murk get KEY` prints the decrypted value to stdout; run interactively, that means it lands in your terminal and its scrollback. Strict mode blocks plaintext to a redirected file, but not to a TTY. Prefer piping into the consumer over reading secrets on screen.

**Key names are plaintext** — the `.murk` header exposes key names (e.g. `STRIPE_SECRET_KEY`, `DATABASE_URL`) so that `murk info` works without a key and git diffs stay readable. Only values are encrypted. If your threat model requires hiding what services you use, this is a trade-off to be aware of.

**Key storage** — your secret key lives in `~/.config/murk/keys/` with `chmod 600` permissions, outside your repository. The `.env` file in your project contains only a `MURK_KEY_FILE` reference to this path, not the key itself. Similar to SSH keys in `~/.ssh`, but murk also exposes secrets via `export` and `exec` into subprocess environments. If a machine is compromised, rotate your key and re-authorize with a new one.

**Hardware-backed keys** — for stronger protection, point `MURK_KEY_FILE` at an age plugin identity file (YubiKey, Apple Secure Enclave, FIDO2, etc.) so the private key lives in hardware and never exists as bytes on disk. See [hardware identities](#hardware-identities) below.

**Shared secrets are readable by every recipient except agent grants.** Any other recipient can decrypt every secret in the shared tier. Schema fields such as tags do not restrict human recipients. For narrower access, assign a secret to a named group (encrypted to that group's members) or set a private value for one recipient (`--group me`).

**Reserved variable names** — whoever last wrote the vault chooses its key names, so `murk export`, `murk exec` and `murk agent exec` refuse to set variables that change how programs, shells or murk itself run: `PATH`, `HOME`, `NODE_OPTIONS`, `BASH_ENV`, `EDITOR`, `RUSTFLAGS`, anything ending in `_PROXY`, and anything starting with `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `DOTNET_`, `CARGO_`, `SSL_`, `PIP_`, `GEM_`, `BUNDLE_`, `NPM_CONFIG_` or `MURK_` (case-insensitive; `NODE_ENV` is not reserved; the full list is in [Environment variables](https://murk.interrupted.sh/concepts/env-vars/#variable-names-a-vault-may-not-set)). Review who added the key, then pass `--allow-reserved` if you mean it. The MCP `murk_exec` tool never allows them.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model.

**AI agents** — if you're using murk with AI coding agents, see [docs/ai-agents.md](docs/ai-agents.md) for safe patterns.

## Hardware identities

By default `murk init` generates a raw age key and stores it under `~/.config/murk/keys/`. That's fine for development, but the key lives on disk as plaintext — anyone with read access to the file can decrypt everything.

For production use, point `MURK_KEY_FILE` at an [age plugin identity file](https://github.com/FiloSottile/age#plugins) so the private key lives in tamper-resistant hardware and only consents to decrypt with a physical action (touch, Touch ID, PIN):

| Hardware | Plugin |
| --- | --- |
| YubiKey 4 and 5 (other PIV tokens with a P-256 key may work) | [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) |
| Apple Secure Enclave (Touch ID) | [`age-plugin-se`](https://github.com/remko/age-plugin-se) |
| Any FIDO2 security key | [`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) |
| OpenPGP Card | [`age-plugin-openpgp-card`](https://crates.io/crates/age-plugin-openpgp-card) |

Example setup with a YubiKey:

```bash
# Install the plugin. It must be on $PATH because murk runs it to decrypt.
brew install age-plugin-yubikey

# Create an identity on the YubiKey. The plugin asks for the PIV PIN
# (default 123456) and a touch. --touch-policy always asks for a tap on every
# decrypt. --pin-policy once asks for the PIN once per session.
mkdir -p ~/.config/murk
age-plugin-yubikey --generate --touch-policy always --pin-policy once \
  > ~/.config/murk/yubikey.txt

# murk refuses identity files that others can read
chmod 600 ~/.config/murk/yubikey.txt

# Authorize the YubiKey while you still use your current key
murk circle authorize "$(grep -i recipient ~/.config/murk/yubikey.txt | awk '{print $NF}')"

# Switch to the YubiKey. murk does not read .env, so export the variable.
unset MURK_KEY
export MURK_KEY_FILE="$HOME/.config/murk/yubikey.txt"

# Read a secret. The YubiKey blinks; tap it to decrypt.
murk get SOME_KEY
```

To keep using the YubiKey in new shells, put that `export` in your shell profile, or in `.env` if you load it with `source .env`. `murk init` wrote a `MURK_KEY_FILE` line to `.env` for your software key. Remove or replace it so a later `source .env` does not switch you back.

The identity file contains a `#    Recipient: age1yubikey1...` header followed by an `AGE-PLUGIN-YUBIKEY-1...` pointer. murk reads the pubkey from the header, so looking up your scoped secrets needs no plugin call. murk runs the plugin when it decrypts with this identity, and when it encrypts to a YubiKey recipient. A save encrypts to every recipient, so anyone who writes the vault needs the plugin on `$PATH`. Decryption is when the YubiKey asks for a tap.

If the plugin binary isn't on `$PATH`, murk fails with `age-plugin-yubikey unavailable` — install it and retry. `MURK_KEY` (the inline env var) rejects `AGE-PLUGIN-...` strings: a bare plugin identity doesn't carry the recipient pubkey, so use `MURK_KEY_FILE` pointing at the identity file.

**No BIP39 recovery for hardware identities.** The whole point of hardware-backed keys is that the raw key bytes never leave the device, so there are no bytes to encode as a recovery phrase. Instead, enroll a second hardware device at setup and add both pubkeys as recipients (`murk circle authorize <backup-pubkey>`) — if you lose one, the backup still decrypts.

**`MURK_KEY` vs `MURK_KEY_FILE`.** Setting `MURK_KEY` to a raw `AGE-SECRET-KEY-1...` string in `.env` works once your shell loads that file, but the key is then plaintext on disk. Prefer `MURK_KEY_FILE` pointing at either a file under `~/.config/murk/keys/` (convenience) or a hardware-backed plugin identity file (strongly recommended for production). Set one, not both: murk refuses to run when both are non-empty, and treats an empty value as unset.

## License

MIT OR Apache-2.0
