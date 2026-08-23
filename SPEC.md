# murk — Specification v2.0

> Encrypted secrets manager for developers. One key unlocks everything.

## Motivation

Existing secrets tools are either too complex (SOPS, Vault), tied to a runtime (dotenvx requires Node), or don't support teams cleanly. murk is a minimal Rust binary that:

- Stores encrypted secrets in a single `.murk` file safe to commit to git
- Uses one key (`MURK_KEY`) to unlock everything, stored in `~/.config/murk/keys/`
- Integrates naturally with `direnv`
- Supports multiple users and per-identity private secrets
- Documents itself via `murk info` — no key required

---

## Design Philosophy

- **Header is public, values are private.** Anyone with repo access can see what keys exist and what they're for. Only authorized recipients can see values.
- **age does the crypto.** murk handles UX and data structure. No custom crypto.
- **One binary, no runtime dependency.** Wrappable from any language via subprocess.
- **Git is the audit trail.** murk doesn't try to replicate what git already does.
- **Explicit over magic.** murk never silently overwrites or destroys data.

---

## Terminology

- **murk** — the shared layer. Secrets encrypted to all recipients (the implicit `everyone` group).
- **mote** — a private secret. Encrypted to a single recipient's key. Overrides the shared value during export. On the CLI this is the `me` tier (`--group me`).
- **group** — a named subset of recipients. A secret assigned to a group is encrypted only to that group's members, so a leaked member key can't read secrets outside that member's groups. `everyone` (all recipients) and `me` (just you) are the two reserved, implicit groups; named groups (e.g. `prod`) sit between them.

---

## Environment Variables

| Variable       | Required | Description                                             |
| -------------- | -------- | ------------------------------------------------------- |
| `MURK_KEY`     | No       | Raw age private key (`AGE-SECRET-KEY-1...`). Dev-mode convenience — the key is plaintext on disk. |
| `MURK_KEY_FILE`| Yes      | Path to a private key file. Set by `murk init`. May be a raw age key, an SSH PEM key, or an age plugin identity file with a `# Recipient: age1...` (or `# public key: age1...`) header. |
| `MURK_VAULT`   | No       | Vault filename. Defaults to `.murk`.                    |
| `MURK_STRICT`  | No       | When `1`/`true`/`yes`, fail closed rather than let a secret touch disk: requires `murk edit`'s scratch file to live on a RAM-backed filesystem, and refuses `export`/`get` when stdout is a regular file (plaintext to disk). |

Your identity is your key. murk derives your public key from `MURK_KEY` or `MURK_KEY_FILE` to determine which private secrets are yours and to identify you in the recipient list.

### Hardware-backed identities

When `MURK_KEY_FILE` points at an age plugin identity file, murk uses the hardware-backed key without ever seeing the raw bytes. The file format is:

```
#    Recipient: age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm8cn9ss4xswuaalgb5wh5ug3pcs3
AGE-PLUGIN-YUBIKEY-1Q9WFTQQVZN3FASCJ3N9WEHUMFCYMCQSA2F8YVRMMGY6N76C6DMC6A8FTMP
```

A recipient header is required — murk reads it to determine the recipient without spawning the plugin. murk accepts either `# Recipient:` (what `age-plugin-yubikey` writes) or `# public key:` (what age x25519/SSH identity files use), case-insensitively. The `AGE-PLUGIN-<NAME>-1...` line is the opaque pointer the plugin binary understands. On decrypt, murk invokes `age-plugin-<name>` (which must be on `$PATH`) and the plugin may prompt the user for physical consent (touch, PIN). Plugin identities have no BIP39 recovery phrase; `murk recover` errors on them. Back up a second hardware device as a vault recipient instead.

Setting `MURK_KEY` (the inline env var) to an `AGE-PLUGIN-...` string is rejected — bare plugin identities don't carry the recipient pubkey, so murk can't resolve private secrets without spawning the plugin. Use a file path via `MURK_KEY_FILE`.

### Key storage

`murk init` writes the secret key to `~/.config/murk/keys/<vault-hash>` (chmod 600) and writes a `MURK_KEY_FILE` reference to `.env`:

```
export MURK_KEY_FILE=/home/alice/.config/murk/keys/a1b2c3d4e5f6a7b8
MURK_VAULT=prod.murk  # optional
```

The key never appears in the project directory. `.murk` should always be committed.

---

## File Format

A `.murk` file is a single JSON document. All fields except encrypted values and the meta blob are plaintext.

```json
{
  "version": "2.0",
  "created": "2026-02-27T00:00:00Z",
  "vault_name": ".murk",
  "repo": "https://github.com/org/repo",
  "recipients": [
    "age1abc...",
    "age1xyz..."
  ],
  "schema": {
    "DATABASE_URL": {
      "description": "postgres connection string",
      "example": "postgres://user:pass@host/db",
      "created": "2026-02-27T00:00:00Z",
      "updated": "2026-02-27T00:00:00Z",
      "rotation_interval_days": 90,
      "expires_at": "2026-09-01T23:59:59Z"
    },
    "OPENAI_KEY": {
      "description": "openai api key"
    }
  },
  "policy": {
    "agent_allow_tags": ["agents"]
  },
  "secrets": {
    "DATABASE_URL": {
      "shared": "<base64 age ciphertext>",
      "scoped": {
        "age1xyz...": "<base64 age ciphertext>"
      }
    },
    "STRIPE_KEY": {
      "shared": "",
      "grouped": {
        "prod": "<base64 age ciphertext>"
      }
    },
    "OPENAI_KEY": {
      "shared": "<base64 age ciphertext>"
    }
  },
  "meta": "<base64 age ciphertext>"
}
```

### Version

The `version` field uses semver. murk validates the major version on load — a vault with major version other than `2` is rejected. Minor version bumps (e.g. `2.1`) are accepted.

### Recipients

Public keys only — no names or emails. Name-to-pubkey mappings live inside the encrypted meta blob where only authorized recipients can see them.

### Schema

Key metadata stored as a map of key name to entry. Each entry has a `description` and optional `example` and `tags` fields. Schema is public and readable without decryption.

Entries also carry optional lifecycle metadata:

- `created` / `updated` — ISO-8601 UTC timestamps. `updated` is bumped on every value change (`add`, `edit`, `rotate`) and so doubles as the "last rotated" anchor.
- `rotation_interval_days` — soft rotation policy. `doctor` flags the key as overdue when `updated + rotation_interval_days` is in the past.
- `expires_at` — ISO-8601 UTC hard expiry for credentials with a known end-of-life (e.g. a token). `doctor` flags it as expired or expiring soon.
- `revoked_at` — ISO-8601 UTC marker set when a recipient who could read this key is revoked and rotation is deferred. Its *presence* is the obligation: the revoked recipient can still decrypt the live value from git history until it changes. `doctor` flags it until then; any value write clears it. Omitted when there is no pending rotation.

Set the rotation/expiry fields with `murk describe KEY "desc" --rotate-every 90d --expires 2026-09-01` (`never` clears either); `revoked_at` is managed automatically by `circle revoke`. All lifecycle fields are covered by the integrity MAC (see Integrity), so rotation policy and pending-rotation flags cannot be silently weakened without a key.

Key names must be valid shell identifiers: `[A-Za-z_][A-Za-z0-9_]*`.

### Policy

Optional agent access policy, in the plaintext header so it is readable without a key and at the same trust level as the recipient list. It is **not** access control — every recipient can read every shared secret by design, and an insider can use age directly or an old murk binary. Its value is constraining what the murk binary exposes to *agents*, enforced at the agent entry points (`agent exec`, `agent grant`).

- `agent_allow_tags` — in agent mode, a secret may be injected or granted only if its schema carries at least one of these tags. Once a policy is set it is default-deny: an untagged or wrong-tagged key is refused with a clear error (no override — the operator edits the policy). An empty list locks agents out entirely.

The policy is covered by the integrity MAC (see Integrity), so it cannot be stripped or weakened without a key. The field is omitted entirely when no policy is set, keeping policy-free vaults byte-identical to pre-policy murk.

### Secrets

Each secret has a `shared` field containing age ciphertext encrypted to all recipients (the `everyone` group), an optional `scoped` map of recipient pubkey to age ciphertext encrypted to only that recipient (the **private** / `me` tier — the on-disk field is named `scoped` for compatibility with vaults written before the tier was renamed), and an optional `grouped` map of group name to age ciphertext encrypted to that group's current members.

A secret's base tier is exactly one of: shared (`everyone`), or a single named group (in which case `shared` is empty and `grouped` holds one entry). The `me` tier is a per-identity override layered on top. Group *names* are plaintext, like key names; group *membership* lives in the encrypted meta. age determines readability — a non-member simply can't decrypt a `grouped` ciphertext.

During `murk export` / `get`, resolution is: a personal private (`me`) override first, then a named-group value the current identity can read, then the shared value.

All age ciphertext is base64-encoded (standard alphabet, with padding).

### Meta

The `meta` field is a single age blob encrypted to all recipients. It contains:

```json
{
  "recipients": {
    "age1abc...": "mickey@example.com",
    "age1xyz...": "alice@example.com"
  },
  "mac": "blake3v5:abc123...",
  "hmac_key": "0a1b2c3d...",
  "signers": {
    "age1abc...": "base64-ed25519-verifying-key"
  },
  "sig": {
    "signer": "age1abc...",
    "v": 1,
    "sig": "base64-ed25519-signature"
  },
  "groups": {
    "prod": ["age1abc...", "age1xyz..."]
  },
  "grants": {
    "codex": {
      "pubkey": "age1agent...",
      "scope": ["STRIPE_KEY"],
      "issued_at": "2026-06-16T00:00:00Z",
      "expires_at": "2026-06-16T02:00:00Z",
      "issuer": "age1abc..."
    }
  }
}
```

`recipients` maps public keys to display names. This is the only place names are stored.

`mac` is a keyed integrity hash over the vault's encrypted content (see Integrity below).

`hmac_key` is a hex-encoded 32-byte random key used for BLAKE3 keyed hashing. Generated fresh on each save.

`signers` maps a recipient pubkey to its base64 Ed25519 verifying key, recorded when that recipient signs. `sig` is the current Ed25519 signature: `signer` (the recipient pubkey that produced it), `v` (signed-view version), and `sig` (base64). Both are omitted when the last writer had no signing-capable identity. See Signatures below.

`groups` maps a group name to its member pubkeys (a subset of `recipients`). Stored here, not in the plaintext header, so org structure — who is in which group — does not leak. Members are covered by the MAC. The field is omitted entirely when the vault has no named groups, keeping group-free vaults byte-identical to pre-groups murk.

`grants` maps an agent grant name to its metadata: the agent's ephemeral `pubkey` (also a `recipients` entry), the `scope` of keys it may read, `issued_at`/`expires_at` timestamps, and the `issuer` pubkey. The agent is excluded from the `everyone` layer — its access is the set of `scoped` ciphertexts encrypted to its pubkey, one per scope key. Stored here (not in the header) so an agent's existence and scope don't leak. Covered by the MAC so TTL/scope/issuer can't be altered undetected. The field is omitted entirely when the vault has no grants. The `expires_at` TTL is enforced by the murk binary at read time — an expired grant fails closed — though not cryptographically (see THREAT_MODEL.md).

### Integrity

The MAC is a BLAKE3 keyed hash covering, in order:

1. **Key names** — iterated in sorted order (BTreeMap), each followed by `\x00`
2. **Per-key encrypted values** — for each key (sorted):
   - The shared ciphertext, followed by `\x00`
   - For each scoped entry (sorted by pubkey): the pubkey followed by `\x01`, the scoped ciphertext followed by `\x00`
   - (v6 only) For each grouped entry (sorted by group name): `\x03`, the group name followed by `\x00`, the grouped ciphertext followed by `\x00`
3. **Recipient pubkeys** — sorted, each followed by `\x00`
4. **Schema** — for each key (sorted): `\x02`, then the key name, description, and example (empty if unset) each followed by `\x00`, then each tag followed by `\x00`, then the lifecycle fields `created`, `updated`, `rotation_interval_days` (decimal text), and `expires_at` — each emitted as its bytes (empty if unset) followed by `\x00`
5. **Group definitions** (v6 and v7) — for each group (sorted by name): `\x04`, the group name followed by `\x00`, then each member pubkey (sorted) prefixed by `\x05`
6. **Grant definitions** (v7 and v8) — for each grant (sorted by name): `\x06`, then the grant name, agent pubkey, `issued_at`, `expires_at`, and issuer each followed by `\x00`, then each scope key (sorted) prefixed by `\x07`
7. **Policy** (v8 and v9) — `\x08` opens the policy block, then each agent allow-tag (sorted) is length-prefixed (4-byte big-endian length + bytes) so tag contents can't forge a boundary
8. **Revoked-at markers** (v9 only) — for each schema entry with `revoked_at` set (sorted by key name): `\x09`, the key name followed by `\x00`, the marker timestamp followed by `\x00`. Absent markers emit nothing, so setting then clearing one hashes identically to never setting it.

The resulting digest is prefixed with `blake3v7:` (v9) when any key has a `revoked_at` marker, `blake3v6:` (v8) when the vault has a policy, `blake3v5:` (v7) when it has a grant, `blake3v4:` (v6) when it has a group, or `blake3v3:` (v5) when it has none, and stored as the `mac` field in meta. The 32-byte BLAKE3 key is stored as `hmac_key` in the same encrypted meta blob.

On load, murk verifies the MAC. Legacy prefixes `sha256:` (v1, no scoped coverage), `sha256v2:` (v2, unkeyed), `blake3:` (v3, no schema coverage), `blake3v2:` (v4, no lifecycle-metadata coverage), `blake3v3:` (v5, no group coverage), `blake3v4:` (v6, no grant coverage), `blake3v5:` (v7, no policy coverage), and `blake3v6:` (v8, no revoked-at coverage) are accepted for backward compatibility. On save, murk writes the lowest version that covers the vault's contents (`blake3v7:` if any `revoked_at` exists, else `blake3v6:` for a policy, `blake3v5:` for grants, `blake3v4:` for groups, otherwise `blake3v3:`), always with a fresh key. Gating each version bump on the first group/grant/policy/marker keeps simpler vaults byte-identical to older murk. A vault carrying groups, grants, a policy, or a revoked-at marker is rejected under an older prefix that doesn't cover them, so an attacker can't strip coverage (e.g. clear a pending-rotation flag) by downgrading the MAC. (A vault written by a newer murk cannot be MAC-verified by an older binary that predates the prefix it uses.)

Because both the MAC and its key live inside the encrypted meta blob, only authorized recipients can compute or verify the hash. This makes the MAC a keyed integrity check for recipients and a tamper/corruption detector — but it is **not** a defense against a deliberate attacker with write access to the repo. age encryption needs only the recipients' *public* keys (which are in the plaintext header), so a repo-writer can mint a fresh `hmac_key`, recompute a valid MAC over tampered content, and re-encrypt the meta blob. Authorship integrity is provided by the signature below, not the MAC.

### Signatures

murk signs the vault with an Ed25519 key so tampering by a repo-writer is detectable — the property the MAC cannot provide, since anyone can recompute it.

**Signing key.** Two signing-capable key types:
- **age** — derived from the writer's raw age key bytes via `blake3::derive_key("murk.vault.signing.ed25519.v1", age_key_bytes)` → Ed25519 `SigningKey`. The domain-separated KDF keeps the signing key independent of the encryption key while deriving from the same seed, so the BIP39 phrase recovers both. Its verifying key is published in the `signers` registry (below).
- **ssh-ed25519** — the SSH key is itself an Ed25519 signing key, parsed from the OpenSSH private key (age does not expose the scalar, so murk re-parses the retained PEM with the `ssh-key` crate). Its verifying key is the one embedded in the `ssh-ed25519 …` recipient string, so it is **not** added to `signers`.

`ssh-rsa` and plugin/hardware identities cannot sign; their saves are written unsigned.

**Signed message.** A domain-tagged (`murk.vault.sig.v1\n`) canonical JSON serialization of a signed view (version 1) covering: `version`, sorted `recipients`, `schema`, `secrets` (all tiers), `policy`, `groups`, `grants`, `github_pins`, and the `signers` registry itself — so a rogue verifying key cannot be registered without invalidating the signature. It excludes `sig` (which it produces) and the MAC/`hmac_key` (a shared secret the signature supersedes for authenticity). Determinism comes from sorted maps and a sorted recipient list.

`serde_json` is not a formal canonical encoding, but it does not need to be here: the same serializer both signs and verifies, the signed view holds only strings, sorted maps, and lists (no floats or other ordering ambiguity), and no second implementation has to reproduce these bytes. Its deterministic output is therefore sufficient — a formal canonical form (CBOR/DER) would add nothing.

**Verify.** On load, if `sig` is present murk requires: the signed-view version is understood, the `signer` is a current recipient, and the signature matches the recomputed message. The verifying key comes from the `ssh-ed25519 …` recipient string for SSH signers (self-authenticating; recipient match tolerates a trailing comment), or the `signers` registry for age signers. A present-but-invalid signature fails the load as tampering. An absent signature loads with a warning (`SignatureState::Unsigned`); integrity then rests on git. `sign_vault` only signs as a current recipient, so it never writes a self-invalidating signature.

**Merge driver.** The merge driver runs without deciding to vouch for content, so it leaves the merged vault unsigned (`sig: null`), carrying the `signers` registry forward. A keyholder re-signs on the next write after reviewing `murk diff`.

**Signer-registry pinning (TOFU).** Because the age `signers` registry lives in the re-encryptable meta, a repo-writer could register their own verifying key under an existing recipient's pubkey and forge that recipient's signature. To close this, `load_vault` pins each pubkey→verifying-key mapping locally in `~/.config/murk/signer-pins/<vault-hash>.json` on first sight and enforces it: a *changed* verifying key for an already-pinned pubkey is never legitimate (the mapping is a fixed derivation), so the load fails with an integrity error. The check runs in the library load path, so it covers the CLI and the language bindings alike. New pubkeys are trust-on-first-use, and murk marks them as such: `load_vault` reports an age signature as `Signed { anchored: false }` until its key matches a prior pin, and `murk verify` surfaces the unanchored state rather than claiming verified authorship (git commit signing is the anchor for a first load). `MURK_NO_SIGNER_PIN=1` disables the check. The pin is local and does not travel with the repo. ssh-ed25519 signers are never in the registry (their verifying key rides in the recipient string), so they are self-authenticating — `anchored: true` even on a first clone — and need no pin.

---

## Commands

### `murk init [--vault NAME]`

Interactive setup. Prompts for a display name. Then:

1. Generates an age keypair via BIP39 (24-word mnemonic encodes the key directly)
2. Writes the secret key to `~/.config/murk/keys/<vault-hash>` with mode 0600
3. Writes `export MURK_KEY_FILE=<path>` to `.env` (creates if missing, warns if key already present)
4. Creates empty `.murk` vault with user's pubkey as first recipient
5. Prints BIP39 24-word recovery phrase to stderr

---

### `murk add KEY [--group NAME] [--desc DESC] [--tag TAG] [--vault NAME]`

Adds or updates a secret. Prompts for the value interactively (hidden input via rpassword) or reads from stdin when piped.

`--group` selects who can read it: `everyone` (the default; the shared/murk layer), `me` (only your key; the private/mote layer), or a named group (encrypted to that group's members; you must be a member). Assigning a secret to a named group makes that group its sole base tier — any existing shared value is dropped. `--scoped` is a deprecated alias for `--group me`.

Key names are validated as shell identifiers. Invalid names are rejected.

---

### `murk generate KEY [--length N] [--hex] [--group NAME] [--desc DESC] [--tag TAG] [--vault NAME]`

Generates a cryptographically random value and stores it. Default length is 32 bytes, output as URL-safe base64 (no padding). Use `--hex` for hexadecimal output. `--group` works as for `murk add`. Uses the same RNG as key generation.

---

### `murk rotate KEY [--generate] [--length N] [--hex] [--vault NAME]`

Replaces a secret value. Prompts for the new value interactively, or generates a random one with `--generate`. Use after revoking a recipient to ensure they can no longer use the old value.

`murk rotate --all` rotates every secret in the vault, prompting for each in sequence. `--generate` is not allowed with `--all` — external credentials (database passwords, API keys from third-party services) require manual rotation at the source.

`murk rotate --list` reports the keys that need rotating — the same overdue/expiry/post-revoke signals `doctor` evaluates, scoped to rotation. It reads only the plaintext schema, so it works without a key. Human output exits 1 when anything needs rotating (usable as a script gate); `--list --json` emits a `reason`-tagged array (`overdue`, `no_baseline`, `expired`, `expiring_soon`, `revoke_pending`, `bad_timestamp`) and always exits 0.

---

### `murk rm KEY [--vault NAME]`

Removes a key from the vault (shared value, schema entry, and all private entries). No confirmation prompt — git is your safety net.

---

### `murk get KEY [--vault NAME]`

Prints a single decrypted value to stdout. Scoped values take priority over shared values. Exits with code 1 if key not found.

---

### `murk ls [--tag TAG] [--json] [--vault NAME]`

Lists key names, one per line. `--tag` filters by tag (repeatable). `--json` outputs JSON.

---

### `murk describe KEY "description" [--example EX] [--tag T]... [--rotate-every DAYS] [--expires DATE] [--vault NAME]`

Sets metadata for a key in the plaintext schema. Does not touch encrypted values.

`--rotate-every` takes a day count (`90` or `90d`) and `--expires` takes a date (`2026-09-01`) or RFC-3339 timestamp; pass `never` to either to clear it. Both are sticky — a later `describe` that omits the flag leaves the existing value untouched. `doctor` reports keys that are overdue for rotation or past/near their expiry.

---

### `murk edit [KEY] [--scoped] [--group NAME] [--vault NAME]`

Opens secrets in `$EDITOR`. With KEY, edits a single value; without, edits all secrets as `KEY=VALUE` lines. With `--scoped`, edits private overrides (motes) instead of shared values; with `--group NAME`, edits the values for that named group (you must be a member).

The plaintext buffer is written to a mode-0600 temp file (preferring `XDG_RUNTIME_DIR`), then overwritten with zeros and deleted after the editor exits. An empty value or non-zero editor exit aborts without saving.

The overwrite-and-delete is best-effort — it can't undo a write to a journaled or copy-on-write disk, and editors leave their own swap files behind. When `MURK_STRICT` is set, `edit` requires the temp file to live on a RAM-backed filesystem (tmpfs/ramfs) and aborts before launching the editor otherwise, so the secret never reaches persistent storage. Default systems without a RAM-backed temp dir (e.g. macOS) keep the best-effort behavior; use `add`/`rotate`/`import` from stdin to avoid the editor entirely.

---

### `murk export [--tag TAG] [--json] [--vault NAME]`

Prints all secrets as `export KEY=VALUE` statements to stdout. Scoped values override shared values for the current identity. Errors go to stderr. `--tag` filters by tag (repeatable). `--json` outputs JSON instead of shell exports.

When `MURK_STRICT` is set, `export` refuses to run if stdout is a regular file (e.g. `murk export > .env`), since that persists plaintext secrets to disk; piping to a process (the direnv flow) and printing to a terminal are still allowed. `get` is guarded the same way. This is a guardrail against accidental redirects, not an airtight control — an explicit `murk export | tee .env` still writes the file.

Primary usage via direnv:

```bash
# .envrc
eval "$(murk export)"
```

---

### `murk exec [--only KEY] [--tag TAG] [--clean-env] COMMAND...`

Runs a command with decrypted secrets injected as environment variables. Scoped values override shared values. `--only` injects only the named keys (repeatable), `--tag` filters by tag, `--clean-env` strips the inherited environment so the child sees only murk secrets plus a minimal base. On Unix, murk replaces itself with the command via `exec`.

---

### `murk env [--vault NAME]`

Writes a `.envrc` for direnv integration. Creates the file if missing, appends the murk export line if absent, and leaves it untouched when already present.

---

### `murk agent plan [--tag TAG] [--json] [-o FILE] [--vault NAME]`

Emits schema-only context safe to paste into an AI agent prompt — key names, descriptions, examples, and tags. No decryption and no `MURK_KEY` required; the output contains no secret values, recipient pubkeys, vault name, or meta blob. `--tag` filters by tag (repeatable). `--json` outputs JSON. Prints to stdout, or writes to a file with `-o`.

---

### `murk agent exec --only KEY [--vault NAME] COMMAND...`

`murk exec` with strict agent-safe defaults: clears the inherited environment, strips `MURK_KEY` so the child process cannot read the vault, and requires explicit `--only` keys (repeatable). Agent mode fails closed — there is no inject-everything path. See `docs/ai-agents.md`.

---

### `murk agent grant --name NAME --only KEY [--ttl DUR] [--renew] [--out PATH] [--vault NAME]`

Mints a fresh ephemeral age identity and gives it read access to exactly the `--only` keys (repeatable, required) — never the operator's own key. The agent becomes a recipient of the encrypted meta and gets a private (per-recipient) ciphertext of each `--only` key's shared value, but is excluded from the `everyone` layer. Records grant metadata (scope, TTL, issuer) in the encrypted meta. A live grant name is refused unless `--renew` is passed, which revokes the existing key and mints the replacement in one vault write. `--ttl` accepts `30m`/`2h`/`7d` (default `2h`). Reads fail closed after expiry, though the enforcement is binary-level, not cryptographic (see THREAT_MODEL.md). The agent key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, or `--out -` to stream it to stdout). Run the agent with `MURK_KEY_FILE` pointing at that key and `MURK_STRICT=1` so it can't fall back to the operator's stored key.

---

### `murk agent ls [--json] [--vault NAME]`

Lists active grants: name, truncated pubkey, scope, and TTL status (time remaining, or how long expired). Works offline. `--json` outputs structured data including an `expired` flag.

---

### `murk agent revoke NAME [--rotate] [--vault NAME]`

Removes the grant and its ephemeral recipient (clearing the agent's private ciphertexts), persisting before any rotation. Because the handed-off key can still decrypt old `.murk` versions from git history, rotation is the real close: `--rotate` (or the interactive prompt) re-prompts for new values for the grant's scope.

---

### `murk mcp [--allow-exec] [--vault NAME]`

Runs an in-process MCP (Model Context Protocol) stdio server so AI-agent harnesses can read murk secrets on the capability-not-credential model. Calls the murk-cli library directly — no subprocess, no Node. Fails closed unless the loaded identity is a scoped agent grant with `MURK_AGENT=1`: run with the operator's stored key, a plain recipient, or no grant and it refuses to start. stdout is the JSON-RPC channel (never written to otherwise); all logs go to stderr.

Tools, all bounded to the grant:

- `murk_plan` — the schema (key names, descriptions, examples, tags) of the secrets this grant may read, as JSON, with an optional `tags` filter. No values, and no keys outside the grant's scope or the agent policy.
- `murk_get { key }` — one secret value, if the grant may read it; a forbidden or out-of-scope key returns an error result, never the value.
- `murk_exec { only, command }` — opt-in via `--allow-exec` (off by default). Runs a command with the named secrets injected into its environment (no shell), returning captured stdout/stderr and the exit code; every key must be in scope and policy-allowed, and output and runtime are bounded. `only` scopes the injected secrets, not the command — it is not a sandbox.

See `docs/ai-agents.md` for setup (`murk agent init`) and a verify snippet.

---

### `murk import [FILE] [--group NAME] [--vault NAME]`

Imports secrets from a `.env` file. Parses `KEY=VALUE` lines (supports `export` prefix, single/double quotes). Skips `MURK_*` keys with a warning. Invalid key names are skipped with a warning. `--group` assigns all imported secrets to a tier (`everyone` default, `me`, or a named group), as for `murk add`.

---

### `murk info [--tag TAG] [--json] [--vault NAME]`

Prints the public schema. Works without `MURK_KEY`. With a valid key, also shows recipient names and count. `--tag` filters by tag (repeatable). `--json` outputs JSON.

Each key's row shows any rotation interval and expiry as a trailing `rotate 90d  expires 2026-09-01` segment (public, shown without a key); `--json` includes `rotation_interval_days` and `expires_at` per entry. `murk doctor` evaluates these against the clock — `info` just shows the policy.

---

### `murk recover`

Prints the BIP39 24-word recovery phrase for the current `MURK_KEY`.

---

### `murk restore`

Recovers `MURK_KEY` from a BIP39 recovery phrase. Prompts for the phrase interactively (hidden input) or reads from stdin when piped.

---

### `murk circle`

Lists all recipients. With `MURK_KEY`, shows display names from the encrypted meta and marks the current user with `*`.

---

### `murk circle authorize PUBKEY [--name NAME] [--group NAME] [--vault NAME]`

Adds a new recipient. Re-encrypts all shared secrets to include the new public key. Accepts `age1...`, `ssh-ed25519 ...`, or `github:username` formats. With `--group`, also adds the new recipient(s) to that group in the same step (you must be a member of the group).

---

### `murk group create NAME [--vault NAME]`

Creates a new named recipient group, seeded with you as its first member so you can always read and re-encrypt it. Reserved names (`everyone`, `me`, `all`, `self`, `mine`, `shared`) are rejected.

---

### `murk group ls [--json] [--vault NAME]`

Lists groups and their members (resolved to display names; the current user is marked with `*`). Requires `MURK_KEY` to decrypt membership.

---

### `murk group add NAME --member RECIPIENT [--vault NAME]`

Adds a recipient (by pubkey or display name) to a group. You must already be a member. The group's secrets are re-encrypted to include the new member on save.

---

### `murk group rm NAME [--member RECIPIENT] [--vault NAME]`

With `--member`, removes a recipient from the group and re-encrypts its secrets so the removed member loses access to current values (git history stays readable — rotate to fully close). Without `--member`, deletes the group entirely; refused if any secret is still assigned to it. You must be a member to modify a group.

---

### `murk policy show [--json] [--vault NAME]`

Prints the agent access policy. Works without a key — the policy is in the plaintext header. Shows the allowed tags, or notes that agent mode is unrestricted (no policy) or locked out (empty allow-list).

---

### `murk policy set --allow-tag TAG... [--vault NAME]`

Sets the agent allow-list: in agent mode (`agent exec`, `agent grant`) a secret may be injected or granted only if it carries one of these tags. `--allow-tag` is repeatable and required. Default-deny once set. Writes the policy into the header and bumps the MAC to `blake3v6:`.

---

### `murk policy clear [--vault NAME]`

Removes the policy. Agent mode becomes unrestricted again.

---

### `murk circle revoke RECIPIENT [--rotate] [--vault NAME]`

Removes a recipient by pubkey or display name. Re-encrypts all shared secrets without their key. Removes their private entries.

Lists the secrets the revoked recipient had access to. With `--rotate`, prompts for a new value for each in the same session and re-encrypts them. Without the flag on an interactive terminal, offers to rotate; otherwise prints a hint. The recipient can still decrypt previous versions from git history, so rotation is the only way to close the exposure.

---

### `murk diff [REF] [--show-values] [--json] [--vault NAME]`

Shows which secrets changed between the current vault and a git ref (defaults to `HEAD`). `--show-values` prints the actual values, not just key names. `--json` outputs JSON.

---

### `murk merge-driver ANCESTOR OURS THEIRS [--vault NAME]`

Git merge driver for `.murk` files. Merges non-conflicting secret changes automatically.

---

### `murk setup-merge-driver`

Configures git to use `murk merge-driver` for `.murk` files via `.gitattributes` and `.git/config`.

---

### `murk verify [--vault NAME]`

Verifies vault integrity (MAC) and runs safety checks without exporting secrets. Exits 1 on any finding.

---

### `murk doctor [--vault NAME]`

Checks the surrounding repo for hygiene issues — inline keys in `.env`, key files sitting next to the vault, state that would be bad to commit. If a vault is present it also reads the plaintext schema (no key required) and reports keys overdue for rotation or past/near their `expires_at`. Exits 1 on findings.

---

### `murk skeleton [-o FILE] [--vault NAME]`

Exports a schema-only copy of the vault — key names, descriptions, examples, and tags, with no secrets and no recipients. Prints to stdout, or writes to a file with `-o`.

---

### `murk scan [PATHS]... [--vault NAME]`

Scans files for leaked secret values. Decrypts the vault and searches text files under the given paths (defaults to the current directory) for value substrings. Skips hidden directories, `target/`, `node_modules/`, lockfiles, vault files, and binary files; values shorter than 8 characters are skipped to avoid false positives. Exits 1 if any leak is found.

---

### `murk completion generate|install SHELL`

Prints shell completions to stdout (`generate`) or installs them to the shell's standard completion path (`install`). Supports bash, zsh, fish, elvish, and powershell.

---

## Security Model

**What murk protects against:**

- Repo leaks — `.murk` is safe to commit, useless without a private key
- Accidental secret exposure — `.env` is never committed if `.gitignore` is set correctly
- Private overrides — private secrets (motes) are encrypted only to their owner

**What murk does not protect against:**

- A compromised machine with `MURK_KEY` present
- Historical access after revocation — old `.murk` versions remain in git history. Always rotate credentials when revoking.
- Fine-grained audit logging — use a secrets server for regulated environments
- Malicious recipients — any authorized recipient can decrypt all shared secrets

**Treat `MURK_KEY` like your SSH private key.** Never commit it. Never share it.

**Revocation is incomplete without credential rotation.** murk always warns about this.

### Scope

murk is appropriate for dev tooling and small teams. It is not designed for regulated environments requiring audit trails, key management infrastructure, or provable access controls.

---

## Crate Dependencies

- `age` / `rage` — encryption
- `bip39` — recovery phrase generation
- `serde` / `serde_json` — serialization
- `clap` — CLI argument parsing
- `blake3` — keyed integrity hashing
- `sha2` — legacy integrity hashing (backward compatibility)
- `chrono` — timestamps
- `colored` — terminal output
- `rpassword` — hidden input prompting
