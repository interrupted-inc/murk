# murk — Specification v3.0

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
| `MURK_STRICT`  | No       | When set to anything but `0`/`false`/`no`/`off` (or empty), fail closed rather than let a secret touch disk: requires `murk edit`'s scratch file to live on a RAM-backed filesystem, and refuses `export`/`get`/`diff --show-values` when stdout is a regular file (plaintext to disk). An unrecognised value turns it on. |
| `MURK_TRUSTED_SIGNERS` | No | Signers trusted to sign the vault, separated by commas or newlines, replacing the local trust pin's set: `age1…:<verifying key>` for an age signer, the public key line for an ssh-ed25519 signer (`murk trust --print-key` prints the entry). For CI runners and other machines without a pin. See Trust. |
| `MURK_NO_SIGNER_PIN` | No | When present, murk neither reads nor writes the local trust pin; trust then comes only from `MURK_TRUSTED_SIGNERS`. |

Your identity is your key. murk derives your public key from `MURK_KEY` or `MURK_KEY_FILE` to determine which private secrets are yours and to identify you in the recipient list. Set one, not both: when both are non-empty murk refuses to resolve a key instead of picking one, and an empty value counts as unset.

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

**Discovery.** With neither `MURK_KEY` nor `MURK_KEY_FILE` set, murk looks up `keys/<vault-hash>` itself, where the hash covers the vault's absolute path. A git worktree puts the same committed vault at a different absolute path, so murk also accepts the key stored for that vault in a sibling worktree of the same repository — the main checkout first, then linked worktrees in a stable order. A fresh worktree therefore needs no key provisioning. Membership is read straight out of git's own worktree metadata (never a `git` subprocess) and verified in both directions: the current directory must be a checkout the repository records, and each sibling must resolve back to the same common directory. A `.git` entry is a file anyone can write, so an unverified claim of kinship — like a copied vault under a planted `.git` pointer — resolves to no key at all. Discovery of any kind is off under `MURK_STRICT` and in agent context.

---

## File Format

A `.murk` file is a single JSON document. All fields except encrypted values and the meta blob are plaintext.

```json
{
  "version": "3.0",
  "created": "2026-02-27T00:00:00Z",
  "vault_name": ".murk",
  "repo": "https://github.com/org/repo",
  "vault_id": "0123456789abcdef0123456789abcdef",
  "generation": 12,
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
  "meta": "<base64 age ciphertext>",
  "sig": {
    "signer": "age1abc...",
    "v": 2,
    "sig": "base64-ed25519-signature"
  }
}
```

### Vault identity and counter

`vault_id` is 16 random bytes as 32 lowercase hex characters, minted by `murk init` (or by the first save of a vault written by murk 0.13 or older). `generation` is a save counter: every save writes `max(loaded generation, highest generation this machine accepted) + 1`, and a keyed merge writes `max(ours, theirs, highest accepted) + 1`. Both are covered by the signature (signed view v2) and checked against the local trust pin on load (see Trust), so another vault's file and an older revision are refused. A load also refuses a `generation` more than 1,000,000 above this machine's mark, or above 2^53 − 1 (see Trust, rule 9). Both are omitted when unset, so a vault written by older murk parses unchanged.

### Version

The `version` field is `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` (decimal, no leading zeros) with major `2` or `3`. Any other major is rejected on load; minor bumps (e.g. `3.1`) are accepted. murk writes `3.0`. Major 3 means the MAC (`blake3v8:`) and the signature (signed view 2) cover the header identity fields; murk 0.13 and older only accept `2.x`, so they refuse a 3.x vault with "unsupported vault version" instead of reading its MAC as tampering. A 2.x vault still loads and verifies under its old MAC and signed view 1, and is rewritten as 3.0 on the next save (including a merge-driver merge that regenerates the meta).

`vault_id` and `generation` are header fields too, and both are omitted when unset: `vault_id` is a random vault identity (32 lowercase hex characters), and `generation` is a save counter. `agents` maps an agent grant's pubkey to that grant's own record, encrypted to that grant only, and is omitted when the vault has no grants (see Agent grants). `sig` is the signature over the rest of the file (see Signatures).

### Load-time validation

A `.murk` file arrives through git and is untrusted. Every reader (the working vault, git revisions read by `diff`, and all three merge-driver inputs) checks each field against an allowlist and refuses the whole vault on the first failure, naming the field. `murk` applies the same checks before it writes, so it never commits a vault it cannot load.

- File size: at most 64 MiB, checked before parsing.
- `version`: as above.
- `created` and the schema `created`/`updated`/`expires_at`/`revoked_at`: RFC 3339 timestamps.
- Key names in `schema`, `secrets`, and grant scopes: `[A-Za-z_][A-Za-z0-9_]*`.
- `recipients`, `scoped` keys, `agents` keys, the `sig` signer, and every pubkey in the meta: a public key that murk can encrypt to (age X25519, `ssh-ed25519`/`ssh-rsa`, or an age plugin recipient).
- `recipients`: each key once, compared by canonical spelling (lowercase for age, `type blob` for SSH). murk ≤ 0.13 compared exact strings and could list one key twice (an SSH key with and without its comment), so a 2.x header may repeat a key: it loads, `murk verify` reports it, `murk circle revoke` by either spelling removes every copy, and every save writes each recipient once in its canonical spelling. In a 3.x header a repeated key fails the load.
- `grouped` keys and meta group names: 1–64 characters of `[A-Za-z0-9_-]`, and not a reserved tier alias (`everyone`, `all`, `shared`, `me`, `self`, `mine`). Meta grant names: the same character rule.
- `rotation_interval_days`: at least 1.
- Ciphertexts (`shared`, `scoped`/`grouped` values, `agents` values, `meta`, signer keys, signature): standard base64 with padding. `shared` and `meta` may be empty.
- Free text (`vault_name`, `repo`, descriptions, examples, tags, `agent_allow_tags`, display names): no control characters other than tab, CR, and LF.
- Meta `mac_key`: 64 hex characters. `github_pins`: GitHub usernames (1–39 of `[A-Za-z0-9-]`, written lowercase and matched case-insensitively) mapped to `SHA256:` fingerprints — the SHA-256 of the decoded key blob, as `ssh-keygen -l` prints it. Pins written before 0.14 hash the key text instead; they are still matched and are rewritten on the next `authorize`.

The MAC value is not interpreted here, and signature bytes are only checked as base64. The integrity checks below verify both, and a failed check stops the load.

### Recipients

Public keys only — no names or emails. Name-to-pubkey mappings live inside the encrypted meta blob where only authorized recipients can see them.

murk only writes a vault as one of its recipients: a save is refused when the saving key is not in `recipients`, because the values would be encrypted to keys the saver can't read back. A vault with an empty `meta` and no secrets loads only for a key listed in `recipients`; any other key gets "not a recipient". Otherwise anyone with repo write could plant such a vault listing only their own key and receive the next secret written into it.

### Schema

Key metadata stored as a map of key name to entry. Each entry has a `description` and optional `example` and `tags` fields. Schema is public and readable without decryption.

Entries also carry optional lifecycle metadata:

- `created` / `updated` — ISO-8601 UTC timestamps. `updated` is bumped on every value change (`add`, `edit`, `rotate`) and so doubles as the "last rotated" anchor.
- `rotation_interval_days` — soft rotation policy. `doctor` flags the key as overdue when `updated + rotation_interval_days` is in the past.
- `expires_at` — ISO-8601 UTC hard expiry for credentials with a known end-of-life (e.g. a token). `doctor` flags it as expired or expiring soon.
- `revoked_at` — ISO-8601 UTC marker set when a recipient who could read this key is revoked and rotation is deferred, or is removed from the group holding it. Its *presence* is the obligation: they can still decrypt the live value from git history until it changes. `doctor` flags it until then. A write that replaces the shared or group value (`add`, `rotate`, `import`) clears it; writing a personal override (`--group me`) does not, since that leaves the exposed value in place. Omitted when there is no pending rotation.

Set the rotation/expiry fields with `murk describe KEY "desc" --rotate-every 90d --expires 2026-09-01` (`never` clears either); `revoked_at` is managed automatically by `circle revoke`, `group rm --member`, and `agent revoke` / `agent grant --renew`. All lifecycle fields are covered by the integrity MAC (see Integrity), so an edit that weakens rotation policy or clears a pending-rotation flag is caught by any command that loads the vault with a key. A command that reads the header without a key shows these fields unchecked and says so (see Trust, Header reads).

Key names must be valid shell identifiers: `[A-Za-z_][A-Za-z0-9_]*`.

### Policy

Optional agent access policy, in the plaintext header so it is readable without a key and at the same trust level as the recipient list. It is **not** access control — every recipient can read every shared secret by design, and an insider can use age directly or an old murk binary. Its value is constraining what the murk binary exposes to *agents*, enforced at the agent entry points (`agent exec`, `agent grant`).

- `agent_allow_tags` — in agent mode, a secret may be injected or granted only if its schema carries at least one of these tags. Once a policy is set it is default-deny: an untagged or wrong-tagged key is refused with a clear error (no override — the operator edits the policy). An empty list locks agents out entirely.

The policy is covered by the integrity MAC (see Integrity), so a keyed load catches a policy that was stripped or weakened. The field is omitted entirely when no policy is set, keeping policy-free vaults byte-identical to pre-policy murk. `murk policy show` reads the header without a key and labels what it prints unverified (see Trust, Header reads).

### Secrets

Each secret has a `shared` field containing age ciphertext encrypted to all recipients (the `everyone` group), an optional `scoped` map of recipient pubkey to age ciphertext encrypted to only that recipient (the **private** / `me` tier — the on-disk field is named `scoped` for compatibility with vaults written before the tier was renamed), and an optional `grouped` map of group name to age ciphertext encrypted to that group's current members.

A secret's base tier is exactly one of: shared (`everyone`), or a single named group (in which case `shared` is empty and `grouped` holds one entry). The `me` tier is a per-identity override layered on top. Group *names* are plaintext, like key names; group *membership* lives in the encrypted meta. age determines readability — a non-member simply can't decrypt a `grouped` ciphertext.

During `murk export` / `get`, resolution is: a personal private (`me`) override first, then a named-group value the current identity can read, then the shared value.

All age ciphertext is base64-encoded (standard alphabet, with padding).

### Meta

The `meta` field is a single age blob encrypted to every recipient except agent grants (a grant reads its own record in `agents` instead; see Agent grants). It contains:

```json
{
  "recipients": {
    "age1abc...": "mickey@example.com",
    "age1xyz...": "alice@example.com"
  },
  "mac": "blake3v8:abc123...",
  "hmac_key": "0a1b2c3d...",
  "signers": {
    "age1abc...": "base64-ed25519-verifying-key"
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

`signers` is the signer registry: it maps a recipient pubkey to the base64 Ed25519 verifying key that recipient's age key signs with, recorded when that recipient signs (ssh-ed25519 keys are never listed: the recipient string is the verifying key). The vault's author writes it, so loaders believe an entry only as described in Trust below. It is omitted when no age key has signed. Vaults written before 3.0 also carry `sig` here: a signed-view-1 signature with `signer`, `v` (`1`), and `sig` (base64). murk now writes the signature to the top-level `sig` field instead and never writes one into the meta. See Signatures below.

`groups` maps a group name to its member pubkeys (a subset of `recipients`). Stored here, not in the plaintext header, so org structure — who is in which group — does not leak. Members are covered by the MAC. The field is omitted entirely when the vault has no named groups, keeping group-free vaults byte-identical to pre-groups murk.

`grants` maps an agent grant name to its metadata: the agent's ephemeral `pubkey` (also a `recipients` entry), the `scope` of keys it may read, `issued_at`/`expires_at` timestamps, and the `issuer` pubkey. The agent is excluded from the `everyone` layer and from the meta — its access is the set of `scoped` ciphertexts encrypted to its pubkey, one per scope key, plus its own record in `agents`. Stored here (not in the header) so an agent's existence and scope don't leak. Covered by the MAC so TTL/scope/issuer can't be altered undetected. The field is omitted entirely when the vault has no grants. The `expires_at` TTL is enforced by the murk binary at read time — an expired grant, or one with no or an unreadable `expires_at`, fails closed — though not cryptographically (see THREAT_MODEL.md). The next save removes an expired grant (record, recipient and scoped copies) and marks its keys as owed a rotation.

A grant record whose `pubkey` is the key that opened the meta was written by a meta writer: grants never open the meta. When that key is an operator key the trust rules know (rule 5 under Trust), the vault is refused as tampering. Otherwise the record is ignored on load and dropped by the next save, and it never makes that key a grant.

### Integrity

The MAC is a BLAKE3 keyed hash covering, in order:

1. **Key names** — iterated in sorted order (BTreeMap), each followed by `\x00`
2. **Per-key encrypted values** — for each key (sorted):
   - The shared ciphertext, followed by `\x00`
   - For each scoped entry (sorted by pubkey): the pubkey followed by `\x01`, the scoped ciphertext followed by `\x00`
   - (v6 and later) For each grouped entry (sorted by group name): `\x03`, the group name followed by `\x00`, the grouped ciphertext followed by `\x00`
3. **Recipient pubkeys** — sorted, each followed by `\x00`
4. **Schema** — for each key (sorted): `\x02`, then the key name, description, and example (empty if unset) each followed by `\x00`, then each tag followed by `\x00`, then the lifecycle fields `created`, `updated`, `rotation_interval_days` (decimal text), and `expires_at` — each emitted as its bytes (empty if unset) followed by `\x00`
5. **Group definitions** (v6 and later) — for each group (sorted by name): `\x04`, the group name followed by `\x00`, then each member pubkey (sorted) prefixed by `\x05`
6. **Grant definitions** (v7 and later) — for each grant (sorted by name): `\x06`, then the grant name, agent pubkey, `issued_at`, `expires_at`, and issuer each followed by `\x00`, then each scope key (sorted) prefixed by `\x07`
7. **Policy** (v8 and later, only when a policy is set) — `\x08` opens the policy block, then each agent allow-tag (sorted) is length-prefixed (8-byte big-endian length + bytes) so tag contents can't forge a boundary
8. **Revoked-at markers** (v9 and later) — for each schema entry with `revoked_at` set (sorted by key name): `\x09`, the key name followed by `\x00`, the marker timestamp followed by `\x00`. Absent markers emit nothing, so setting then clearing one hashes identically to never setting it.
9. **Header identity** (v10 only) — `\x0A`, then `vault_name`, `repo`, `created`, and `vault_id` (empty if unset), each as an 8-byte big-endian length followed by its bytes, then `generation` as an 8-byte big-endian integer (`0` if unset)
10. **Agent blobs** (v10 only) — for each `agents` entry (sorted by pubkey): `\x0B`, then the pubkey and the ciphertext, each as an 8-byte big-endian length followed by its bytes

murk writes v10, prefixed `blake3v8:`, on every keyed save, so every vault upgrades on its next write. The digest is stored as the `mac` field in meta, and the 32-byte BLAKE3 key as `hmac_key` in the same encrypted meta blob.

On load, murk verifies the MAC. Older prefixes are accepted for vaults written before 3.0: `sha256:` (v1, no scoped coverage), `sha256v2:` (v2, unkeyed), `blake3:` (v3, no schema coverage), `blake3v2:` (v4, no lifecycle-metadata coverage), `blake3v3:` (v5, no group coverage), `blake3v4:` (v6, no grant coverage), `blake3v5:` (v7, no policy coverage), `blake3v6:` (v8, no revoked-at coverage), and `blake3v7:` (v9, no header-identity or agent-blob coverage). Each was written only when the vault needed it, so older murk saves of simpler vaults used older prefixes. A vault is rejected under an older prefix that doesn't cover what it carries, so an attacker can't strip coverage (for example, clear a pending-rotation flag) by downgrading the MAC: groups need v6 or later, grants v7, a policy v8, a revoked-at marker v9, and a 3.x `version`, a `vault_id`, a non-zero `generation`, or an `agents` entry v10. A `blake3vN:` prefix newer than `blake3v8:` fails the load with "written by a newer murk" rather than as tampering.

Because both the MAC and its key live inside the encrypted meta blob, only authorized recipients can compute or verify the hash. This makes the MAC a keyed integrity check for recipients and a tamper/corruption detector — but it is **not** a defense against a deliberate attacker with write access to the repo. age encryption needs only the recipients' *public* keys (which are in the plaintext header), so a repo-writer can mint a fresh `hmac_key`, recompute a valid MAC over tampered content, and re-encrypt the meta blob. Authorship integrity is provided by the signature below, not the MAC.

### Signatures

murk signs the vault with an Ed25519 key so that a change by someone without a recipient's private key is detectable — the property the MAC cannot provide, since anyone can recompute it. Whether the signer is someone *this machine trusts* is a separate check (see Trust below).

**Signing key.** Two signing-capable key types, both plain Ed25519 (RFC 8032, `ed25519-dalek`):
- **age** — an Ed25519 key derived from the raw 32-byte X25519 secret with `blake3::derive_key("murk.vault.signing.ed25519.v1", age_key_bytes)`, as in murk 0.13. The BIP39 phrase recovers it. Its verifying key cannot be computed from the `age1…` recipient, so the signer records it in the meta's `signers` registry on every save.
- **ssh-ed25519** — the SSH key is itself an Ed25519 signing key, parsed from the OpenSSH private key (age does not expose the scalar, so murk re-parses the retained PEM with the `ssh-key` crate). Its verifying key is the one embedded in the `ssh-ed25519 …` recipient string.

`ssh-rsa` and plugin/hardware identities cannot sign; their saves are written unsigned. All signing and verification goes through one module (`src/signing.rs`: `VaultSigningKey::sign`, `VaultSigningKey::verifying_key`, `signing::verify`), so a different scheme would replace that module, not the trust logic.

**Signed message (view 2).** murk writes view 2: the domain tag `murk.vault.sig.v2\n` followed by the JSON serialization of the vault file with the top-level `sig` field omitted, fields in file order. That covers every header field (`version`, `created`, `vault_name`, `repo`, `vault_id`, `generation`, `recipients` in stored order, `schema`, `policy`), the `agents` and `secrets` ciphertexts, and the `meta` ciphertext. Because the meta ciphertext is covered, the decrypted meta (MAC, names, `signers`, groups, grants, pins) is authentic too, and the message is rebuilt from the file alone. The signature is computed after the meta is encrypted and stored in the top-level `sig` (`signer`, `v` = `2`, base64 `sig`).

**Signed message (view 1).** Vaults written before 3.0 carry a view-1 signature inside the meta: a domain-tagged (`murk.vault.sig.v1\n`) canonical JSON serialization of a signed view covering `version`, sorted `recipients`, `schema`, `secrets` (all tiers), `policy`, `groups`, `grants`, `github_pins`, and the `signers` registry. It does not cover `vault_name`, `repo`, `created`, `vault_id` or `generation`. It excludes `sig` and the MAC/`hmac_key`. murk still verifies view 1, only on a 2.x vault without a `vault_id` or `generation`, and replaces it with view 2 on the next save.

`serde_json` is not a formal canonical encoding, but it does not need to be here: the same serializer both signs and verifies, the signed view holds only strings, integers, sorted maps, and lists (no floats or other ordering ambiguity), and no second implementation has to reproduce these bytes. Its deterministic output is therefore sufficient — a formal canonical form (CBOR/DER) would add nothing.

**Verify.** On load, murk accepts a view-2 signature only in the top-level `sig` and a view-1 signature only in the meta; anything else (both present, a view in the wrong place) fails the load as tampering. A view newer than 2 fails with "written by a newer murk". Then the `signer` must be a current recipient (compared by canonical spelling: lowercase for age, `type blob` for SSH) and the signature must verify under the signer's verifying key: the `ssh-ed25519 …` recipient string for SSH signers, the `signers` registry entry for age signers. A present-but-invalid signature fails the load as tampering, and so does a signature by an agent-grant key (grants are read-only). A valid signature only proves the registry entry's owner signed; whether that key is really the recipient's is the trust check's job (rule 4 below). `sign_vault` only signs as a current recipient, so it never writes a self-invalidating signature.

**Merge driver.** A keyed merge first authenticates the common ancestor (MAC, signature, a signer this machine ever trusted). An unsigned ancestor without a `vault_id` is accepted as pre-0.14 history but never used as authority: the sides' metas are then merged as if the ancestor were unreadable (any difference is a conflict), and group changes are judged against the pinned membership. It then checks ours and theirs the way a load does — MAC, valid signature, a signer this machine trusts, not a grant, the same `vault_id`, and, for a side that changed the vault, a `generation` above the ancestor's; group changes are judged against the authenticated ancestor's membership. A side written by murk 0.13 (no `vault_id` or no `generation`) carries no authenticated identity or order, so only the ancestor may be pre-0.14 history: when this machine has a pin for the vault, a side without a `vault_id` or `generation`, or with a `vault_id` other than the pinned one, is refused (it could be an older signed revision, or another 0.13 vault of the team, committed on a branch forked from 0.13 history), and its intended change has to be made again with murk after merging. With no pin, such a side is refused when it changed the vault and the other side was written by 0.14. Both sides may lack a `vault_id` only when the whole merge is 0.13 history and this machine has no pin. A side's `generation` is compared with the ancestor's, not with the pin's mark: a branch saved on another machine legitimately carries a lower counter than this machine has accepted, and its content enters the merge only as its change from the ancestor. A side (or ancestor) that fails is a conflict naming it, and nothing from it is merged, re-MACed or signed. A merge that would change a group's membership relative to ours is a conflict when the merging key is not a member of that group, since every machine would refuse the result signed by it. Otherwise the merged vault gets a fresh MAC, `generation = max(ours, theirs, highest accepted) + 1`, and a v2 signature by the merging key (none if that key cannot sign). git passes the vault's path as `%P` (`murk merge-driver %O %A %B %P`) so the driver reads the right trust pin; a driver configured before 0.14 has no `%P` and falls back to `.murk`. A merge done without the driver (GitHub's web merge, merge queues) either conflicts textually or produces a vault whose MAC and signature fail, so it is never served. A cherry-pick or `git apply --3way` of commits from history replays their genuine delta; that is git's semantics, not something the driver can tell apart.

**Merge driver and removed keys.** A merge judges removals on every branch, whichever branch it merges into (rule 8 below). A side signed by a key this machine recorded as removed is refused. A side that lists a removed key that the ancestor does not list, at or below the generation the key was removed at, is an older revision adding the key again: it is refused as rolled back. A side that only still lists the key (a branch forked before the removal) passes, because the merge takes the removal from the other side or reports a conflict. If the merged recipients still list a removed key, some side numbered above the removal must list it. Otherwise the merge is a conflict and nothing is signed. A side's `generation` may be below the pin's mark, but it may be at most 1,000,000 above both the mark and the ancestor's. A side that sets a secret back to an older ciphertext, signed by a trusted signer, looks the same as a normal edit by that signer, so the merge accepts it.

**Merging a removal into a branch the removed member wrote to.** Alice revokes Bob on `feature`; before that is merged, Carol (trusted) and then Bob change the vault on `main`. On `main`, Alice's load of Bob's vault is refused ("signed by bob, who was removed from this vault …"), and the hint says how to recover: merge the branch that removed him. She runs `git merge feature` with the murk driver. The merge stops with a conflict on the vault: "ours failed its authenticity check, so nothing was merged or signed: rolled back: it is signed by bob, who was removed …". The driver cannot merge Bob's side, because nothing he signed after his removal is trusted. So Alice keeps the side that removed him: `git checkout --theirs -- .murk`, then `git add .murk`. That drops every vault change made on `main` since the branches split, Carol's included, and the hint says so. She runs `murk trust`: the kept vault reads as a rollback or fork of `main`, because her machine already accepted Carol's newer vault there, and accepting it does not re-trust Bob. She finds `main`'s last vault commit not signed by Bob (`git log -- .murk`) and lists what differs with `murk diff <that commit> --show-values`. She reviews it change by change, because a vault someone else signed on top of Bob's write can still carry his changes. She makes only the changes trusted members made again with murk, and commits. `main` then carries the removal and loads, and Bob is never trusted again. murk 0.14 has no command that re-merges `main`'s last trusted vault with the removing side automatically.

### Trust

A valid signature proves that some key listed as a recipient signed the vault, and the vault chooses its own recipients. Acceptance is therefore anchored in state the repository cannot write: the local **trust pin** or the `MURK_TRUSTED_SIGNERS` environment variable. `load_vault` (`src/load.rs`, rules in `src/trust.rs`) applies these rules on every keyed load by a key that opens the meta, before any value is decrypted for the caller — for the CLI, the MCP server and the Python/Node bindings alike, and for write commands too, so a write never re-signs untrusted content. An agent grant's load is anchored in its key file instead (see Agent grants):

1. **Unsigned.** Refused when the loading key can sign (age, ssh-ed25519), or when `MURK_TRUSTED_SIGNERS` is set. Loaded with a warning otherwise (ssh-rsa, hardware/plugin keys): such a team relies on signed git commits.
2. **Stripped.** A vault this machine accepted signed that is now unsigned is refused, for every key.
3. **Trusted signer.** The signer must be in `MURK_TRUSTED_SIGNERS` when that is set (it replaces the pin's set), otherwise in the pin's `trusted` set: the non-grant recipients of the last vault accepted here. With neither, the vault is refused until `murk trust`.
4. **Signing key.** For an age signer, the registry key the signature verified under must be the one pinned for that signer (pin `signers`), or the one `MURK_TRUSTED_SIGNERS` gives for it. A trusted signer with no pinned key yet — a newly authorized teammate's first signed write — is refused until `murk trust` confirms the key: trust on first use. A different key for a signer whose key is pinned is refused outright, and `murk trust` will not accept it: an age key's verifying key is derived from its secret, so a second one for the same recipient is a forgery. ssh-ed25519 signers need no pinned key.
5. **Grants.** A signer that is an agent grant in the vault, or was ever seen here as one, is refused; so is a former grant key listed as a recipient without its grant. A vault whose grant record names an operator key — a signer this machine trusts or ever trusted, a signer named in `MURK_TRUSTED_SIGNERS` or a grant's key-file anchor, a key with a signer-registry entry (grants never sign), or the loading key when it is an ssh or plugin identity (murk mints grant keys as age keys) — is refused as tampering, and `murk trust` will not accept it: grants get freshly minted keys, and recording it would mark that teammate as a grant on this machine. A key the pin trusts as a signer is never recorded as a grant and stays a trusted signer, and a pinned grant entry never overrides signer trust.
6. **Identity and rollback.** `vault_id` must match the pinned one. `generation` must not be below the highest accepted on the git branch the vault is checked out on; a branch never seen here and a detached HEAD have no mark, and outside a git checkout the single highest mark applies. Once this machine has seen the vault with a `vault_id` or a `generation`, a view-1-signed vault is refused as rolled back.
7. **Groups.** A change to a group's membership must be signed by a member of that group as pinned (a new group by one of its members). Removing a member who left the vault entirely is exempt, because `circle revoke` does that for any recipient.
8. **Removal.** When this machine accepts a vault that removes a key from the trusted signers, the pin records the key in `removed` with that vault's generation, the branch the removal was made or accepted on in `removed_on`, and the commit checked out at that moment in `removed_at_commit`. From then on a vault signed by the key is refused on every branch, on a detached HEAD and outside git, in `MURK_TRUSTED_SIGNERS` mode too, with one exception: a vault the key signed before its removal, checked out on a branch the removal has not reached, at the recorded removal commit or an ancestor of it, with the vault file exactly as committed there. That vault is the key's own history from before the removal, so it loads like any other, and it never makes the key trusted again. A vault at any other commit is not covered, even one in the history of a branch the removal reached, so a vault the key signs after its removal is always refused. When the removal commit is unknown (the removal was made or accepted outside git, or recorded by an older murk), there is no exception. No vault drops the recorded removal except as described below. A vault that lists the key at that generation or below is refused as rolled back wherever the history contains the removal: on the branch it was made or accepted on, on any branch where this machine later accepts a vault at or after the removal that no longer lists the key (the removal was merged or pulled there), on a detached HEAD, outside git, and on a branch this machine has never accepted, whose history is unknown, so it may be a replay. Two places are exempt from this listing rule, because their vaults may still legitimately list the key until the removal is merged there: a branch this machine accepted before the removal reached it, and a never-accepted branch checked out at the recorded removal commit or an ancestor of it, with the vault file exactly as committed there (an uncommitted change to the vault file loses the exemption). Reading there works, and on a branch this machine accepted before, saves work too; on a never-accepted branch a save that would keep the key is still refused. Loads on a never-accepted branch stay history, so they never add trust, and a vault there listing the key again never drops the removal. A newer vault from a trusted signer that lists the key again where the listing rule applies re-adds it, and so does `murk trust --re-add` naming the key. A save over an older revision that still lists the key is refused where the listing rule applies, with a message to update to the vault that removed it. A save that adds the key itself (`circle authorize`) re-adds it on purpose. A merge judges removals on every branch (see Merge driver and removed keys, and the recovery after it). A removal recorded before `removed_on` existed applies everywhere.
9. **Counter.** `generation` may be at most 1,000,000 above the pin's mark. Above that, the vault is refused until `murk trust`. A `generation` above 2^53 − 1 (the largest integer every JSON reader holds exactly) is refused as tampering, everywhere, and `murk trust` does not accept it. So no signer can push the counter to where it stops increasing. The pin keeps a fingerprint (the SHA-256 of the signature) of the vault accepted at each branch's mark, and outside git at the overall mark. A different vault with the same generation on that branch is a fork: refused until `murk trust`. Two saves with the same counter on different branches are normal (two people saving from one revision), and the merge driver combines them.

An accepted load is either **current** or **history**. It is current when it is newer than everything this machine accepted (its `generation` above the pin's mark) and it is checked out outside git or on a branch this machine accepted before (one with a mark from an earlier `murk trust`, own save or current load). Any other accepted load is history: a branch this machine has never accepted (an unmerged pull request, say), a detached HEAD, a branch behind the mark, the vault already accepted, or a different vault with the counter this machine already accepted. Reviewing a pull request from a trusted signer therefore never trusts what it adds: branch protection may stop that signer from making the same change on main. A teammate added on such a branch signs there only after the change reaches a branch this machine accepted, or after `murk trust`. A current load updates the pin: `trusted` becomes its non-grant recipients, `groups` is replaced, the counters move up, and the signer's verifying key and the registry entries of the vault's trusted recipients are recorded in `signers` where none was pinned. A history load only narrows the pin. It adds grant keys to `grants`, raises the mark of a branch accepted before (it never gives a branch its first mark), and keeps `was_signed`. It never adds a trusted signer, a verifying key or a group member, so reading history (another branch, a detached HEAD, `murk diff`) never adds trust. Keys that a current load drops from `trusted` are recorded in `removed` (rule 8).

A registry entry is believed only from a vault signed by an already-trusted signer (whose own key matched), or one the user confirmed with `murk trust`. A pinned key is never replaced. An entry for a member of a group (as pinned, or in the vault) is believed only from a member of that group: binding a key to someone's name lets the signer speak as them, so it must not reach a group the signer could not change itself. A save signs the registry it writes, so on a machine with a pin it writes only the keys this machine confirmed (plus the writer's own). It never writes an entry the loaded file claimed that this machine did not confirm, and never one this machine pinned on another signer's word. A teammate's key therefore reaches every machine through the next write by anyone who confirmed it. Without a pin (trust from `MURK_TRUSTED_SIGNERS`) the loaded entries are carried forward. When the trust came from `MURK_TRUSTED_SIGNERS`, the pin's `trusted`, `groups`, `signers`, `added_by` and `removed` are left unchanged, so the variable never widens trust that outlives it. A pin write that fails during a load only warns. `murk trust` and `murk init` record their result like a current load. The machine's own save changes `trusted` only by what the save itself added and removed, compared with the file it replaced. So a save over a vault read as history does not trust the keys that vault carried. Nothing from a refused or unverified vault is ever written to the pin.

**Registry entries depend on whoever added them.** When the pin takes a verifying key for a recipient from the registry of a vault signed by someone else, it records that signer in `added_by`. The entry counts only while that signer is trusted. When an accepted vault removes the signer, every entry they added is dropped, and is not pinned again from that same vault. The recipient's next signed write is then refused as unconfirmed until `murk trust` confirms the key. A save never writes an entry this machine holds on another signer's word. Otherwise the save would vouch for it under the writer's name, and other machines would keep it after the adder is removed. An entry with no `added_by` was **independently confirmed**: the user accepted it with `murk trust` after the fingerprint was shown, or it is this machine's own key (its own save or `murk init`). Nothing else confirms an entry. A vault signed by the recipient's key and accepted while the adder was still trusted proves only that someone holds that key, and the adder chose that key. If the adder bound their own key to the recipient's name, the adder signed that vault. Another trusted signer whose registry carries the same entry does not confirm it either, because their machine may have pinned it on the adder's word. Pins written before 0.14 have no `added_by`, so their entries count as confirmed, and a machine still on such a pin can vouch for them.

**The pin.** `~/.config/murk/signer-pins/<hash>.json`, `0600`, written atomically, a symlink at the path refused. The hash is over the repository's common git directory plus the vault's path in the checkout, so every worktree of a repository shares one pin; outside a repository it is over the resolved absolute path. A pin that exists but cannot be parsed is an error, never an empty pin. Every update — an accepted load, `murk trust`, a save — re-reads the pin under an exclusive lock on `<hash>.lock` and writes from that fresh copy, and a load's acceptance is re-checked against it first: a load that read the pin before another process accepted a newer revision is then refused as rolled back instead of writing its stale view back. Fields: `trusted`, `ever_trusted` (every key ever trusted here), `grants`, `groups`, `vault_id`, `generation`, `branches` (per-branch high-water marks), `head` and `branch_heads` (fingerprints of the vaults accepted at those marks), `signers` (canonical recipient → pinned verifying key), `added_by` (recipient → the signer whose registry entry pinned its key), `removed` (canonical key → the generation it was removed at), `removed_on` (canonical key → the branches whose accepted history contains its removal), `removed_at_commit` (canonical key → the commit checked out when this machine made or accepted its removal), `was_signed`. `removed`, `removed_on` and `removed_at_commit` belong to one vault: accepting a vault with another `vault_id` clears them. A murk ≤ 0.13 pin was written trust-on-first-use from unverified vaults, so murk keeps only its `was_signed` bit.

**`murk trust`.** The explicit trust step: needed once per vault on each machine (a fresh clone, a new laptop, the first run after upgrading from 0.13), on each machine when a newly authorized age-key teammate first writes, and whenever a load is refused for a reason a human can accept. It shows the vault id and counter, the signer's name and full key (the name is chosen by whoever wrote the file), the signer's **signing-key fingerprint** (`SHA256:` and the unpadded base64 SHA-256 of the 32 verifying-key bytes, the `ssh-keygen -l` form) marked "trust on first use" when this machine has not confirmed it, and every recipient with its fingerprint, marked as new or removed since this machine last trusted the vault; then it asks (or takes `--yes`). The fingerprint should be checked with its owner out of band: `murk trust --print-key` prints one's own (and `murk init` prints it for a key that is not yet authorized). Accepting an unsigned or stripped vault with a signing key re-signs it with that key (a save); otherwise the vault is pinned as shown, a rollback or fork acceptance resetting the branch's mark. It refuses vaults signed by a grant key, with a changed signing key, or with a `generation` above 2^53 − 1, and refuses to run for a grant identity. A vault signed by or listing a key recorded in `removed` is refused, whatever its generation, unless each such key is named with `--re-add KEY` (its public key or its name in the vault). Naming it takes the key out of `removed`.

**Trusted-signer entries.** `MURK_TRUSTED_SIGNERS` and an agent grant's key-file anchor use one entry format. An age signer is `age1…:<verifying key>` (the recipient, a colon, the base64 Ed25519 verifying key); an ssh-ed25519 signer is its public key line. `murk trust --print-key` prints the entry for the current key. In `MURK_TRUSTED_SIGNERS` entries are separated by commas or newlines; an invalid entry, or an age key without its verifying key, is an error.

**Historical revisions.** `trust::assess_revision` checks an older revision against `ever_trusted` without rollback or group checks, and never writes the pin, so a revision signed by a teammate revoked since still verifies. The merge driver uses it for the common ancestor. `murk diff` warns when the working vault is not trusted, but does not yet verify the revision it compares against.

**CI.** A fresh runner has no pin. `MURK_TRUSTED_SIGNERS` (from a CI secret, in the entry format above) names the keys allowed to sign and pins their verifying keys. Without a pin there is no rollback mark on a runner.

**Opting out.** `MURK_NO_SIGNER_PIN` (present with any value, or no home directory) stops murk reading or writing the pin. It does not switch the trust check off: every signed vault is then refused unless `MURK_TRUSTED_SIGNERS` names its signer, and rollback and stripped-signature detection are off.

**Bindings.** The Python and Node bindings load through `load_vault` like the CLI, on every call that reads the vault (Node's `add` and `describe` included), with no option to skip it, and update the pin exactly as the CLI's load does. A refusal (`MurkError::Trust`) or a failed integrity check (`MurkError::Integrity`) raises `murk.TrustError` (a `RuntimeError` subclass) in Python and throws an `Error` with `code` `'MURK_TRUST'` in Node, carrying the message the CLI prints. A grant key with no anchor, or reading a 2.x vault, is a trust refusal too. Warnings about an accepted vault (an unsigned vault loaded by a key that cannot sign, a legacy MAC, a pin that could not be written) are collected in `Murk::warnings`: the CLI prints each as `warn …`, the bindings expose them as `vault.warnings`.

**Header reads.** The MAC and the signature need a key, so a command that only reads the plaintext header checks nothing: anyone who can write the repo can drop an `expires_at` or `revoked_at`, or edit a description, and the command shows the edit as fact. `ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show` and `doctor` (its rotation check) never load the vault, so they keep working on one this machine has not trusted yet; run with no key (no `MURK_KEY`, no `MURK_KEY_FILE`, no stored key for the vault), each prints `warn unverified header — read without a key, so nothing here is integrity-checked` to stderr, once, in human and `--json` mode alike. A run that has a key is not labelled, but is not checked either: these commands do not load the vault with it. `murk rotate --list`, whose exit status gates scripts, is the one that verifies: see its entry.

**Deliberate revert.** Restore the older file, run `murk trust` (it shows the counter going back), then any write: the save is numbered above everything this machine accepted, so teammates accept it as newer.

**Upgrading from 0.13.** Every teammate needs 0.14 (a 0.14 save writes a 3.0 vault with signed view 2, which 0.13 refuses as written by a newer murk). On each machine the first load is refused once with the current signer and its fingerprint shown; review `git log -p -- .murk` and `murk diff`, then run `murk trust`. The first 0.14 save adds `generation` and a `vault_id` derived from the vault's `created` and `vault_name` (`sha256("murk.vault_id.v1\0" ‖ created ‖ "\0" ‖ vault_name)`, first 16 bytes), so teammates who upgrade separately, or on different branches, agree on it; from then on this machine refuses the view-1-signed revisions, and the merge driver refuses a 0.13-era branch that changed the vault (review it on that branch and re-sign it there with `murk trust`, or redo its change after merging). CI needs `MURK_TRUSTED_SIGNERS` in the entry format above.

### Agent grants

An agent grant is never a recipient of the meta, which holds the MAC key, every name, group, grant and signer. It gets two things only:

- the `scoped` copies of the keys in its scope, encrypted to its pubkey, and
- its own record: `agents[<grant pubkey>]`, an age blob encrypted to its pubkey alone, holding `{"name": "<grant name>", "grant": {pubkey, scope, issued_at, expires_at, issuer}}` (the same fields as its `meta.grants` entry, and nothing else). murk rewrites the blob when the grant record changes and drops it with the grant.

A grant cannot check the MAC, so it trusts a vault only by its signature, against signers named outside the vault: its key file's **anchor**. When `murk agent grant` (or `agent init`, `agent connect`, `--renew`) writes a key file, it puts one line per trusted signer above the key, in the trusted-signer entry format (see Trust):

```
# murk-trusted-signer: age1…:<base64 verifying key>
# murk-trusted-signer: ssh-ed25519 AAAA…
AGE-SECRET-KEY-1…
```

The lines list this machine's pinned trusted signers for the vault plus the minting key; grant keys are never among them. age ignores `#` lines, so the file is still a valid age identity file. Re-minting or renewing the grant rewrites the lines. `MURK_TRUSTED_SIGNERS` adds to the anchor.

A load whose key has an `agents` entry and cannot open the meta is a grant load, in this order, before anything is handed out:

1. **Anchor.** The key-file lines plus `MURK_TRUSTED_SIGNERS`. If both are empty, the load is refused: "this grant key names no trusted signers, so murk can't check the vault it reads: ask the operator to re-mint the grant (`murk agent grant --renew`), or set MURK_TRUSTED_SIGNERS". A key file from before 0.14 gets this message.
2. **Signature.** The top-level view-2 `sig` must be by a signer in the anchor and verify under the anchor's key for it (the `ssh-ed25519` line for SSH signers). Nothing inside the vault, the `signers` registry included, is read for this. An unsigned vault, a signer not in the anchor and a signature that doesn't verify are each refused.
3. **Record.** The grant's own `agents` blob is decrypted and its TTL checked; an expired grant fails closed.
4. **Values.** Only then are its `scoped` values decrypted.

A grant load reads and writes no trust pin, so it has no rollback check. Every write by a grant is refused ("agent grants are read-only"). A key that can open the meta always loads as an operator, even with an `agents` entry. A 2.x vault still encrypted its meta to grants: a grant key reading one is refused until the operator saves it with 0.14 or later and re-mints the grant.

---

## Commands

### `murk init [--vault NAME]`

Interactive setup. Prompts for a display name. Then:

1. Generates an age keypair via BIP39 (24-word mnemonic encodes the key directly)
2. Writes the secret key to `~/.config/murk/keys/<vault-hash>` with mode 0600
3. Writes `export MURK_KEY_FILE=<path>` to `.env` (creates if missing, warns if key already present)
4. Creates the `.murk` vault with user's pubkey as first recipient, a fresh `vault_id` and `generation` 1, signed by the new key, and records it in the local trust pin with the creator as its trusted signer
5. Prints BIP39 24-word recovery phrase to stderr

---

### `murk add KEY [--group NAME] [--desc DESC] [--tag TAG] [--vault NAME]`

Adds or updates a secret. Prompts for the value interactively (hidden input via rpassword) or reads it from stdin when piped. Piped input is the whole of stdin with one trailing newline removed, so a multi-line value such as a PEM key arrives intact (`cat key.pem | murk add TLS_KEY`).

`--group` selects who can read it: `everyone` (the shared/murk layer), `me` (only your key; the private/mote layer), or a named group (encrypted to that group's members; you must be a member). Assigning a secret to a named group makes that group its sole base tier — any existing shared value is dropped. When an explicit `--group` moves an existing key to a different tier, murk reports the move. `--scoped` is a deprecated alias for `--group me`.

Without `--group`, an existing key keeps its tier, so an update never widens who can read it: a shared value stays shared, a group value stays in its group (encrypted to the group's current members), and a key that has only your `me` override gets a new override value. Only a new key defaults to `everyone`; a key whose only values are other recipients' `me` overrides is refused until you choose a tier with `--group`. If a group you are not a member of holds the key, murk refuses the write (only `--group me` can add your own override); a member of that group must update it.

Key names are validated as shell identifiers. Invalid names are rejected. A name that `export`/`exec` treat as reserved (see `murk export`) is accepted with a warning.

---

### `murk generate KEY [--length N] [--hex] [--group NAME] [--desc DESC] [--tag TAG] [--vault NAME]`

Generates a cryptographically random value and stores it. Default length is 32 bytes, output as URL-safe base64 (no padding). Use `--hex` for hexadecimal output. `--group` works as for `murk add`. Uses the same RNG as key generation.

---

### `murk rotate KEY [--generate] [--length N] [--hex] [--values-from FILE] [--vault NAME]`

Replaces a secret value. Prompts for the new value interactively, or generates a random one with `--generate`. Use after revoking a recipient to ensure they can no longer use the old value.

Rotation keeps each value in its tier and never widens who can read it: a shared value stays shared, a group value stays in its group (encrypted to the group's current members), and a key held only as your personal override stays your override. A personal override on top of a shared or group value is left unchanged. A key held by a group you are not a member of can't be rotated by you: `rotate KEY` refuses it, and `--all` skips it with a warning. The same goes for a key that holds only other recipients' overrides. Other recipients' overrides are never touched.

`murk rotate --all` rotates every secret in the vault, prompting for each in sequence. `--generate` is not allowed with `--all` — external credentials (database passwords, API keys from third-party services) require manual rotation at the source.

Piped stdin works the same way when the batch takes one value (e.g. `murk rotate KEY`): all of stdin is the value. A batch of several values reads one value per line, matched to keys by position, so values can't span lines; input with more lines than values is refused before anything is written. If anything would be skipped, or a key would take more than one value, the batch is refused before any value is read, since later values would land on the wrong keys. `--values-from FILE` (`-` for stdin) matches values by name instead. It reads the file with the same `.env` parsing as `murk import`: `KEY=value` lines, with an optional `export` prefix and single- or double-quoted values that may span lines. An unclosed quote or other parse error aborts with nothing rotated, and so does a file that names a key more than once. Skipped entries (invalid or `MURK_*` names, lines without `=`) and unquoted values containing ` #` are reported by line number, never by value. Every key it names must be one this command can rotate, with exactly one value to replace; otherwise the whole batch is refused before anything is written, naming the keys. Keys it doesn't name are left unrotated and reported. `--values-from` can't be combined with `--generate`. A values file that is a symlink is refused, and one readable by others gets a warning; `--values-from -` keeps the new values off disk.

`murk rotate --list` reports the keys that need rotating — the same overdue/expiry/post-revoke signals `doctor` evaluates, scoped to rotation. Human output exits 1 when anything needs rotating (usable as a script gate); `--list --json` always exits 0 for a clean or flagged vault.

A gate must not be passable by editing the header, so the result is verified whenever it can be. **With a key** the vault loads through the full load path first (MAC, signature, this machine's trust verdict; `into_trusted` also records the pin like any load), and the report comes from the verified vault. Deleting `revoked_at` or `expires_at` from the header then fails the command (non-zero, no report) instead of reporting that no keys need rotating, and so does a vault this machine does not trust or a key that cannot open it; it never falls back to an unchecked read. **With no key** nothing can be checked: it reads the schema as written, prints the unverified warning (see Trust, Header reads), and under `MURK_STRICT` (or agent context) refuses the result by exiting 1 — in human mode instead of `ok`, in `--json` mode after printing it.

`--json` prints an object, `{"verified": bool, "issues": [...]}`. `issues` is the `reason`-tagged array (`overdue`, `no_baseline`, `expired`, `expiring_soon`, `revoke_pending`) that `--json` printed alone before 0.14; `verified` is `true` when a key verified the vault and `false` otherwise. The array moved under a key because the flag has to be present when no key needs rotating, and an empty array has no element to carry it: `[]` is exactly what a header stripped of its flags produces. Consumers that iterated the old top-level array read `.issues` instead.

---

### `murk rm KEY [--vault NAME]`

Removes a key from the vault (shared value, schema entry, and all private entries). No confirmation prompt — git is your safety net. Refused when the key has a value in a group you are not a member of, or holds only other recipients' personal overrides: those values would stay in the vault, so only their owners can remove them.

---

### `murk get KEY [--vault NAME]`

Prints a single decrypted value to stdout. Scoped values take priority over shared values. Exits with code 1 if key not found.

---

### `murk ls [--tag TAG] [--json] [--vault NAME]`

Lists key names, one per line. `--tag` filters by tag (repeatable). `--json` outputs JSON.

---

### `murk describe KEY "description" [--example EX] [--tag T]... [--rotate-every DAYS] [--expires DATE] [--vault NAME]`

Sets metadata for a key in the plaintext schema. Does not touch encrypted values. Refused for a key held by a group you are not a member of, since its tags and policy belong to that group's members.

`--rotate-every` takes a day count (`90` or `90d`) and `--expires` takes a date (`2026-09-01`) or RFC-3339 timestamp; pass `never` to either to clear it. Both are sticky — a later `describe` that omits the flag leaves the existing value untouched. `doctor` reports keys that are overdue for rotation or past/near their expiry.

---

### `murk edit [KEY] [--scoped] [--group NAME] [--vault NAME]`

Opens secrets in `$EDITOR`. With KEY, edits a single value; without, edits all secrets as `KEY=VALUE` lines. With `--scoped`, edits private overrides (motes) instead of shared values; with `--group NAME`, edits the values for that named group (you must be a member). An edited value stays in the tier you edited it in. If a group you are not a member of also holds the key, murk refuses to change its shared or group value, as `murk add` does. A new line for a key that is in a different tier is written as `murk add` writes it: without a tier flag, the key keeps its tier; with a tier flag, the key moves to that tier.

The plaintext buffer is written to a mode-0600 temp file (preferring `XDG_RUNTIME_DIR`), then overwritten with zeros and deleted after the editor exits. An empty value or non-zero editor exit aborts without saving.

The overwrite-and-delete is best-effort — it can't undo a write to a journaled or copy-on-write disk, and editors leave their own swap files behind. When `MURK_STRICT` is set, `edit` requires the temp file to live on a RAM-backed filesystem (tmpfs/ramfs) and aborts before launching the editor otherwise, so the secret never reaches persistent storage. Default systems without a RAM-backed temp dir (e.g. macOS) keep the best-effort behavior; use `add`/`rotate`/`import` from stdin to avoid the editor entirely.

---

### `murk export [--tag TAG] [--json] [--vault NAME]`

Prints all secrets as `export KEY=VALUE` statements to stdout. Scoped values override shared values for the current identity. Errors go to stderr. `--tag` filters by tag (repeatable). `--json` outputs JSON instead of shell exports; both forms skip keys that are not valid shell identifiers.

**Reserved names.** A key named like a variable that changes how a program, its loader, its shell, git or murk runs is refused — the whole export fails before anything is printed — unless `--allow-reserved` is passed: `PATH`, `HOME`, `IFS`, `SHELL`, `ENV`, `BASH_ENV`, `ZDOTDIR`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `PS0`–`PS4`, `PROMPT_COMMAND`, `XDG_CONFIG_HOME`, `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `BROWSER`, `SSH_ASKPASS`, `SUDO_ASKPASS`, `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `CLASSPATH`, `GCONV_PATH`, `GLIBC_TUNABLES`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `GOFLAGS`, `MAVEN_OPTS`, `GRADLE_OPTS`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`; every name starting with `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `_JAVA_`, `JDK_`, `DOTNET_`, `CARGO_`, `RUSTC`, `SSL_`, `PIP_`, `GEM_`, `BUNDLE_`, `NPM_CONFIG_` or `MURK_`; and every name ending in `_PROXY` (all compared case-insensitively; `NODE_ENV` is not reserved). Whoever can write the vault must not get to run code in the shell that evaluates it, redirect its traffic, or switch off murk's own settings there. `exec`, `agent exec` and the MCP `murk_exec` tool apply the same list; `murk_exec` has no override.

When `MURK_STRICT` is set, `export` refuses to run if stdout is a regular file (e.g. `murk export > .env`), since that persists plaintext secrets to disk; piping to a process (the direnv flow) and printing to a terminal are still allowed. `get` and `diff --show-values` are guarded the same way. This is a guardrail against accidental redirects, not an airtight control — an explicit `murk export | tee .env` still writes the file.

Primary usage via direnv:

```bash
# .envrc
eval "$(murk export)"
```

---

### `murk exec [--only KEY] [--tag TAG] [--clean-env] COMMAND...`

Runs a command with decrypted secrets injected as environment variables. Scoped values override shared values. `--only` injects only the named keys (repeatable), `--tag` filters by tag, `--clean-env` strips the inherited environment so the child sees only murk secrets plus a minimal base. Reserved names (see `murk export`) are refused unless `--allow-reserved` is passed. On Unix, murk replaces itself with the command via `exec`.

---

### `murk env [--vault NAME]`

Writes a `.envrc` for direnv integration. Creates the file if missing, appends the murk export line if absent, and leaves it untouched when already present.

---

### `murk agent plan [--tag TAG] [--json] [-o FILE] [--vault NAME]`

Emits schema-only context safe to paste into an AI agent prompt — key names, descriptions, examples, and tags. No decryption and no `MURK_KEY` required; the output contains no secret values, recipient pubkeys, vault name, or meta blob. `--tag` filters by tag (repeatable). `--json` outputs JSON. Prints to stdout, or writes to a file with `-o`. Without a key the schema is unchecked and the command says so on stderr (see Trust, Header reads).

---

### `murk agent exec --only KEY [--allow-operator-key] [--vault NAME] COMMAND...`

`murk exec` with strict agent-safe defaults: clears the inherited environment, strips `MURK_KEY` so the child process cannot read the vault, and requires explicit `--only` keys (repeatable). Agent mode fails closed — there is no inject-everything path.

The key must be handed over explicitly via `MURK_KEY` or `MURK_KEY_FILE` (normally a grant key). An auto-discovered key from `~/.config/murk/keys` is refused before the vault is loaded, unless `--allow-operator-key` is passed; that flag prints a warning on every run.

The child runs supervised, not `exec`-ed: its stdout and stderr are pipes, and every injected value of 4 bytes or more is replaced with `***KEY***` before it is written out. murk forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to it by another process, and exits with the child's code or re-raises its terminating signal. See `docs/ai-agents.md`.

---

### `murk agent grant --name NAME --only KEY [--ttl DUR] [--renew] [--out PATH [--force]] [--vault NAME]`

Mints a fresh ephemeral age identity and gives it read access to exactly the `--only` keys (repeatable, required) — never the operator's own key. The agent becomes a vault recipient and gets a private (per-recipient) ciphertext of each `--only` key's shared value and its own record in `agents`; it is excluded from the `everyone` layer and is not a recipient of the meta. Records grant metadata (scope, TTL, issuer) in the encrypted meta. A live grant name is refused unless `--renew` is passed, which revokes the existing key and mints the replacement in one vault write. `--ttl` accepts `30m`/`2h`/`7d` (default `2h`), at most `365d`; a longer TTL is refused. Reads fail closed after expiry, though the enforcement is binary-level, not cryptographic (see THREAT_MODEL.md). The agent key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, or `--out -` to stream it to stdout), always owner-only (`0600`): it is written to a temporary file beside the destination and renamed into place only after the vault is saved, so a failed save leaves an existing key file untouched. `--out PATH` refuses a file that already exists — it may be the operator's own key — unless `--force` is passed, and refuses before the vault changes; the default path is murk's own slot for the grant and is replaced on renewal. The key file is headed by `# murk-trusted-signer:` lines (see Agent grants). Run the agent with `MURK_KEY_FILE` pointing at that key and `MURK_STRICT=1` so it can't fall back to the operator's stored key.

---

### `murk agent ls [--json] [--vault NAME]`

Lists active grants: name, truncated pubkey, scope, and TTL status (time remaining, or how long expired). Works offline. `--json` outputs structured data including an `expired` flag.

---

### `murk agent revoke NAME [--rotate] [--values-from FILE] [--vault NAME]`

Removes the grant and its ephemeral recipient (clearing the agent's private ciphertexts). Because the handed-off key can still decrypt old `.murk` versions from git history, every key it could read — its scope, any key holding a private copy for it, and keys in groups it belonged to — is marked as owing a rotation (`revoked_at`) if it still has a shared value or a value in one of those groups, as with `circle revoke`; `agent grant --renew` marks the previous key's keys the same way. Rotation is the real close: `--rotate` (or the interactive prompt) re-prompts for a new value for each of those keys, in its own tier. The revoke and the rotated values are written together in one save, so a refused, short, or aborted batch writes nothing and the grant is not revoked either; the error says how to revoke now and rotate afterwards. `--values-from FILE` supplies the values by name, as for `murk rotate`.

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

Imports secrets from a `.env` file. Parses `KEY=VALUE` lines (supports `export` prefix, single/double quotes). Skips `MURK_*` keys with a warning. Invalid key names are skipped with a warning. If keys already exist, murk refuses the import unless you give `--force`. `--group` assigns all imported secrets to a tier (`everyone`, `me`, or a named group), as for `murk add`. Without `--group`, each existing key keeps its tier and new keys are shared. If murk refuses any key (for example, a key that a group you are not a member of holds), it imports nothing.

---

### `murk info [--tag TAG] [--json] [--vault NAME]`

Prints the public schema. Works without `MURK_KEY`. With a valid key, also shows recipient names and count. `--tag` filters by tag (repeatable). `--json` outputs JSON.

Each key's row shows any rotation interval and expiry as a trailing `rotate 90d  expires 2026-09-01` segment (public, shown without a key); `--json` includes `rotation_interval_days` and `expires_at` per entry. `murk doctor` evaluates these against the clock — `info` just shows the policy. Without a key none of it is integrity-checked, and `info` says so on stderr (see Trust, Header reads).

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

With `--member`, removes a recipient from the group and re-encrypts its secrets so the removed member loses access to current values. Git history stays readable, so each of the group's secrets is marked as owing a rotation (`revoked_at`) and listed; `murk rotate --list` and `doctor` flag them until they are rotated. Without `--member`, deletes the group entirely; refused if any secret is still assigned to it. You must be a member to modify or delete a group.

---

### `murk policy show [--json] [--vault NAME]`

Prints the agent access policy. Works without a key — the policy is in the plaintext header — but without one it is unchecked, and the command says so on stderr (see Trust, Header reads). Shows the allowed tags, or notes that agent mode is unrestricted (no policy) or locked out (empty allow-list).

---

### `murk policy set --allow-tag TAG... [--vault NAME]`

Sets the agent allow-list: in agent mode (`agent exec`, `agent grant`) a secret may be injected or granted only if it carries one of these tags. `--allow-tag` is repeatable and required. Default-deny once set. Writes the policy into the header, where the MAC and signature cover it.

---

### `murk policy clear [--vault NAME]`

Removes the policy. Agent mode becomes unrestricted again.

---

### `murk circle revoke RECIPIENT [--rotate] [--values-from FILE] [--vault NAME]`

Removes a recipient by pubkey or display name. Re-encrypts all shared secrets without their key. Removes their private entries.

Lists the secrets the revoked recipient had access to. With `--rotate`, prompts for a new value for each value they could read, in the same session, and re-encrypts it in its own tier: the shared value stays shared, and a value in a group they belonged to stays in that group, encrypted to its remaining members. Values they could not read (other groups, your personal overrides) are not prompted for. A group value the revoked recipient could read but you can't (you are not in that group) can't be re-encrypted by you: its current ciphertext still opens with their key until a member of that group rotates it. The revoke says so, and the key keeps its pending-rotation marker. A key they reached only through their own personal override is not marked, since nothing of it is left to rotate. The revoke and the rotated values are written together in one save, so input that is refused, runs short, or is aborted writes nothing and the recipient is not revoked either; the error says how to revoke now (`murk circle revoke RECIPIENT` without `--rotate`) and rotate afterwards (`murk rotate --all --values-from FILE`). Piped values and `--values-from FILE` follow the rules of `murk rotate`. Keys `--values-from` doesn't name stay marked, and `murk rotate --list` keeps listing them. Without the flag on an interactive terminal, offers to rotate; otherwise prints a hint. The recipient can still decrypt previous versions from git history, so rotation is the only way to close the exposure.

---

### `murk diff [REF] [--show-values] [--json] [--vault NAME]`

Shows which secrets changed between the current vault and a git ref (defaults to `HEAD`), and what changed in who can read or sign it: recipients added or removed, a changed signer, a changed signing key for a recipient, the policy, agent grants and group members. `--show-values` prints the actual values, not just key names. Structural lines come before value lines, and every warning goes to stderr before either. Every vault-supplied string (key and group names, display names, grant names, values) is escaped before it reaches the terminal.

`--json` prints one object, `{"secrets": [...], "changes": [...]}`; both arrays are always present. Each `secrets` entry has `key` and `kind` (`added`, `removed`, `changed`), plus `old_value` and `new_value` only with `--show-values`; entries are sorted by key. Each `changes` entry has `kind` and `op` (`added`, `removed`, `changed`) and never carries a secret value:

| `kind` | Fields |
|--------|--------|
| `recipient` | `key`, `name` |
| `signer` | `from`, `to` (public keys; `null` for unsigned) |
| `signing_key` | `key`, `name`, `to` (the new verifying key's `SHA256:` fingerprint) |
| `policy` | none |
| `grant` | `name`, `key` (`null` when removed) |
| `group_member` | `group`, `key`, `name` |

JSON strings are exact (JSON escapes control characters); escaping for the terminal applies only to the human output.

`diff` runs on a working vault this machine does not trust yet — it is the review step before `murk trust` — and says so on stderr; it still fails on a broken MAC or signature. The vault at the ref is verified before anything in it is decrypted: its MAC and signature as a load checks them, then its signer against the local trust pin, which is read and never extended. The signer must be one this machine ever trusted, with its pinned verifying key, so a teammate revoked since still verifies for the revisions they signed. When this machine has a trust pin for the vault or `MURK_TRUSTED_SIGNERS` is set, `diff` exits non-zero rather than show a revision that is refused, that fails verification, or that your key cannot decrypt. With neither, the revision is shown under the same "not trusted on this machine" warning as the working vault. An unsigned revision written by a key that cannot sign, or from before 0.14 (no vault id), is shown with a warning that its integrity rests on git. Under `MURK_STRICT` both warning cases are refused instead.

`diff` also exits non-zero when the ref does not name a commit or git fails. The vault path is resolved inside the repository that holds it, so `diff` works from a subdirectory. Only a vault that git shows is absent from the ref (or a repository with no commits yet) counts as empty, and then every secret shows as added. A ref that starts with `-` is refused, so it can never reach git as an option.

---

### `murk merge-driver ANCESTOR OURS THEIRS [PATH]`

Git merge driver for `.murk` files. Merges non-conflicting secret changes automatically. With a key it checks both sides against the trust pin of `PATH` (git's `%P`, default `.murk`), refuses an untrusted side as a conflict, and signs the merged result. See Signatures.

---

### `murk setup-merge-driver`

Configures git to use `murk merge-driver %O %A %B %P` for `.murk` files via `.gitattributes` and `.git/config`.

---

### `murk verify [--vault NAME]`

Verifies vault integrity (MAC and signature), reports whether this machine trusts the signer and why not (the same reasons a load refuses with), checks who signed the last git commit that touched the vault, and runs safety checks without exporting secrets. Exits 1 on any finding.

**Commit check.** Only when the vault has git history. A signed commit proves nothing about who the signer is: git vouches for any key it is told about, an attacker's throwaway key included. So verify reports the commit as ok only when git verified the signature and the signing key is a trusted signer of this vault: an ssh-ed25519 key in the set the Trust rules used (`MURK_TRUSTED_SIGNERS` and a grant key file's anchor when either is given, otherwise the pin's trusted set; grant keys never count), matched by its `ssh-keygen -l` fingerprint. Only an ssh-ed25519 key can match, because it is the only key type that both signs git commits and is a murk signer. The line then reads `ok commit  last .murk commit signed by <name> with key <fingerprint>, a trusted signer of this vault`. Every other outcome is a finding, and exits 1:

- **Signed by another key** — a gpg key, or an ssh key that is not a trusted signer: `signed by key <id>, which is not a trusted signer of this vault`, naming the recipient when the key is one. The vault's own recipients are not trusted by being listed; trust comes from the pin or the environment.
- **Not vouched for by git** — the signature could not be checked, has expired, or was made with an expired key.
- **Bad** — the signature does not match the commit, or the key is revoked in the user's `gpg.ssh.revocationFile`.
- **Unsigned.**

verify runs git with `gpg.ssh.allowedSignersFile` set to a temporary file listing the trusted ssh-ed25519 signers, so the result does not depend on the user's own allowed-signers list; without one git cannot check an ssh signature and reports a signed commit as unsigned.

---

### `murk trust [--yes | --print-key] [--re-add KEY]... [--vault NAME]`

Shows who signed the vault (name, full key and signing-key fingerprint, marked trust on first use when this machine has not confirmed it), its id and counter, and every recipient with its fingerprint and its change since this machine last trusted the vault, then asks before recording it in the local trust pin. `--yes` accepts without asking; without a terminal and without `--yes` it only shows and exits 1. An unsigned or stripped vault is re-signed with your key. Refuses a vault signed by an agent grant, with a changed signing key or with a generation past the limit, and refuses to run with a grant key. A vault signed by or listing a key this machine recorded as removed is trusted only when `--re-add` names each such key (its public key or its name in the vault). `--print-key` prints your own trusted-signer entry to stdout (`age1…:<verifying key>`, or the ssh-ed25519 key line) and your fingerprint to stderr, then exits. See Trust.

---

### `murk doctor [--vault NAME]`

Checks the surrounding repo for hygiene issues — inline keys in `.env`, key files sitting next to the vault, state that would be bad to commit. If a vault is present it also reads the plaintext schema and reports keys overdue for rotation or past/near their `expires_at`. That read is never integrity-checked: with no key `doctor` says so on stderr (see Trust, Header reads), and with one it still does not load the vault, so use `murk rotate --list` or `murk verify` where the result must be trusted. Exits 1 on findings.

---

### `murk skeleton [-o FILE] [--vault NAME]`

Exports a schema-only copy of the vault — key names, descriptions, examples, and tags, with no secrets and no recipients. Prints to stdout, or writes to a file with `-o`.

---

### `murk scan [PATHS]... [--vault NAME]`

Scans files for leaked secret values. Decrypts the vault and searches text files under the given paths (defaults to the current directory) for value substrings. Skips hidden directories, `target/`, `node_modules/`, lockfiles, vault files, and binary files; values shorter than 8 characters are skipped to avoid false positives. Exits 1 if any leak is found. A given path that doesn't exist or can't be read exits 2 before scanning. A file or directory under it that can't be read is reported, and the scan exits 1 as incomplete instead of reporting no leaks.

---

### `murk completion generate|install SHELL`

Prints shell completions to stdout (`generate`) or installs them to the shell's standard completion path (`install`). Supports bash, zsh, fish, elvish, and powershell.

---

## Security Model

**What murk protects against:**

- Repo leaks — `.murk` is safe to commit, useless without a private key
- Accidental secret exposure — `.env` is never committed if `.gitignore` is set correctly
- Private overrides — private secrets (motes) are encrypted only to their owner
- A repo-writer replacing the vault — an unsigned vault, one signed by a key they listed as a recipient, an older revision, another vault's file — is refused unless its signer is trusted on this machine (see Trust)

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
