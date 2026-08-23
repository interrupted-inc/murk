# Threat Model

This document describes murk's security properties and limitations. It is intended for security leads evaluating murk for team use.

murk is pre-1.0 and has not been independently audited. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## What murk protects

**Secrets at rest in git.** The `.murk` file is designed to be committed. Secret values are individually encrypted with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). An attacker with read access to the repository cannot decrypt values without a recipient's private key.

**Secrets in transit via git.** Since values are encrypted before they enter git, pushing/pulling over any transport (HTTPS, SSH, unencrypted) does not expose secret values.

**Cross-value integrity (tamper-evidence).** A BLAKE3 keyed MAC inside the encrypted meta blob covers all key names, encrypted values, and recipient public keys, binding the independent age ciphertexts together. It is mandatory whenever the vault contains secrets and detects accidental corruption and naive tampering. For a vault with no signature — a team entirely on ssh-rsa or hardware/plugin keys, which cannot sign — the MAC is the only tamper-evidence murk itself provides (git remains the anchor).

The MAC is **not** by itself a defense against a deliberate attacker with write access to the repo. Its key lives in the meta blob, and age encryption needs only the recipients' *public* keys — which are in the plaintext header — so anyone who can write the file can mint a fresh MAC key, recompute a valid MAC over tampered content, and re-encrypt the meta blob. age provides confidentiality, not authentication of *who* produced a ciphertext.

**Authorship integrity (signatures).** To close that gap, murk signs the vault with an Ed25519 key derived from the writer's age key (see [Vault signatures](#vault-signatures) below). A signature can only be produced by a holder of a recipient's private key, so an outsider cannot forge one. This is the mechanism that makes tampering by a repo-writer detectable; the MAC remains as a fast corruption check. Together with signed git commits, git is the integrity anchor.

**Per-recipient secrets.** Private secrets (motes) are encrypted to a single recipient's public key. Other authorized recipients cannot decrypt them.

## What murk does not protect

**Compromised machines.** If an attacker has access to a machine where the secret key is present (`~/.config/murk/keys/`, in memory, or in environment variables), they can decrypt all shared secrets and any private secrets belonging to that key.

**Key names are public.** The `.murk` header stores key names, descriptions, and examples in plaintext. An attacker with repo access knows you have `STRIPE_SECRET_KEY`, `DATABASE_URL`, etc. This is a design trade-off that enables `murk info` to work without a key and keeps git diffs readable. If your threat model requires hiding what services you use, murk does not address this.

**In-memory secret exposure.** Decrypted secret values are wrapped in `zeroize::Zeroizing<String>` so that plaintext is wiped from memory when the wrapper is dropped. The secret key itself uses age's `SecretString`, which also zeroizes on drop. Zeroization is best-effort: transient buffers inside the age decryption path, the shell-escape output used by `murk export`, `serde_json` serialization, and OS-level copies (stdout, child process environments, swap, core dumps) can still retain plaintext that murk cannot reach. If your threat model includes swap forensics or memory dumps of live processes, treat decrypted values as recoverable.

**Historical access after revocation.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions remain in git history. The revoked recipient can still decrypt any version they previously had access to. Always rotate credentials after revocation. murk warns about this at revocation time.

**Fine-grained access control.** All authorized recipients can decrypt all *shared* secrets — anything in the `everyone` layer is readable by every recipient. Named recipient groups narrow this: a secret assigned to a group is age-encrypted only to that group's members, so a leaked member key can read only the groups it belongs to (plus the shared layer), not the whole vault. This is enforced cryptographically by age, and group membership is covered by the keyed MAC (`blake3v4:`) so it can't be altered undetected. Limits: group *names* and which key belongs to which group are plaintext in the header (only membership is hidden, in the encrypted meta); managing a group requires being a member of it (you can't re-encrypt what you can't read); and the historical-access caveat above applies per group — removing a member re-encrypts going forward, but old `.murk` versions in git remain readable, so rotate.

**Agent grants.** `murk agent grant` mints an ephemeral age identity and gives it read access to a fixed set of keys (`--only`) without ever exposing the operator's own key. The agent is a recipient of the encrypted meta blob — so it can verify integrity and read group/grant state — but is deliberately excluded from the `everyone` layer: it can decrypt only the private values granted to it, enforced cryptographically by age. Grant metadata (scope, TTL, issuer) lives in the encrypted meta and is covered by the keyed MAC (`blake3v5:`) so it can't be altered undetected. Limits to understand: (1) the agent *can* read the meta blob, so it learns recipient display names, group membership, and other grants' metadata — it learns the org structure, though no other secret *values*; (2) the TTL is enforced at read time, not cryptographically — murk refuses an expired grant at every entry point (CLI, MCP, bindings), but age keys cannot self-destruct and old `.murk` versions stay readable in git, so a leaked grant key works against history with raw age until `agent revoke` + rotate (`agent ls` flags expired grants); (3) the ephemeral key is a bearer credential — whoever holds the key file has the access. Real containment requires OS-level isolation: an agent running as the same user with read access to your home directory can read `~/.config/murk/keys` directly and bypass murk entirely, so run agents in a sandbox, container, or under a separate user. `MURK_STRICT` disables key auto-discovery so a granted agent cannot silently fall back to the operator's stored key, and `murk agent exec` (which injects secret *values* into a child process and hands the agent no key at all) is the safest pattern where it fits.

**Agent access policy.** `murk policy set --allow-tag TAG` records a tag allow-list in the plaintext header (MAC-covered, so it can't be stripped or weakened without a key). In agent mode (`agent exec`, `agent grant`) a secret may be injected or granted only if it carries an allowed tag; anything else is refused, with no override flag. This is explicitly NOT access control — it is a machine-enforceable guardrail. Its scope and limits: it constrains the *murk binary*, so it does nothing against a human insider using age directly or an older murk that predates the policy MAC version; it gates what reaches agents, not what recipients can decrypt; and it travels with the repo so the same constraint applies in CI. The value is keeping production secrets out of agent reach by accident or by a misbehaving agent that asks for them. Merging two branches that changed the policy differently raises a conflict rather than silently picking one side.

**Post-revoke rotation tracking.** Revoking a recipient re-encrypts going forward, but old `.murk` versions in git stay readable with the revoked key — so the exposed values must be rotated to actually cut access. When rotation is deferred at revoke time, murk stamps each exposed key with a `revoked_at` marker in the plaintext header; `doctor` flags it until a value write clears it, so the obligation survives the prompt being declined and is visible without a key. The marker is covered by the keyed MAC (`blake3v7:`), so an attacker editing `.murk` can't silently clear the flag without a key. This is a hygiene reminder, not enforcement: it does not and cannot rotate the underlying credential at its provider, and the revoked key keeps working against git history until you do.

**Audit logging.** murk has no built-in audit trail beyond git history. It does not log who decrypted what or when. For regulated environments requiring provable access controls, use a dedicated secrets server.

**Admin-change accountability (agents and otherwise).** Every administrative change is a commit to the `.murk` file, so **git history is the admin audit trail**: creating or revoking an agent grant, setting or clearing a policy, authorizing or revoking a recipient, and rotating a value after an agent session all show up in `git log -p .murk` / `murk diff`, attributed to the commit author (and cryptographically signed if you use git commit signing). murk deliberately does **not** keep a second event log inside the vault: it would duplicate git, can drift from it, and — because the integrity MAC uses a key every recipient shares — any keyholder could forge entries, so it would be weaker than git on attribution, not stronger. What cannot be audited at all: secret *reads* on a developer's machine (murk can't see them), and any action taken with age directly or an old murk binary. Provable per-actor attribution beyond git's commit identity would require signed events, which needs a signing key murk's age identities don't have — deferred until a concrete requirement exists.

**Agent MCP server.** `murk mcp` exposes secrets to AI-agent harnesses over the Model Context Protocol on a local stdio pipe (not a network listener). It is bound by the same machinery as every other agent path: it refuses to start unless the loaded identity is a scoped grant with `MURK_AGENT=1`, so it can never serve the operator's full read scope, and `murk_plan`/`murk_get` are limited to the keys the grant may read and the agent policy allows, failing closed on anything else. `murk_exec` — running a command with scoped secrets injected — is off by default and enabled only with `--allow-exec`: `only` bounds the injected *secrets*, but the command itself runs as the server's user with its filesystem and network access, so it is a guardrail, not a sandbox. As with `agent exec`, the real containment boundary is the OS — run the server (and the agent) under a separate user or container.

## Vault signatures

murk signs the vault with an Ed25519 key so that tampering by someone with write access to the repo is detectable — the property the MAC alone cannot provide.

**How it works.** On save, a signing-capable writer signs a canonical serialization of the vault — recipients, all ciphertexts, schema, groups, grants, policy, github pins, and the signer registry. On load, murk verifies the signature and confirms the signer is a current recipient. A **present-but-invalid** signature fails the load as tampering; an **absent** signature is a warning (integrity then rests on git). Where the *verifying* key comes from depends on the key type:

- **age keys:** the signing key is derived from the age key via a domain-separated BLAKE3 KDF (so the BIP39 phrase recovers it too), but its verifying key cannot be recovered from the public age recipient. So the writer publishes it in a **signer registry** (`signers` in the encrypted meta), and verification looks it up there.
- **ssh-ed25519 keys:** the SSH key *is* an Ed25519 signing key, so murk signs with it directly. Its verifying key is already embedded in the `ssh-ed25519 …` recipient string, so the signature is **self-authenticating** — verified straight against the recipient, with no registry entry and no pin needed. This is the stronger form: there is no registry state an attacker could tamper with.

**Sign-when-capable.** age keys and ssh-ed25519 keys can sign. `ssh-rsa` and hardware/plugin identities cannot (age exposes no signing scalar for them), so their saves are written unsigned. A team entirely on hardware keys gets no signatures and relies on git; a mixed team is signed whenever a signing-capable holder last wrote.

**What signatures prevent.** An outsider (non-recipient) with repo write access cannot forge a signature — they hold no recipient private key. So injecting or swapping a ciphertext and re-MACing it (the attack the MAC does not stop) now fails signature verification on the next load.

**Signer-registry pinning (TOFU).** The age signer registry (pubkey → verifying key) lives in the encrypted meta, which a repo-writer can re-encrypt — so on its own a signature verified against that registry is forgeable (register your own key under a recipient's pubkey, sign with it). To close this, murk pins each pubkey → verifying-key mapping locally on first sight (`~/.config/murk/signer-pins/`) and **enforces it in the trusted load path**: a *changed* verifying key for an already-pinned pubkey is never legitimate (the mapping is a fixed derivation), so the load **fails hard** — in the library, so the CLI and the Python/Node bindings are all covered. New pubkeys are trust-on-first-use: on a fresh clone with no prior pin, an age signer's key is whatever the file says, so the signature is *not* authenticated authorship yet — an attacker who tampered before your first load would be pinned as legitimate. murk does not present this as verified: `load` marks such a signature unanchored and `murk verify` reports it as trust-on-first-use, pointing you at signed git commits (the real anchor for a first load) or an ssh-ed25519 key. Once pinned, any later key change is caught. The pin is local and does not travel with the repo; `MURK_NO_SIGNER_PIN=1` disables the check. **ssh-ed25519 signers need no pin** — their verifying key comes from the recipient string itself, so they are self-authenticating and anchored even on a first clone.

**Limits.** (1) A **malicious recipient** can always sign — they hold a valid key. Signatures make tampering *attributable* (which recipient last signed), not impossible, exactly like signed git commits; the malicious-recipient boundary is unchanged. (2) An attacker can **strip** the signature and re-MAC, producing an unsigned vault. That is not silently accepted — it loads with an "unsigned" warning, and if the vault was signed in git history the unsigned commit is visible — but the signature alone does not *block* it. Git commit signing is the anchor against strip/downgrade. (3) An attacker who can **add themselves as a recipient** can sign as that new recipient — but the recipient list is plaintext in the header, so the addition is visible in `git diff` and (on a shared branch) conflicts under the merge driver. (4) Signature verification requires decrypting the meta, so it is a recipient-only check, like the MAC.

## Trust boundaries

```
┌─────────────────────────────────────┐
│         Developer machine           │
│                                     │
│  ~/.config/murk/keys/ ── secret key  │  ← Trust boundary: local machine
│  MURK_KEY in memory ── during ops   │
│                                     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│          Git repository             │
│                                     │
│  .murk file:                        │
│    Header (plaintext) ── key names, │  ← Public: anyone with repo access
│      descriptions, recipient keys   │
│    Values (encrypted) ── per-value  │  ← Protected: requires MURK_KEY
│      age ciphertexts                │
│    Meta (encrypted) ── MAC,         │  ← Protected: requires MURK_KEY
│      recipient names                │
│                                     │
└─────────────────────────────────────┘
```

**What crosses the boundary encrypted:** secret values, recipient display names, integrity MAC.

**What crosses the boundary in plaintext:** key names, key descriptions, example values, recipient public keys, vault metadata (version, creation date, repo URL).

## GitHub SSH key onboarding

`murk authorize github:username` fetches SSH public keys from `https://github.com/username.keys` without authentication. This introduces trust assumptions:

**You trust GitHub as a key directory.** The keys returned by GitHub are whatever the user has uploaded to their GitHub account. If an attacker compromises a GitHub account and adds their own SSH key, `murk authorize github:attacker` would grant them access to vault secrets.

**You trust that the GitHub username belongs to who you think it does.** There is no out-of-band verification. If you authorize `github:alice` you are trusting that the GitHub user "alice" is your teammate Alice. For most teams this is reasonable — you already trust teammates' GitHub accounts for code review and merge access.

**TOFU (Trust On First Use) pinning.** The first successful `murk authorize github:username` records the SHA-256 fingerprints of the fetched keys in the encrypted vault meta. Subsequent `authorize` calls against the same username refuse to proceed if any fingerprint has been added or removed upstream, unless `--force` is passed. This detects GitHub key rotation — whether benign (a teammate rotated their key) or malicious (an attacker added a key to a compromised GitHub account) — and surfaces the diff for a human to decide. The pin covers the full upstream key set, including `ssh-rsa` keys that murk will not authorize, so rotation is still detected even when no new recipient ends up in the vault.

**SSH keys in the vault are just longer pubkey strings.** The vault format is unchanged — `vault.recipients` stores `ssh-ed25519 AAAA...` strings alongside `age1...` strings. All existing integrity protections (MAC, per-value encryption) apply equally to SSH recipients.

**Acceptable risk profile:** For a team secrets tool, trusting GitHub as a key directory is a reasonable trade-off. You are already trusting your teammates with code access, CI credentials, and production deployments through the same GitHub accounts. The alternative (manual key exchange) has worse security properties in practice because teams resort to sharing keys over Slack or email.

## Merge driver

murk includes a git merge driver (`murk merge-driver`) that performs three-way merges on `.murk` vault files at the ciphertext level — without decryption.

**Trust assumptions:**
- The merge driver operates without a key. It cannot verify the MAC of any version. Integrity is verified on the next `load_vault` after merge.
- Recipient additions and removals on only one side produce a merge conflict. Both sides must agree on recipient changes for a clean merge.
- Secret additions from one side are accepted if the other side did not touch secrets. If both sides modified secrets (e.g. from a re-encryption after recipient change), all overlapping secrets conflict.
- Group membership lives in the encrypted meta, which the merge driver cannot read without a key. When a key is available it merges memberships (union, ours-wins, dropping non-recipients); without one it keeps `ours` meta. Either way, group definitions are covered by the `blake3v4:` MAC, so any inconsistency between merged group ciphertexts and membership is caught on the next `load_vault`.

**What the merge driver prevents:**
- Silent recipient removal (one-sided removal → conflict)
- Silent recipient injection (one-sided addition → conflict)
- Secret value conflicts from independent edits to the same key

**What the merge driver does not prevent:**
- An attacker with write access to a branch can add or replace ciphertext entries. Anyone can encrypt to the (public) recipient keys, so an injected value can be *readable*, not just noise — the MAC alone does not catch this, because a repo-writer can recompute it (see [Cross-value integrity](#what-murk-protects)). What catches it is the signature: **the merge driver leaves the merged vault unsigned.** It runs non-interactively and must not vouch for content a human has not reviewed, so it recomputes the MAC (needed to load at all) but does not sign. The next load reports the vault as unsigned; a keyholder re-signs it with any write command *after* reviewing `murk diff`. Until then, integrity rests on git.

**Recommendation:** Protect your main branch with required reviews and commit signing. The merge driver is a safety net for concurrent vault edits, not a substitute for branch protection. Review `murk diff` before re-signing a merged vault.

## Supply chain

**Binary distribution:** Release binaries are built in GitHub Actions, checksummed (SHA256SUMS), and signed with Sigstore build provenance attestation ([SLSA Level 2](https://slsa.dev)). Provenance is in [in-toto/SLSA v1](https://slsa.dev/provenance/v1) format, covering the release binaries and `SHA256SUMS`. The npm and PyPI packages carry their own provenance; crates.io has no attestation support yet — see [VERIFYING.md](VERIFYING.md) for per-channel details. Verify a binary with:

```bash
gh attestation verify murk-v*.tar.gz --owner interrupted-inc
```

**Install script:** `install.sh` downloads the binary archive and SHA256SUMS, then verifies the checksum before extracting. It does not execute downloaded code before verification.

**Dependencies:** murk depends on age (via the `age` crate) for all cryptography, plus standard Rust crates for CLI, serialization, and I/O. `cargo deny` checks for known advisories and license compliance in CI. All CI actions are pinned to full SHA commit hashes.

**Cargo.lock:** Committed and used for reproducible builds (`--locked` in release workflows).

## Key compromise scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| `MURK_KEY` leaked | Attacker can decrypt all shared secrets and the owner's private secrets | Revoke the compromised key, rotate all secrets, re-authorize with a new key |
| `.env` committed to git | Same as key leak, but the key is now in git history | Remove from history (`git filter-repo`), revoke, rotate |
| Recovery phrase exposed | Attacker can derive the secret key | Same as key leak |
| Repository made public | Key names and encrypted values exposed; values remain safe if keys are secure | Rotate secrets as a precaution if key names alone are sensitive |
| Recipient revoked | Revoked user retains access to historical versions in git | Rotate all secrets that the revoked user had access to |
| GitHub account compromised | Attacker could be authorized via `github:username` if the vault owner runs authorize after compromise. TOFU pinning detects subsequent key changes for an already-authorized user | Verify teammate identity before the first authorize; investigate the diff when `authorize github:user` reports pinned-key changes; revoke and rotate if compromise is suspected |
| SSH private key leaked | Attacker can decrypt all secrets the SSH key was a recipient for | Revoke the compromised SSH key from the vault, rotate secrets |

## Cryptographic properties

murk uses age for all encryption and decryption. It does not implement custom cryptographic primitives, but defines a vault format and BLAKE3 keyed integrity layer on top of age.

- **Encryption:** age v1 (X25519 key agreement, ChaCha20-Poly1305 payload encryption)
- **Per-value encryption:** each secret value is encrypted independently with a fresh age file key
- **Recipient types:** age x25519 keys (`age1...`) and SSH keys (`ssh-ed25519`, `ssh-rsa`) — age handles both natively
- **Integrity (tamper-evidence):** BLAKE3 keyed MAC over sorted key names + encrypted shared values + sorted recipient public keys, stored inside an age-encrypted meta blob (legacy SHA-256 accepted on load)
- **Integrity (authorship):** Ed25519 signature over a canonical serialization of the vault, verified against the signer's registered verifying key; the signing key is derived from the age key via a domain-separated BLAKE3 KDF (`blake3::derive_key`)
- **Key derivation:** BIP39 mnemonic (256 bits of entropy) → direct Bech32 encoding → age identity (no intermediate hash; same bytes, same key). The Ed25519 signing key derives from those same bytes, so the recovery phrase recovers both. SSH keys use their native format.

The MAC binds independent age ciphertexts together, so accidental corruption or naive tampering is caught. Because its key travels in the (re-encryptable) meta blob, it does not stop a deliberate repo-writer — the Ed25519 signature does, since only a recipient's private key can produce a valid one.

## Scope

murk is appropriate for dev teams and small organizations. It replaces sharing `.env` files over Slack, email, or shared documents — a meaningful improvement over that baseline.

murk is not designed for regulated environments handling PII, financial data, or healthcare data where audit trails, key management infrastructure, and provable access controls are required.
