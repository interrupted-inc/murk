---
title: Threat model
description: What murk protects against, and what it doesn't.
sidebar:
  order: 1
---

This document describes murk's security properties and limits. It's for anyone evaluating murk for team use. Read it before you trust it with production credentials.

murk is pre-1.0 software and has **not been independently audited**. If you find a vulnerability, see the [security policy](https://github.com/interrupted-inc/murk/blob/main/SECURITY.md) for how to report it privately.

![What an unauthorized person with the repo sees: key names, but no values](https://raw.githubusercontent.com/interrupted-inc/murk/demo/eve.gif)

## What murk protects

**Secrets at rest in git.** The `.murk` file is designed to be committed. Every secret value is individually encrypted with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). Anyone with read access to the repository cannot decrypt values without a recipient's private key.

**Secrets in transit via git.** Values are encrypted before they ever reach git, so pushing or pulling over any transport (HTTPS, SSH, or unencrypted) never exposes plaintext.

**Cross-value integrity (tamper-evidence).** A BLAKE3 keyed MAC inside the encrypted meta blob covers every key name, all encrypted values (shared, grouped, and private), the recipient set, and the vault's schema, group definitions, grants, policy, and revocation markers, binding the independent age ciphertexts together. It's mandatory whenever the vault holds secrets, and it catches accidental corruption and naive tampering. On a vault with no signature (a team entirely on `ssh-rsa` or hardware/plugin keys, which can't sign), the MAC is the only tamper-evidence murk itself provides, and git remains the anchor.

:::caution
The MAC alone is **not** a defense against a deliberate attacker with write access to the repo. Its key lives in the meta blob, and age encryption needs only the recipients' *public* keys (which sit in the plaintext header). So anyone who can write the file can mint a fresh MAC key, recompute a valid MAC over tampered content, and re-encrypt the meta blob. age gives you confidentiality, not authentication of who produced a ciphertext.
:::

**Authorship integrity (signatures).** To close that gap, murk signs the vault with an Ed25519 key derived from the writer's age key (see [Vault signatures](#vault-signatures) below). Only a holder of a recipient's private key can produce a valid signature, so an outsider can't forge one. This is what makes tampering by a repo-writer detectable. The MAC stays on as a fast corruption check. Combined with signed git commits, git is the integrity anchor.

**Per-recipient secrets.** Private secrets (motes) are encrypted to a single recipient's public key. No other recipient, authorized or not, can decrypt them.

## What murk does not protect

These aren't bugs. They're the edges of the design. Know them before you rely on murk.

**Compromised machines.** If an attacker gets access to a machine where the secret key lives (`~/.config/murk/keys/`, in memory, or in an environment variable), they can decrypt every shared secret and any private secret belonging to that key.

**Key names are public.** The `.murk` header stores key names, descriptions, and examples in plaintext. Anyone with repo access knows you have a `STRIPE_SECRET_KEY` or a `DATABASE_URL`. That's a deliberate trade-off: it's what lets `murk info` work without a key and keeps git diffs readable. If your threat model requires hiding *what services you use*, murk doesn't address that.

**In-memory secret exposure.** Decrypted values are wrapped in `zeroize::Zeroizing<String>` so plaintext is wiped from memory when the wrapper drops. The secret key itself uses age's `SecretString`, which zeroizes the same way. Zeroization is best-effort: transient buffers inside age's decryption path, the shell-escape output from `murk export`, `serde_json` serialization, and OS-level copies (stdout, child-process environments, swap, core dumps) can still retain plaintext murk has no way to reach. If your threat model includes swap forensics or memory dumps of live processes, treat decrypted values as recoverable.

:::caution[Revocation doesn't erase git history]
**Historical access after revocation.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions stay in git history exactly as they were. The revoked recipient can still decrypt any version they previously had access to. Always rotate credentials after revocation. murk warns about this at revoke time.
:::

**Fine-grained access control.** Every authorized recipient can decrypt every *shared* secret: anything in the `everyone` layer is readable by all of them. [Named recipient groups](/concepts/grants/) narrow that: a secret assigned to a group is age-encrypted only to that group's members, so a leaked member key exposes only the groups it belongs to (plus the shared layer), not the whole vault. age enforces this cryptographically, and the keyed MAC (`blake3v4:`) covers group membership, so it can't be altered undetected. Limits: group *names* and which key belongs to which group are plaintext in the header, and only membership is hidden, in the encrypted meta. Managing a group requires being a member of it (you can't re-encrypt what you can't read). The historical-access caveat above applies per group too: removing a member re-encrypts going forward, but old `.murk` versions in git remain readable, so rotate.

**[Agent grants](/concepts/grants/).** `murk agent grant` mints an ephemeral age identity and gives it read access to a fixed set of keys (`--only`) without ever exposing the operator's own key. The agent is a recipient of the encrypted meta blob (so it can verify integrity and read group/grant state), but is deliberately excluded from the `everyone` layer: it can decrypt only the private values granted to it, enforced cryptographically by age. Grant metadata (scope, TTL, issuer) lives in the encrypted meta, and the keyed MAC (`blake3v5:`) covers it, so it can't be altered undetected. Limits to understand:

1. The agent *can* read the meta blob, so it learns recipient display names, group membership, and other grants' metadata. It learns the org structure, though no other secret values.
2. **The TTL is advisory.** Age keys can't self-destruct, and old `.murk` versions stay readable in git, so a leaked grant key works until `agent revoke` plus rotation, regardless of expiry. The TTL signals *when* to revoke. `agent ls` flags expired grants.
3. The ephemeral key is a bearer credential: whoever holds the key file has the access. Real containment requires OS-level isolation: an agent running as the same user with read access to your home directory can read `~/.config/murk/keys` directly and bypass murk entirely, so run agents in a sandbox, container, or under a separate user. `MURK_STRICT` disables key auto-discovery so a granted agent can't silently fall back to the operator's stored key, and `murk agent exec`, which injects secret *values* into a child process and hands the agent no key at all, is the safest pattern where it fits.

**Agent access policy.** `murk policy set --allow-tag TAG` records a tag allow-list in the plaintext header (MAC-covered, so it can't be stripped or weakened without a key). In agent mode (`agent exec`, `agent grant`), a secret can be injected or granted only if it carries an allowed tag. Anything else is refused, with no override flag.

:::note[A guardrail, not access control]
It constrains the *murk binary*: it does nothing against a human insider using age directly, or an older murk build that predates the policy MAC version. It gates what reaches agents, not what recipients can decrypt. It travels with the repo, so the same constraint applies in CI. The value is keeping production secrets out of agent reach by accident, or by a misbehaving agent that asks for them. Merging two branches that changed the policy differently raises a conflict rather than silently picking one side.
:::

**Post-revoke rotation tracking.** Revoking a recipient re-encrypts going forward, but old `.murk` versions in git stay readable with the revoked key, so the exposed values still have to be rotated to actually cut access. When rotation is deferred at revoke time, murk stamps each exposed key with a `revoked_at` marker in the plaintext header. `doctor` flags it until a value write clears it, so the obligation survives a declined prompt and stays visible without a key. The keyed MAC (`blake3v7:`) covers the marker, so an attacker editing `.murk` can't silently clear the flag without a key. This is a hygiene reminder, not enforcement: it doesn't and can't rotate the underlying credential at its provider, and the revoked key keeps working against git history until you do.

**Audit logging.** murk has no built-in audit trail beyond git history. It does not log who decrypted what, or when. For regulated environments that require provable access controls, use a dedicated secrets server.

**Admin-change accountability (agents and otherwise).** Every administrative change is a commit to the `.murk` file, so **git history is the admin audit trail**: creating or revoking an agent grant, setting or clearing a policy, authorizing or revoking a recipient, and rotating a value after an agent session all show up in `git log -p .murk` / `murk diff`, attributed to the commit author (and cryptographically signed if you use git commit signing). murk deliberately does not keep a second event log inside the vault: it would duplicate git, could drift from it, and, because the integrity MAC uses a key every recipient shares, any keyholder could forge entries, so it would be weaker than git on attribution, not stronger. What cannot be audited at all: secret *reads* on a developer's machine (murk can't see them), and any action taken with age directly or an old murk binary. Provable per-actor attribution beyond git's commit identity would require signed events, which needs a signing key murk's age identities don't have. That's deferred until a concrete requirement exists.

**[Agent MCP server](/guides/ai-agents-mcp/).** `murk mcp` exposes secrets to AI-agent harnesses over the Model Context Protocol on a local stdio pipe, not a network listener. It's bound by the same machinery as every other agent path: it refuses to start unless the loaded identity is a scoped grant with `MURK_AGENT=1`, so it can never serve the operator's full read scope, and `murk_plan`/`murk_get` are limited to the keys the grant may read and the agent policy allows, failing closed on anything else.

:::caution[A guardrail, not a sandbox]
`murk_exec` (running a command with scoped secrets injected) is off by default and enabled only with `--allow-exec`. `only` bounds the injected *secrets*, but the command itself runs as the server's user with its filesystem and network access. As with `agent exec`, the real containment boundary is the OS: run the server (and the agent) under a separate user or container.
:::

## Vault signatures

murk signs the vault with an Ed25519 key so tampering by someone with write access to the repo is detectable: the property the MAC alone can't provide.

![Tampering with the vault by an unauthorized writer is caught on load](https://raw.githubusercontent.com/interrupted-inc/murk/demo/mallory.gif)

**How it works.** On save, a signing-capable writer signs a canonical serialization of the vault: recipients, all ciphertexts, schema, groups, grants, policy, GitHub pins, and the signer registry. On load, murk verifies the signature and confirms the signer is a current recipient. A present-but-invalid signature fails the load as tampering. An absent signature is a warning (integrity then rests on git). Where the *verifying* key comes from depends on the key type:

- **age keys**: the signing key is derived from the age key via a domain-separated BLAKE3 KDF (so the BIP39 phrase recovers it too), but its verifying key can't be recovered from the public age recipient. So the writer publishes it in a signer registry (`signers` in the encrypted meta), and verification looks it up there.
- **ssh-ed25519 keys**: the SSH key *is* an Ed25519 signing key, so murk signs with it directly. Its verifying key is already embedded in the `ssh-ed25519 …` recipient string, so the signature is self-authenticating: verified straight against the recipient, with no registry entry and no pin needed. This is the stronger form: there's no registry state an attacker could tamper with.

**Sign-when-capable.** age keys and ssh-ed25519 keys can sign. `ssh-rsa` and hardware/plugin identities can't (age exposes no signing scalar for them), so their saves are written unsigned. A team entirely on hardware keys gets no signatures and relies on git. A mixed team is signed whenever a signing-capable holder last wrote.

**What signatures prevent.** An outsider (a non-recipient) with repo write access can't forge a signature: they hold no recipient private key. So injecting or swapping a ciphertext and re-MACing it (the attack the MAC alone doesn't stop) now fails signature verification on the next load.

**Signer-registry pinning (TOFU).** The age signer registry (pubkey → verifying key) lives in the encrypted meta, which a repo-writer can re-encrypt, so on its own, a signature verified against that registry is forgeable (register your own key under a recipient's pubkey, sign with it). To close this, murk pins each pubkey → verifying-key mapping locally on first sight (`~/.config/murk/signer-pins/`) and enforces it in the trusted load path: a *changed* verifying key for an already-pinned pubkey is never legitimate (the mapping is a fixed derivation), so the load fails hard, in the library, meaning the CLI and the Python/Node bindings are all covered. New pubkeys are trust-on-first-use: on a fresh clone with no prior pin, an age signer's key is whatever the file says, so the signature is *not* authenticated authorship yet: an attacker who tampered before your first load would be pinned as legitimate. murk doesn't present this as verified: `load` marks such a signature unanchored, and `murk verify` reports it as trust-on-first-use, pointing you at signed git commits (the real anchor for a first load) or an ssh-ed25519 key. Once pinned, any later key change is caught. The pin is local and doesn't travel with the repo. `MURK_NO_SIGNER_PIN=1` disables the check. ssh-ed25519 signers need no pin: their verifying key comes from the recipient string itself, so they're self-authenticating and anchored even on a first clone.

**Limits.**

1. A **malicious recipient** can always sign: they hold a valid key. Signatures make tampering *attributable* (which recipient last signed), not impossible, exactly like signed git commits. The malicious-recipient boundary is unchanged.
2. An attacker can **strip** the signature and re-MAC, producing an unsigned vault. That's not silently accepted: it loads with an "unsigned" warning, and if the vault was signed in git history the unsigned commit is visible, but the signature alone doesn't *block* it. Git commit signing is the anchor against strip/downgrade.
3. An attacker who can **add themselves as a recipient** can sign as that new recipient, but the recipient list is plaintext in the header, so the addition is visible in `git diff` and, on a shared branch, conflicts under the merge driver.
4. Signature verification requires decrypting the meta, so it's a recipient-only check, like the MAC.

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

`murk authorize github:username` fetches SSH public keys from `https://github.com/username.keys` without authentication. That introduces trust assumptions:

**You trust GitHub as a key directory.** The keys GitHub returns are whatever the user has uploaded to their account. If an attacker compromises a GitHub account and adds their own SSH key, `murk authorize github:attacker` would grant them access to vault secrets.

**You trust that the GitHub username belongs to who you think it does.** There's no out-of-band verification. Authorizing `github:alice` means trusting that the GitHub user "alice" is your teammate Alice. For most teams this is reasonable: you already trust teammates' GitHub accounts for code review and merge access.

**TOFU (trust on first use) pinning.** The first successful `murk authorize github:username` records the SHA-256 fingerprints of the fetched keys in the encrypted vault meta. Subsequent `authorize` calls against the same username refuse to proceed if any fingerprint was added or removed upstream, unless `--force` is passed. This catches GitHub key rotation, benign (a teammate rotated their key) or malicious (an attacker added a key to a compromised account), and surfaces the diff for a human to decide. The pin covers the full upstream key set, including `ssh-rsa` keys murk won't authorize, so rotation is still detected even when no new recipient ends up in the vault.

**SSH keys in the vault are just longer pubkey strings.** The vault format is unchanged: `vault.recipients` stores `ssh-ed25519 AAAA...` strings alongside `age1...` strings. Every existing integrity protection (MAC, per-value encryption) applies equally to SSH recipients.

**Acceptable risk profile.** For a team secrets tool, trusting GitHub as a key directory is a reasonable trade-off. You're already trusting your teammates with code access, CI credentials, and production deployments through the same GitHub accounts. The alternative, manual key exchange, has worse security properties in practice, because teams resort to sharing keys over Slack or email.

## Merge driver

murk includes a git merge driver (`murk merge-driver`) that performs three-way merges on `.murk` vault files at the ciphertext level, without decryption.

**Trust assumptions:**
- The merge driver operates without a key. It can't verify the MAC of any version. Integrity is verified on the next load after merge.
- Recipient additions and removals on only one side produce a merge conflict. Both sides must agree on recipient changes for a clean merge.
- Secret additions from one side are accepted if the other side didn't touch secrets. If both sides modified secrets (e.g. from a re-encryption after a recipient change), all overlapping secrets conflict.
- Group membership lives in the encrypted meta, which the merge driver can't read without a key. When a key is available it merges memberships (union, ours-wins, dropping non-recipients). Without one it keeps `ours` meta. Either way, the `blake3v4:` MAC covers group definitions, so any inconsistency between merged group ciphertexts and membership is caught on the next load.

**What the merge driver prevents:**
- Silent recipient removal (one-sided removal → conflict)
- Silent recipient injection (one-sided addition → conflict)
- Secret value conflicts from independent edits to the same key

:::caution
**What the merge driver does not prevent:** an attacker with write access to a branch can add or replace ciphertext entries. Anyone can encrypt to the (public) recipient keys, so an injected value can be *readable*, not just noise: the MAC alone doesn't catch this, because a repo-writer can recompute it (see [cross-value integrity](#what-murk-protects) above). What catches it is the signature: **the merge driver leaves the merged vault unsigned.** It runs non-interactively and must not vouch for content a human hasn't reviewed, so it recomputes the MAC (needed to load at all) but doesn't sign. The next load reports the vault as unsigned. A keyholder re-signs it with any write command *after* reviewing `murk diff`. Until then, integrity rests on git.
:::

**Recommendation:** protect your main branch with required reviews and commit signing. The merge driver is a safety net for concurrent vault edits, not a substitute for branch protection. Review `murk diff` before re-signing a merged vault.

## Supply chain

Release binaries are built in GitHub Actions, checksummed (`SHA256SUMS`), and signed with Sigstore build provenance attestation ([SLSA Level 2](https://slsa.dev)). The npm and PyPI packages carry their own provenance. crates.io has no attestation support yet. `install.sh` downloads the archive and the checksums file, then verifies before extracting: it never executes downloaded code before verification. See [Verifying releases](/security/verifying/) for the full per-channel verification story.

murk depends on [age](https://age-encryption.org/) (via the `age` crate) for all cryptography, plus standard Rust crates for CLI, serialization, and I/O. `cargo deny` checks for known advisories and license compliance in CI, and all CI actions are pinned to full SHA commit hashes. `Cargo.lock` is committed and used for reproducible builds (`--locked` in release workflows).

## Key compromise scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| `MURK_KEY` leaked | Attacker can decrypt all shared secrets and the owner's private secrets | Revoke the compromised key, rotate all secrets, re-authorize with a new key |
| `.env` committed to git | Same as key leak, but the key is now in git history | Remove from history (`git filter-repo`), revoke, rotate |
| Recovery phrase exposed | Attacker can derive the secret key | Same as key leak |
| Repository made public | Key names and encrypted values exposed. Values remain safe if keys are secure | Rotate secrets as a precaution if key names alone are sensitive |
| Recipient revoked | Revoked user retains access to historical versions in git | Rotate all secrets that the revoked user had access to |
| GitHub account compromised | Attacker could be authorized via `github:username` if the vault owner runs authorize after compromise. TOFU pinning detects later key changes for an already-authorized user | Verify teammate identity before the first authorize. Investigate the diff when `authorize github:user` reports pinned-key changes. Revoke and rotate if compromise is suspected |
| SSH private key leaked | Attacker can decrypt all secrets the SSH key was a recipient for | Revoke the compromised SSH key from the vault, rotate secrets |

## Cryptographic properties

murk uses age for all encryption and decryption. It doesn't implement custom cryptographic primitives. It defines a vault format and a BLAKE3 keyed integrity layer on top of age.

- **Encryption:** age v1 (X25519 key agreement, ChaCha20-Poly1305 payload encryption)
- **Per-value encryption:** each secret value is encrypted independently with a fresh age file key
- **Recipient types:** age x25519 keys (`age1...`) and SSH keys (`ssh-ed25519`, `ssh-rsa`). age handles both natively
- **Integrity (tamper-evidence):** BLAKE3 keyed MAC over key names, all encrypted values (shared, grouped, private), the recipient set, schema, group definitions, grants, policy, and revocation markers, stored inside an age-encrypted meta blob (legacy SHA-256 accepted on load)
- **Integrity (authorship):** Ed25519 signature over a canonical serialization of the vault, verified against the signer's registered verifying key. The signing key derives from the age key via a domain-separated BLAKE3 KDF (`blake3::derive_key`)
- **Key derivation:** BIP39 mnemonic (256 bits of entropy) → direct Bech32 encoding → age identity, no intermediate hash, same bytes, same key. The Ed25519 signing key derives from those same bytes, so the recovery phrase recovers both. SSH keys use their native format.

The MAC binds independent age ciphertexts together, so accidental corruption or naive tampering is caught. Because its key travels in the (re-encryptable) meta blob, it doesn't stop a deliberate repo-writer. The Ed25519 signature does, since only a recipient's private key can produce a valid one.

## Scope

murk is appropriate for dev teams and small organizations. It replaces sharing `.env` files over Slack, email, or shared documents, a meaningful improvement over that baseline.

murk is not designed for regulated environments handling PII, financial data, or healthcare data, where audit trails, key management infrastructure, and provable access controls are required.
