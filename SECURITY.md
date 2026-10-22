# Security Policy

## Cryptography

murk implements no cryptographic primitives. [age](https://age-encryption.org/) (the [rage](https://github.com/str4d/rage) Rust crate) encrypts and decrypts every value. BLAKE3 and Ed25519 provide the integrity MAC, the signing-key derivation and the vault signatures, and murk defines how they combine (see [THREAT_MODEL.md](THREAT_MODEL.md)). A new key is 32 random bytes from a cryptographically secure random number generator, shown as a 24-word BIP39 recovery phrase.

If you find a vulnerability in the underlying cryptographic primitives, report it to the [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage) project directly. Report a flaw in how murk combines them (its MAC, signature or signing-key construction) to murk, as described below.

For a detailed analysis of what murk protects and what it doesn't, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Known Limitations

- **Not audited.** murk has not had an independent security audit. It is pre-1.0 software. Use good judgment with production secrets.
- **Not a secrets server.** murk is a file-based secrets manager for dev teams. It is not designed for regulated environments, dynamic secrets, automatic provider-side rotation or provable access controls. murk can record rotation intervals and expiry dates and report overdue secrets. If you need a secrets server, use one such as HashiCorp Vault.
- **Revoked recipients can read old git history.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions remain in git. The revoked user can still decrypt any version they had access to. Always rotate secrets after revocation.
- **Plaintext during edit.** `murk edit` writes decrypted values to a temp file for `$EDITOR`. The file is overwritten with zeros and deleted afterward, but the plaintext is on disk for as long as the editor runs. Core dumps, swap, or filesystem journaling could retain fragments.
- **Compromised workstation = full access.** If an attacker has access to the machine where your key lives, they can decrypt all shared secrets. murk is not a defense against a compromised machine — it protects secrets at rest in git and in transit.
- **Key names are public.** The `.murk` header exposes what secrets exist (e.g. `STRIPE_SECRET_KEY`). Only values are encrypted. This is a deliberate trade-off for usability (`murk info` without a key, readable git diffs).
- **No custom cryptographic primitives.** murk uses age, BLAKE3 and Ed25519. The vault format, its keyed MAC and its signature scheme are murk's own.

## Known Issues

**SSH-RSA timing sidechannel (RUSTSEC-2023-0071)** — The `rsa` crate used by age's SSH-RSA support is affected by the Marvin Attack, a timing sidechannel. murk rejects `ssh-rsa` recipients by default: `circle authorize` and `ssh:` paths refuse to authorize RSA keys unless the caller passes `--allow-ssh-rsa`. `github:username` skips RSA keys with a warning, and refuses only when every key it finds is RSA. The risk is low for a local CLI (the attack requires many decryption queries against a server), but the default-closed posture keeps weak keys out of the recipient list. Prefer ed25519 keys. No upstream fix is available yet.

## Supply Chain

Every release artifact is built and published from GitHub Actions on hosted runners, and most carry signed provenance. Release binaries include [Sigstore artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). Verify one downloaded binary at a time:

```bash
gh attestation verify murk-v<version>-<target>.tar.gz --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml
```

This covers murk 0.12.0 and later. Earlier releases name an older repository in their provenance. That is `interrupted-inc/murk` for 0.10.2 to 0.11.0 and `iicky/murk` for 0.3.1 to 0.10.1. [VERIFYING.md](VERIFYING.md) shows how to verify them.

Release tags are signed with SSH. Verify a tag (replace `vX.Y.Z` with the release tag) after adding the maintainer's signing key to your allowed signers, as described in [VERIFYING.md](VERIFYING.md#release-tag):

```bash
git verify-tag vX.Y.Z
```

See [VERIFYING.md](VERIFYING.md) for per-channel verification, including the npm, PyPI, and crates.io packages.

### Repository automation secrets

Release and CI automation uses these long-lived secrets. Each must be held to the minimum scope it needs:

- **`HOMEBREW_TAP_TOKEN`**: a fine-grained personal access token for the `interrupted-sh/homebrew-tap` repository only, with `contents: write` and nothing else. Only the release workflow uses it, to push the Homebrew formula. The tap is shared by all interrupted.sh tools, so the token can write every formula in it.
- **`PREFLIGHT_APP_ID`** and **`PREFLIGHT_APP_PRIVATE_KEY`**: a GitHub App installed on `interrupted-sh/murk` with `administration: read`, `contents: write` and `pull-requests: write`. Each workflow requests a narrower token. The release preflight uses a read-only token to check branch protection. The advisories workflow uses a `contents: write` and `pull-requests: write` token to open dependency fix pull requests.
- **`CODECOV_TOKEN`**: a Codecov repository upload token (not a personal account token), used only to upload coverage for this repository.
- **`CLOUDFLARE_API_TOKEN`** and **`CLOUDFLARE_ACCOUNT_ID`**: used only to deploy the docs site and its previews.

Workflow `GITHUB_TOKEN` permissions follow least privilege: read-only by default, elevated per job only where a step needs it (for example `id-token: write` for OIDC publishing and build provenance, `security-events: write` for code scanning).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Latest release only |

murk is pre-1.0 software. Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/interrupted-sh/murk/security/advisories/new) to submit a report. You'll get a response within 14 days.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

## Scope

In scope:
- Secret values leaking into plaintext (logs, error messages, temp files)
- Bypassing recipient-based access control
- Key material exposure beyond the key file, `MURK_KEY`, or a `.env` that holds an inline `MURK_KEY`
- Bypassing MAC or signature verification, or signer pinning
- Flaws in murk's MAC, signature or signing-key construction
- Bypassing a grant's scope or expiry, or the agent allow-tag policy, inside the murk binary

Out of scope:
- Vulnerabilities in the age or rage primitives (report upstream)
- Attacks that need local access to your key file, `MURK_KEY`, or an `.env` that contains `MURK_KEY` (these hold the secret key by definition). The default `.env` from `murk init` holds only the key file's path
- Limits that [THREAT_MODEL.md](THREAT_MODEL.md) lists under "What murk does not protect", for example values that output masking misses, or a policy bypassed by using age directly
- Denial of service against the CLI
