# Security Policy

## Cryptography

murk does not implement any cryptography. All encryption and decryption is performed by [age](https://age-encryption.org/) via the [rage](https://github.com/str4d/rage) Rust implementation. Key generation uses BIP39 mnemonics over cryptographically random bytes.

If you find a vulnerability in the underlying cryptographic primitives, please report it to the [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage) projects directly.

For a detailed analysis of what murk protects and what it doesn't, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Known Limitations

- **Not audited.** murk has not had an independent security audit. It is pre-1.0 software. Use good judgment with production secrets.
- **Not a Vault replacement.** murk is a file-based secrets manager for dev teams. It is not designed for regulated environments, dynamic secrets, rotation policies, or provable access controls. If you need a secrets server, use HashiCorp Vault.
- **Revoked recipients can read old git history.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions remain in git. The revoked user can still decrypt any version they had access to. Always rotate secrets after revocation.
- **Plaintext during edit.** `murk edit` writes decrypted values to a temp file for `$EDITOR`. The file is overwritten with zeros and deleted afterward, but the plaintext existed on disk briefly. Core dumps, swap, or filesystem journaling could retain fragments.
- **Compromised workstation = full access.** If an attacker has access to the machine where your key lives, they can decrypt all shared secrets. murk is not a defense against a compromised machine — it protects secrets at rest in git and in transit.
- **Key names are public.** The `.murk` header exposes what secrets exist (e.g. `STRIPE_SECRET_KEY`). Only values are encrypted. This is a deliberate trade-off for usability (`murk info` without a key, readable git diffs).
- **No custom cryptography.** murk delegates all crypto to [age](https://age-encryption.org/). Minimal custom code, explicit trade-offs, single-file format.

## Known Issues

**SSH-RSA timing sidechannel (RUSTSEC-2023-0071)** — The `rsa` crate used by age's SSH-RSA support is affected by the Marvin Attack, a timing sidechannel. murk rejects `ssh-rsa` recipients by default: `circle authorize`, `ssh:` paths, and `github:username` all refuse to authorize RSA keys unless the caller passes `--allow-ssh-rsa`. The risk is low for a local CLI (the attack requires many decryption queries against a server), but the default-closed posture keeps weak keys out of the recipient list. Prefer ed25519 keys. No upstream fix is available yet.

## Supply Chain

Every release artifact is built and published from GitHub Actions on hosted runners, and most carry signed provenance. Release binaries include [Sigstore artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). Verify a downloaded binary:

```bash
gh attestation verify murk-v*.tar.gz --owner interrupted-inc
```

Release tags are signed with SSH. Verify a tag (replace `vX.Y.Z` with the release tag):

```bash
git verify-tag vX.Y.Z
```

See [VERIFYING.md](VERIFYING.md) for per-channel verification, including the npm, PyPI, and crates.io packages.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Latest release only |

murk is pre-1.0 software. Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/interrupted-inc/murk/security/advisories/new) to submit a report. You'll get a response within 14 days.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

## Scope

In scope:
- Secret values leaking into plaintext (logs, error messages, temp files)
- Bypassing recipient-based access control
- Key material exposure beyond `.env`
- Integrity check bypass (MAC validation)

Out of scope:
- Vulnerabilities in age/rage cryptographic primitives (report upstream)
- Attacks requiring local access to `.env` or `MURK_KEY` (these contain the secret key by design)
- Denial of service against the CLI
