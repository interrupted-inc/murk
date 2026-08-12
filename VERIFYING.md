# Verifying releases

Every murk release is built and published from this repository's GitHub Actions
workflows on GitHub-hosted runners. Most artifacts carry signed provenance you
can verify against [Sigstore](https://www.sigstore.dev/). This page shows how,
per distribution channel.

## Release tag

Tags are signed with SSH. Verify the tag you build from (requires the
maintainer's public key configured as an allowed signer):

```bash
git verify-tag v0.8.0
```

## GitHub release binaries

The prebuilt binaries and `SHA256SUMS` on the [releases page][releases] carry
signed build provenance (`actions/attest-build-provenance`, Sigstore/Fulcio).
Verify a downloaded artifact:

```bash
gh attestation verify murk-v0.8.0-<target>.tar.gz --owner interrupted-inc
```

This confirms the artifact was produced by this repository's release workflow —
a builder you can inspect, with a signing identity an attacker cannot forge.

## npm — `@interrupted/murk-secrets`

Published with npm provenance (`npm publish --provenance`). After installing,
verify the registry signatures and provenance:

```bash
npm audit signatures
```

## PyPI — `murk-secrets`

Wheels and the sdist are published through PyPI Trusted Publishing, which
attaches [PEP 740](https://peps.python.org/pep-0740/) digital attestations by
default. Attestations are shown on each file's entry on PyPI and are available
through PyPI's Integrity API.

Programmatic verification is still maturing. The experimental
[`pypi-attestations`](https://pypi.org/project/pypi-attestations/) CLI verifies
a downloaded file against its published provenance:

```bash
pipx run pypi-attestations verify pypi \
  --repository https://github.com/interrupted-inc/murk \
  pypi:murk_secrets-0.8.0-<...>.whl
```

`pip` does not verify attestations natively yet.

## crates.io — `murk-cli`

crates.io does not yet support artifact provenance or attestations, so there is
nothing to attach at publish time. Trust here rests on two things:

- the crate is published via crates.io **OIDC Trusted Publishing**, so no
  long-lived registry token exists to steal, and
- the release tag above is signed, and the crate is published only from that
  tagged CI run.

This is the one gap in murk's provenance story, and it is upstream: it closes
when crates.io ships attestation support.

[releases]: https://github.com/interrupted-inc/murk/releases
