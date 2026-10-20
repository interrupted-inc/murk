# Verifying releases

Every murk release is built and published from this repository's GitHub Actions
workflows on GitHub-hosted runners. The source tag carries the maintainer's SSH
signature, and each published package carries a signature you can check. This
page shows how, per distribution channel.

| Channel | What is signed | Signed by | Verify with |
| --- | --- | --- | --- |
| Source: git tag `vX.Y.Z` | The annotated tag (v0.3.1 and later) | Maintainer's SSH signing key | [`git verify-tag`](#release-tag) |
| GitHub release archives and `SHA256SUMS` | Sigstore build provenance per file | `release.yaml` in this repository | [`gh attestation verify`](#github-release-binaries) |
| Homebrew tap | The formula pins the SHA-256 of the attested GitHub release archives | (inherits the GitHub release attestation) | `brew` checks the hash; [`gh attestation verify`](#github-release-binaries) on the archive |
| crates.io: `murk-cli` | Sigstore build provenance for the exact `.crate` file (releases after 0.12.0) | `release.yaml` in this repository | [`gh attestation verify`](#cratesio--murk-cli) on the `.crate` |
| npm: `@interrupted/murk-secrets` | npm registry signatures and Sigstore provenance | `node.yaml` in this repository | [`npm audit signatures`](#npm--interruptedmurk-secrets) |
| PyPI: `murk-secrets` | PEP 740 Sigstore attestations per wheel and sdist | `python.yaml` in this repository | [`pypi-attestations verify`](#pypi--murk-secrets) |

The Sigstore signatures are keyless. Each signing key is ephemeral, and Fulcio
certifies it for the workflow identity that ran (repository, workflow file, and
tag). No long-lived private key exists, on a distribution site or anywhere
else. The verifying tools fetch Sigstore's public trust root themselves, so the
one input you supply is the expected identity: `--owner interrupted-sh`, or the
repository URL.

## Release tag

Release tags from v0.3.1 onward are signed with the maintainer's SSH key. (Tags
v0.2.0 through v0.3.0 are unsigned.)

GitHub publishes the key as an SSH **signing** key at
<https://api.github.com/users/iicky/ssh_signing_keys>. Do not use
`https://github.com/iicky.keys`: it lists authentication keys, which do not
sign tags. The signing key's fingerprint is
`SHA256:rvLxyoK1U/TDmpbh8U76u1GglXPzqZPr5Jnn3ok6CGw`. The fingerprint on this page
and the key from GitHub come from two different sources, so each one checks the
other.

Write the key to an allowed-signers file and verify the tag you build from.
Replace `vX.Y.Z` with the release tag:

```bash
curl -fsSL https://api.github.com/users/iicky/ssh_signing_keys \
  | jq -r '.[] | "5324300+iicky@users.noreply.github.com namespaces=\"git\" \(.key)"' \
  > murk-allowed-signers
git -c gpg.ssh.allowedSignersFile=murk-allowed-signers verify-tag vX.Y.Z
```

The output must contain `Good "git" signature` and the fingerprint above. To
make the setting permanent, add the line to your own allowed-signers file and
set `git config --global gpg.ssh.allowedSignersFile <path>`.

## GitHub release binaries

The prebuilt binaries and `SHA256SUMS` on the [releases page][releases] carry
signed build provenance (`actions/attest-build-provenance`, Sigstore/Fulcio).
Verify a downloaded artifact of murk 0.12.0 or later:

```bash
gh attestation verify murk-<version>-<target>.tar.gz --owner interrupted-sh
```

This confirms the artifact was produced by this repository's release workflow —
a builder you can inspect, with a signing identity an attacker cannot forge.

Releases up to and including 0.11.0 were built before the GitHub organization
was renamed from `interrupted-inc` to `interrupted-sh`, so their provenance
names `interrupted-inc/murk`. Fetch the attestation from the current
repository, then verify it against the old identity:

```bash
gh attestation download murk-<version>-<target>.tar.gz --repo interrupted-sh/murk
gh attestation verify murk-<version>-<target>.tar.gz \
  --bundle sha256:<sha256-of-archive>.jsonl --repo interrupted-inc/murk
```

`gh attestation download` prints the bundle file name it wrote.

### Rebuilding a release binary

`rust-toolchain.toml` at the release tag names the exact Rust version the release
was built with. With [rustup](https://rustup.rs), building from a checkout of
the tag uses that toolchain automatically; `rustup show active-toolchain`
confirms it. Releases tagged before `rust-toolchain.toml` was added were built
with the then-current stable Rust.

The release workflow ([`release.yaml`](.github/workflows/release.yaml)) also
fixes the other build inputs: `SOURCE_DATE_EPOCH` set to the commit timestamp,
`CARGO_INCREMENTAL=0`, the checkout and cargo home remapped to `/src` and
`/cargo` with `--remap-path-prefix`, and `-Clink-arg=/Brepro` on Windows. Build
with the same settings and `cargo build --release --locked --target <target>`
(the Linux ARM targets use `cross`), then compare the binary inside the release
archive by SHA-256. CI's reproducibility job checks that two builds of one
commit from different paths are byte-identical on Linux and Windows; a build on
a different OS image or linker can still differ.

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
  --repository https://github.com/interrupted-sh/murk \
  pypi:murk_secrets-<version>-<...>.whl
```

For murk-secrets 0.11.0 and earlier, pass
`--repository https://github.com/interrupted-inc/murk` instead; those files
were published before the organization rename.

`pip` does not verify attestations natively yet.

## crates.io — `murk-cli`

crates.io has no signing or attestation support of its own, so the release
workflow signs the crate file itself. For each murk-cli release after 0.12.0, the
workflow does the following:

1. It packages the crate with `cargo package --locked`.
2. It publishes the crate through crates.io **OIDC Trusted Publishing**, so no
   long-lived registry token exists to steal.
3. It confirms that the SHA-256 of the packaged file equals the checksum that the
   crates.io index records for that version. cargo rejects any download that does
   not match this checksum.
4. It attests the file with `actions/attest-build-provenance` and attaches it to
   the GitHub release as `murk-cli-<version>.crate`.

The file that cargo downloads is therefore the attested file. To verify it:

```bash
# The file cargo downloads. A copy is also cached in
# ~/.cargo/registry/cache/index.crates.io-*/ after a build or install.
curl -fsSLO https://static.crates.io/crates/murk-cli/murk-cli-<version>.crate
gh attestation verify murk-cli-<version>.crate --owner interrupted-sh

# Optional: the checksum cargo enforces for that version must be the same
curl -fsSL https://index.crates.io/mu/rk/murk-cli \
  | jq -r 'select(.vers == "<version>") | .cksum'
sha256sum murk-cli-<version>.crate
```

For murk-cli 0.12.0 and earlier there is no crate attestation. Instead, check
the crate against the signed tag. Crate packaging is deterministic, so a
checkout of the tag gives back the same bytes:

```bash
git verify-tag vX.Y.Z && git checkout vX.Y.Z
cargo package --locked --no-verify
sha256sum target/package/murk-cli-X.Y.Z.crate   # must equal the index cksum above
```

[releases]: https://github.com/interrupted-sh/murk/releases
