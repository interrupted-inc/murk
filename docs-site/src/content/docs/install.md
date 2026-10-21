---
title: Install & verify
description: Install murk and verify the release you downloaded.
sidebar:
  order: 1
---

murk ships as a single binary with no runtime dependencies. Pick whichever
install method fits your setup.

## Homebrew

```bash
brew install interrupted-sh/tap/murk
```

Installing by the full name trusts only the murk formula, not every formula
in the tap ([Homebrew tap trust](https://docs.brew.sh/Tap-Trust)).

**Upgrading from the old tap name.** The tap used to be `interrupted-sh/murk`.
You don't need to untap or reinstall: `brew update` follows the rename and
moves your tap to `interrupted-sh/tap`. Trust doesn't follow a rename, so
trust the formula under its new name once, then upgrade:

```bash
brew update
brew trust --formula interrupted-sh/tap/murk
brew upgrade murk
```

## Cargo

Requires the [Rust toolchain](https://rustup.rs):

```bash
cargo install murk-cli
```

## install.sh

Downloads a pre-built binary for Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/interrupted-sh/murk/main/install.sh | sh
```

The script checks the archive against the release's `SHA256SUMS`, which catches a
corrupt download but not a tampered release. It then checks the release's build
provenance with the [GitHub CLI](https://cli.github.com) (`gh`, logged in with
`gh auth login` or `GH_TOKEN`). A check that fails stops the install. If `gh` is
missing or not logged in, it asks whether to install anyway (default no).
Without a terminal, as in CI or a docker build, it stops unless
`MURK_SKIP_ATTESTATION=1` is set for `sh`. Set `MURK_TAG=v0.14.0` to install a
specific release.

It installs to `/usr/local/bin/murk` by default, using `sudo` only when that
directory is not writable. The location follows the standard conventions:

- `PREFIX` sets the installation prefix; the binary goes to `$PREFIX/bin`
  (default `/usr/local`).
- `DESTDIR` is prepended to the final path for staged installs, as with
  `make install`: `DESTDIR=/tmp/stage PREFIX=/usr` writes
  `/tmp/stage/usr/bin/murk`.
- `MURK_INSTALL_DIR` names the exact bin directory and takes precedence over
  `PREFIX`. `DESTDIR` still applies on top of it.

Set the variables for `sh`, not `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/interrupted-sh/murk/main/install.sh | PREFIX="$HOME/.local" sh
```

## GitHub Releases

murk provides pre-built binaries for Linux (x86_64, aarch64, armhf), macOS
(x86_64, Apple Silicon), and Windows on the
[releases page](https://github.com/interrupted-sh/murk/releases).

## Language bindings

[`@interrupted/murk-secrets`](https://www.npmjs.com/package/@interrupted/murk-secrets)
on npm and [`murk-secrets`](https://pypi.org/project/murk-secrets/) on PyPI
let a program read a vault from code. The Node package can also store
secrets. Neither package includes the `murk` command. Install the CLI first
and use it to create the vault. See [Library bindings](/reference/bindings/).

## Verify your download

Binary releases carry signed build provenance
([`actions/attest-build-provenance`](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds),
backed by Sigstore/Fulcio). Verify a downloaded artifact with the GitHub CLI:

```bash
gh attestation verify murk-v0.14.0-aarch64-apple-darwin.tar.gz \
  --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml
```

File names include the tag with its `v`. The Windows file is a `.zip`. This
checks that the release workflow in this repository built the file. `gh` must
be logged in (`gh auth login`). The same check works for `SHA256SUMS`.

Releases 0.11.0 and earlier name an older repository in their provenance
(`interrupted-inc/murk` or `iicky/murk`). See
[Verifying releases](/security/verifying/#github-release-binaries) for the
commands that verify them.

The npm, PyPI and crates.io packages are verified differently: npm provenance
for the npm package, PEP 740 attestations for PyPI, and an attested `.crate`
for crates.io (0.13.0 and later). Release tags are SSH-signed.
[Verifying releases](/security/verifying/) covers each channel and where to
get the tag-signing key.

## Next steps

Once murk is installed, follow the [quick start](/quick-start/) to join an
existing project, or [start a new vault](/quick-start/#start-a-new-vault).
