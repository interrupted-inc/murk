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
brew tap interrupted-sh/murk && brew install murk
```

## Cargo

Requires the [Rust toolchain](https://rustup.rs):

```bash
cargo install murk-cli
```

## install.sh

Downloads a pre-built binary for your platform:

```bash
curl -fsSL https://raw.githubusercontent.com/interrupted-sh/murk/main/install.sh | sh
```

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

murk is also published to npm as
[`@interrupted/murk-secrets`](https://www.npmjs.com/package/@interrupted/murk-secrets) and
to PyPI as [`murk-secrets`](https://pypi.org/project/murk-secrets/), if either
fits your project's toolchain better than a system-wide binary. Both read
vault secrets from your code, and the Node package can store them too — see
[Library bindings](/reference/bindings/) for the API and usage.

## Verify your download

Binary releases carry signed build provenance
([`actions/attest-build-provenance`](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds),
backed by Sigstore/Fulcio). Verify a downloaded artifact with the GitHub CLI:

```bash
gh attestation verify murk-<version>-<target>.tar.gz --owner interrupted-sh
```

This confirms the artifact was produced by this repository's release
workflow: a builder you can inspect, with a signing identity an attacker
cannot forge.

Releases up to and including 0.11.0 were signed as `interrupted-inc/murk`,
before the organization rename; see
[Verifying releases](/security/verifying/#github-release-binaries) for the
command that verifies them.

npm, PyPI, and crates.io releases each have their own verification path (npm
provenance, PEP 740 attestations, and signed release tags respectively). See
[Verifying releases](/security/verifying/) for the full walkthrough across
every distribution channel.

## Next steps

Once murk is installed, run through the [quick start](/quick-start/) to
generate a key and create your first vault.
