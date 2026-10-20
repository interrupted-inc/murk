#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Install murk — https://github.com/interrupted-sh/murk
# Usage: curl -fsSL https://raw.githubusercontent.com/interrupted-sh/murk/main/install.sh | sh
#
# Install location (standard conventions):
#   PREFIX            installation prefix; the binary goes to $PREFIX/bin (default /usr/local)
#   MURK_INSTALL_DIR  exact bin directory; takes precedence over PREFIX
#   DESTDIR           staging root prepended to the final path, as in `make install`:
#                     DESTDIR=/tmp/stage PREFIX=/usr installs to /tmp/stage/usr/bin/murk
set -e

REPO="interrupted-sh/murk"
# Releases up to v0.11.0 were built before the GitHub org rename and are signed
# as this repository under its old name.
LEGACY_REPO="interrupted-inc/murk"
PREFIX="${PREFIX:-/usr/local}"
INSTALL_DIR="${DESTDIR:-}${MURK_INSTALL_DIR:-$PREFIX/bin}"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)
        case "$arch" in
            x86_64)  target="x86_64-unknown-linux-gnu" ;;
            aarch64) target="aarch64-unknown-linux-gnu" ;;
            armv7*)  target="arm-unknown-linux-gnueabihf" ;;
            *)       echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$arch" in
            x86_64)  target="x86_64-apple-darwin" ;;
            arm64)   target="aarch64-apple-darwin" ;;
            *)       echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "error: unsupported OS: $os (try cargo install murk-cli)" >&2
        exit 1
        ;;
esac

# Resolve the release tag. MURK_TAG pins a version (and skips the API lookup),
# which also lets a smoke test install from a fixture without a live release.
tag="${MURK_TAG:-}"
if [ -z "$tag" ]; then
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
fi
if [ -z "$tag" ]; then
    echo "error: could not determine latest release" >&2
    exit 1
fi

archive="murk-${tag}-${target}.tar.gz"
# Download base. MURK_BASE_URL overrides it to install from a local fixture or
# a mirror; it defaults to the GitHub release for this tag.
base_url="${MURK_BASE_URL:-https://github.com/$REPO/releases/download/$tag}"
url="$base_url/$archive"

echo "installing murk $tag ($target)"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

curl -fsSL "$url" -o "$tmpdir/$archive"

# Verify checksum.
checksums_url="$base_url/SHA256SUMS"
curl -fsSL "$checksums_url" -o "$tmpdir/SHA256SUMS"
expected=$(grep "$archive" "$tmpdir/SHA256SUMS" | cut -d' ' -f1)
if [ -z "$expected" ]; then
    echo "error: checksum not found for $archive" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmpdir/$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmpdir/$archive" | cut -d' ' -f1)
else
    echo "error: no sha256sum or shasum found — cannot verify download" >&2
    echo "hint: install coreutils or use 'cargo install murk-cli' instead" >&2
    exit 1
fi
if [ "$actual" != "$expected" ]; then
    echo "error: checksum mismatch — expected $expected, got $actual" >&2
    exit 1
fi

# Verify build provenance attestation.
# If gh CLI is installed, attestation MUST succeed — a failure is treated
# as fatal so a tampered release channel cannot silently defeat the check.
# If gh is not installed, warn loudly and continue. Set MURK_REQUIRE_ATTESTATION=1
# to refuse install without attestation, or MURK_SKIP_ATTESTATION=1 to bypass it
# (not recommended; used by the install smoke test against a local fixture).
if [ "${MURK_SKIP_ATTESTATION:-0}" = "1" ]; then
    echo "warning: skipping provenance verification (MURK_SKIP_ATTESTATION=1)" >&2
elif command -v gh >/dev/null 2>&1; then
    verified=0
    if gh attestation verify "$tmpdir/$archive" --repo "$REPO" >/dev/null 2>&1; then
        verified=1
    else
        case "$tag" in
            v0.[0-9].*|v0.1[01].*)
                # Fetch the attestation from the current repository and check it
                # against the signing identity the release was built under.
                bundle="$tmpdir/sha256:$actual.jsonl"
                if (cd "$tmpdir" && gh attestation download "$archive" --repo "$REPO" >/dev/null 2>&1) &&
                    gh attestation verify "$tmpdir/$archive" --bundle "$bundle" --repo "$LEGACY_REPO" >/dev/null 2>&1; then
                    verified=1
                fi
                ;;
        esac
    fi
    if [ "$verified" = "1" ]; then
        echo "verified build provenance attestation"
    else
        echo "error: attestation verification failed — aborting install" >&2
        echo "hint: this binary may not have been built by CI, or the release was tampered with" >&2
        echo "hint: to bypass, set MURK_SKIP_ATTESTATION=1 (not recommended)" >&2
        exit 1
    fi
elif [ "${MURK_REQUIRE_ATTESTATION:-0}" = "1" ]; then
    echo "error: MURK_REQUIRE_ATTESTATION is set but gh CLI is not installed" >&2
    echo "hint: install gh from https://cli.github.com or unset MURK_REQUIRE_ATTESTATION" >&2
    exit 1
else
    echo "warning: gh CLI not installed — skipping provenance verification" >&2
    echo "hint: install gh to verify that this binary was built by CI" >&2
fi

tar xzf "$tmpdir/$archive" -C "$tmpdir"

# Create the bin directory if needed (a DESTDIR staging tree usually starts
# empty), escalating with sudo only when the current user cannot.
if [ ! -d "$INSTALL_DIR" ] && ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    sudo mkdir -p "$INSTALL_DIR"
fi
if [ -w "$INSTALL_DIR" ]; then
    mv "$tmpdir/murk" "$INSTALL_DIR/murk"
else
    sudo mv "$tmpdir/murk" "$INSTALL_DIR/murk"
fi

echo "installed murk to $INSTALL_DIR/murk"
