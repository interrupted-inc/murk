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
#
# Provenance: the script checks the release's build attestation with the GitHub
# CLI (gh installed and logged in: gh auth login, or GH_TOKEN). A check that
# fails always stops the install. If gh is missing or not logged in, the script
# asks on the terminal whether to install anyway (default no); without a
# terminal it stops. MURK_SKIP_ATTESTATION=1 installs without the check.
set -e

REPO="interrupted-sh/murk"
PREFIX="${PREFIX:-/usr/local}"
INSTALL_DIR="${DESTDIR:-}${MURK_INSTALL_DIR:-$PREFIX/bin}"

# HTTPS only, also after a redirect. file:// stays allowed so MURK_BASE_URL can
# point at a local fixture.
fetch() {
    curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL "$@"
}

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
    tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
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

fetch "$url" -o "$tmpdir/$archive"

# Verify checksum. SHA256SUMS comes from the same place as the archive, so this
# catches a corrupt download, not a tampered release; the attestation below
# does that.
checksums_url="$base_url/SHA256SUMS"
fetch "$checksums_url" -o "$tmpdir/SHA256SUMS"
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

# show_gh LOG — print gh's output, without blank lines or anything shaped like
# a GitHub token.
show_gh() {
    sed -e '/^[[:space:]]*$/d' \
        -e 's/gh[opsur]_[A-Za-z0-9_]*/<token>/g' \
        -e 's/github_pat_[A-Za-z0-9_]*/<token>/g' \
        -e 's/^/  gh: /' "$1" >&2
}

# unverifiable REASON HINT [LOG] — the attestation cannot be checked here.
# Say why, with gh's output if there is any. On a terminal, ask whether to
# install anyway (default no); without one (CI, a docker build), refuse.
# Returns only when the user answered yes.
unverifiable() {
    if (true </dev/tty) 2>/dev/null && (true >/dev/tty) 2>/dev/null; then
        level=warning
    else
        level=error
    fi
    echo "$level: cannot verify the build provenance of murk $tag: $1" >&2
    if [ -n "${3:-}" ]; then show_gh "$3"; fi
    echo "hint: $2" >&2
    if [ "$level" = warning ]; then
        printf "Can't verify this binary was built by murk's CI (gh is missing or not logged in). Install anyway? [y/N] " >/dev/tty
        answer=""
        read -r answer </dev/tty || answer=""
        case "$answer" in
            [yY]|[yY][eE][sS])
                echo "warning: installing murk $tag without provenance verification" >&2
                return 0
                ;;
        esac
        echo "error: not installing murk $tag without provenance verification" >&2
    else
        echo "hint: to install without this check, set MURK_SKIP_ATTESTATION=1" >&2
    fi
    echo "hint: other ways to install: 'brew install interrupted-sh/tap/murk' or 'cargo install murk-cli'" >&2
    echo "hint: or run 'gh auth login' and rerun this script" >&2
    exit 1
}

# gh_logged_in LOG — the active github.com account works. Plain `gh auth
# status` also fails for an expired account that is not the active one, so ask
# about the active account only; gh releases without --active fall back to
# the plain check.
gh_logged_in() {
    gh auth status --active --hostname github.com >"$1" 2>&1 && return 0
    grep -q 'unknown flag: --active' "$1" || return 1
    gh auth status --hostname github.com >"$1" 2>&1
}

# Verify build provenance. The attestation must name the repository and release
# workflow that built this tag, from a tag push, on a GitHub-hosted runner. The
# repository has moved twice, so older releases name an older identity:
#   v0.3.1 - v0.3.x     iicky/murk, release.yml
#   v0.4.0 - v0.10.1    iicky/murk, release.yaml
#   v0.10.2 - v0.11.x   interrupted-inc/murk, release.yaml
#   v0.12.0 and later   interrupted-sh/murk, release.yaml
# The attestations of the two older identities are fetched first, by the owner
# that holds them, then checked against that identity. A check that ran and
# failed always stops the install; only a check that could not run (no gh, no
# confirmed login) offers to go on.
verify=1
if [ "${MURK_SKIP_ATTESTATION:-0}" = "1" ]; then
    echo "warning: skipping provenance verification (MURK_SKIP_ATTESTATION=1)" >&2
else
    workflow=release.yaml
    case "$tag" in
        v0.[0-2].*|v0.3.0)
            echo "error: cannot verify the build provenance of murk $tag: releases before v0.3.1 have no attestation" >&2
            echo "hint: install v0.3.1 or later, or set MURK_SKIP_ATTESTATION=1 to install it without this check" >&2
            exit 1
            ;;
        v0.3.*)
            signer=iicky/murk workflow=release.yml fetch_from="--owner iicky" ;;
        v0.[4-9].*|v0.10.[01])
            signer=iicky/murk fetch_from="--owner iicky" ;;
        v0.10.*|v0.11.*)
            signer=interrupted-inc/murk fetch_from="--repo $REPO" ;;
        *)
            signer=$REPO fetch_from="" ;;
    esac
    auth_log="$tmpdir/gh-auth.log"
    if ! command -v gh >/dev/null 2>&1; then
        unverifiable "the GitHub CLI (gh) is not installed" \
            "install gh from https://cli.github.com, run 'gh auth login', then rerun"
        verify=0
    elif ! gh_logged_in "$auth_log"; then
        unverifiable "gh could not confirm a login to github.com" \
            "run 'gh auth login' (or set GH_TOKEN), or if gh reported a network error, rerun later" \
            "$auth_log"
        verify=0
    fi
fi
if [ "$verify" = "1" ] && [ "${MURK_SKIP_ATTESTATION:-0}" != "1" ]; then
    gh_log="$tmpdir/gh.log"
    set -- "$tmpdir/$archive"
    verified=1
    if [ -n "$fetch_from" ]; then
        # $fetch_from is an option and its value, so it must split.
        # shellcheck disable=SC2086
        if (cd "$tmpdir" && gh attestation download "$archive" $fetch_from) >"$gh_log" 2>&1; then
            set -- "$@" --bundle "$tmpdir/sha256:$actual.jsonl"
        else
            verified=0
        fi
    fi
    if [ "$verified" = "1" ] && ! gh attestation verify "$@" \
        --repo "$signer" \
        --signer-workflow "$signer/.github/workflows/$workflow" \
        --source-ref "refs/tags/$tag" \
        --deny-self-hosted-runners >"$gh_log" 2>&1; then
        verified=0
    fi
    if [ "$verified" = "1" ]; then
        echo "verified build provenance attestation ($signer)"
    else
        echo "error: attestation verification failed — aborting install" >&2
        show_gh "$gh_log"
        echo "hint: $archive does not carry a valid attestation from the $signer release workflow for $tag" >&2
        echo "hint: do not install it. If gh could not reach GitHub, rerun later" >&2
        exit 1
    fi
fi

# --no-same-owner: as root, tar would otherwise keep the archive's uid (the CI
# runner's), and that local account could then replace the installed binary.
tar --no-same-owner -xzf "$tmpdir/$archive" -C "$tmpdir"

# Create the bin directory if needed (a DESTDIR staging tree usually starts
# empty), escalating with sudo only when the current user cannot.
if [ ! -d "$INSTALL_DIR" ] && ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    sudo mkdir -p "$INSTALL_DIR"
fi
# install(1) copies, so the result belongs to whoever runs it: root under sudo,
# not the user who downloaded the archive.
if [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$tmpdir/murk" "$INSTALL_DIR/murk"
else
    sudo install -m 0755 "$tmpdir/murk" "$INSTALL_DIR/murk"
fi

echo "installed murk $tag to $INSTALL_DIR/murk"
