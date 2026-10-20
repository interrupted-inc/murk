#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Checks where install.sh puts the binary: DESTDIR, PREFIX and
# MURK_INSTALL_DIR, against a local fake release served over file:// (no
# network, no root). Run from the repository root: sh scripts/test-install.sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tag=v0.0.0-test
rel="$work/release"
mkdir -p "$rel" "$work/stage"
printf '#!/bin/sh\necho fake-murk\n' > "$work/stage/murk"
chmod +x "$work/stage/murk"
# One archive per supported target, so the fixture matches whichever
# target install.sh picks for this host.
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    arm-unknown-linux-gnueabihf x86_64-apple-darwin aarch64-apple-darwin; do
    tar czf "$rel/murk-${tag}-${target}.tar.gz" -C "$work/stage" murk
done
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$rel" && sha256sum ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)
else
    (cd "$rel" && shasum -a 256 ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)
fi

failures=0

# install NAME ASSIGNMENTS... — run install.sh with only the given location
# variables set.
install() {
    name=$1
    shift
    if ! (
        unset DESTDIR PREFIX MURK_INSTALL_DIR
        export MURK_TAG="$tag" MURK_BASE_URL="file://$rel" MURK_SKIP_ATTESTATION=1
        for assignment in "$@"; do export "${assignment?}"; done
        sh "$root/install.sh"
    ) > "$work/$name.log" 2>&1; then
        echo "FAIL $name: install.sh exited non-zero"
        cat "$work/$name.log"
        failures=$((failures + 1))
        return 1
    fi
}

# expect NAME PATH — the installed binary exists at PATH and runs.
expect() {
    if [ "$("$2" 2>/dev/null)" = "fake-murk" ]; then
        echo "ok   $1"
    else
        echo "FAIL $1: no working binary at $2"
        failures=$((failures + 1))
    fi
}

# absent NAME PATH — nothing was written to PATH.
absent() {
    if [ -e "$2" ]; then
        echo "FAIL $1: unexpected file at $2"
        failures=$((failures + 1))
    fi
}

if install prefix "PREFIX=$work/prefix"; then
    expect prefix "$work/prefix/bin/murk"
fi

if install destdir "DESTDIR=$work/dest" "PREFIX=$work/usr"; then
    expect destdir "$work/dest$work/usr/bin/murk"
    absent destdir "$work/usr/bin/murk"
fi

if install install-dir "PREFIX=$work/ignored" "MURK_INSTALL_DIR=$work/custom"; then
    expect install-dir "$work/custom/murk"
    absent install-dir "$work/ignored/bin/murk"
fi

if install destdir-install-dir "DESTDIR=$work/dest2" "MURK_INSTALL_DIR=$work/custom2"; then
    expect destdir-install-dir "$work/dest2$work/custom2/murk"
    absent destdir-install-dir "$work/custom2/murk"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures install location check(s) failed"
    exit 1
fi
echo "install location checks passed"
