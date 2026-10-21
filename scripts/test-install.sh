#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Checks install.sh against a local fake release served over file:// (no
# network): where it puts the binary (DESTDIR, PREFIX, MURK_INSTALL_DIR), how
# it verifies provenance (with a fake gh that records its arguments), that it
# refuses plain http, and, when run as root, who owns the installed binary.
# Run from the repository root: sh scripts/test-install.sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
server=""
trap '[ -n "$server" ] && kill "$server" 2>/dev/null; rm -rf "$work"' EXIT

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# One archive per supported target and tag, so the fixture matches whichever
# target install.sh picks for this host.
rel="$work/release"
mkdir -p "$rel" "$work/stage"
printf '#!/bin/sh\necho fake-murk\n' > "$work/stage/murk"
chmod +x "$work/stage/murk"
for tag in v0.0.0-test v0.13.0 v0.11.0 v0.10.2 v0.10.1 v0.4.1 v0.3.1 v0.2.0; do
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
        arm-unknown-linux-gnueabihf x86_64-apple-darwin aarch64-apple-darwin; do
        tar czf "$rel/murk-${tag}-${target}.tar.gz" -C "$work/stage" murk
    done
done
(cd "$rel" && sha256 ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)

# A fake gh that logs every call. FAKE_GH_AUTH picks how `gh auth status`
# behaves:
#   ok        logged in
#   no        not logged in; the output carries a token-shaped string
#   network   the login check times out
#   inactive  the active account works, an inactive one has expired, so only
#             --active succeeds
#   old       a gh without --active that is logged in
# FAKE_GH_VERIFY=no makes `gh attestation verify` fail. `download` writes the
# bundle under the name gh uses, and `verify --bundle` needs that file.
mkdir -p "$work/fakegh"
cat > "$work/fakegh/gh" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_GH_LOG"
active=no
for arg in "$@"; do [ "$arg" = --active ] && active=yes; done
case "$1 $2" in
    "auth status")
        case "${FAKE_GH_AUTH:-ok}:$active" in
            ok:*|inactive:yes|old:no) ;;
            no:*)
                echo "You are not logged into any GitHub hosts. Token: ghp_FAKESECRET123" >&2
                exit 1
                ;;
            network:*)
                echo "X Timeout trying to log in to github.com account someone (keyring)" >&2
                exit 1
                ;;
            inactive:no)
                echo "X Failed to log in to github.com account expired-old (keyring)" >&2
                exit 1
                ;;
            old:yes)
                echo "unknown flag: --active" >&2
                exit 1
                ;;
        esac
        ;;
    "attestation download")
        if command -v sha256sum >/dev/null 2>&1; then
            digest=$(sha256sum "$3" | cut -d' ' -f1)
        else
            digest=$(shasum -a 256 "$3" | cut -d' ' -f1)
        fi
        echo '{}' > "sha256:$digest.jsonl"
        ;;
    "attestation verify")
        prev=""
        for arg in "$@"; do
            if [ "$prev" = "--bundle" ] && [ ! -f "$arg" ]; then
                echo "Error: bundle $arg not found" >&2
                exit 1
            fi
            prev=$arg
        done
        if [ "${FAKE_GH_VERIFY:-ok}" != ok ]; then
            echo "Error: verifying with issuer \"sigstore.dev\": fake-gh-refused" >&2
            exit 1
        fi
        ;;
esac
EOF
chmod +x "$work/fakegh/gh"

# A PATH with the tools install.sh needs and no gh.
mkdir -p "$work/nogh"
for tool in sh uname curl grep cut mktemp rm sha256sum shasum tar gzip mkdir \
    install mv sed cat; do
    if p=$(command -v "$tool"); then ln -s "$p" "$work/nogh/$tool"; fi
done

failures=0
fail() {
    echo "FAIL $1: $2"
    [ -f "$work/$1.log" ] && sed 's/^/    /' "$work/$1.log"
    failures=$((failures + 1))
}

# terminal.py ANSWER COMMAND... — run COMMAND with a terminal, or without one.
# ANSWER "-": no controlling terminal (a new session, stdin from /dev/null), as
# in CI or a docker build. Any other ANSWER: COMMAND runs on a pseudo-terminal;
# when it asks "[y/N]" the ANSWER is typed. COMMAND's output goes to stdout;
# the exit status is COMMAND's.
py=$(command -v python3) || { echo "FAIL: scripts/test-install.sh needs python3"; exit 1; }
cat > "$work/terminal.py" <<'EOF'
import os, pty, select, sys

answer, cmd = sys.argv[1], sys.argv[2:]
if answer == "-":
    pid = os.fork()
    if pid == 0:
        os.setsid()
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        os.execvp(cmd[0], cmd)
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
out, sent = b"", False
while True:
    ready, _, _ = select.select([fd], [], [], 60)
    if not ready:
        os.kill(pid, 9)
        break
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    if not sent and b"[y/N]" in out:
        os.write(fd, answer.encode() + b"\n")
        sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(status))
EOF

# run NAME ASSIGNMENTS... — run install.sh with only the given variables set
# (plus the fixture release); its output goes to $work/NAME.log, and its gh
# calls to $work/NAME.gh. There is no terminal unless TTY_ANSWER=ANSWER is
# passed: install.sh then runs on a pseudo-terminal that types ANSWER when
# asked. Returns install.sh's exit status.
run() {
    name=$1
    shift
    : > "$work/$name.gh"
    (
        unset DESTDIR PREFIX MURK_INSTALL_DIR MURK_SKIP_ATTESTATION FAKE_GH_AUTH FAKE_GH_VERIFY TTY_ANSWER
        export MURK_TAG=v0.0.0-test MURK_BASE_URL="file://$rel" FAKE_GH_LOG="$work/$name.gh"
        for assignment in "$@"; do export "${assignment?}"; done
        "$py" "$work/terminal.py" "${TTY_ANSWER--}" sh "$root/install.sh"
    ) > "$work/$name.log" 2>&1
}

# asked NAME — install.sh asked its question on the terminal of run NAME.
asked() {
    if ! grep -qF "Install anyway? [y/N]" "$work/$1.log"; then
        fail "$1" "install.sh did not ask on the terminal"
    fi
}

# succeeds NAME ASSIGNMENTS... — install.sh exits 0.
succeeds() {
    if ! run "$@"; then
        fail "$1" "install.sh exited non-zero"
        return 1
    fi
}

# refuses NAME ASSIGNMENTS... — install.sh exits non-zero and installs nothing.
# Every run passes MURK_INSTALL_DIR=$work/NAME/bin.
refuses() {
    if run "$@"; then
        fail "$1" "install.sh exited 0"
        return 1
    fi
    absent "$1" "$work/$1/bin/murk"
}

# passed NAME SINCE — print ok for NAME if no check failed since the failure
# count was SINCE.
passed() {
    if [ "$failures" -eq "$2" ]; then echo "ok   $1"; fi
}

# expect NAME PATH — the installed binary exists at PATH and runs.
expect() {
    if [ "$("$2" 2>/dev/null)" != "fake-murk" ]; then
        fail "$1" "no working binary at $2"
    fi
}

# absent NAME PATH — nothing was written to PATH.
absent() {
    if [ -e "$2" ]; then
        fail "$1" "unexpected file at $2"
    fi
}

# says NAME TEXT — the output of run NAME contains TEXT.
says() {
    if ! grep -qF -- "$2" "$work/$1.log"; then
        fail "$1" "output lacks: $2"
    fi
}

# never_says NAME TEXT — the output of run NAME does not contain TEXT.
never_says() {
    if grep -qF -- "$2" "$work/$1.log"; then
        fail "$1" "output contains: $2"
    fi
}

# called NAME ARGS — fake gh saw a call with exactly ARGS.
called() {
    if ! grep -qxF -- "$2" "$work/$1.gh"; then
        fail "$1" "gh was not called as: gh $2"
        sed 's/^/    gh /' "$work/$1.gh"
    fi
}

## Install location

before=$failures
if succeeds prefix MURK_SKIP_ATTESTATION=1 "PREFIX=$work/prefix"; then
    expect prefix "$work/prefix/bin/murk"
fi
passed prefix "$before"

before=$failures
if succeeds destdir MURK_SKIP_ATTESTATION=1 "DESTDIR=$work/dest" "PREFIX=$work/usr"; then
    expect destdir "$work/dest$work/usr/bin/murk"
    absent destdir "$work/usr/bin/murk"
fi
passed destdir "$before"

before=$failures
if succeeds install-dir MURK_SKIP_ATTESTATION=1 "PREFIX=$work/ignored" "MURK_INSTALL_DIR=$work/custom"; then
    expect install-dir "$work/custom/murk"
    absent install-dir "$work/ignored/bin/murk"
fi
passed install-dir "$before"

before=$failures
if succeeds destdir-install-dir MURK_SKIP_ATTESTATION=1 "DESTDIR=$work/dest2" "MURK_INSTALL_DIR=$work/custom2"; then
    expect destdir-install-dir "$work/dest2$work/custom2/murk"
    absent destdir-install-dir "$work/custom2/murk"
fi
passed destdir-install-dir "$before"

## Provenance: no check possible

# Without gh nothing can be checked. Without a terminal to ask on (CI, a docker
# build), the install stops.
before=$failures
if refuses no-gh MURK_TAG=v0.13.0 "PATH=$work/nogh" "MURK_INSTALL_DIR=$work/no-gh/bin"; then
    says no-gh "gh) is not installed"
    says no-gh "MURK_SKIP_ATTESTATION=1"
    says no-gh "brew install interrupted-sh/tap/murk"
    passed no-gh "$before"
fi

# On a terminal it asks, and installs only on yes.
before=$failures
if succeeds tty-yes MURK_TAG=v0.13.0 TTY_ANSWER=y "PATH=$work/nogh" \
    "MURK_INSTALL_DIR=$work/tty-yes/bin"; then
    asked tty-yes
    says tty-yes "installing murk v0.13.0 without provenance verification"
    expect tty-yes "$work/tty-yes/bin/murk"
fi
passed tty-yes "$before"

before=$failures
if refuses tty-no MURK_TAG=v0.13.0 TTY_ANSWER=n "PATH=$work/nogh" \
    "MURK_INSTALL_DIR=$work/tty-no/bin"; then
    asked tty-no
    says tty-no "brew install interrupted-sh/tap/murk"
    says tty-no "cargo install murk-cli"
    says tty-no "gh auth login"
    passed tty-no "$before"
fi

# Just pressing return is no; so is an unconfirmed login.
before=$failures
if refuses tty-default MURK_TAG=v0.13.0 TTY_ANSWER= FAKE_GH_AUTH=no \
    "PATH=$work/fakegh:$PATH" "MURK_INSTALL_DIR=$work/tty-default/bin"; then
    asked tty-default
    says tty-default "could not confirm a login to github.com"
    passed tty-default "$before"
fi

before=$failures
if succeeds tty-yes-logged-out MURK_TAG=v0.13.0 TTY_ANSWER=yes FAKE_GH_AUTH=no \
    "PATH=$work/fakegh:$PATH" "MURK_INSTALL_DIR=$work/tty-yes-logged-out/bin"; then
    asked tty-yes-logged-out
    if grep -q '^attestation' "$work/tty-yes-logged-out.gh"; then
        fail tty-yes-logged-out "gh attestation was called"
    fi
    expect tty-yes-logged-out "$work/tty-yes-logged-out/bin/murk"
fi
passed tty-yes-logged-out "$before"

# gh without a login cannot check either. That is not evidence of tampering.
# gh's own reason is shown, without anything shaped like a token.
before=$failures
if refuses gh-logged-out MURK_TAG=v0.13.0 FAKE_GH_AUTH=no "PATH=$work/fakegh:$PATH" \
    "MURK_INSTALL_DIR=$work/gh-logged-out/bin"; then
    says gh-logged-out "could not confirm a login to github.com"
    says gh-logged-out "gh: You are not logged into any GitHub hosts."
    never_says gh-logged-out "ghp_FAKESECRET123"
    never_says gh-logged-out "tampered"
    never_says gh-logged-out "verification failed"
    passed gh-logged-out "$before"
fi

# A login check that times out is reported as gh reported it, not as a
# missing login.
before=$failures
if refuses gh-network MURK_TAG=v0.13.0 FAKE_GH_AUTH=network "PATH=$work/fakegh:$PATH" \
    "MURK_INSTALL_DIR=$work/gh-network/bin"; then
    says gh-network "gh: X Timeout trying to log in to github.com"
    says gh-network "rerun later"
    never_says gh-network "verification failed"
    passed gh-network "$before"
fi

# An expired account that is not the active one does not block the install.
before=$failures
if succeeds gh-inactive-expired MURK_TAG=v0.13.0 FAKE_GH_AUTH=inactive "PATH=$work/fakegh:$PATH" \
    "MURK_INSTALL_DIR=$work/gh-inactive-expired/bin"; then
    expect gh-inactive-expired "$work/gh-inactive-expired/bin/murk"
fi
passed gh-inactive-expired "$before"

# A gh that predates --active falls back to the plain check.
before=$failures
if succeeds gh-without-active MURK_TAG=v0.13.0 FAKE_GH_AUTH=old "PATH=$work/fakegh:$PATH" \
    "MURK_INSTALL_DIR=$work/gh-without-active/bin"; then
    expect gh-without-active "$work/gh-without-active/bin/murk"
fi
passed gh-without-active "$before"

# No attestation was ever published before v0.3.1.
before=$failures
if refuses unattested MURK_TAG=v0.2.0 "PATH=$work/fakegh:$PATH" "MURK_INSTALL_DIR=$work/unattested/bin"; then
    says unattested "before v0.3.1 have no attestation"
    if grep -q '^attestation' "$work/unattested.gh"; then
        fail unattested "gh attestation was called"
    fi
    passed unattested "$before"
fi

before=$failures
if succeeds skip MURK_TAG=v0.13.0 MURK_SKIP_ATTESTATION=1 "PATH=$work/nogh" "MURK_INSTALL_DIR=$work/skip/bin"; then
    expect skip "$work/skip/bin/murk"
fi
passed skip "$before"

## Provenance: failed check

# A failed verification is fatal, shows gh's reason, does not advertise the
# bypass, and does not ask, even on a terminal.
before=$failures
if refuses gh-refuses MURK_TAG=v0.13.0 FAKE_GH_VERIFY=no TTY_ANSWER=y \
    "PATH=$work/fakegh:$PATH" "MURK_INSTALL_DIR=$work/gh-refuses/bin"; then
    says gh-refuses "attestation verification failed"
    says gh-refuses "fake-gh-refused"
    never_says gh-refuses "MURK_SKIP_ATTESTATION"
    if grep -qF "Install anyway" "$work/gh-refuses.log"; then
        fail gh-refuses "install.sh asked whether to install anyway"
    fi
    passed gh-refuses "$before"
fi

## Provenance: the identity each release is checked against

# identity TAG REPO WORKFLOW FETCH — install TAG with gh present and check that
# it verified against REPO's WORKFLOW, from the tag, on a hosted runner. FETCH
# is where gh attestation download fetches the bundle from ("" when verify
# fetches it from REPO itself).
identity() {
    name="identity-$1"
    before=$failures
    succeeds "$name" "MURK_TAG=$1" "PATH=$work/fakegh:$PATH" "MURK_INSTALL_DIR=$work/$name/bin" || return 0
    archive=$(sed -n 's/^attestation verify \([^ ]*\) .*/\1/p' "$work/$name.gh")
    if [ -z "$archive" ]; then
        fail "$name" "gh attestation verify was not called"
        return 0
    fi
    file=$(basename "$archive")
    pin="--repo $2 --signer-workflow $2/.github/workflows/$3 --source-ref refs/tags/$1 --deny-self-hosted-runners"
    if [ -n "$4" ]; then
        digest=$(grep -F " $file" "$rel/SHA256SUMS" | cut -d' ' -f1)
        called "$name" "attestation download $file $4"
        called "$name" "attestation verify $archive --bundle $(dirname "$archive")/sha256:$digest.jsonl $pin"
    else
        called "$name" "attestation verify $archive $pin"
    fi
    expect "$name" "$work/$name/bin/murk"
    passed "$name" "$before"
}

identity v0.13.0 interrupted-sh/murk release.yaml ""
identity v0.11.0 interrupted-inc/murk release.yaml "--repo interrupted-sh/murk"
identity v0.10.2 interrupted-inc/murk release.yaml "--repo interrupted-sh/murk"
identity v0.10.1 iicky/murk release.yaml "--owner iicky"
identity v0.4.1 iicky/murk release.yaml "--owner iicky"
identity v0.3.1 iicky/murk release.yml "--owner iicky"

## Transport

# Plain http, even for a mirror, is refused.
if command -v python3 >/dev/null 2>&1; then
    port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    python3 -m http.server "$port" --bind 127.0.0.1 --directory "$rel" >/dev/null 2>&1 &
    server=$!
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        curl -fsS "http://127.0.0.1:$port/SHA256SUMS" -o /dev/null 2>/dev/null && break
        sleep 0.25
    done
    if refuses plain-http MURK_SKIP_ATTESTATION=1 "MURK_BASE_URL=http://127.0.0.1:$port" \
        "MURK_INSTALL_DIR=$work/plain-http/bin"; then
        echo "ok   plain-http"
    fi
    kill "$server"
    wait "$server" 2>/dev/null || true
    server=""
else
    echo "skip plain-http: no python3 to serve the fixture"
fi

## Ownership

# As root, the installed binary belongs to root, not to the uid recorded in the
# release archive (the CI runner's).
if [ "$(id -u)" = 0 ]; then
    mkdir -p "$work/owned/release" "$work/owned/stage"
    cp "$work/stage/murk" "$work/owned/stage/murk"
    chown 1001:1001 "$work/owned/stage/murk"
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
        arm-unknown-linux-gnueabihf x86_64-apple-darwin aarch64-apple-darwin; do
        tar czf "$work/owned/release/murk-v0.0.0-test-${target}.tar.gz" -C "$work/owned/stage" murk
    done
    (cd "$work/owned/release" && sha256 ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)
    if succeeds root-owner MURK_SKIP_ATTESTATION=1 "MURK_BASE_URL=file://$work/owned/release" \
        "MURK_INSTALL_DIR=$work/owned/bin"; then
        if [ -n "$(find "$work/owned/bin/murk" -user 0)" ]; then
            echo "ok   root-owner"
        else
            fail root-owner "installed binary is not owned by root"
        fi
    fi
else
    echo "skip root-owner: needs root"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures install check(s) failed"
    exit 1
fi
echo "install checks passed"
