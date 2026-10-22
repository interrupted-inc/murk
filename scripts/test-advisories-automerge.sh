#!/usr/bin/env bash
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Checks scripts/advisories-automerge.sh against a throwaway git repository
# and a fake gh that records its calls: which advisory fix PRs get auto-merge,
# and that it is turned off again when a PR no longer qualifies.
# Run from the repository root: bash scripts/test-advisories-automerge.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The fake gh: `pr diff --name-only` prints $FAKE_FILES, `pr view` prints
# $FAKE_AUTO (whether auto-merge is on), every call is logged to $FAKE_GH_LOG.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/bin/sh
echo "$*" >>"$FAKE_GH_LOG"
case "$1 $2" in
  "pr diff") printf '%s\n' "$FAKE_FILES" ;;
  "pr view") echo "$FAKE_AUTO" ;;
esac
EOF
chmod +x "$work/bin/gh"

lock() {
  printf 'version = 4\n'
  while [ "$#" -gt 0 ]; do
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' "$1" "$2"
    shift 2
  done
}

# repo NAME NEW_LOCK_ARGS... — a repository whose HEAD^ has the base lockfiles
# and whose HEAD changes Cargo.lock to the given packages.
repo() {
  local dir="$work/$1"
  shift
  mkdir -p "$dir/fuzz"
  git -C "$dir" init -q
  lock clap 4.6.1 keccak 0.1.5 >"$dir/Cargo.lock"
  lock clap 4.6.1 >"$dir/fuzz/Cargo.lock"
  git -C "$dir" add -A
  git -C "$dir" -c user.name=t -c user.email=t@t commit -qm base
  lock "$@" >"$dir/Cargo.lock"
  git -C "$dir" -c user.name=t -c user.email=t@t commit -qam fix
}

failures=0

# check NAME FILES AUTO MANUAL WANT — run the script for a repo NAME made by
# repo, with the PR's file list FILES, auto-merge already on if AUTO is true,
# and MANUAL as the manual-commit list. WANT is the merge call expected:
# "auto", "disable" or "none".
check() {
  local name=$1 files=$2 auto=$3 manual=$4 want=$5 log="$work/$1.gh"
  : >"$log"
  if ! (cd "$work/$name" && PATH="$work/bin:$PATH" FAKE_GH_LOG="$log" FAKE_FILES="$files" \
    FAKE_AUTO="$auto" bash "$root/scripts/advisories-automerge.sh" 7 "$manual") >"$work/$name.out" 2>&1; then
    echo "FAIL $name: script exited non-zero"
    sed 's/^/    /' "$work/$name.out"
    failures=$((failures + 1))
    return
  fi
  local got=none
  if grep -qxF 'pr merge 7 --auto --rebase' "$log"; then got=auto; fi
  if grep -qxF 'pr merge 7 --disable-auto' "$log"; then got=${got/none/}disable; fi
  if [ "$got" = "$want" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: wanted $want, got $got"
    sed 's/^/    gh /' "$log"
    failures=$((failures + 1))
  fi
}

locks=$'Cargo.lock\nfuzz/Cargo.lock'

repo clap-bump clap 4.6.2 keccak 0.1.5
check clap-bump "$locks" false "" auto

repo held-bump clap 4.6.1 keccak 0.1.6
check held-bump "$locks" false "" none

# An earlier run turned auto-merge on; this run's fix moves a held crate.
repo held-bump-armed clap 4.6.1 keccak 0.1.6
check held-bump-armed "$locks" true "" disable

# The branch has a maintainer's commit, so a human merges it.
repo manual-armed clap 4.6.2 keccak 0.1.5
check manual-armed "$locks" true "Maintainer <m@example.com>" disable

repo more-than-locks-armed clap 4.6.2 keccak 0.1.5
check more-than-locks-armed "$locks"$'\n'"deny.toml" true "" disable

if [ "$failures" -ne 0 ]; then
  echo "$failures advisories auto-merge check(s) failed"
  exit 1
fi
echo "advisories auto-merge checks passed"
