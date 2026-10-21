#!/usr/bin/env bash
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Turn auto-merge of the advisories fix PR on or off. Used by
# .github/workflows/advisories.yaml, from the default branch checkout.
#
# Usage: scripts/advisories-automerge.sh PR [MANUAL]
#   PR      the fix PR's number
#   MANUAL  non-empty when the fix branch has commits from someone other than
#           the workflow; HEAD is then the default branch, not the fix commit
#
# The PR merges on green CI only when it changes nothing but Cargo.lock and
# fuzz/Cargo.lock, has no manual commits, and moves no crate that
# scripts/automerge-policy.cjs holds for review. Otherwise auto-merge is turned
# off, also when an earlier run turned it on. Run from the repository root,
# with HEAD at the fix commit and HEAD^ at the default branch.
set -euo pipefail

pr=$1
manual=${2:-}
here=$(cd "$(dirname "$0")" && pwd)

# Fetch the file list on its own line so a failed request fails the script
# instead of reading as "lockfiles only".
files=$(gh pr diff "$pr" --name-only)
others=$(grep -vxE 'Cargo\.lock|fuzz/Cargo\.lock' <<<"$files" || true)

reason=''
if [ -n "$manual" ]; then
  reason="has commits from others"
elif [ -n "$others" ]; then
  reason="changes more than lockfiles: $(paste -sd, - <<<"$others")"
else
  base=$(mktemp -d)
  trap 'rm -rf "$base"' EXIT
  mkdir -p "$base/fuzz"
  git show 'HEAD^:Cargo.lock' >"$base/Cargo.lock"
  git show 'HEAD^:fuzz/Cargo.lock' >"$base/fuzz/Cargo.lock"
  rc=0
  node "$here/automerge-policy.cjs" --lockfiles \
    "$base/Cargo.lock" Cargo.lock \
    "$base/fuzz/Cargo.lock" fuzz/Cargo.lock || rc=$?
  case "$rc" in
    0)
      gh pr merge "$pr" --auto --rebase
      exit 0
      ;;
    10) reason="updates a security-relevant crate" ;;
    *) exit "$rc" ;;
  esac
fi

echo "::notice::PR #$pr $reason, leaving it for review"
if [ "$(gh pr view "$pr" --json autoMergeRequest --jq '.autoMergeRequest != null')" = true ]; then
  gh pr merge "$pr" --disable-auto
fi
