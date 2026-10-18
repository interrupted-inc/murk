#!/usr/bin/env bash
# Run one cargo-mutants section and fail if its filters matched no mutants.
#
# cargo-mutants exits 0 when --file/--re (or examine_globs) match nothing, so a
# renamed file or function silently turns a section into a no-op. That is how
# the MAC section tested nothing after the module split.
#
# Usage: scripts/mutants-step.sh <section name> <output dir> [cargo-mutants args...]
set -euo pipefail

name="${1:?usage: scripts/mutants-step.sh <section name> <output dir> [args...]}"
out="${2:?usage: scripts/mutants-step.sh <section name> <output dir> [args...]}"
shift 2

status=0
cargo mutants --output "$out" "$@" || status=$?

# mutants.json lists every mutant the filters selected; it is written before
# any testing, so it exists whenever cargo-mutants got as far as filtering.
list="$out/mutants.out/mutants.json"
if [ -f "$list" ] && [ "$(jq length "$list")" -eq 0 ]; then
  echo "::error title=No mutants::$name: its file/function filters match nothing, so this section tested no code. Fix the --file/--re filters (or examine_globs) to point at the current source." >&2
  exit 1
fi
exit "$status"
