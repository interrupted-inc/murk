#!/usr/bin/env bash
# Fix RustSec advisories in Cargo.lock and fuzz/Cargo.lock with the smallest
# updates that clear them, then verify the result.
#
# Usage: scripts/fix-advisories.sh [OUT_DIR]
#
# For every advisory cargo audit reports (vulnerabilities, plus the unsound and
# unmaintained warnings CI denies), minus the ones deny.toml ignores, the script
# runs `cargo update -p <crate>@<current> --precise <version>`, where <version>
# is the lowest published, semver-compatible version the advisory lists as
# patched. It never runs a blanket `cargo update`. Advisories with no such
# version, or whose update fails, are reported as unfixable.
#
# When a lockfile changed, the script checks that `cargo deny check advisories`
# reports nothing beyond the unfixable advisories, and that the workspace still
# builds (`cargo build --locked --all-features` for the root, `cargo check
# --locked` for fuzz). It exits non-zero if either check fails.
#
# It writes these files to OUT_DIR (default: a new temporary directory):
#   fixed.tsv        workspace, advisory, crate, old version, new version, title
#   unfixable.tsv    workspace, advisory, crate, version, reason, title
#   commit-message   one line, also the PR title (only when something was fixed)
#   pr-body.md       (only when something was fixed)
#   issue-body.md    (only when something is unfixable)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$(mktemp -d)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$root"

workspaces=(. fuzz)
tab=$'\t'

# Print the RUSTSEC IDs in the ignore list of deny.toml's [advisories] table.
ignored_ids() {
  awk '
    /^[[:space:]]*\[/ { in_adv = ($0 ~ /^[[:space:]]*\[advisories\]/); in_list = 0 }
    in_adv && /^[[:space:]]*ignore[[:space:]]*=/ { in_list = 1 }
    in_list { sub(/#.*/, ""); print; if (/\]/) in_list = 0 }
  ' deny.toml | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' || true
}

audit_args=(--json)
while read -r id; do
  [ -n "$id" ] && audit_args+=(--ignore "$id")
done < <(ignored_ids)

# Write one TSV row per advisory affecting workspace $1 to stdout: advisory,
# crate, version, patched requirements joined with ";" ("-" when none), title.
# $2 is "fetch" for the first audit, which downloads the advisory database.
audit() {
  local json=$work/audit.json fetch=()
  [ "$2" = fetch ] || fetch=(--no-fetch)
  # cargo audit exits non-zero when it finds anything, so judge by its output.
  cargo audit "${fetch[@]}" "${audit_args[@]}" --file "$1/Cargo.lock" >"$json" || true
  jq -e '.vulnerabilities.list' "$json" >/dev/null \
    || { echo "cargo audit failed for $1/Cargo.lock" >&2; exit 1; }
  jq -r '
    [.vulnerabilities.list[], (.warnings.unsound // [])[], (.warnings.unmaintained // [])[]]
    | map(select(.advisory != null))
    | .[]
    | [.advisory.id, .package.name, .package.version,
       ((.versions.patched // []) | if length == 0 then "-" else join(";") end),
       (.advisory.title | gsub("[\t\n]"; " "))]
    | @tsv
  ' "$json" | sort -u
}

# Succeed when x.y.z version $1 compares to x.y.z version $3 as operator $2.
ver_test() {
  local a1 a2 a3 b1 b2 b3 c=0
  IFS=. read -r a1 a2 a3 <<<"$1"
  IFS=. read -r b1 b2 b3 <<<"$3"
  if ((a1 != b1)); then c=$((a1 < b1 ? -1 : 1))
  elif ((a2 != b2)); then c=$((a2 < b2 ? -1 : 1))
  elif ((a3 != b3)); then c=$((a3 < b3 ? -1 : 1))
  fi
  case $2 in
    '<') ((c < 0)) ;;
    '<=') ((c <= 0)) ;;
    '>') ((c > 0)) ;;
    '>=') ((c >= 0)) ;;
    '=') ((c == 0)) ;;
  esac
}

# Succeed when x.y.z version $1 satisfies Cargo version requirement $2, such as
# "^1.2.3", ">=0.23.46" or ">=1.2.0, <1.3.0". Partial versions ("1.2") and
# wildcards ("1.*") follow Cargo's rules.
satisfies() {
  local ver=$1 cmp op v maj min pat n lo hi
  local -a cmps
  IFS=, read -ra cmps <<<"$2"
  for cmp in "${cmps[@]}"; do
    cmp=${cmp//[[:space:]]/}
    op=${cmp%%[0-9*]*}
    v=${cmp#"$op"}
    v=${v%%[-+]*}  # drop pre-release and build metadata
    v=${v%%.\**}   # "1.*" means "1"
    [ "$v" = '*' ] || [ -z "$v" ] && continue
    IFS=. read -r maj min pat <<<"$v"
    n=3; [ -z "$pat" ] && n=2; [ -z "$min" ] && n=1
    min=${min:-0}; pat=${pat:-0}
    lo=$maj.$min.$pat
    # The first version above the given components, e.g. "1.2" -> 1.3.0.
    case $n in
      1) hi=$((maj + 1)).0.0 ;;
      2) hi=$maj.$((min + 1)).0 ;;
      3) hi=$maj.$min.$((pat + 1)) ;;
    esac
    case $op in
      '' | '^')
        if ((maj > 0 || n == 1)); then hi=$((maj + 1)).0.0
        elif ((min > 0 || n == 2)); then hi=0.$((min + 1)).0
        else hi=0.0.$((pat + 1))
        fi
        ver_test "$ver" '>=' "$lo" && ver_test "$ver" '<' "$hi" || return 1 ;;
      '~')
        ((n == 1)) || hi=$maj.$((min + 1)).0
        ver_test "$ver" '>=' "$lo" && ver_test "$ver" '<' "$hi" || return 1 ;;
      '=')
        ver_test "$ver" '>=' "$lo" && ver_test "$ver" '<' "$hi" || return 1 ;;
      '>=') ver_test "$ver" '>=' "$lo" || return 1 ;;
      '>') ver_test "$ver" '>=' "$hi" || return 1 ;;
      '<') ver_test "$ver" '<' "$lo" || return 1 ;;
      '<=') ver_test "$ver" '<' "$hi" || return 1 ;;
      *) echo "unsupported version requirement: $2" >&2; return 1 ;;
    esac
  done
}

# Print the published, non-yanked release versions of crate $1 that are newer
# than $2 and semver-compatible with it, lowest first.
candidates() {
  local name path
  name=$(tr '[:upper:]' '[:lower:]' <<<"$1")
  case ${#name} in
    1) path=1/$name ;;
    2) path=2/$name ;;
    3) path=3/${name:0:1}/$name ;;
    *) path=${name:0:2}/${name:2:2}/$name ;;
  esac
  curl -fsSL "https://index.crates.io/$path" \
    | jq -r 'select(.yanked | not) | .vers' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -t. -k1,1n -k2,2n -k3,3n \
    | while read -r v; do
        if ver_test "$v" '>' "$2" && satisfies "$v" "^$2"; then echo "$v"; fi
      done
}

: >"$out/fixed.tsv"
: >"$out/unfixable.tsv"
rm -f "$out/commit-message" "$out/pr-body.md" "$out/issue-body.md"
changed=()
fetch_mode=fetch

for ws in "${workspaces[@]}"; do
  lock=$ws/Cargo.lock
  label=${lock#./}
  echo "== $label"
  audit "$ws" "$fetch_mode" >"$work/before.tsv"
  fetch_mode=no-fetch
  cp "$lock" "$work/lock.orig"
  : >"$work/reasons.tsv"  # advisory, reason
  : >"$work/updates.tsv"  # crate, old version, new version

  # Pick one target version per affected crate@version: the highest of each
  # advisory's lowest compatible patched version, so one update clears them all.
  cut -f2,3 "$work/before.tsv" | sort -u >"$work/pairs.tsv"
  while IFS=$tab read -r crate version; do
    candidates "$crate" "$version" >"$work/candidates"
    target=
    while IFS=$tab read -r id _ _ patched _; do
      pick=
      if [ "$patched" = - ]; then
        printf '%s\tno patched version\n' "$id" >>"$work/reasons.tsv"
        continue
      fi
      while read -r v; do
        IFS=';' read -ra reqs <<<"$patched"
        for req in "${reqs[@]}"; do
          if satisfies "$v" "$req"; then pick=$v; break 2; fi
        done
      done <"$work/candidates"
      if [ -z "$pick" ]; then
        printf '%s\tno semver-compatible patched version (patched: %s)\n' \
          "$id" "${patched//;/, }" >>"$work/reasons.tsv"
      elif [ -z "$target" ] || ver_test "$pick" '>' "$target"; then
        target=$pick
      fi
    done < <(awk -F'\t' -v c="$crate" -v v="$version" '$2 == c && $3 == v' "$work/before.tsv")
    [ -n "$target" ] || continue

    echo "updating $crate $version -> $target"
    if cargo update --manifest-path "$ws/Cargo.toml" -p "$crate@$version" --precise "$target" \
      </dev/null 2>"$work/update.err"; then
      printf '%s\t%s\t%s\n' "$crate" "$version" "$target" >>"$work/updates.tsv"
    else
      cat "$work/update.err" >&2
      reason="cargo update to $target failed: $(grep -m1 '^error' "$work/update.err" || echo 'see the workflow log')"
      awk -F'\t' -v c="$crate" -v v="$version" '$2 == c && $3 == v { print $1 }' "$work/before.tsv" \
        | while read -r id; do printf '%s\t%s\n' "$id" "$reason" >>"$work/reasons.tsv"; done
    fi
  done <"$work/pairs.tsv"

  # The second audit decides: whatever it still reports is unfixable, and
  # whatever it no longer reports was fixed by the updates.
  audit "$ws" no-fetch >"$work/after.tsv"
  while IFS=$tab read -r id crate version _ title; do
    reason=$(awk -F'\t' -v i="$id" '$1 == i { print $2; exit }' "$work/reasons.tsv")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$id" "$crate" "$version" \
      "${reason:-still reported after the update}" "$title" >>"$out/unfixable.tsv"
  done <"$work/after.tsv"
  while IFS=$tab read -r id crate version _ title; do
    grep -q "^$id$tab" "$work/after.tsv" && continue
    new=$(awk -F'\t' -v c="$crate" -v v="$version" '$1 == c && $2 == v { print $3; exit }' "$work/updates.tsv")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$id" "$crate" "$version" "${new:-?}" "$title" \
      >>"$out/fixed.tsv"
  done <"$work/before.tsv"

  cmp -s "$lock" "$work/lock.orig" || changed+=("$ws")
done

# Verify each changed workspace: cargo deny must report no advisory beyond the
# unfixable ones, and the workspace must still build.
for ws in "${changed[@]}"; do
  label=${ws#.}; label=${label:-root}
  echo "== verifying $label"
  deny_rc=0
  cargo deny --all-features --format json --manifest-path "$ws/Cargo.toml" \
    check --config "$root/deny.toml" advisories 2>"$work/deny.json" || deny_rc=$?
  unexpected=$(jq -r --rawfile known <(cut -f2 "$out/unfixable.tsv") '
    select(.type == "diagnostic" and .fields.severity == "error")
    | (.fields.advisory.id // .fields.message)
    | select(. as $id | $known | split("\n") | index($id) | not)
  ' "$work/deny.json")
  if [ -n "$unexpected" ]; then
    echo "cargo deny check advisories still fails for $label:" >&2
    echo "$unexpected" >&2
    exit 1
  fi
  if [ "$deny_rc" -ne 0 ] && ! [ -s "$out/unfixable.tsv" ]; then
    cat "$work/deny.json" >&2
    echo "cargo deny check advisories failed for $label" >&2
    exit 1
  fi
  if [ "$ws" = . ]; then
    cargo build --locked --all-features
  else
    cargo check --locked --manifest-path "$ws/Cargo.toml"
  fi
done

if [ -s "$out/fixed.tsv" ]; then
  ids=$(cut -f2 "$out/fixed.tsv" | sort -u | paste -sd, - | sed 's/,/, /g')
  echo "fix: update dependencies for $ids" >"$out/commit-message"
  {
    echo "Updates dependencies with the smallest change that clears these RustSec advisories."
    echo
    echo "| Advisory | Crate | Update | Lockfile | Title |"
    echo "| --- | --- | --- | --- | --- |"
    while IFS=$tab read -r label id crate old new title; do
      echo "| [$id](https://rustsec.org/advisories/$id) | \`$crate\` | $old -> $new | \`$label\` | ${title//|/\\|} |"
    done <"$out/fixed.tsv"
    if [ -s "$out/unfixable.tsv" ]; then
      echo
      echo "Some advisories have no automatic fix. They are listed in the \"Unfixable RustSec advisories\" issue."
    fi
    echo
    echo "Opened by the daily advisories workflow, which force-pushes this branch on each run."
  } >"$out/pr-body.md"
fi

if [ -s "$out/unfixable.tsv" ]; then
  {
    echo "These RustSec advisories have no automatic fix: no semver-compatible patched release exists, or the update failed. Each needs a maintainer decision: a manual upgrade, replacing the dependency, or a documented ignore in \`deny.toml\`."
    echo
    echo "| Advisory | Crate | Version | Lockfile | Reason | Title |"
    echo "| --- | --- | --- | --- | --- | --- |"
    while IFS=$tab read -r label id crate version reason title; do
      echo "| [$id](https://rustsec.org/advisories/$id) | \`$crate\` | $version | \`$label\` | ${reason//|/\\|} | ${title//|/\\|} |"
    done <"$out/unfixable.tsv"
    echo
    echo "<!-- advisories: $(cut -f1-4 "$out/unfixable.tsv" | sort | tr '\t\n' ' ' | sed 's/ *$//') -->"
  } >"$out/issue-body.md"
fi

echo "== summary (files in $out)"
echo "fixed:"
sed 's/^/  /' "$out/fixed.tsv"
echo "unfixable:"
sed 's/^/  /' "$out/unfixable.tsv"
