#!/usr/bin/env bash
# Build murk_lints and run it over every crate in the murk workspace
# (murk-cli at the repo root, and the murk-napi bindings under node/). This
# is the verified, reproducible invocation — see README.md "Running".
#
# Prerequisites (one-time):
#   rustup toolchain install nightly-2026-05-28 --profile minimal \
#     --component rustc-dev,llvm-tools-preview
#   rustup run stable cargo install cargo-dylint dylint-link --locked
#
# Why the wrapper: some environments put a non-rustup `cargo`/`rustc` first on
# PATH (e.g. a Homebrew Rust install). `cargo dylint` shells out to plain
# `cargo`/`rustc` (not `rustup run ...`) to build its driver and to check the
# target workspace, and that inner build script reads `RUSTUP_TOOLCHAIN` from
# its own environment. A thin wrapper that re-execs the pinned toolchain's
# real `cargo`/`rustc` binaries, forcing `RUSTUP_TOOLCHAIN`, makes both steps
# resolve the correct nightly regardless of what's first on the ambient PATH.
set -euo pipefail

toolchain="nightly-2026-05-28-aarch64-apple-darwin"
lint_crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$lint_crate_dir/../.." && pwd)"
toolchain_bin="$HOME/.rustup/toolchains/$toolchain/bin"
wrapper_dir="$(mktemp -d)"
trap 'rm -rf "$wrapper_dir"' EXIT

for tool in cargo rustc; do
  cat > "$wrapper_dir/$tool" <<EOF
#!/bin/sh
export RUSTUP_TOOLCHAIN="$toolchain"
exec "$toolchain_bin/$tool" "\$@"
EOF
  chmod +x "$wrapper_dir/$tool"
done

export PATH="$HOME/.cargo/bin:$wrapper_dir:$PATH"

# `--ui-tests`: run the lint crate's UI test suite inside the same wrapper
# env. A bare `rustup run nightly-2026-05-28 cargo test` fails on machines
# whose first-on-PATH cargo/rustc are not rustup proxies (the rustc-private
# deps build against the wrong toolchain), so tests need this wrapper too.
if [ "${1:-}" = "--ui-tests" ]; then
  echo "==> running murk_lints UI tests" >&2
  cd "$lint_crate_dir"
  status=0
  cargo test "${@:2}" || status=$?
  exit "$status"
fi

echo "==> building murk_lints (release)" >&2
(cd "$lint_crate_dir" && cargo build --release)

dylib="$lint_crate_dir/target/release/libmurk_lints@${toolchain}.dylib"
if [ ! -f "$dylib" ]; then
  # non-macOS fallback
  dylib="$lint_crate_dir/target/release/libmurk_lints@${toolchain}.so"
fi

echo "==> running murk_lints over the murk workspace" >&2
cd "$repo_root"
status=0
cargo dylint --lib-path "$dylib" --no-deps --workspace -- --lib --tests --bins "$@" || status=$?
exit "$status"
