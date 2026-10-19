# Contributing

murk is pre-1.0. Contributions are welcome, especially in these areas:

- Bug reports and security issues (see [SECURITY.md](SECURITY.md) for private reporting)
- Test coverage, especially adversarial/edge-case tests
- Documentation improvements
- Platform compatibility fixes (Windows, Linux, macOS)

## Development

```bash
cargo build              # Build
cargo test               # Run all tests
cargo clippy             # Lint
cargo fmt                # Format
cargo run -- <command>   # Run murk with arguments
```

Run `make hooks` once per clone to install the pre-commit hook, which runs the same fmt and clippy checks as CI.

### Rust toolchain

`rust-toolchain.toml` pins the exact Rust version CI builds, lints and releases with. If you installed Rust with [rustup](https://rustup.rs), `cargo` in this repository uses the pinned toolchain automatically and rustup installs it, with rustfmt and clippy, on first use (or run `rustup toolchain install`).

Homebrew's `rust` formula and distro packages ignore `rust-toolchain.toml`. Their `cargo` runs whatever version they ship, so the pre-commit hook can fail on lints CI doesn't enforce yet, or pass code CI rejects. Use rustup to match CI. If both are installed, make sure rustup's `cargo` comes first on your `PATH`; `rustup show active-toolchain` in the repository should name the pinned version.

Dependabot opens a PR for each new Rust release. Patch releases merge automatically once CI is green. Minor releases wait for a maintainer: fix any new lints on that PR before merging it.

### Security advisories

CI checks dependencies against the RustSec advisory database only on pushes to `main`, tags, and PRs that change `Cargo.toml`, `Cargo.lock`, their `fuzz/` copies or `deny.toml`, so a newly published advisory does not fail unrelated PRs. A daily workflow (`.github/workflows/advisories.yaml`, logic in `scripts/fix-advisories.sh`) updates each affected crate to the lowest semver-compatible patched version and opens or refreshes one PR from the `deps/rustsec-fixes` branch; it merges automatically once CI is green if it changes only lockfiles. Once anyone else pushes a commit to that branch, the job stops updating it and leaves the PR for review. Advisories it cannot fix this way go to an open issue titled "Unfixable RustSec advisories" for a maintainer to resolve: upgrade by hand, replace the dependency, or add a documented ignore to `deny.toml`. Run `scripts/fix-advisories.sh` locally to apply the same fixes.

## Pull Requests

- Keep PRs focused — one logical change per PR
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting
- PR descriptions should be a short bullet list of changes
- New features must include tests

## Security

If you find a security vulnerability, **do not open a public issue**. Use [GitHub's private vulnerability reporting](https://github.com/interrupted-inc/murk/security/advisories/new) instead.

## Developer Certificate of Origin

By contributing, you certify that your contribution is your original work or you have the right to submit it under the project's license, per the [Developer Certificate of Origin](https://developercertificate.org/). This is asserted by the act of submitting a pull request.

## License

Contributions are licensed under the same terms as the project (MIT OR Apache-2.0).
