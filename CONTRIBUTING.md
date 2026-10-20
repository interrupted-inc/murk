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

CI checks dependencies against the RustSec advisory database only on pushes to `main`, tags, and PRs that change any `Cargo.toml`, any `Cargo.lock` or `deny.toml`, so a newly published advisory does not fail unrelated PRs. A daily workflow (`.github/workflows/advisories.yaml`, logic in `scripts/fix-advisories.sh`) updates each affected crate to the lowest semver-compatible patched version and opens or refreshes one PR from the `deps/rustsec-fixes` branch; it merges automatically once CI is green if it changes only lockfiles. Once anyone else pushes a commit to that branch, the job stops updating it and leaves the PR for review. Advisories it cannot fix this way go to an open issue titled "Unfixable RustSec advisories" for a maintainer to resolve: upgrade by hand, replace the dependency, or add a documented ignore to `deny.toml`. Run `scripts/fix-advisories.sh` locally to apply the same fixes.

## Pull Requests

- Keep PRs focused — one logical change per PR
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting
- PR descriptions should be a short bullet list of changes
- New features must include tests

## Security

If you find a security vulnerability, **do not open a public issue**. Use [GitHub's private vulnerability reporting](https://github.com/interrupted-sh/murk/security/advisories/new) instead.

## Governance

murk has one maintainer, [@iicky](https://github.com/iicky). The maintainer makes every final decision about the project. No other person holds a project role, so the bus factor is 1.

### Roles and responsibilities

**Maintainer ([@iicky](https://github.com/iicky)):**

- Decides the project's scope and direction, including the [roadmap](ROADMAP.md).
- Triages issues.
- Reviews and merges pull requests. [`.github/CODEOWNERS`](.github/CODEOWNERS) assigns every file to the maintainer. Two kinds of automated dependency PR merge without a manual review once CI passes: Dependabot patch updates, and the lockfile-only advisory fixes described in [Security advisories](#security-advisories). The maintainer sets those rules.
- Cuts releases (see [Releases](#releases)).
- Handles private vulnerability reports as described in [SECURITY.md](SECURITY.md), and ships the fixes.
- Enforces the [Code of Conduct](CODE_OF_CONDUCT.md).

**Contributors:** anyone who opens an issue or a pull request. Contributors follow the [pull request rules](#pull-requests), certify the [Developer Certificate of Origin](#developer-certificate-of-origin), and report vulnerabilities privately, not in public issues.

### How decisions are made

Decisions are made in the open, in GitHub issues and pull requests. Open an issue to discuss a significant change before you write the code. The maintainer makes the final decision on each issue and pull request, and records it there. To disagree with a decision, reply on the issue or pull request with your reasoning, or open a new issue. The maintainer can reopen an issue or change a decision. Security reports are the exception: they go through [private reporting](#security) until a fix ships.

### Releases

The maintainer cuts a release in three steps:

1. Bump the version everywhere it appears with `scripts/bump-version.sh <x.y.z>`.
2. Merge that change to `main` through a pull request.
3. Push a signed `vX.Y.Z` tag.

The tag starts [`.github/workflows/release.yaml`](.github/workflows/release.yaml). Its `preflight` job refuses to release unless the tagged commit is on `main`, reached `main` through a merged pull request, and `main`'s branch protection matches the release baseline. The workflow then builds, attests and publishes the release. The npm and PyPI packages are published from the same tag. [VERIFYING.md](VERIFYING.md) shows how to verify each release channel.

## Developer Certificate of Origin

By contributing, you certify that your contribution is your original work or you have the right to submit it under the project's license, per the [Developer Certificate of Origin](https://developercertificate.org/). This is asserted by the act of submitting a pull request.

## License

Contributions are licensed under the same terms as the project (MIT OR Apache-2.0).
