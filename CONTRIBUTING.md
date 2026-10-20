# Contributing

murk is pre-1.0. Contributions are welcome, especially in these areas:

- Bug reports and security issues (see [SECURITY.md](SECURITY.md) for private reporting)
- Test coverage, especially adversarial/edge-case tests
- Documentation improvements
- Platform compatibility fixes (Windows, Linux, macOS)

For a first contribution, pick an issue labelled [good first issue](https://github.com/interrupted-sh/murk/labels/good%20first%20issue) or [help wanted](https://github.com/interrupted-sh/murk/labels/help%20wanted). Each of these issues is small, names the files to change, and lists acceptance criteria.

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

### Code review

Every change reaches `main` through a pull request. The maintainer reviews each pull request before merging it, including their own. murk has one maintainer, so the maintainer's own pull requests get no second human review: CI is the independent check on them. The only changes that merge without a manual review are the automated dependency PRs described in [Roles and responsibilities](#roles-and-responsibilities).

The maintainer checks each pull request for:

- **Correctness and tests.** The change does what its description says and nothing unrelated. New features include tests. Bug fixes include a regression test where the bug can be reproduced in a test.
- **Security impact.** Changes to encryption, signing, the vault format, key and recipient handling, secret output, or the agent and MCP surfaces are checked against [THREAT_MODEL.md](THREAT_MODEL.md), in particular its [trust boundaries](THREAT_MODEL.md#trust-boundaries) and [common implementation weaknesses](THREAT_MODEL.md#common-implementation-weaknesses). A change that adds an asset, moves a trust boundary or weakens a stated property updates the threat model in the same pull request.
- **Documentation and changelog.** User-visible changes update the README or the docs site. A change to a command or flag regenerates the CLI and env references (`make docs`); CI fails if they are out of date. The pull request title is a conventional commit summary (`feat:`, `fix:`, `docs:` …), because the release notes are generated from commit subjects ([`cliff.toml`](cliff.toml)).
- **CI.** The `Lint`, `Test` and `VHS` checks are required by branch protection, and the protection applies to the maintainer too. CodeQL runs on every pull request; the Node, Python and docs-preview workflows run when their paths change. Lint covers formatting, clippy, generated docs, version consistency, guide commands, demo tapes and SPDX headers ([`scripts/spdx-headers.cjs`](scripts/spdx-headers.cjs)).
- **Dependency changes.** A pull request that changes a `Cargo.toml`, a `Cargo.lock` or `deny.toml` runs `cargo deny` (advisories, bans, licenses, sources) and `cargo audit`. For a new dependency, the maintainer also checks that it is needed and maintained.

A pull request does not merge while:

- a required check fails;
- the maintainer has requested changes that are not addressed;
- an item in the list above is not met, for example a new feature without tests or a security-relevant change without a threat-model update.

### Releases

The maintainer cuts a release in three steps:

1. Bump the version everywhere it appears with `scripts/bump-version.sh <x.y.z>`.
2. Merge that change to `main` through a pull request.
3. Push a signed `vX.Y.Z` tag.

The tag starts [`.github/workflows/release.yaml`](.github/workflows/release.yaml). Its `preflight` job refuses to release unless the tagged commit is on `main`, reached `main` through a merged pull request, and `main`'s branch protection matches the release baseline. The workflow then builds, attests and publishes the release. The npm and PyPI packages are published from the same tag. [VERIFYING.md](VERIFYING.md) shows how to verify each release channel.

### Repositories

The project is made up of these three repositories, all maintained by the maintainer above:

- [interrupted-sh/murk](https://github.com/interrupted-sh/murk) (this repository): the CLI, the Rust library, the Python and Node bindings, the bb plugin (`integrations/bb/`) and the docs site (`docs-site/`). Active, pre-1.0.
- [interrupted-sh/murk-action](https://github.com/interrupted-sh/murk-action): the GitHub Action that decrypts murk secrets into a CI job's environment. Active, published on the [GitHub Marketplace](https://github.com/marketplace/actions/murk-action) as `interrupted-sh/murk-action@v1`.
- [interrupted-sh/homebrew-murk](https://github.com/interrupted-sh/homebrew-murk): the Homebrew tap. Active. The `homebrew` job in [`.github/workflows/release.yaml`](.github/workflows/release.yaml) updates its formula automatically on each release.

## Developer Certificate of Origin

By contributing, you certify that your contribution is your original work or you have the right to submit it under the project's license, per the [Developer Certificate of Origin](https://developercertificate.org/). This is asserted by the act of submitting a pull request.

## License

Contributions are licensed under the same terms as the project (MIT OR Apache-2.0).

Each source file starts with an SPDX header that names the copyright holder and the license:

```text
SPDX-FileCopyrightText: murk contributors
SPDX-License-Identifier: MIT OR Apache-2.0
```

Run `node scripts/spdx-headers.cjs` to add the header to new files. CI runs it with `--check` and fails if a source file lacks the header. Generated files, the lint UI fixtures and non-code files carry no header; the script lists the exclusions.
