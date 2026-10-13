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
