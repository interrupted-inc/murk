---
title: Changelog
description: Release history for murk and how releases are versioned.
sidebar:
  order: 2
---

The authoritative, per-version changelog lives on the GitHub releases page:

- **[github.com/interrupted-inc/murk/releases](https://github.com/interrupted-inc/murk/releases)**

Each release's notes are generated from the commit history at tag time (via
[git-cliff](https://git-cliff.org/), grouped by
[conventional-commit](https://www.conventionalcommits.org/) type), so they never
drift from what actually shipped. Rather than mirror a copy here that would go
stale between builds, this page points at that single source.

## Versioning

murk is pre-1.0 and follows [Semantic Versioning](https://semver.org/). While on
the 0.x line, treat **minor** bumps (0.9 → 0.10) as the ones that may carry
breaking changes. Patch bumps are fixes and additions. The vault format is
stable across 0.x. See the [roadmap](/roadmap/) for the stability guarantees
1.0 will add.

## Installing a specific version

Pick a version from the releases page, then install it through your channel of
choice:

```bash
cargo install murk-cli --version X.Y.Z
```

```bash
pip install murk-secrets==X.Y.Z
```

Pre-built binaries for each release are attached to its GitHub release. Every
release is signed and attested. See [verifying releases](/security/verifying/)
before trusting a downloaded artifact.
