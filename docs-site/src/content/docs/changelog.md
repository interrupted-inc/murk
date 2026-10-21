---
title: Changelog
description: Release history for murk and how releases are versioned.
sidebar:
  order: 2
---

The authoritative, per-version changelog lives on the GitHub releases page:

- **[github.com/interrupted-sh/murk/releases](https://github.com/interrupted-sh/murk/releases)**

Each release's notes are generated from the commit subjects at tag time (via
[git-cliff](https://git-cliff.org/), grouped by
[conventional-commit](https://www.conventionalcommits.org/) type). Rather than
mirror a copy here that would go stale between builds, this page points at that
single source.

## Versioning

murk is pre-1.0 and uses [Semantic Versioning](https://semver.org/). Before
1.0, a **minor** bump (0.12 to 0.13) may break compatibility. Patch bumps are
fixes and additions. Breaking changes are marked with `!` in the release notes,
for example `fix!: refuse to run when both key variables are set` in 0.13.0. A
newer murk reads vaults written by older 0.x versions, but a vault written by a
newer murk may not open in an older one. The [roadmap](/roadmap/) lists the
format guarantee 1.0 will add.

## Installing a specific version

Pick a version from the releases page, then install it through your channel of
choice:

```bash
cargo install murk-cli --version X.Y.Z
```

```bash
pip install murk-secrets==X.Y.Z
```

Pre-built binaries for each release are attached to its GitHub release. Recent
releases carry signed build provenance on every channel (the crates.io package
from 0.13.0). See [verifying releases](/security/verifying/) for what each
version has and how to check it before you trust a downloaded artifact.
