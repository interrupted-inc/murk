---
title: Roadmap
description: Where murk is heading on the way to 1.0.
sidebar:
  order: 1
---

murk is pre-1.0. This page covers direction, not commitments: priorities shift
with real usage. The 0.x line is a public beta: safe to use with good judgment,
not yet independently audited. See the [threat model](/security/threat-model/)
for what murk protects and what it doesn't.

For who murk is for, who should use SOPS or Vault instead, and what the 0.x
beta promises, see [Is murk right for you?](/suitability/).

## Toward 1.0

1.0 is a **trust milestone, not a feature milestone.** The feature set
(encrypted single-file vault, per-recipient encryption, scoped agent access
over MCP, team management, and BIP39 recovery) is already in place. What 1.0
adds is validation and stability guarantees. It ships when all of these hold:

- **Vault-format stability**: 1.x reads every 0.x vault. Any format change
  ships with a documented, tested migration.
- **External security review**: an independent review of the age recipient
  management and grant-scope enforcement, with findings published and addressed.
- **Continuous fuzzing**: OSS-Fuzz onboarding, beyond the current nightly
  in-repo fuzz run.
- **SLSA Build L3 provenance**: up from the current attested (L2) releases.
- **Soak**: several months of 0.9.x in real use with no vault-format change and
  no critical security fix.
- **Migration & policy docs**: an upgrade guide, an MSRV policy, and a
  deprecation policy.

## Later

- Secret versioning (`murk history`, `murk rollback`)
- Per-key timestamps and access logging
- First-class environment separation (dev/staging/prod)
- Nix flake, Debian packages

## Non-goals

These are deliberate boundaries, not gaps waiting to be filled:

- **Centralized secrets server**: use [HashiCorp Vault](https://www.vaultproject.io/)
  if you need one.
- **Custom cryptographic primitives**: murk uses [age](https://age-encryption.org/).
- **Fine-grained cryptographic access control**: all recipients can read shared
  secrets by design. See [grants](/concepts/grants/) for the scoped-access model
  that does exist.
- **Regulated/compliance environments**: no audit trail beyond git, no provable
  access controls.
- **Algorithm agility**: age uses a fixed suite by design.

Released versions and their notes live in the [changelog](/changelog/).
