---
title: Is murk right for you?
description: "Who murk is for, who should use SOPS or Vault instead, and what the 0.x public beta does and does not promise."
---

murk is a public beta (the 0.x line). It is safe to use with good judgment for
developer and team secrets, and it has not been independently audited. This page
helps you decide whether murk fits your situation, points you elsewhere when it
does not, and states plainly what the beta does and does not promise.

For a feature-by-feature comparison with SOPS, Vault, dotenvx, and git-crypt, see
the table on the [overview](/). This page is about your situation, not a feature
grid.

## Suitability at a glance

| Your situation | Use murk? | Why, or what to use instead |
|---|---|---|
| Solo dev or small team keeping secrets out of git and synced through the repo | Yes | This is the core use case: one key, one committed `.murk` file. |
| Onboarding and offboarding teammates with age or SSH keys | Yes | `murk circle` adds and revokes recipients; `murk rotate` reissues after someone leaves. |
| Giving an AI agent or CI job scoped access to specific secrets without sharing your key | Yes | `murk agent exec` and grants inject only the named keys and fail closed. See [AI agents & MCP](/guides/ai-agents-mcp/). |
| Application and CI configuration secrets loaded through your shell | Yes | Works with [direnv](/guides/direnv/); no runtime to install. |
| You want dynamic, short-lived credentials or server-driven rotation | No | Use HashiCorp Vault or a cloud secrets manager. murk stores static secrets in a file. |
| You need provable access control and audit logs for compliance (SOC 2, PCI, HIPAA) | Not yet | murk's only audit trail is git history, and it is not independently audited. Use Vault. |
| You need HSM or cloud-KMS-backed keys, or per-secret cryptographic access control | No | Use Vault or a cloud KMS. Every authorized recipient can read shared secrets by design. |
| You want the broadest KMS backend support and the largest ecosystem today | Consider SOPS | SOPS is the closest alternative, with more backends and a bigger community. |

## Use murk if

- You want encrypted secrets committed next to your code, with readable key
  names so diffs stay meaningful.
- Your team manages access by adding and removing recipients, not by sharing one
  password.
- You want no server and no runtime dependency: a single binary.
- You want to hand agents or CI scoped access to named secrets without exposing
  your key.

## Look elsewhere if

- You need a secrets server, dynamic credentials, or server-driven rotation
  (HashiCorp Vault, cloud secrets managers).
- You are in a regulated or compliance environment that needs provable access
  control and a formal audit trail (Vault). murk's audit trail is git history.
- You need per-secret cryptographic access control. In murk, every authorized
  recipient can read every shared secret by design; only per-recipient motes are
  scoped to one key.
- You want the widest KMS backend support and ecosystem available today (SOPS).

## The 0.x release contract

"Public beta" is a specific promise, not a disclaimer. Here is what it means.

**What murk is.** A git-native secrets tool for developers, built on
[age](https://age-encryption.org/): one key on your machine, one encrypted file
in your repo, no server, no runtime. It is meant to be used with real secrets,
with good judgment, today.

**What the 0.x line already gives you:**

- Values encrypted with age; key names stay readable.
- Per-recipient encryption, so revoking a teammate does not hand them future
  secrets.
- Tamper evidence: the vault is signed with a key derived from the writer's age
  key, and git is the integrity anchor. See the [threat model](/security/threat-model/).
- A documented, tested vault format.
- Reproducible, attested releases (SLSA Build L2) that you can
  [verify](/security/verifying/).
- Coordinated vulnerability reporting through
  [SECURITY.md](https://github.com/interrupted-inc/murk/blob/main/SECURITY.md).

**What murk deliberately does not claim yet:**

- No independent security audit has been completed.
- No suitability for regulated or compliance use: there is no audit trail beyond
  git and no provable access controls.
- No server-side guarantees, dynamic credentials, or automatic rotation.
- No promises beyond what the [threat model](/security/threat-model/) states.

**What changes at 1.0.** 1.0 is a trust milestone, not a feature milestone: the
feature set is already in place, and what 1.0 adds is validation and stability.
It ships only when all of these gates hold, each tracked on the [roadmap](/roadmap/):

- Vault-format stability: 1.x reads every 0.x vault, and any format change ships
  with a documented, tested migration.
- An independent external security review of recipient management and grant-scope
  enforcement, with findings published and addressed.
- Continuous fuzzing through OSS-Fuzz, beyond the current nightly in-repo run.
- SLSA Build L3 provenance, up from the current L2.
- A soak period: several months of 0.9.x in real use with no vault-format change
  and no critical security fix.
- Migration and policy docs: an upgrade guide, an MSRV policy, and a deprecation
  policy.

If you are unsure whether murk fits, read the [threat model](/security/threat-model/)
first: it states exactly what murk protects and what it does not.
