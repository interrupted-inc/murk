---
title: Feature status
description: Which murk features are core and which are experimental.
sidebar:
  order: 5
---

murk sorts its features into two groups. **Core** features are what murk is
for. They are tested the most and are the ones to build on. **Experimental**
features work and ship in every release, but they are newer, rely on narrower
guarantees than they may seem to, or have had little testing against the
tools they work with. Their behavior, flags or file layout may change in a
minor release. murk does not print a warning when you use them; this page,
the guides and `murk --help` mark them instead.

## Trust model

murk has no admin role. Every recipient except agent grants can add and remove recipients, manage groups, set the policy and mint grants. Group-only and personal values stay protected from recipients outside the group. Changes are attributable through vault signatures (keys that cannot sign, such as hardware and ssh-rsa keys, rely on signed git commits).

## Core

| Feature | What it covers |
| --- | --- |
| Shared secrets | `init`, `add`, `generate`, `get`, `exec`, `export`, `ls`, `info`, `rm`, `import`, `rotate` and `describe`. |
| [Personal overrides](/guides/shared-vs-scoped/) | `--group me`: a value only you can read, which overrides the shared one. |
| [Recipients](/guides/teams/) | `murk circle` with age and SSH keys (`ssh:`): list, authorize and revoke recipients. |
| [Offboarding](/guides/offboarding/) | `circle revoke --rotate` and `rotate --list`. |
| [Vault integrity](/concepts/vault-format/) | The vault format and its MAC, checked by `murk verify`. |
| [Key recovery](/guides/recovery/) | The 24-word BIP39 phrase, `murk recover` and `murk restore`. |
| Leak checks | `murk scan`, `murk doctor` and the pre-commit hook. |
| [direnv](/guides/direnv/) | `murk env` and loading secrets on `cd`. |
| [Install](/install/) | Homebrew, `cargo install murk-cli` and `install.sh`, with verified releases. |
| [Library bindings](/reference/bindings/) | Reading secrets from Python (`murk-secrets` on PyPI) and Node.js. |

## Experimental

| Feature | Why it is experimental |
| --- | --- |
| [Agent grants, `agent exec`, `murk mcp`, `agent connect`/`disconnect`](/guides/ai-agents-mcp/) | New, and their access rules changed in 0.14. A running `murk mcp` server does not see a revocation or policy change until it restarts. A guardrail, not a security boundary. |
| [Agent policy](/guides/ai-agents-mcp/) (`murk policy`, `--allow-tag`) | Limits which tagged secrets agents receive. A guardrail, not access control. |
| [Named groups](/guides/teams/#listing-and-managing-recipients) (`murk group`, `--group NAME`) | Newer than the shared and personal layers, with less test coverage across update paths. |
| [Signatures and signer pinning](/concepts/recipients-signatures/) | New in 0.14: the trust pin, `murk trust` and the signed form may change in a minor release. Keys that cannot sign (hardware, `ssh-rsa`) leave a vault unsigned and rely on signed git commits, and the first trust decision on a machine is yours to check. |
| [Strict mode](/concepts/env-vars/#safety-and-agent-context) (`MURK_STRICT`) | A short list of specific checks, not a guarantee that no plaintext reaches disk. |
| `murk edit` | The edit lifecycle is new, and its process handling is Unix-only. |
| [Git merge driver](/guides/git-merge-ssh/) | Few tests run a real git merge. Review a merged vault before you push it. |
| [`murk diff`](/guides/git-merge-ssh/) | New in its present form: it reports recipient, signer, policy, grant and group changes as well as secrets, and its output may change in a minor release. |
| [GitHub recipients](/guides/teams/#authorizing-via-github) (`github:`) | Keys are fetched over the network and trusted on first use. |
| [Hardware and plugin identities](/guides/hardware-keys/) | No test runs a real plugin yet, and once a plugin recipient exists every writer needs the plugin installed. |
| [Node.js writes](/reference/bindings/#nodejs) (`add`, `describe`) | The write API is new. Reading from Node.js is stable. |
