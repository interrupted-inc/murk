---
title: Git worktrees
description: Use a vault from any worktree of a repo, with no per-checkout setup.
sidebar:
  order: 8
---

A git worktree gives you a second working directory for the same repository —
a branch checked out somewhere else, without stashing or cloning again. It's
the natural fit for reviewing a PR while you keep working, and it's how most
AI coding harnesses isolate a task: one throwaway checkout per job.

The catch is normally secrets. A fresh worktree contains tracked files and
nothing else, so every gitignored dotenv you rely on is simply missing. The
usual fix is to hand-copy or symlink `.env` into each new checkout, and to
redo it every time a worktree is created — which is exactly the kind of
manual step that is forgotten once and debugged for twenty minutes.

murk doesn't have that problem, because the two halves of a murk setup travel
differently:

- **The vault is committed.** `.murk` is a tracked file, so a new worktree
  checks it out like any other source file. All the secrets are already there,
  encrypted.
- **The key was never in the repo.** It lives in `~/.config/murk/keys/`, and
  murk finds it by looking up the vault — including from a worktree.

So there is nothing to provision.

## What this looks like

Create a worktree and use the vault immediately:

```bash
git worktree add ../murk-feature-x
cd ../murk-feature-x
murk get API_KEY
murk exec ./deploy.sh
```

No `.env` to copy, no `murk env` to re-run, no key to export. The same holds
for a worktree created by an agent harness, a `git worktree add` in a
post-checkout hook, or a bare-repo layout where *every* checkout is a linked
worktree and there is no "main" one.

## Which checkouts count

murk stores your key under a hash of the vault's absolute path, which is what
keeps a copy of someone else's vault from borrowing your key. A worktree puts
the same vault at a different absolute path, so murk also accepts the key
stored for that vault in a sibling checkout of the same repository.

"Sibling" here means what git says it means. murk reads git's own worktree
metadata — never a `git` subprocess — and verifies the relationship in both
directions: your current directory has to be a checkout the repository
records, and the checkout whose key is used has to point back at the same
repository. A `.git` entry is just a file that any local process can write, so
a directory that merely *claims* to be a worktree resolves to no key at all
and murk fails closed.

The practical version: real worktrees of your repo work, copies of the vault
elsewhere on disk don't.

## Agents get no free ride

Discovery of a stored key is disabled entirely in strict mode
(`MURK_STRICT=1`) and in agent context (`MURK_AGENT=1`), worktree or not. An
agent working in a fresh worktree still has to present its own key — normally
a scoped grant — or fail closed. That is deliberate: the convenience here is
for you, not for a process running as you.

See [AI agents & MCP](/guides/ai-agents-mcp/) for issuing an agent a scoped
grant to use in its worktree.

## direnv in a worktree

If you use [direnv](/guides/direnv/), the `.envrc` that `murk env` writes holds
no secret material — just a `murk export` call — so committing it is safe, and
then it arrives with every checkout like the vault does. direnv still requires
an explicit opt-in per directory, so a new worktree needs one command:

```bash
direnv allow
```

That is direnv's safety model — it refuses to auto-execute an `.envrc` it
hasn't been told to trust — and not something murk can or should skip on your
behalf. If you'd rather not run it, `murk exec` needs no shell integration.

## Related

- [direnv integration](/guides/direnv/) for loading secrets on `cd`.
- [Environment variables](/concepts/env-vars/) documents the full key
  resolution order, including when automatic lookup is disabled.
- [Threat model](/security/threat-model/) explains what the stored key is
  bound to, and why a copied vault can't use it.
