---
title: CI/CD
description: Use murk secrets in continuous integration.
sidebar:
  order: 4
---

CI runners aren't people, but they still need a key to decrypt the vault.
The pattern is the same as any other recipient: authorize a key, store it as
a CI secret, and decrypt at run time.

## GitHub Actions

Use [murk-action](https://github.com/interrupted-inc/murk-action) to decrypt secrets
into the job environment:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-inc/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # all vault secrets are now in the environment
```

Store your `MURK_KEY` as a GitHub Actions secret (`Settings → Secrets and
variables → Actions`). GitHub's log masking registers decrypted values,
but masking depends on GitHub's runner behavior: it is a
convenience, not a hard security boundary. Don't `echo` a decrypted value in
a step if you can avoid it.

## Other CI systems

There's no action for other platforms yet, but the underlying flow is just
the CLI: install murk, put the recipient's `MURK_KEY` in your CI system's
secret store, and run

```bash
murk exec -- ./deploy.sh
```

`murk exec` reads `MURK_KEY` from the environment, decrypts, and runs the
given command with every secret injected: no `.envrc` or direnv step
needed for a non-interactive runner. Use `--only KEY` to hand a command a
subset of secrets, or `--clean-env` to avoid also inheriting the runner's
own ambient environment.

## Prefer a scoped grant over a full key

Handing CI the same `MURK_KEY` a human recipient uses means CI can decrypt
everything in the shared layer. A leaked CI secret is as bad as a leaked
developer key. If the job only needs a handful of secrets (deploy
credentials, not every key in the vault), consider a short-lived, narrowly
scoped **agent grant** instead:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 1h
```

This mints a time-limited key that can only read the named secret(s). It's
the same mechanism murk uses to scope AI agent access. See [AI agents &
MCP](/guides/ai-agents-mcp/) for the full grant/revoke lifecycle and the
[CLI reference](/reference/cli/#murk-agent-grant) for the flag surface. The
TTL is advisory: age keys can't self-destruct and old `.murk` versions stay
readable in git, so it doesn't cut access on its own. Treat a CI grant the
same way you'd treat any credential. Revoke it (`murk agent revoke NAME
--rotate`) once you no longer need it, and rotate what it exposed if the CI
runner or logs might have leaked it.

Whichever path you use, keep [shared vs scoped
secrets](/guides/shared-vs-scoped/) in mind: production values used by CI
belong in the shared layer, not as a scoped override on someone's personal
key.
