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

Use [murk-action](https://github.com/interrupted-sh/murk-action) to decrypt secrets
into the job environment:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # all vault secrets are now in the environment
```

Workflows that still reference `interrupted-inc/murk-action` must switch to
`interrupted-sh/murk-action`: GitHub does not redirect action references after
an organization rename.

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
credentials, not every key in the vault), consider a narrowly scoped
**agent grant** instead:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --out - | gh secret set MURK_KEY
git commit -am "grant ci-deploy" && git push
```

`--out -` writes the grant key to stdout and stores no copy, so it goes
straight into the Actions secret. The key is a drop-in for murk-action's
`murk-key` input; no other workflow change is needed. It's the same mechanism
murk uses to scope AI agent access. See [AI agents &
MCP](/guides/ai-agents-mcp/) for the full grant/revoke lifecycle and the
[CLI reference](/reference/cli/#murk-agent-grant) for the flag surface.

The grant lives in `.murk`, so CI can only use the key once the vault
containing the grant is on the branch it checks out. `murk export` under the
grant yields only the granted keys; a `murk get` of anything else fails with
`KEY is outside this grant's scope`.

### Renewing the grant

Before the grant expires, run the same two lines with `--renew`:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --renew --out - | gh secret set MURK_KEY
git commit -am "grant ci-deploy" && git push
```

`--renew` revokes the old key as it mints the new one, in a single vault
write. Update the Actions secret and push the vault together: a job that runs
between the two fails loudly with `not a recipient`, never silently. If you
miss the renewal, the job fails with `grant ci-deploy expired`; that's the
intended fail-closed behavior.

murk enforces the TTL at read time, so an expired grant fails closed. But age
keys can't self-destruct and old `.murk` versions stay readable in git, so
treat a CI grant the same way you'd treat any credential. Revoke it (`murk
agent revoke NAME --rotate`) once you no longer need it, and rotate what it
exposed if the CI runner or logs might have leaked it.

Whichever path you use, keep [shared vs scoped
secrets](/guides/shared-vs-scoped/) in mind: production values used by CI
belong in the shared layer, not as a scoped override on someone's personal
key.
