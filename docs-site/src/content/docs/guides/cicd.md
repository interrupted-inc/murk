---
title: CI/CD
description: Use murk secrets in continuous integration.
sidebar:
  order: 4
---

A CI job needs its own key to decrypt the vault. Authorize that key, store it
in your CI system's secret store, and decrypt at run time.

## Create a key for CI

If the job needs only some secrets, mint a scoped grant (see [Prefer a scoped
grant over a full key](#prefer-a-scoped-grant-over-a-full-key) below). For a
key with the same access as a teammate, generate a key pair with
[`age-keygen`](https://github.com/FiloSottile/age), authorize the public key,
and store the secret key:

```bash
age-keygen -o ci.key                    # prints the public key (age1...)
murk circle authorize age1... --name ci
grep AGE-SECRET-KEY ci.key | gh secret set MURK_KEY
rm ci.key
```

murk-action needs an age secret key (`AGE-SECRET-KEY-1...`), not an SSH key.

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

The organization was renamed from `interrupted-inc` to `interrupted-sh`.
Change any workflow that still uses `interrupted-inc/murk-action` to
`interrupted-sh/murk-action`.

Store the key as a GitHub Actions secret (`Settings → Secrets and variables
→ Actions`). The action registers each decrypted value with GitHub's log
masking. Masking depends on the runner and is not a security boundary, so
never print a decrypted value.

## Other CI systems

For other CI systems, install murk (see [Install](/install/)), store the key
in the system's secret store as `MURK_KEY`, and wrap the command:

```bash
murk exec -- ./deploy.sh
```

`murk exec` decrypts the vault and runs the command with the secrets in its
environment. It needs no `.envrc` or direnv. The command does not receive
`MURK_KEY`. Use `--only KEY` (repeatable) to pass a subset of the secrets. Use
`--clean-env` to drop the runner's other variables. On Unix it keeps `PATH`,
`HOME` and `TERM`. On Windows it keeps `PATH` and the system variables
Windows programs need.

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

![A CI grant piped into the CI secret input (gh shimmed locally for the recording) exports only DEPLOY_TOKEN, fails loudly once expired, and comes back after --renew](/demos/ci-grant.gif)

murk enforces the TTL at read time, so an expired grant fails closed. But age
keys can't self-destruct and old `.murk` versions stay readable in git, so
treat a CI grant the same way you'd treat any credential. Revoke it (`murk
agent revoke NAME --rotate`) once you no longer need it, and rotate what it
exposed if the CI runner or logs might have leaked it.

Whichever path you use, keep [shared vs scoped
secrets](/guides/shared-vs-scoped/) in mind: production values used by CI
belong in the shared layer, not as a scoped override on someone's personal
key.
