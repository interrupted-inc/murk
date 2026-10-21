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

## Telling CI who may sign the vault

A fresh CI runner has no [trust pin](/concepts/recipients-signatures/#trusting-a-signer),
and nobody is there to run `murk trust`. Without help, murk refuses the vault
with "not trusted on this machine yet". Set `MURK_TRUSTED_SIGNERS` to the
people who write the vault, from a secret, next to
`MURK_KEY`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
    env:
      MURK_TRUSTED_SIGNERS: ${{ secrets.MURK_TRUSTED_SIGNERS }}
  - run: ./deploy.sh
```

Each entry names one signer. An age signer is `age1...:<verifying key>` (the
recipient, a colon, the base64 Ed25519 verifying key). An `ssh-ed25519`
signer is its public key line. Entries are separated by commas or newlines.

To build the value, each person who writes the vault runs
`murk trust --print-key` on their own machine. It prints their entry to
stdout and their signing-key fingerprint to stderr, so
`murk trust --print-key > entry.txt` keeps just the entry. Join the
entries, one per line, into the secret. A bare `age1...` key without
`:<verifying key>` is an error, because an age key's verifying key can't be
computed from its recipient string. A key that can't sign (`ssh-rsa`,
hardware) has no entry.

Include the people who write the vault, not every recipient (`murk circle`
lists the recipients). The variable
replaces the pin's trusted set, so the job accepts a vault only when one of
those keys signed it, and an age signer's signature has to verify under the
verifying key in its entry. Agent grant keys listed there still never count,
and an entry in neither form is an error. Trust that comes from the variable
is not written into the pin, so a self-hosted runner that keeps its home
directory doesn't carry the signers you named into later jobs that don't set
it. A runner whose home can't be written only prints a warning when murk
can't save the pin.

The action has to pass the variable through to the `murk` process. If your
version of `murk-action` doesn't, run murk yourself with the variable in the
step's `env:`:

```yaml
  - run: murk exec -- ./deploy.sh
    env:
      MURK_KEY: ${{ secrets.MURK_KEY }}
      MURK_TRUSTED_SIGNERS: ${{ secrets.MURK_TRUSTED_SIGNERS }}
```

This applies to a scoped grant key too: a grant can't run `murk trust`, so
give the grant's runner `MURK_TRUSTED_SIGNERS` as well.

Two limits to know. A runner with no pin can't detect rollback: an older,
validly signed revision on the checked-out branch loads. Protect the branch
the job deploys from. And a vault left unsigned by a hardware-key or
`ssh-rsa` teammate's write is refused by CI until a signing teammate runs
`murk trust` and commits the re-signed vault. That holds for every key once
`MURK_TRUSTED_SIGNERS` is set, including a runner key that can't sign: naming
the signers you require means an unsigned vault is never accepted.

## Upgrading to 0.14

Before CI loads a vault written by murk 0.14 or later, do two things:

1. Install murk 0.14 or later on the runner. A 0.14 save writes a signature
   format that 0.13 refuses.
2. Add `MURK_TRUSTED_SIGNERS` as above. A runner with a 0.13-era setup has no
   pin, so without the variable the first 0.14 vault is refused.

Upgrade the people who write the vault too. Once a runner or machine has seen
a vault saved by 0.14, a vault signed by 0.13 is refused as rolled back.

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
