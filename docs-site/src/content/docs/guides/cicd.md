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

## Telling CI who may sign the vault

A fresh CI runner has no [trust pin](/concepts/recipients-signatures/#trusting-a-signer),
and nobody is there to run `murk trust`. Without help, murk refuses the vault
with "not trusted on this machine yet". A [scoped grant's whole key
file](#prefer-a-scoped-grant-over-a-full-key) names its own signers. Any other
key needs `MURK_TRUSTED_SIGNERS`: the people who write the vault, from a
secret, next to `MURK_KEY`. Pass it to murk-action as `trusted-signers`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
      trusted-signers: ${{ secrets.MURK_TRUSTED_SIGNERS }}
  - run: ./deploy.sh
```

The `trusted-signers` input needs murk-action v1.2.0 or later, which `@v1`
gives. On an older murk-action, set `MURK_TRUSTED_SIGNERS` in the step's
`env:` instead.

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

The action sets the variable only for the murk commands it runs. A later step
that runs murk itself needs it in its own `env:`:

```yaml
  - run: murk exec -- ./deploy.sh
    env:
      MURK_KEY: ${{ secrets.MURK_KEY }}
      MURK_TRUSTED_SIGNERS: ${{ secrets.MURK_TRUSTED_SIGNERS }}
```

A scoped grant key is the exception. It never reads the pin. It trusts the
signers named in its key file, which are the `# murk-trusted-signer:` lines that
`murk agent grant` writes above the key, plus any in `MURK_TRUSTED_SIGNERS`. So
the whole key file works on a runner with no pin and no variable. murk-action
v1.2.0 and later take the whole file as `murk-key`. A bare key line names no
signer, so a grant passed that way needs `MURK_TRUSTED_SIGNERS`. A signer added
after you minted the grant isn't in its key file. The grant then refuses the
vault until you re-mint it with `--renew` or list that signer in
`MURK_TRUSTED_SIGNERS`.

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
2. Give CI its trusted signers: `trusted-signers` or `MURK_TRUSTED_SIGNERS` as
   above, or a grant's whole key file. A runner with a 0.13-era setup has no
   pin, so without them the first 0.14 vault is refused.

Upgrade the people who write the vault too. Once a runner or machine has seen
a vault saved by 0.14, a vault signed by 0.13 is refused as rolled back.

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

`--out -` writes the grant key file to stdout and stores no copy, so it goes
straight into the Actions secret. Above the key, the file has
`# murk-trusted-signer:` lines and the grant's `# murk-grant-id:` and
`# murk-grant-expires:` lines.

Pass the secret to murk-action as `murk-key`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # DEPLOY_TOKEN is now in the environment
```

This needs murk-action v1.2.0 or later, which `@v1` gives. The action passes
the whole file to murk. A job that runs `murk` itself takes the same secret as
`MURK_KEY`. The trusted-signer lines name who may sign the vault, so the job
needs no `MURK_TRUSTED_SIGNERS`. One secret is enough. The key
stops working at the expiry it was minted with, whatever a later vault says.
When the vault's record would allow more, the refusal names the key file's
expiry:

```
✕ grant ci-deploy expired 2026-11-20T19:56:49Z (its key file's expiry) — renew with `murk agent grant --renew` or close it with `murk agent revoke ci-deploy`
```

If you pin a murk-action older than v1.2.0, it takes only the bare key line.
Keep just that line with `grep`:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --out - | grep AGE-SECRET-KEY | gh secret set MURK_KEY
```

A bare key names no signer, so also give the job its signers: the
`trusted-signers` input on v1.2.0 and later, or `MURK_TRUSTED_SIGNERS` in the
step's `env:` on any version, as described above. A bare key carries no expiry
either, so only the grant record in the vault bounds it, and each `murk`
command in the job prints a warning:

```
warn this grant key file carries no expiry, so only the vault's grant record bounds it — ask the operator to re-mint it (`murk agent grant --renew`)
```

It's the same mechanism murk uses to scope AI agent access. See [AI agents & MCP](/guides/ai-agents-mcp/) for the full grant/revoke
lifecycle and the [CLI reference](/reference/cli/#murk-agent-grant) for the flag
surface.

The grant lives in `.murk`, so CI can only use the key once the vault
containing the grant is on the branch it checks out. `murk export` under the
grant yields only the granted keys; a `murk get` of anything else fails with
`KEY is outside this grant's scope`.

### Renewing the grant

Before the grant expires, run the same two lines with `--renew` (add the
`grep` if you store the bare key line):

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --renew --out - | gh secret set MURK_KEY
git commit -am "grant ci-deploy" && git push
```

`--renew` revokes the old key as it mints the new one, in a single vault
write. Update the Actions secret and push the vault together: a job that runs
between the two fails loudly with `not a recipient`, never silently. If you
miss the renewal, the job fails with `grant ci-deploy expired`. If anyone writes
the vault first, that write removes the expired grant and the job fails with
`not a recipient` instead. Either way it fails closed, as intended.

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
