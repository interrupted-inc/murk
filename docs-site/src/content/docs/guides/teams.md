---
title: Working in teams
description: Authorize teammates and manage a shared vault.
sidebar:
  order: 2
---

murk's vault is per-recipient: every teammate has their own key, and adding
or removing someone is a normal git-tracked change to the vault file: no
shared password to rotate, no separate secrets server to run.

![Alice authorizes Bob as a recipient, then Bob decrypts the shared vault](https://raw.githubusercontent.com/interrupted-sh/murk/demo/team.gif)

## Adding a teammate

Each person has their own key. The handoff takes four steps:

1. Alice creates the vault and commits it:

   ```bash
   murk init
   murk add DATABASE_URL
   git add .murk && git commit -m "add vault" && git push
   ```

2. Bob clones the repository and runs `murk init` once in his clone. It
   creates his key (or reuses the one he already has for this vault) and,
   because he is not authorized yet, prints his public key. He sends that
   key to Alice.

   ```bash
   murk init
   ```

3. Alice authorizes the key, then commits and pushes. This re-encrypts the
   shared secrets to include Bob's key.

   ```bash
   murk circle authorize age1bob... --name bob@example.com
   git commit -am "authorize bob" && git push
   ```

4. Bob pulls. murk refuses the vault on his machine until he trusts it, so
   he reviews it and runs `murk trust` once (see [Trusting the vault on a new
   machine](#trusting-the-vault-on-a-new-machine)). He can then read the
   shared secrets:

   ```bash
   git pull
   murk trust
   murk get DATABASE_URL
   ```

Bob can still keep his own local overrides on top of the shared secrets. See
[shared vs scoped secrets](/guides/shared-vs-scoped/):

```bash
murk add DATABASE_URL --group me
```

## Trusting the vault on a new machine

A signed vault proves that a recipient wrote it, but the vault lists its own
recipients, so murk also needs to know whose signature *this machine*
accepts. The first time Bob loads the vault, murk refuses it with "not
trusted on this machine yet" and shows who signed it:

```bash
git log -p -- .murk    # who changed the vault, and how
murk diff 'HEAD@{1}'   # after a pull: the changes since before it, decoded
murk trust             # show the signer, its signing-key fingerprint and every recipient, then ask
```

A plain `murk diff` compares with `HEAD`, which is the pulled commit, so it
shows nothing right after a pull. A fresh clone has no `HEAD@{1}`, and a newly
authorized teammate's key can't open the revisions from before they were
authorized. In that case, read `git log -p -- .murk` and what `murk trust`
prints.

`murk trust` prints the signer's full key and signing-key fingerprint, and
marks each recipient that is new since this machine last trusted the vault.
Check the signer's fingerprint with Alice over a channel other than the repo.
This first check is a human
decision, and everything murk enforces afterwards builds on it. In a script,
pass `--yes` once you have reviewed the vault.

You need `murk trust` once per vault on each machine, and again whenever murk
refuses a vault and you've reviewed why: an unsigned vault, a signature from
a key the machine doesn't trust, a teammate's signing key it hasn't confirmed
yet, an older revision, another vault's file, or
a group membership change not signed by a member of that group. Switching to
an older branch is not a rollback, because each branch keeps its own counter.
But an accepted vault replaces the set of trusted signers with its own
recipients. After you load an older branch, the newer branch can be refused
as "not a trusted signer on this machine" if the teammate who signed it was
added after that older vault. Review it and run `murk trust` again.
After that, teammates' ordinary writes are accepted without a prompt: the
signer is a recipient of the vault this machine last accepted, and its
signing key is already known here. A newly authorized teammate's first write
is the exception (see below). See [Recipients &
signatures](/concepts/recipients-signatures/#trusting-a-signer) for the full
rules.

CI runners have no pin. Give them `MURK_TRUSTED_SIGNERS` instead, with each
signer's entry from `murk trust --print-key` (see
[CI/CD](/guides/cicd/)).

### A new teammate's first write

When Bob has an age key, his first write after he is authorized carries a
signing key that no other machine has seen. Each of them refuses that write
once ("a trusted recipient whose signing key this machine has not confirmed
yet") and shows the key's fingerprint.

1. Bob runs `murk trust --print-key`, which prints his own signing-key
   fingerprint. `murk init` shows the same fingerprint next to his public key
   while he isn't authorized yet, so he can send it along with the key.
2. Alice and every other teammate compare it with the fingerprint in their
   refusal, over a channel other than the repo, then run `murk trust`.

This is trust on first use: the key arrives inside the vault, so the
fingerprint comparison is the check. From then on murk pins Bob's key, and a
different key for Bob is refused as a forgery that `murk trust` won't accept.
Once a teammate who confirmed the key writes, their signed vault carries it,
and machines that load that vault learn Bob's key without another prompt.

If Bob uses an `ssh-ed25519` key, for example when Alice runs
`murk circle authorize github:bob`, nobody confirms anything: his recipient
string is his verifying key.

## Teams with hardware or `ssh-rsa` keys

Hardware/plugin and `ssh-rsa` keys can't sign. A teammate on one of them
writes the vault unsigned, and signing teammates' machines refuse it. One of
the signing teammates reviews the change and runs `murk trust`, which
re-signs the vault with their key, then commits the result. A machine that
sets `MURK_TRUSTED_SIGNERS` refuses an unsigned vault whatever its own key
can do. See [Hardware-backed keys](/guides/hardware-keys/#mixed-teams).

## Authorizing via GitHub

:::caution[Experimental]
GitHub recipients (`github:`) are experimental. murk fetches GitHub keys over the network and trusts them on first use, so confirm the keys belong to the person you mean.
:::

Instead of exchanging age keys, you can authorize by GitHub username:

```bash
murk circle authorize github:bob
```

This fetches Bob's SSH public keys from `https://github.com/bob.keys` (no
authentication required) and adds every `ssh-ed25519` key on the account as a
recipient: no pasting an age public key over Slack. It skips `ssh-rsa` keys with
a warning unless you pass `--allow-ssh-rsa`, and fails if every key is RSA.
`ssh-ed25519` keys sign directly, so teammates added this way need no
signing-key confirmation.

Bob decrypts with the matching private key by setting `MURK_KEY_FILE` to it
(for example `~/.ssh/id_ed25519`). murk does not search `~/.ssh` on its own.
It needs an unencrypted SSH private key that only Bob can read, and it cannot
read a passphrase-protected one. If Bob has no such key, use the age key
exchange above.

### Recipient pinning

The first successful `murk circle authorize github:bob` records the SHA-256
fingerprints of the fetched keys in the encrypted vault metadata. If Bob's
GitHub keys change later, the next `authorize github:bob` refuses to proceed
silently: it flags the diff and requires `--force` to accept the new keys.
This catches both benign key rotation and a compromised GitHub account adding
an attacker's key. It turns either into something a human has to actively
confirm rather than something that happens invisibly.

This pinning trusts GitHub as a key directory and trusts that the
username belongs to who you think it does. Treat `authorize github:user` with
the same care you'd give any access grant: verify identity out of band for
sensitive vaults. See the [threat model](/security/threat-model/) for the
full trust analysis.

## Listing and managing recipients

```bash
murk circle                    # list recipients
murk circle revoke RECIPIENT   # a public key, a display name or github:user (see offboarding)
```

murk compares keys by their canonical spelling, so `authorize` refuses a
second spelling of a key that is already a recipient, and `revoke` removes
every spelling of a key. An `age1...` key with a non-canonical encoding (the
high bit of its value set) is refused outright, so it can't serve as an alias
that outlives a revocation.

To share a secret with only part of the team, use a group (experimental):

```bash
murk group create ops
murk group add ops --member bob@example.com
murk add STRIPE_KEY --group ops
```

`murk group ls` lists groups, and `murk group rm ops --member bob@example.com`
removes a member. `murk circle authorize ... --group ops` adds a new
recipient to a group in the same step. See [shared vs scoped
secrets](/guides/shared-vs-scoped/) and the [CLI
reference](/reference/cli/#murk-group) for the full flag surface.

A change to a group's membership has to be signed by a member of that group.
A machine that has pinned the earlier membership refuses a change made by
anyone else, until you review it and run `murk trust`. For the same reason
`murk group rm NAME` needs you to be a member of the group, and the merge
driver refuses a merge that changes a group's membership when the merging key
isn't in that group: a member has to do that merge (see [the merge
driver](/guides/git-merge-ssh/)).

When someone leaves the team, don't just stop there. See
[offboarding a teammate](/guides/offboarding/) for revocation and rotation.

## Upgrading to 0.14

0.14 changes how vaults are signed and trusted, so a vault written by 0.14
can't be read by 0.13 or earlier. Upgrade everyone who writes or reads the
vault, and CI, before the first 0.14 write lands on the shared branch.

1. On each machine, the first load of an existing vault is refused once,
   with "not trusted on this machine yet" and the current signer. Review the
   history (`git log -p -- .murk`, and `murk diff REF` against the last
   revision you reviewed), then run `murk trust`. A
   0.13 pin carried no trust, so everyone does this once.
2. The first 0.14 save adds a vault id and a save counter and re-signs the
   vault in the new format. A vault from 0.13 has no id, so murk derives it
   from the vault's `created` timestamp and name. Every copy derives the
   same one, so teammates who upgrade on different days still agree.
3. Once a machine has seen a vault saved by 0.14, a vault signed by 0.13 is
   refused as rolled back. That is the order to follow: trust once, then
   make the first 0.14 save. A write from a teammate who is still on 0.13
   won't be accepted.
4. Give CI `MURK_TRUSTED_SIGNERS`. See [CI/CD](/guides/cicd/#upgrading-to-014).
5. Re-run `murk setup-merge-driver` in each clone, so the driver gets the
   vault path. See [the merge driver](/guides/git-merge-ssh/#upgrading-an-older-driver-config).
6. If part of your team is on hardware or `ssh-rsa` keys, read the section
   above: their writes are unsigned until a signing teammate runs `murk trust`.
