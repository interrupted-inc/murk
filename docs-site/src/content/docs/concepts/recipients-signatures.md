---
title: Recipients & signatures
description: How recipients are authorized, how the MAC and signature protect the vault, and how a machine decides to trust a signer.
sidebar:
  order: 3
---

Three mechanisms protect a `.murk` file: the **recipient list** controls who can decrypt it, the **integrity MAC and signature** detect whether it's been tampered with, and a **trust check** on each machine decides whether the signer is someone that machine accepts.

## Adding and removing recipients

`murk circle authorize PUBKEY --name NAME` adds a new recipient and re-encrypts every shared secret so the new key can read it. It accepts three formats: a raw `age1...` key, an `ssh-ed25519 ...` key, or `github:username`, which fetches that user's SSH public keys from `https://github.com/<username>.keys`. GitHub-sourced keys are pinned by fingerprint on first authorize (in the encrypted meta's `github_pins`), so if the account's keys change later, the next `authorize github:<user>` flags the diff instead of silently trusting new keys. Pass `--group` to add the recipient to a named group in the same step.

Keys are compared by their canonical spelling: lowercase for `age1...` and plugin keys, `type blob` without the comment for SSH keys. `authorize` refuses a second spelling of a key that is already a recipient, and stores age keys in lowercase. An `age1...` key whose encoding isn't canonical (the high bit of its 32-byte value is set, or the value is out of range) names the same key under another string, so murk refuses it. `revoke` removes every spelling, and a vault header that lists one key twice fails validation. Without this, an alias spelling of a revoked key could outlive the revocation.

Display names are stored only inside the encrypted `meta` blob, never in the plaintext `recipients` list, so the pubkey-to-person mapping is itself protected, even though the existence of a pubkey isn't.

`murk circle revoke RECIPIENT [--rotate]` removes a recipient's pubkey, re-encrypts shared secrets without it, and drops that recipient's private entries. **Revocation doesn't erase git history**: the revoked recipient can still decrypt any vault version they previously had access to. `--rotate` (or the interactive prompt) walks through generating new values for everything they could read. That's the only way to actually close the exposure.

## The integrity MAC

Every save computes a BLAKE3 keyed hash over the vault's key names, per-key ciphertexts, recipient list, schema, group and grant definitions, policy, and any pending-rotation markers, storing the digest as `mac` alongside its key (`mac_key`) in the encrypted meta. On load, murk recomputes and checks it, catching accidental corruption or a non-recipient's tampering immediately.

It is **not** a defense against a malicious recipient or anyone else with write access to the repo. age only needs recipients' *public* keys (which sit in the plaintext header) to re-encrypt content, so a repo-writer can mint a fresh `mac_key`, recompute a valid MAC over tampered content, and re-encrypt `meta` to match. Authorship integrity comes from the signature below, not the MAC.

## Signatures

murk signs the vault with Ed25519 on every save where the writer holds a signing-capable identity. The MAC can't say who wrote a vault, because anyone who can write the file can recompute it. A signature can.

Two identity types can sign:

- **age keys** sign with plain Ed25519, using a key derived from the age secret through a BLAKE3 KDF, so the BIP39 phrase still recovers it. Decryption and signing use separate keys. The verifying key can't be computed from the `age1...` recipient, so the signer publishes it in the vault's signer registry on every save, and murk checks the signature against that entry. Because a vault can't vouch for its own registry, a machine believes an entry only after it has been confirmed (see [A new teammate's first write](#a-new-teammates-first-write)).
- **ssh-ed25519 keys** sign directly, since the key is already Ed25519. The verifying key is the one in the recipient string, so there is no registry entry to confirm.

`ssh-rsa` keys and hardware/plugin identities can't sign, so a save made with one of them is written unsigned. See [Hardware-backed keys](/guides/hardware-keys/) for what a mixed team does about that.

The signature covers the vault id, the save counter, the recipients, the schema, every secret, the policy, groups, grants and GitHub pins. Verification is strict: it rejects small-order keys and non-canonical encodings. A present-but-invalid signature fails the load as tampering.

## Trusting a signer

A valid signature only proves that *some* key listed as a recipient signed the file, and the file chooses its own recipients. Someone with write access to the repo could list their own key and sign. So murk also asks whether *this machine* trusts the signer, and anchors that answer in state the repo can't write.

That state is the **trust pin**, a file under `~/.config/murk/signer-pins/` (mode `0600`, one per repository and vault path, so every git worktree of a repo shares it). It records:

- the keys allowed to sign the next version: the non-grant recipients of the last vault this machine accepted
- the vault's id, and the highest save counter accepted, overall and per git branch
- group membership as last accepted
- every agent-grant key seen, which never counts as a signer
- the verifying key of each age signer this machine has confirmed, which a different key can never replace

Only an accepted load, `murk trust`, or this machine's own `init` and saves write the pin. Nothing from an unverified vault ever does. A pin that can't be parsed is an error, not an empty pin. A pin that can't be written during a normal load (a read-only home, say) only prints a warning: the vault is trusted either way, but murk can't remember it.

Every keyed load checks the vault against it, for the CLI, the MCP server and the Python and Node bindings alike. Write commands load through the same check, so a write never re-signs content the machine doesn't trust. murk refuses the vault when:

- **It's unsigned and your key could have signed it.** An `age` or `ssh-ed25519` key never loads an unsigned vault. A key that can't sign (`ssh-rsa`, hardware) loads it with a warning, since a team on those keys relies on signed git commits. That allowance ends when `MURK_TRUSTED_SIGNERS` is set: once you name the signers you require, an unsigned vault is refused for every key.
- **It was signed when this machine last accepted it and is now unsigned.** Refused for every key. Someone stripped the signature, or a merge or a hardware-key write left it unsigned.
- **The signer isn't trusted here.** With no pin yet, the message is "not trusted on this machine yet". Otherwise the signer isn't among the keys the pin trusts.
- **An age signer's signing key isn't confirmed here yet.** The signer is a trusted recipient, but this machine hasn't seen their signing key before, typically because it is a newly authorized teammate's first signed write. murk refuses it once and shows the key's fingerprint until `murk trust` confirms it. See [A new teammate's first write](#a-new-teammates-first-write).
- **An agent grant signed it.** Grants are read-only, so a grant key never signs. A former grant key that is back in the recipients without its grant is refused too. `murk trust` won't accept these: restore the file from git.
- **It's a different vault.** The vault id doesn't match the pinned one, as if another vault's file had been copied over it.
- **It rolled back.** Its save counter is below the highest accepted on the checked-out branch, so an older revision may have been replayed. A murk 0.13 signature counts too: once this machine has seen a vault written by 0.14, a vault with a 0.13 signature can only be an older revision, so it is refused as rolled back. See below.
- **A group changed without a member's signature.** A change to a group's membership must be signed by a member of that group as pinned. Removing someone who left the vault entirely is exempt, since `circle revoke` does that. `murk group rm NAME` likewise needs you to be a member of the group.
- **A pinned signer shows a different signing key.** An age key's verifying key is derived from its secret, so a second key for the same recipient is a forgery. murk refuses it, and `murk trust` won't accept it: restore the file from git.

Each refusal says what happened, shows the signer's key next to its name (the name is chosen by whoever wrote the file) and the recipient changes since the pin, and points you at the review step.

### `murk trust`

`murk trust` is that step. Review `git log -p -- .murk` and `murk diff` first. `murk diff` runs on a vault this machine refuses, warns that it isn't trusted, and lists recipient and signer changes next to the value changes. Then run `murk trust`. It prints the vault id, the counter (and the highest one trusted here), the signer's name and full key, the signer's signing-key fingerprint, and every recipient, marked `+` when it's new since this machine last trusted the vault. The fingerprint is marked "trust on first use" when this machine hasn't confirmed that key before. Grant keys are labelled "agent grant, never a signer", and trusted keys that are gone are marked `-`. Then it asks. `--yes` skips the question for scripts; without a terminal and without `--yes`, it refuses.

What accepting does depends on the vault:

- An unsigned or stripped vault, with a key that can sign: murk re-signs it with your key. That is a save, so commit the result.
- A stripped vault, with a key that can't sign: murk forgets that a signed version was seen, and the vault loads with the warning.
- Anything else: murk pins the vault as shown. For a rollback or another vault, the counter resets.

You need it once per vault on each machine: a fresh clone, a new laptop, and the first run after [upgrading to 0.14](/guides/teams/#upgrading-to-014). After that, you need it again when murk refuses a vault and you've reviewed why, including an age-key teammate's first signed write (next section). The first run on a new machine is a human decision: check the signer's fingerprint with the person who owns the key, over a channel other than the repo.

`murk trust --print-key` shows your own key instead of reviewing a vault: it prints your `MURK_TRUSTED_SIGNERS` entry to stdout and your signing-key fingerprint to stderr. It fails for a key that can't sign. The fingerprint is `SHA256:` and the unpadded base64 of the SHA-256 of the 32-byte verifying key, the form `ssh-keygen -l` prints.

### A new teammate's first write

When someone is authorized with an age key, their signing key isn't in any vault yet. Their first signed write adds it to the registry, and every other machine refuses that write once: "a trusted recipient whose signing key this machine has not confirmed yet". The refusal shows the key's fingerprint.

1. The teammate runs `murk trust --print-key` to see their own fingerprint. `murk init` prints it too, next to the public key, while they're not yet authorized.
2. Everyone else compares it with the fingerprint murk showed them, over a channel other than the repo, and runs `murk trust`.

This is trust on first use. The key arrives in a vault, so the fingerprint comparison is what stops someone with write access from registering their own key under a teammate's recipient. Once confirmed, the key is pinned and never replaced.

Confirmation spreads. A machine that confirmed the key writes a vault whose signed registry carries it, and a machine that loads that vault learns the key without another prompt, because the entry comes from a vault signed by a signer it already trusts. `ssh-ed25519` teammates, including those added with `murk circle authorize github:user`, need none of this: their recipient string is their verifying key.

### CI

A CI runner has no pin. Set `MURK_TRUSTED_SIGNERS` to the people who write the vault, separated by commas or newlines, usually as a CI secret. An age signer is `age1...:<verifying key>` and an `ssh-ed25519` signer is its public key line; each signer runs `murk trust --print-key` to get their entry. When set, it replaces the pin's trusted set, and an age signer's signature has to verify under the verifying key in its entry. Grant keys listed there still never count, and an entry in neither form, including a bare `age1...` key, is an error. Setting it also makes an unsigned vault an error for every key, including keys that can't sign. A trust decision made through `MURK_TRUSTED_SIGNERS` doesn't widen the local pin: the variable never adds trust that would outlive it. A runner without a pin can't detect rollback. See [CI/CD](/guides/cicd/).

`MURK_NO_SIGNER_PIN` stops murk reading or writing the pin. It doesn't switch the check off: without `MURK_TRUSTED_SIGNERS`, every signed vault is then refused, and rollback and stripped-signature detection are off. A machine with no home directory behaves the same way.

### Rollback and deliberate reverts

Every save writes a counter one above the highest this machine has seen, and a keyed merge writes one above both sides. The pin keeps the highest counter per git branch, so a branch that went backwards is refused, while switching to an older branch is fine: that branch has its own mark. On a detached HEAD, or a branch this machine has never seen, there is no counter check.

To revert a branch on purpose, restore the older file, run `murk trust` (it shows the counter going back), then make any write. The write is numbered above everything this machine accepted, so teammates accept it as newer.

### Vault ids and upgrading from 0.13

A new vault gets a random id at `murk init`. A vault written by 0.13 has none, so the first 0.14 save derives one from the vault's `created` timestamp and name, which every copy shares. Teammates who upgrade separately therefore agree on the id and don't refuse each other's saves as another vault. After a machine has seen a 0.14 vault, a 0.13-signed one is refused as rolled back, so the upgrade is: run `murk trust` once, then make the first 0.14 save. A teammate who stays on 0.13 can't load a vault that 0.14 has saved, and a vault they write from 0.13 is refused as rolled back on every machine that has seen 0.14's.

## What this doesn't cover

A trusted signer can still change values or add recipients. That's authorized by design, and a compromised trusted key is a compromised signer. A rollback onto a branch or detached HEAD this machine never recorded isn't detected, for example when you review a PR branch. The commands that only read the plaintext header (`ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show`, `doctor`) don't run the check. Run without a key, each prints a `warn unverified header` line on stderr, so what they show isn't mistaken for checked data. `rotate --list` is the exception: with a key it verifies the vault before reporting and fails on a header that was edited; without one it prints the same warning, and `MURK_STRICT` refuses the result.

## Where this fits

The [threat model](/security/threat-model/) covers the full malicious-recipient boundary and what signatures do and don't close. [Vault format](/concepts/vault-format/) shows where the MAC, signature and trust fields live on disk. [Hardware-backed keys](/guides/hardware-keys/) covers plugin identities, which authorize and decrypt normally but can't sign. [SSH keys & git merge](/guides/git-merge-ssh/) covers `ssh-ed25519` signing and how the merge driver verifies and signs.
