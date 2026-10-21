# Quick start for teammates

You've been invited to a project that uses murk for secrets. Here's how to get set up.

## 1. Install murk

```bash
brew install interrupted-sh/tap/murk
```

Or: `cargo install murk-cli`, `pip install murk-secrets`, or download from [GitHub Releases](https://github.com/interrupted-sh/murk/releases).

## 2. Generate your key

```bash
murk init
```

This creates your keypair and prints 24 recovery words. **Write them down.** If you lose your key, these words are the only way to recover it.

Your key is stored in `~/.config/murk/keys/`, not in the repo.

## 3. Get authorized

Ask whoever maintains the vault to authorize you. The easiest path is GitHub — no manual key exchange:

```bash
# (run by a current recipient, not you)
murk circle authorize github:YOUR_USERNAME
```

This fetches your SSH public keys from `https://github.com/YOUR_USERNAME.keys` and adds them as recipients. murk pins the fingerprints on first authorize, so if your GitHub keys change later the next `authorize github:YOU` will flag the diff before accepting new keys.

If GitHub isn't an option, send them your raw age pubkey instead. Run `murk init` a second time in the project directory — when the vault already exists and you are not yet authorized, it prints the pubkey you need to share:

```
⚠ not authorized — share your public key to get added:
  age1…
  signing key SHA256:… — teammates confirm this on your first write
```

They authorize it with `murk circle authorize age1… --name you@example.com`. The signing-key fingerprint is for them: your first write after you're authorized is refused once on each teammate's machine until they check that fingerprint with you, over something other than the repo, and run `murk trust`. `murk trust --print-key` shows it again later. A GitHub `ssh-ed25519` key needs no such check.

## 4. Pull and trust the vault

Once authorized:

```bash
git pull                    # get the updated .murk file
murk trust                  # once per machine: review the signer, then accept
```

`murk trust` prints who signed the vault (their full key and its signing-key fingerprint) and every recipient, then asks before it records anything. Check the signer's fingerprint with the person who invited you, over something other than the repo. Run `murk diff` and `git log -p -- .murk` first if you want to see what changed. Skip this step and the first load on a machine is refused with "not trusted on this machine yet". murk remembers your answer on this machine, not in the repo, and asks again only if a later vault looks wrong: unsigned, signed by an unfamiliar key, or older than one you've already accepted.

## 5. Use secrets

```bash
murk ls                     # see what secrets are available
murk get DATABASE_URL       # print one secret
murk export                 # print all as shell exports
murk exec -- ./my-script.sh # run a command with secrets in env
```

## 6. Set up direnv (optional)

```bash
murk env
direnv allow
```

Now secrets are automatically loaded when you `cd` into the project.

## What to know

- **Key names are public.** Anyone with repo access can see what secrets exist (e.g. `STRIPE_KEY`). Only values are encrypted.
- **Your key is your identity.** Don't share it. Don't paste it into chat. Don't commit it.
- **Recovery phrase = your key.** If someone has your 24 words, they have your key.
- **Revocation doesn't erase history.** If you leave the team, your access to old git history remains. The team should rotate secrets after revoking you.
- **Trust is per machine.** murk checks every vault against what your machine has accepted, so a file copied over the vault or an older revision is refused. Pass `--yes` to `murk trust` only in scripts, after reviewing the vault.
- **A vault can't set sensitive variables.** `murk export`, `exec` and `agent exec` refuse a key named like `PATH`, `LD_PRELOAD`, `GIT_*`, `HTTPS_PROXY` or `MURK_*`, because whoever last wrote the vault chose those names. Review who added it, then pass `--allow-reserved` if you mean it.
