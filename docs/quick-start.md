# Quick start for teammates

You've been invited to a project that uses murk for secrets. Here's how to get set up. Starting a project of your own? See [Start a new vault](#start-a-new-vault).

## 1. Install murk

```bash
brew install interrupted-sh/tap/murk
```

Or use `cargo install murk-cli`, the `install.sh` script (Linux and macOS), or download a binary from [GitHub Releases](https://github.com/interrupted-sh/murk/releases). See [Install](../README.md#install) for every option.

## 2. Generate your key

Clone the repo and change into it. Run `murk init` next to the `.murk` file. In a directory without a `.murk` file, `murk init` creates a new, unrelated vault.

```bash
murk init
```

murk generates a key for this vault, prints 24 recovery words, and prints your public key:

```
⚠ not authorized — share your public key to get added:
  age1…
```

If `MURK_KEY` or `MURK_KEY_FILE` is already set in your shell, or murk already stores a key for this vault, murk uses that key instead of generating one. It then prints no recovery words. Unsetting the variable gives you a new key only if murk stores no key for this vault.

**Write the recovery words down.** If you lose your key, these words are the only way to recover it. Copy the `age1…` line for step 3.

If you lose the `age1…` line, run `murk init` again in the same directory. It reuses your stored key and prints the same public key. It never replaces a key that is already stored.

murk stores your key in `~/.config/murk/keys/`, not in the repo. It also writes a `.env` file that points at the key: add `.env` to `.gitignore`.

## 3. Get authorized

Send your `age1…` public key to someone who can already decrypt the vault. They run:

```bash
# (run by a current recipient, not you)
murk circle authorize age1… --name you@example.com
```

Then they commit and push `.murk`.

**Using a GitHub SSH key instead.** If you have an ed25519 SSH key on GitHub, the recipient can add it without exchanging keys. They run `murk circle authorize github:YOUR_USERNAME`, then commit and push `.murk`. murk adds your GitHub SSH public keys as recipients (RSA keys are skipped). On this path your SSH key is your murk identity, so you do not need the key from step 2. murk does not look in `~/.ssh` on its own. After you `git pull`, unset `MURK_KEY` and point murk at your SSH private key: `export MURK_KEY_FILE=~/.ssh/id_ed25519`. The key must be unencrypted (no passphrase) and readable only by you. Without this, `murk get`, `murk export` and `murk exec` fail with "you are not a recipient".

If your GitHub keys change later, the next `authorize github:YOUR_USERNAME` refuses and lists the added and removed keys. The recipient must review them and pass `--force`.

## 4. Pull and use secrets

Once authorized:

```bash
git pull                    # get the updated .murk file
murk ls                     # see what secrets are available
murk get DATABASE_URL       # print one secret
murk export                 # print all as shell exports
murk exec -- ./my-script.sh # run a command with secrets in env
```

## 5. Set up direnv (optional)

```bash
murk env
direnv allow
```

Now secrets are automatically loaded when you `cd` into the project.

## Start a new vault

Run `murk init` in a project directory that has no `.murk` file. murk asks for your name or email, creates the vault with you as its first recipient, and prints your recovery words. Write them down. If `MURK_KEY` or `MURK_KEY_FILE` is set, or murk already stores a key for this vault (here or in another git worktree of the repo), murk uses that key and prints no recovery words. Then add secrets, commit the vault and load it with direnv:

```bash
murk init
murk add DATABASE_URL   # prompts for the value (hidden input)
git add .murk && git commit -m "add secrets vault"
murk env
direnv allow
```

Add `.env` to `.gitignore` before you commit. To add a teammate, run the `murk circle authorize` command from step 3, then commit and push `.murk`.

## What to know

- **Key names are public.** Anyone with repo access can see what secrets exist (e.g. `STRIPE_KEY`). Only values are encrypted.
- **Your key is your identity.** Don't share it. Don't paste it into chat. Don't commit it.
- **Recovery phrase = your key.** If someone has your 24 words, they have your key.
- **Revocation doesn't erase history.** If you leave the team, your access to old git history remains. The team should rotate secrets after revoking you.
