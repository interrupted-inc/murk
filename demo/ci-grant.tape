# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# CI grant demo — CI gets its own scoped key, which expires loudly.
# `murk agent grant --out -` streams a grant key file to stdout. The file
# starts with `# murk-trusted-signer:` lines, and murk-action takes only the
# key line, so `grep AGE-SECRET-KEY` keeps that line on its way into the
# Actions secret store. The CI job also gets MURK_TRUSTED_SIGNERS, because a
# bare key names no signer. murk-action then runs `murk export` and sees only
# the granted keys. The `gh` CLI is shimmed for the recording (it writes the
# key to a local file) so the on-camera command is exactly what a reader
# copies.
# The TTL is seconds here so the expiry fits on camera; use 30d in real life.

Output demo/ci-grant.gif

Require murk
Require git

Source demo/theme.tape

Set Height 600

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `export DEMO_DIR="$(mktemp -d)" && cd "$DEMO_DIR" && git init -q`
Enter
Type `git config user.email "dev@example.com" && git config user.name "Dev" && git config commit.gpgsign false`
Enter
Type `echo "dev" | murk init 2>/dev/null`
Enter
Sleep 1s
Type `source .env`
Enter
Type `echo "ghp_deploy_7f3a9c1e" | murk add DEPLOY_TOKEN --desc "Deploy token" 2>/dev/null`
Enter
Type `echo "postgres://prod:s3cr3t@db.example.com/app" | murk add PROD_DB --desc "Production database" 2>/dev/null`
Enter
Type `gh() { cat > "$DEMO_DIR/ci-secret"; echo "Set Actions secret MURK_KEY for acme/app"; }`
Enter
Type `CI_SIGNERS="$(murk trust --print-key 2>/dev/null)"`
Enter
Type `printf '.env\n.murk.lock\n' >> .gitignore`
Enter
Type `git add -A && git commit -qm "vault"`
Enter
Type `export PS1="\n\[\e[94m\]dev \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# CI needs DEPLOY_TOKEN. Mint it a key of its own, not yours:"
Enter
Sleep 1500ms

Type "# (use --ttl 30d; 30s here so the expiry fits on camera)"
Enter
Sleep 1s

Type `murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30s \`
Enter
Type `  --out - | grep AGE-SECRET-KEY | gh secret set MURK_KEY`
Enter
Sleep 2500ms

Type "# The grant lives in .murk. Commit and push it before CI can use it."
Enter
Sleep 1s

Type `git commit -qam "grant ci-deploy"`
Enter
Sleep 1500ms

Hide
Type `unset MURK_KEY MURK_KEY_FILE && export MURK_KEY="$(cat "$DEMO_DIR/ci-secret")" MURK_TRUSTED_SIGNERS="$CI_SIGNERS"`
Enter
Type `export PS1="\n\[\e[35m\]ci \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# murk-action runs murk export with this key and MURK_TRUSTED_SIGNERS."
Enter
Sleep 1s

Type "murk export"
Enter
Sleep 2500ms

Type "# DEPLOY_TOKEN only. PROD_DB was never encrypted to this key."
Enter
Sleep 2s

Type "# Day 31:"
Enter
Sleep 1s

# Off camera: outlast the 30s TTL no matter how long the typing above took.
Hide
Sleep 31s
Show

Type "murk export"
Enter
Sleep 3s

Type "# Fails loudly. A stale CI credential never works forever."
Enter
Sleep 2s

Hide
Type `cd "$DEMO_DIR" && unset MURK_KEY MURK_TRUSTED_SIGNERS && source .env`
Enter
Type `export PS1="\n\[\e[94m\]dev \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Renew before then. --renew revokes the old key and mints a new one:"
Enter
Sleep 1500ms

Type `murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30s \`
Enter
Type `  --renew --out - | grep AGE-SECRET-KEY | gh secret set MURK_KEY`
Enter
Sleep 2500ms

Type `git commit -qam "renew ci-deploy"`
Enter
Sleep 1500ms

Type "# Update the secret and push the vault together. A run in the gap"
Enter
Type "# fails loudly, never silently."
Enter
Sleep 2s

Hide
Type `unset MURK_KEY MURK_KEY_FILE && export MURK_KEY="$(cat "$DEMO_DIR/ci-secret")" MURK_TRUSTED_SIGNERS="$CI_SIGNERS"`
Enter
Type `export PS1="\n\[\e[35m\]ci \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "murk export"
Enter
Sleep 3s

Type "# Back in business, with the same one-key scope."
Enter
Sleep 3s
