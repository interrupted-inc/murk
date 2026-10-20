# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Worktree demo — a fresh worktree needs no .env.
# The vault is committed, so it arrives with the checkout. The key was never
# in the repo: murk resolves it from a sibling checkout of the same repo,
# verified against git's worktree metadata. Discovery is off in agent context.

Output demo/worktree.gif

Require murk
Require git

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)" && git init -q`
Enter
Type `git config user.email "dev@example.com" && git config user.name "Dev" && git config commit.gpgsign false`
Enter
Type `echo "dev" | murk init 2>/dev/null`
Enter
Sleep 1s
Type `source .env`
Enter
Type `echo "postgres://prod:s3cr3t@db.example.com/app" | murk add DATABASE_URL --desc "Primary database" 2>/dev/null`
Enter
Type `printf '.env\n.murk.lock\n' >> .gitignore`
Enter
Type `git add -A && git commit -qm "vault"`
Enter
Type `unset MURK_KEY MURK_KEY_FILE`
Enter
Type `export PS1="\n\[\e[94m\]dev \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# A new worktree checks out tracked files and nothing else:"
Enter
Sleep 1500ms

Type "git worktree add ../feature-x"
Enter
Sleep 2s

Type "cd ../feature-x"
Enter
Sleep 1s

Type "ls -a"
Enter
Sleep 2500ms

Type "# The vault came with the checkout. No .env, nothing to provision."
Enter
Sleep 1500ms

Type "# The key was never in the repo. murk finds it in a sibling checkout:"
Enter
Sleep 1500ms

Type "murk get DATABASE_URL"
Enter
Sleep 3s

Type "# Agents get no free ride. Discovery is off in agent context:"
Enter
Sleep 1500ms

Type "MURK_AGENT=1 murk get DATABASE_URL"
Enter
Sleep 3s

Type "# An agent in a worktree presents its own grant, or fails closed."
Enter
Sleep 2500ms
