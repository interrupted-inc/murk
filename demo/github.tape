# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# GitHub demo — onboard a teammate via GitHub SSH keys
#
# Shows: murk authorize github:username fetches SSH keys automatically,
# no key exchange needed.

Output demo/github.gif

Require murk
Require git

Source demo/theme.tape

Set Height 600

# === HIDDEN SETUP ===
Hide

Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `source demo/setup.sh`
Enter
Type `demo_init_dirs alice`
Enter
Sleep 200ms
Type `demo_alice_vault`
Enter
Sleep 3s

# Start as Alice
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

# === ALICE: onboard a teammate via GitHub ===

Type "# One recipient so far"
Enter
Sleep 500ms

Type "murk circle"
Enter
Sleep 2s

Type "# Add a teammate by GitHub username"
Enter
Sleep 500ms

Type "murk circle authorize github:iicky"
Enter
Sleep 3s

Type "# SSH keys fetched and added automatically"
Enter
Sleep 500ms

Type "murk circle"
Enter
Sleep 3s

Type "# Commit and push"
Enter
Sleep 500ms

Type `git add .murk && git commit -m "add iicky via github"`
Enter
Sleep 1s

Type `git push`
Enter
Sleep 2s

Sleep 2s
