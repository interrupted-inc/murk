# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Offboard demo — Bob revokes Carol, rotates secrets, Carol loses access
#
# Shows: revoke, key rotation, git push/pull, and proof that
# revoked users lose access to the new vault.

Output demo/offboard.gif

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
Type `demo_init_dirs alice bob carol`
Enter
Sleep 200ms
Type `demo_alice_vault`
Enter
Sleep 3s

# Onboard Bob and Carol (clone, init, capture keys)
Type `demo_onboard bob`
Enter
Sleep 3s
Type `demo_onboard carol`
Enter
Sleep 3s

# Alice authorizes both, pushes
Type `demo_alice_authorize bob`
Enter
Sleep 1s
Type `demo_alice_authorize carol`
Enter
Sleep 1s
Type `demo_alice_push "add bob and carol"`
Enter
Sleep 500ms

# Bob and Carol pull authorized vault
Type `demo_pull bob`
Enter
Sleep 300ms
Type `demo_pull carol`
Enter
Sleep 300ms

# Start as Bob
Type `cd "$BOB_DIR" && export MURK_KEY="$BOB_KEY"`
Enter
Type `export PS1="\n\[\e[33m\]bob \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

# === BOB: revoke Carol and rotate secrets ===

Type "# Carol is leaving the team"
Enter
Sleep 1s
Type "# Who currently has access?"
Enter
Sleep 500ms

Type "murk circle"
Enter
Sleep 2s

Type "# Revoke Carol's access"
Enter
Sleep 500ms

Type "murk circle revoke carol"
Enter
Sleep 3s

Type "# Rotate all secrets she had access to"
Enter
Sleep 500ms

Type `murk rotate --all`
Enter
Sleep 1s
Type "postgres://prod:rotated@db.example.com/app"
Enter
Sleep 1s
Type "sk-proj-rotated789xyz"
Enter
Sleep 1s
Type "sk_live_rotated456"
Enter
Sleep 2s

Type "murk circle"
Enter
Sleep 2s

Type "# Push the changes"
Enter
Sleep 500ms

Type `git add .murk && git commit -m "revoke carol, rotate secrets"`
Enter
Sleep 1s

Type `git push`
Enter
Sleep 2s

# === SWITCH TO CAROL ===

Hide
Type `cd "$CAROL_DIR" && export MURK_KEY="$CAROL_KEY"`
Enter
Type `export PS1="\n\[\e[35m\]carol \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Carol still has the old vault"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Type "# Carol pulls the latest..."
Enter
Sleep 500ms

Type "git pull"
Enter
Sleep 2s

Type "# Access revoked"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Sleep 2s
