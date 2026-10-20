# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Eve demo — what an unauthorized person sees
# Eve has the repo (and .murk file) but no MURK_KEY

Output demo/eve.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter

# Alice: create vault with secrets
Type `export ALICE_DIR="$(mktemp -d)"`
Enter
Type `cd "$ALICE_DIR"`
Enter
Type `echo "alice" | murk init 2>/dev/null`
Enter
Sleep 2s
Type `source .env`
Enter
Type `echo "postgres://prod:secret@db.example.com/app" | murk add DATABASE_URL --desc "Production database" 2>/dev/null`
Enter
Sleep 500ms
Type `echo "sk-proj-abc123def456" | murk add API_KEY --desc "OpenAI API key" 2>/dev/null`
Enter
Sleep 500ms
Type `echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" 2>/dev/null`
Enter
Sleep 500ms

# Eve: copy .murk, no key
Type `cd "$(mktemp -d)" && cp "$ALICE_DIR/.murk" . && unset MURK_KEY MURK_KEY_FILE`
Enter
Type `export PS1="\n\[\e[31m\]eve \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Eve cloned the repo, so she has the .murk file"
Enter
Sleep 1s

Type "# She can see what secrets exist..."
Enter
Sleep 500ms

Type "murk ls"
Enter
Sleep 2s

Type "# ...and their descriptions"
Enter
Sleep 500ms

Type "murk info"
Enter
Sleep 3s

Type "# But she can't read the values"
Enter
Sleep 500ms

Type "murk get DATABASE_URL"
Enter
Sleep 3s

Type "murk export"
Enter
Sleep 3s

Type "# The .murk file is safe to commit"
Enter
Sleep 2s
