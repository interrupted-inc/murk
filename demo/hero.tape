# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Hero demo — init, add secrets, info, export

Output demo/hero.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Ctrl+L
Sleep 500ms
Show

Type "# Initialize a new vault"
Enter
Sleep 500ms

Type "murk init"
Enter
Sleep 1s
Type "alice"
Enter
Sleep 3s

Type "# Load MURK_KEY_FILE into the environment"
Enter
Sleep 500ms

Type "source .env"
Enter
Sleep 500ms

Type "# Add some secrets"
Enter
Sleep 500ms

Type `murk add DATABASE_URL --desc "Production database"`
Enter
Sleep 1s
Type "postgres://prod:secret@db.example.com/app"
Enter
Sleep 2s

Type `murk add API_KEY --desc "OpenAI API key"`
Enter
Sleep 1s
Type "sk-proj-abc123def456"
Enter
Sleep 2s

Type `murk add STRIPE_SECRET --desc "Stripe secret key"`
Enter
Sleep 1s
Type "sk_live_xyz789"
Enter
Sleep 2s

Type "# Anyone can see what secrets exist"
Enter
Sleep 500ms

Type "murk info"
Enter
Sleep 3s

Type "# Only you can see the values"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s
