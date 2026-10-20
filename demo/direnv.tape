# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Direnv integration — secrets automatically loaded in your shell

Output demo/direnv.gif

Require murk
Require direnv

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)"`
Enter
Type `git init >/dev/null 2>&1`
Enter
Type `eval "$(direnv hook bash)"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Ctrl+L
Sleep 500ms
Show

Type "# Initialize a vault and add secrets"
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

Type "# Set up direnv integration"
Enter
Sleep 500ms

Type "murk env"
Enter
Sleep 2s

Type "direnv allow"
Enter
Sleep 3s

Type "# Secrets are now in your shell"
Enter
Sleep 500ms

Type `echo "DATABASE_URL=$DATABASE_URL"`
Enter
Sleep 2s

Type `echo "API_KEY=$API_KEY"`
Enter
Sleep 2s

Type "# Leave and come back, direnv reloads automatically"
Enter
Sleep 500ms

Type "cd /"
Enter
Sleep 2s

Type "cd -"
Enter
Sleep 3s

Type `echo "DATABASE_URL=$DATABASE_URL"`
Enter
Sleep 2s
