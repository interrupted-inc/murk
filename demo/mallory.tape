# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Mallory demo — tampering with a .murk vault is detected
# Mallory has her own key but isn't authorized on this vault

Output demo/mallory.gif

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
Type `export ALICE_KEY="$MURK_KEY"`
Enter
Type `echo "postgres://prod:secret@db.example.com/app" | murk add DATABASE_URL --desc "Production database" 2>/dev/null`
Enter
Sleep 500ms
Type `echo "sk-proj-abc123def456" | murk add API_KEY --desc "OpenAI API key" 2>/dev/null`
Enter
Sleep 500ms

# Mallory: her own key, copy of Alice's vault
Type `export MALLORY_DIR="$(mktemp -d)"`
Enter
Type `cd "$MALLORY_DIR"`
Enter
Type `echo "mallory" | murk init 2>/dev/null`
Enter
Sleep 2s
Type `source .env`
Enter
Type `export MALLORY_KEY="$MURK_KEY"`
Enter
Type `export MALLORY_PUBKEY=$(murk init 2>&1 | sed "s/$(printf '\033')\[[0-9;]*m//g" | grep -o 'age1[a-z0-9]*')`
Enter
Sleep 1s
Type `cp "$ALICE_DIR/.murk" .`
Enter
Type `export PS1="\n\[\e[35m\]mallory \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Mallory has her own key and a copy of the vault"
Enter
Sleep 1s

Type "murk circle"
Enter
Sleep 2s

Type "# She tries to authorize herself"
Enter
Sleep 500ms

Type `murk circle authorize "$MALLORY_PUBKEY" --name mallory`
Enter
Sleep 3s

Type "# She's not a recipient, so she edits .murk directly"
Enter
Sleep 1s

Hide
Type `python3 -c "import json,os; v=json.load(open('.murk')); v['recipients'].append(os.environ['MALLORY_PUBKEY']); json.dump(v, open('.murk','w'), indent=2)"`
Enter
Sleep 1s
Show

Type `head -8 .murk`
Enter
Sleep 2s

Type "# Alice pulls the tampered vault"
Enter
Sleep 500ms

Hide
Type `cp .murk "$ALICE_DIR/.murk"`
Enter
Type `cd "$ALICE_DIR"`
Enter
Type `export MURK_KEY="$ALICE_KEY"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Integrity check catches the tampering"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Type "murk get DATABASE_URL"
Enter
Sleep 3s

Type "# The vault is safe, restore from git"
Enter
Sleep 2s
