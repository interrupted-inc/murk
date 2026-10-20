# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Agent scan demo — catch secrets an AI agent hardcoded into your code.
# `murk scan` flags vault values that leaked into files in the working tree.

Output demo/agent-scan.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)"`
Enter
Type `echo "dev" | murk init 2>/dev/null`
Enter
Sleep 1s
Type `source .env`
Enter
Type `echo "postgres://prod:s3cr3t@db.example.com/app" | murk add DATABASE_URL --desc "Primary database" 2>/dev/null`
Enter
Type `export PS1="\n\[\e[35m\]agent \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# An AI agent just edited your code. Did it hardcode a secret?"
Enter
Sleep 1500ms

Type `printf 'const db = "postgres://prod:s3cr3t@db.example.com/app";\n' > config.js`
Enter
Sleep 500ms

Type "cat config.js"
Enter
Sleep 2s

Type "# Scan the working tree against your vault's decrypted values:"
Enter
Sleep 1s

Type "murk scan"
Enter
Sleep 3s

Type "# Caught it. Fix the code to read from the environment instead:"
Enter
Sleep 1500ms

Type `printf 'const db = process.env.DATABASE_URL;\n' > config.js`
Enter
Sleep 500ms

Type "murk scan"
Enter
Sleep 3s

Type "# Clean. Run murk scan after every agent-generated change."
Enter
Sleep 2500ms
