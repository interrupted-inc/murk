# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Agent connect demo — the agent gets a scoped grant, never your key.
# `murk agent connect` mints a grant that reads only the named secrets and
# writes the editor's MCP entry pointing at the grant's key file (a path,
# never key material). HOME is redirected so the recording leaves no grant
# key behind in the operator's real ~/.config/murk.

Output demo/agent-connect.gif

Require murk

Source demo/theme.tape

Set Height 600

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `export HOME="$(mktemp -d /tmp/h.XXXXXX)"`
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
Type `echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" 2>/dev/null`
Enter
Type `export PS1="\n\[\e[94m\]dev \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# The agent needs DATABASE_URL to run a migration. Not your key."
Enter
Sleep 1500ms

Type "# Mint it a scoped grant and wire the editor in one step:"
Enter
Sleep 1s

Type "murk agent connect claude --only DATABASE_URL --ttl 2h"
Enter
Sleep 2500ms
Type "y"
Enter
Sleep 2s

Type "# The editor entry holds a key file path, never key material:"
Enter
Sleep 1s

Type "cat .mcp.json"
Enter
Sleep 3s

Type "# Read as the agent would, with its grant key:"
Enter
Sleep 1s

Type `export AGENT_KEY=$(ls ~/.config/murk/agent-keys/*-mcp)`
Enter
Sleep 500ms

Type `MURK_KEY_FILE=$AGENT_KEY MURK_AGENT=1 murk get STRIPE_SECRET`
Enter
Sleep 3s

Type "# Fails closed. STRIPE_SECRET was never encrypted to this key."
Enter
Sleep 2s

Type "# Done with the agent? Remove the entry, revoke the grant, rotate:"
Enter
Sleep 1s

Type "murk agent disconnect claude --rotate"
Enter
Sleep 2500ms
Type "postgres://prod:n3w-s3cr3t@db.example.com/app"
Enter
Sleep 3s

Type "# The grant limits what murk serves. It does not limit what a process"
Enter
Type "# running as you can read from disk. Least privilege, not a sandbox."
Enter
Sleep 3s
