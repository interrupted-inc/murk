# Agent demo — give an AI agent the schema, then one key, never yours.
# `murk agent plan` emits the vault schema with no values and no key. A grant
# mints an ephemeral identity that can decrypt exactly the keys you name, so
# every other secret is out of reach — it was never encrypted to that identity.

Output demo/agent.gif

Require murk

Source demo/theme.tape

# Taller than the shared theme: this demo runs three beats (plan, grant, the
# agent's own shell) and the payoff should still be on screen at the end.
Set Height 720

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
Type `echo "postgres://prod:s3cr3t@db.example.com/app" | murk add DATABASE_URL --desc "Primary database" --tag db 2>/dev/null`
Enter
Type `echo "sk-proj-abc123def456" | murk add OPENAI_KEY --desc "OpenAI API key" --tag ai 2>/dev/null`
Enter
Type `echo "sk_live_xyz789" | murk add STRIPE_KEY --desc "Stripe live key" --tag payments 2>/dev/null`
Enter
# `add` takes no --example, so the example column comes from `describe`.
Type `murk describe DATABASE_URL "Primary database" --example "postgres://host/db" --tag db 2>/dev/null`
Enter
Type `murk describe OPENAI_KEY "OpenAI API key" --example "sk-proj-..." --tag ai 2>/dev/null`
Enter
Type `murk describe STRIPE_KEY "Stripe live key" --example "sk_live_..." --tag payments 2>/dev/null`
Enter
Type `export PS1="\n\[\e[35m\]you \$\[\e[0m\] "`
Enter
# Cosmetic only: flip the prompt when the shell picks up the grant key, so the
# handoff on camera stays a single honest command with nothing else on the line.
Type `export PROMPT_COMMAND='[ "$MURK_KEY_FILE" = agent.key ] && PS1="\n\[\e[33m\]agent \$\[\e[0m\] "'`
Enter
Type `clear`
Enter
Sleep 300ms
Show

# Narration stays under 66 characters: the theme is 75 columns and the prompt
# eats 6. Avoid em dashes inside `Type` — they render fine in the pinned CI vhs
# image but corrupt the input stream under some local ttyd builds (observed on
# ttyd 1.7.7), which silently breaks whatever command was being typed. Program
# output may contain them; only `Type` is affected.
Type "# The agent needs to know which secrets exist, not what they are."
Enter
Sleep 1200ms

Type "murk agent plan"
Enter
Sleep 2500ms

Type "# No key was involved, and no value appears in that output."
Enter
Sleep 1400ms

Type "# Reading an actual value is different. Grant it one key:"
Enter
Sleep 1200ms

Type "murk agent grant --name agent --only DATABASE_URL --out agent.key"
Enter
Sleep 3000ms

Type "# Hand it that key file. Yours never leaves your shell."
Enter
Sleep 1200ms

Type "export MURK_KEY_FILE=agent.key"
Enter
Sleep 800ms

Type "murk get DATABASE_URL"
Enter
Sleep 2000ms

Type "murk get STRIPE_KEY"
Enter
Sleep 2200ms

Type "murk export"
Enter
Sleep 2200ms

Type "# Nothing else was ever encrypted to that key."
Enter
Sleep 3000ms
