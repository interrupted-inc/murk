# Agent exec demo — run the tests with a secret, without handing over the key.
# `murk agent exec` clears the environment, strips MURK_KEY, and injects only
# the keys named with --only into the child process.

Output demo/agent-exec.gif

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
Type `echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" 2>/dev/null`
Enter
Type `printf '#!/bin/sh\ntest -n "$DATABASE_URL" && echo "PASS - connected using DATABASE_URL" || echo "FAIL - DATABASE_URL missing"\n' > run-tests.sh`
Enter
Type `chmod +x run-tests.sh`
Enter
Type `export PS1="\n\[\e[35m\]agent \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# The agent must run the test suite, which needs DATABASE_URL."
Enter
Sleep 1500ms

Type "# Give it that one value in the subprocess only, never your key:"
Enter
Sleep 1s

Type "murk agent exec --only DATABASE_URL -- ./run-tests.sh"
Enter
Sleep 3s

Type "# Tests pass. Only DATABASE_URL was injected, and no key."
Enter
Sleep 2s

Type "# It cannot reach any other secret. No key, and out of scope:"
Enter
Sleep 1500ms

Type "murk agent exec --only DATABASE_URL -- murk get STRIPE_SECRET"
Enter
Sleep 3s

Type "# Fails closed. One value, no key, nothing else in reach."
Enter
Sleep 2500ms
