# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# SSH demo — authorize a recipient from an SSH public key file

Output demo/ssh.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `source demo/setup.sh`
Enter
Type `demo_init_dirs alice bob`
Enter
Sleep 200ms
Type `demo_alice_vault`
Enter
Sleep 3s

# Bob: generate an SSH keypair (no passphrase)
Type `ssh-keygen -t ed25519 -f "$BOB_DIR/id_ed25519" -N "" -q`
Enter
Sleep 500ms

# Start as Alice
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Bob sends Alice his SSH public key"
Enter
Sleep 1s

Type `cat "$BOB_DIR/id_ed25519.pub"`
Enter
Sleep 2s

Type "# Alice authorizes Bob from the key file"
Enter
Sleep 500ms

Type `murk circle authorize "ssh:$BOB_DIR/id_ed25519.pub" --name bob`
Enter
Sleep 2s

Type "murk circle"
Enter
Sleep 2s

Type "# Bob's SSH key is now a recipient"
Enter
Sleep 2s
