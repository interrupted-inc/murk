
use builtin;
use str;

set edit:completion:arg-completer[murk] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'murk'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'murk'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand init 'Initialize a new vault and generate a keypair'
            cand env 'Write a .envrc for direnv integration'
            cand restore 'Restore MURK_KEY from a BIP39 recovery phrase'
            cand recover 'Re-derive recovery phrase from current MURK_KEY'
            cand add 'Add or update a secret'
            cand generate 'Generate a random secret and store it'
            cand rotate 'Rotate secrets with new values'
            cand rm 'Remove a secret'
            cand get 'Get a single decrypted value'
            cand edit 'Edit secrets in $EDITOR'
            cand ls 'List all key names'
            cand export 'Export all secrets as shell export statements'
            cand import 'Import secrets from a .env file'
            cand describe 'Add or update a key description'
            cand info 'Show public schema and key info'
            cand skeleton 'Export schema-only vault with no secrets or recipients'
            cand exec 'Run a command with secrets injected as environment variables'
            cand agent 'Agent-oriented commands (schema-only output for AI agent prompts)'
            cand mcp 'Run an MCP (Model Context Protocol) stdio server for AI agents'
            cand policy 'Manage the agent access policy'
            cand circle 'Manage recipients'
            cand authorize 'Add a recipient to the vault'
            cand revoke 'Remove a recipient from the vault'
            cand group 'Manage recipient groups'
            cand verify 'Verify vault integrity without exporting secrets'
            cand doctor 'Check the surrounding repo for hygiene issues'
            cand scan 'Scan files for leaked secret values'
            cand diff 'Show secret changes vs a git ref'
            cand setup-merge-driver 'Configure git to use murk''s merge driver for .murk files'
            cand merge-driver 'Git merge driver for .murk vault files (called by git)'
            cand completion 'Generate or install shell completions'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;init'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;env'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;restore'= {
            cand --vault 'Vault filename, for the restored-identity recipient check'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;recover'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;add'= {
            cand --desc 'Description for this key'
            cand --example 'Example value'
            cand --group 'Who can read it: a group name, `everyone` (default), or `me`'
            cand --tag 'Tag for grouping (repeatable)'
            cand --vault 'Vault filename'
            cand --scoped 'Deprecated alias for `--group me`'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;generate'= {
            cand --length 'Length in bytes (default 32)'
            cand --desc 'Description for this key'
            cand --example 'Example value'
            cand --group 'Who can read it: a group name, `everyone` (default), or `me`'
            cand --tag 'Tag for grouping (repeatable)'
            cand --vault 'Vault filename'
            cand --hex 'Output as hex instead of base64'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;rotate'= {
            cand --length 'Length in bytes for generated values (default 32)'
            cand --vault 'Vault filename'
            cand --all 'Rotate all secrets in the vault'
            cand --generate 'Generate random values instead of prompting'
            cand --hex 'Output generated values as hex instead of base64'
            cand --list 'List keys needing rotation instead of rotating (exits 1 if any)'
            cand --json 'Output the listing as JSON (with --list, always exits 0)'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;rm'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;get'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;edit'= {
            cand --group 'Edit values for this group instead of shared secrets'
            cand --vault 'Vault filename'
            cand --scoped 'Edit scoped overrides instead of shared secrets'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;ls'= {
            cand --tag 'Filter by tag (repeatable)'
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;export'= {
            cand --tag 'Filter by tag (repeatable)'
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;import'= {
            cand --group 'Assign imported secrets to this group (default: everyone)'
            cand --example 'Example value applied to every imported key'
            cand --vault 'Vault filename'
            cand --force 'Overwrite existing secrets without prompting'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;describe'= {
            cand --example 'Example value'
            cand --tag 'Tag for grouping (repeatable, replaces existing tags)'
            cand --rotate-every 'Rotation interval, e.g. `90d` or `90` (days). `never` clears it'
            cand --expires 'Hard expiry date, e.g. `2026-09-01`. `never` clears it'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;info'= {
            cand --tag 'Filter by tag (repeatable)'
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;skeleton'= {
            cand -o 'Output file (prints to stdout if omitted)'
            cand --output 'Output file (prints to stdout if omitted)'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;exec'= {
            cand --only 'Only inject these specific keys (repeatable)'
            cand --tag 'Filter by tag (repeatable)'
            cand --vault 'Vault filename'
            cand --clean-env 'Strip inherited environment (only murk secrets + PATH)'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand plan 'Emit schema-only context safe to paste into an AI agent prompt'
            cand exec 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
            cand grant 'Mint a scoped ephemeral key that can read only the named secrets'
            cand init 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
            cand ls 'List active agent grants and their TTLs'
            cand revoke 'Revoke an agent grant and rotate the keys it could read'
            cand connect 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
            cand disconnect 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;agent;plan'= {
            cand --tag 'Filter by tag (repeatable)'
            cand -o 'Output file (prints to stdout if omitted)'
            cand --output 'Output file (prints to stdout if omitted)'
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;exec'= {
            cand --only 'Inject these specific keys (required — agent mode fails closed)'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;grant'= {
            cand --name 'Grant name (used to revoke it later)'
            cand --only 'Keys this grant can read (required — fails closed)'
            cand --ttl 'Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)'
            cand --out 'Where to write the agent key: a path, or `-` for stdout'
            cand --vault 'Vault filename'
            cand --renew 'Replace a live grant with this name: revoke its key, mint a fresh one'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;init'= {
            cand --name 'Grant name (used to revoke it later)'
            cand --only 'Keys the agent can read (required — fails closed)'
            cand --allow-tag 'Set the agent allow-list to these tags before granting (repeatable)'
            cand --ttl 'Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)'
            cand --out 'Where to write the agent key: a path, or `-` for stdout'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;ls'= {
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;revoke'= {
            cand --vault 'Vault filename'
            cand --rotate 'Rotate the keys it could read in the same session'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;connect'= {
            cand --only 'Keys the agent may read (required — fails closed)'
            cand --allow-tag 'Set the agent allow-list to these tags before granting (repeatable)'
            cand --ttl 'Grant time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)'
            cand --name 'Grant name (used to disconnect/revoke it later)'
            cand --vault 'Vault filename'
            cand --allow-exec 'Also expose `murk agent exec` to the agent (adds --allow-exec)'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;disconnect'= {
            cand --name 'Grant name to revoke with --rotate'
            cand --vault 'Vault filename'
            cand --rotate 'Revoke the grant and rotate the keys it could read'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;agent;help'= {
            cand plan 'Emit schema-only context safe to paste into an AI agent prompt'
            cand exec 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
            cand grant 'Mint a scoped ephemeral key that can read only the named secrets'
            cand init 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
            cand ls 'List active agent grants and their TTLs'
            cand revoke 'Revoke an agent grant and rotate the keys it could read'
            cand connect 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
            cand disconnect 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;agent;help;plan'= {
        }
        &'murk;agent;help;exec'= {
        }
        &'murk;agent;help;grant'= {
        }
        &'murk;agent;help;init'= {
        }
        &'murk;agent;help;ls'= {
        }
        &'murk;agent;help;revoke'= {
        }
        &'murk;agent;help;connect'= {
        }
        &'murk;agent;help;disconnect'= {
        }
        &'murk;agent;help;help'= {
        }
        &'murk;mcp'= {
            cand --vault 'Vault filename'
            cand --allow-exec 'Enable the murk_exec tool (run commands with scoped secrets injected). Off by default: it runs arbitrary commands as this user — the injected secrets are grant-scoped, but the command itself is not sandboxed'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;policy'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand show 'Show the agent access policy (works without a key)'
            cand set 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
            cand clear 'Remove the policy — agent mode becomes unrestricted again'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;policy;show'= {
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;policy;set'= {
            cand --allow-tag 'Tag agents are allowed to receive (repeatable, required)'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;policy;clear'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;policy;help'= {
            cand show 'Show the agent access policy (works without a key)'
            cand set 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
            cand clear 'Remove the policy — agent mode becomes unrestricted again'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;policy;help;show'= {
        }
        &'murk;policy;help;set'= {
        }
        &'murk;policy;help;clear'= {
        }
        &'murk;policy;help;help'= {
        }
        &'murk;circle'= {
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
            cand authorize 'Add a recipient to the vault'
            cand revoke 'Remove a recipient from the vault'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;circle;authorize'= {
            cand --name 'Display name for this recipient'
            cand --group 'Also add the new recipient to this group'
            cand --vault 'Vault filename'
            cand --force 'Accept changed GitHub keys without confirmation'
            cand --allow-ssh-rsa 'Allow ssh-rsa recipients (rejected by default — use ed25519)'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;circle;revoke'= {
            cand --vault 'Vault filename'
            cand --rotate 'Rotate the secrets they had access to in the same session'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;circle;help'= {
            cand authorize 'Add a recipient to the vault'
            cand revoke 'Remove a recipient from the vault'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;circle;help;authorize'= {
        }
        &'murk;circle;help;revoke'= {
        }
        &'murk;circle;help;help'= {
        }
        &'murk;authorize'= {
            cand --name 'Display name for this recipient'
            cand --vault 'Vault filename'
            cand --force 'Accept changed GitHub keys without confirmation'
            cand --allow-ssh-rsa 'Allow ssh-rsa recipients (rejected by default — use ed25519)'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;revoke'= {
            cand --vault 'Vault filename'
            cand --rotate 'Rotate the secrets they had access to in the same session'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;group'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand create 'Create a new recipient group (you become its first member)'
            cand ls 'List groups and their members'
            cand add 'Add a member to a group'
            cand rm 'Remove a member from a group, or delete the group entirely'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;group;create'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;group;ls'= {
            cand --vault 'Vault filename'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;group;add'= {
            cand --member 'Recipient pubkey or display name to add'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;group;rm'= {
            cand --member 'Recipient pubkey or display name to remove (omit to delete the group)'
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;group;help'= {
            cand create 'Create a new recipient group (you become its first member)'
            cand ls 'List groups and their members'
            cand add 'Add a member to a group'
            cand rm 'Remove a member from a group, or delete the group entirely'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;group;help;create'= {
        }
        &'murk;group;help;ls'= {
        }
        &'murk;group;help;add'= {
        }
        &'murk;group;help;rm'= {
        }
        &'murk;group;help;help'= {
        }
        &'murk;verify'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;doctor'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;scan'= {
            cand --vault 'Vault filename'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;diff'= {
            cand --vault 'Vault filename'
            cand --show-values 'Show actual values (not just key names)'
            cand --json 'Output as JSON'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;setup-merge-driver'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;merge-driver'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;completion'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand generate 'Print completions to stdout'
            cand install 'Install completions to the standard path'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;completion;generate'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;completion;install'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'murk;completion;help'= {
            cand generate 'Print completions to stdout'
            cand install 'Install completions to the standard path'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;completion;help;generate'= {
        }
        &'murk;completion;help;install'= {
        }
        &'murk;completion;help;help'= {
        }
        &'murk;help'= {
            cand init 'Initialize a new vault and generate a keypair'
            cand env 'Write a .envrc for direnv integration'
            cand restore 'Restore MURK_KEY from a BIP39 recovery phrase'
            cand recover 'Re-derive recovery phrase from current MURK_KEY'
            cand add 'Add or update a secret'
            cand generate 'Generate a random secret and store it'
            cand rotate 'Rotate secrets with new values'
            cand rm 'Remove a secret'
            cand get 'Get a single decrypted value'
            cand edit 'Edit secrets in $EDITOR'
            cand ls 'List all key names'
            cand export 'Export all secrets as shell export statements'
            cand import 'Import secrets from a .env file'
            cand describe 'Add or update a key description'
            cand info 'Show public schema and key info'
            cand skeleton 'Export schema-only vault with no secrets or recipients'
            cand exec 'Run a command with secrets injected as environment variables'
            cand agent 'Agent-oriented commands (schema-only output for AI agent prompts)'
            cand mcp 'Run an MCP (Model Context Protocol) stdio server for AI agents'
            cand policy 'Manage the agent access policy'
            cand circle 'Manage recipients'
            cand authorize 'Add a recipient to the vault'
            cand revoke 'Remove a recipient from the vault'
            cand group 'Manage recipient groups'
            cand verify 'Verify vault integrity without exporting secrets'
            cand doctor 'Check the surrounding repo for hygiene issues'
            cand scan 'Scan files for leaked secret values'
            cand diff 'Show secret changes vs a git ref'
            cand setup-merge-driver 'Configure git to use murk''s merge driver for .murk files'
            cand merge-driver 'Git merge driver for .murk vault files (called by git)'
            cand completion 'Generate or install shell completions'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'murk;help;init'= {
        }
        &'murk;help;env'= {
        }
        &'murk;help;restore'= {
        }
        &'murk;help;recover'= {
        }
        &'murk;help;add'= {
        }
        &'murk;help;generate'= {
        }
        &'murk;help;rotate'= {
        }
        &'murk;help;rm'= {
        }
        &'murk;help;get'= {
        }
        &'murk;help;edit'= {
        }
        &'murk;help;ls'= {
        }
        &'murk;help;export'= {
        }
        &'murk;help;import'= {
        }
        &'murk;help;describe'= {
        }
        &'murk;help;info'= {
        }
        &'murk;help;skeleton'= {
        }
        &'murk;help;exec'= {
        }
        &'murk;help;agent'= {
            cand plan 'Emit schema-only context safe to paste into an AI agent prompt'
            cand exec 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
            cand grant 'Mint a scoped ephemeral key that can read only the named secrets'
            cand init 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
            cand ls 'List active agent grants and their TTLs'
            cand revoke 'Revoke an agent grant and rotate the keys it could read'
            cand connect 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
            cand disconnect 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
        }
        &'murk;help;agent;plan'= {
        }
        &'murk;help;agent;exec'= {
        }
        &'murk;help;agent;grant'= {
        }
        &'murk;help;agent;init'= {
        }
        &'murk;help;agent;ls'= {
        }
        &'murk;help;agent;revoke'= {
        }
        &'murk;help;agent;connect'= {
        }
        &'murk;help;agent;disconnect'= {
        }
        &'murk;help;mcp'= {
        }
        &'murk;help;policy'= {
            cand show 'Show the agent access policy (works without a key)'
            cand set 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
            cand clear 'Remove the policy — agent mode becomes unrestricted again'
        }
        &'murk;help;policy;show'= {
        }
        &'murk;help;policy;set'= {
        }
        &'murk;help;policy;clear'= {
        }
        &'murk;help;circle'= {
            cand authorize 'Add a recipient to the vault'
            cand revoke 'Remove a recipient from the vault'
        }
        &'murk;help;circle;authorize'= {
        }
        &'murk;help;circle;revoke'= {
        }
        &'murk;help;authorize'= {
        }
        &'murk;help;revoke'= {
        }
        &'murk;help;group'= {
            cand create 'Create a new recipient group (you become its first member)'
            cand ls 'List groups and their members'
            cand add 'Add a member to a group'
            cand rm 'Remove a member from a group, or delete the group entirely'
        }
        &'murk;help;group;create'= {
        }
        &'murk;help;group;ls'= {
        }
        &'murk;help;group;add'= {
        }
        &'murk;help;group;rm'= {
        }
        &'murk;help;verify'= {
        }
        &'murk;help;doctor'= {
        }
        &'murk;help;scan'= {
        }
        &'murk;help;diff'= {
        }
        &'murk;help;setup-merge-driver'= {
        }
        &'murk;help;merge-driver'= {
        }
        &'murk;help;completion'= {
            cand generate 'Print completions to stdout'
            cand install 'Install completions to the standard path'
        }
        &'murk;help;completion;generate'= {
        }
        &'murk;help;completion;install'= {
        }
        &'murk;help;help'= {
        }
    ]
    $completions[$command]
}
