# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_murk_global_optspecs
    string join \n h/help
end

function __fish_murk_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_murk_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_murk_using_subcommand
    set -l cmd (__fish_murk_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c murk -n "__fish_murk_needs_command" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_needs_command" -f -a "init" -d 'Initialize a new vault and generate a keypair'
complete -c murk -n "__fish_murk_needs_command" -f -a "env" -d 'Write a .envrc for direnv integration'
complete -c murk -n "__fish_murk_needs_command" -f -a "restore" -d 'Restore MURK_KEY from a BIP39 recovery phrase'
complete -c murk -n "__fish_murk_needs_command" -f -a "recover" -d 'Re-derive recovery phrase from current MURK_KEY'
complete -c murk -n "__fish_murk_needs_command" -f -a "add" -d 'Add or update a secret'
complete -c murk -n "__fish_murk_needs_command" -f -a "generate" -d 'Generate a random secret and store it'
complete -c murk -n "__fish_murk_needs_command" -f -a "rotate" -d 'Rotate secrets with new values'
complete -c murk -n "__fish_murk_needs_command" -f -a "rm" -d 'Remove a secret'
complete -c murk -n "__fish_murk_needs_command" -f -a "get" -d 'Get a single decrypted value'
complete -c murk -n "__fish_murk_needs_command" -f -a "edit" -d 'Edit secrets in $EDITOR'
complete -c murk -n "__fish_murk_needs_command" -f -a "ls" -d 'List all key names'
complete -c murk -n "__fish_murk_needs_command" -f -a "export" -d 'Export all secrets as shell export statements'
complete -c murk -n "__fish_murk_needs_command" -f -a "import" -d 'Import secrets from a .env file'
complete -c murk -n "__fish_murk_needs_command" -f -a "describe" -d 'Add or update a key description'
complete -c murk -n "__fish_murk_needs_command" -f -a "info" -d 'Show public schema and key info'
complete -c murk -n "__fish_murk_needs_command" -f -a "skeleton" -d 'Export schema-only vault with no secrets or recipients'
complete -c murk -n "__fish_murk_needs_command" -f -a "exec" -d 'Run a command with secrets injected as environment variables'
complete -c murk -n "__fish_murk_needs_command" -f -a "agent" -d 'Agent-oriented commands (schema-only output for AI agent prompts)'
complete -c murk -n "__fish_murk_needs_command" -f -a "mcp" -d 'Run an MCP (Model Context Protocol) stdio server for AI agents'
complete -c murk -n "__fish_murk_needs_command" -f -a "policy" -d 'Manage the agent access policy'
complete -c murk -n "__fish_murk_needs_command" -f -a "circle" -d 'Manage recipients'
complete -c murk -n "__fish_murk_needs_command" -f -a "authorize" -d 'Add a recipient to the vault'
complete -c murk -n "__fish_murk_needs_command" -f -a "revoke" -d 'Remove a recipient from the vault'
complete -c murk -n "__fish_murk_needs_command" -f -a "group" -d 'Manage recipient groups'
complete -c murk -n "__fish_murk_needs_command" -f -a "verify" -d 'Verify vault integrity without exporting secrets'
complete -c murk -n "__fish_murk_needs_command" -f -a "doctor" -d 'Check the surrounding repo for hygiene issues'
complete -c murk -n "__fish_murk_needs_command" -f -a "scan" -d 'Scan files for leaked secret values'
complete -c murk -n "__fish_murk_needs_command" -f -a "diff" -d 'Show secret changes vs a git ref'
complete -c murk -n "__fish_murk_needs_command" -f -a "setup-merge-driver" -d 'Configure git to use murk\'s merge driver for .murk files'
complete -c murk -n "__fish_murk_needs_command" -f -a "merge-driver" -d 'Git merge driver for .murk vault files (called by git)'
complete -c murk -n "__fish_murk_needs_command" -f -a "completion" -d 'Generate or install shell completions'
complete -c murk -n "__fish_murk_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand init" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand init" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand env" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand env" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand restore" -l vault -d 'Vault filename, for the restored-identity recipient check' -r
complete -c murk -n "__fish_murk_using_subcommand restore" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand recover" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand add" -l desc -d 'Description for this key' -r
complete -c murk -n "__fish_murk_using_subcommand add" -l group -d 'Who can read it: a group name, `everyone` (default), or `me`' -r
complete -c murk -n "__fish_murk_using_subcommand add" -l tag -d 'Tag for grouping (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand add" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand add" -l scoped -d 'Deprecated alias for `--group me`'
complete -c murk -n "__fish_murk_using_subcommand add" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand generate" -l length -d 'Length in bytes (default 32)' -r
complete -c murk -n "__fish_murk_using_subcommand generate" -l desc -d 'Description for this key' -r
complete -c murk -n "__fish_murk_using_subcommand generate" -l group -d 'Who can read it: a group name, `everyone` (default), or `me`' -r
complete -c murk -n "__fish_murk_using_subcommand generate" -l tag -d 'Tag for grouping (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand generate" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand generate" -l hex -d 'Output as hex instead of base64'
complete -c murk -n "__fish_murk_using_subcommand generate" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand rotate" -l length -d 'Length in bytes for generated values (default 32)' -r
complete -c murk -n "__fish_murk_using_subcommand rotate" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand rotate" -l all -d 'Rotate all secrets in the vault'
complete -c murk -n "__fish_murk_using_subcommand rotate" -l generate -d 'Generate random values instead of prompting'
complete -c murk -n "__fish_murk_using_subcommand rotate" -l hex -d 'Output generated values as hex instead of base64'
complete -c murk -n "__fish_murk_using_subcommand rotate" -l list -d 'List keys needing rotation instead of rotating (exits 1 if any)'
complete -c murk -n "__fish_murk_using_subcommand rotate" -l json -d 'Output the listing as JSON (with --list, always exits 0)'
complete -c murk -n "__fish_murk_using_subcommand rotate" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand rm" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand rm" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand get" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand get" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand edit" -l group -d 'Edit values for this group instead of shared secrets' -r
complete -c murk -n "__fish_murk_using_subcommand edit" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand edit" -l scoped -d 'Edit scoped overrides instead of shared secrets'
complete -c murk -n "__fish_murk_using_subcommand edit" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand ls" -l tag -d 'Filter by tag (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand ls" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand ls" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand ls" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand export" -l tag -d 'Filter by tag (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand export" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand export" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand export" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand import" -l group -d 'Assign imported secrets to this group (default: everyone)' -r
complete -c murk -n "__fish_murk_using_subcommand import" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand import" -l force -d 'Overwrite existing secrets without prompting'
complete -c murk -n "__fish_murk_using_subcommand import" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand describe" -l example -d 'Example value' -r
complete -c murk -n "__fish_murk_using_subcommand describe" -l tag -d 'Tag for grouping (repeatable, replaces existing tags)' -r
complete -c murk -n "__fish_murk_using_subcommand describe" -l rotate-every -d 'Rotation interval, e.g. `90d` or `90` (days). `never` clears it' -r
complete -c murk -n "__fish_murk_using_subcommand describe" -l expires -d 'Hard expiry date, e.g. `2026-09-01`. `never` clears it' -r
complete -c murk -n "__fish_murk_using_subcommand describe" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand describe" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand info" -l tag -d 'Filter by tag (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand info" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand info" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand info" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand skeleton" -s o -l output -d 'Output file (prints to stdout if omitted)' -r
complete -c murk -n "__fish_murk_using_subcommand skeleton" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand skeleton" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand exec" -l only -d 'Only inject these specific keys (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand exec" -l tag -d 'Filter by tag (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand exec" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand exec" -l clean-env -d 'Strip inherited environment (only murk secrets + PATH)'
complete -c murk -n "__fish_murk_using_subcommand exec" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "plan" -d 'Emit schema-only context safe to paste into an AI agent prompt'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "exec" -d 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "grant" -d 'Mint a short-lived ephemeral key that can read only the named secrets'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "init" -d 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "ls" -d 'List active agent grants and their TTLs'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "revoke" -d 'Revoke an agent grant and rotate the keys it could read'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "connect" -d 'Wire `murk mcp` into an AI editor\'s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "disconnect" -d 'Remove murk\'s entry from an AI editor\'s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
complete -c murk -n "__fish_murk_using_subcommand agent; and not __fish_seen_subcommand_from plan exec grant init ls revoke connect disconnect help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from plan" -l tag -d 'Filter by tag (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from plan" -s o -l output -d 'Output file (prints to stdout if omitted)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from plan" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from plan" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from exec" -l only -d 'Inject these specific keys (required — agent mode fails closed)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from exec" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from exec" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -l name -d 'Grant name (used to revoke it later)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -l only -d 'Keys this grant can read (required — fails closed)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -l ttl -d 'Time to live, e.g. 30m, 2h, 7d (advisory — see `agent revoke`)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -l out -d 'Where to write the agent key: a path, or `-` for stdout' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from grant" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l name -d 'Grant name (used to revoke it later)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l only -d 'Keys the agent can read (required — fails closed)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l allow-tag -d 'Set the agent allow-list to these tags before granting (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l ttl -d 'Time to live, e.g. 30m, 2h, 7d (advisory — see `agent revoke`)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l out -d 'Where to write the agent key: a path, or `-` for stdout' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from ls" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from ls" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from ls" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from revoke" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from revoke" -l rotate -d 'Rotate the keys it could read in the same session'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from revoke" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l only -d 'Keys the agent may read (required — fails closed)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l allow-tag -d 'Set the agent allow-list to these tags before granting (repeatable)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l ttl -d 'Grant time to live, e.g. 30m, 2h, 7d (advisory — see `agent revoke`)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l name -d 'Grant name (used to disconnect/revoke it later)' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -l allow-exec -d 'Also expose `murk agent exec` to the agent (adds --allow-exec)'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from connect" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from disconnect" -l name -d 'Grant name to revoke with --rotate' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from disconnect" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from disconnect" -l rotate -d 'Revoke the grant and rotate the keys it could read'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from disconnect" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Emit schema-only context safe to paste into an AI agent prompt'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "exec" -d 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "grant" -d 'Mint a short-lived ephemeral key that can read only the named secrets'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "init" -d 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "ls" -d 'List active agent grants and their TTLs'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "revoke" -d 'Revoke an agent grant and rotate the keys it could read'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "connect" -d 'Wire `murk mcp` into an AI editor\'s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "disconnect" -d 'Remove murk\'s entry from an AI editor\'s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
complete -c murk -n "__fish_murk_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand mcp" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand mcp" -l allow-exec -d 'Enable the murk_exec tool (run commands with scoped secrets injected). Off by default: it runs arbitrary commands as this user — the injected secrets are grant-scoped, but the command itself is not sandboxed'
complete -c murk -n "__fish_murk_using_subcommand mcp" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand policy; and not __fish_seen_subcommand_from show set clear help" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand policy; and not __fish_seen_subcommand_from show set clear help" -f -a "show" -d 'Show the agent access policy (works without a key)'
complete -c murk -n "__fish_murk_using_subcommand policy; and not __fish_seen_subcommand_from show set clear help" -f -a "set" -d 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
complete -c murk -n "__fish_murk_using_subcommand policy; and not __fish_seen_subcommand_from show set clear help" -f -a "clear" -d 'Remove the policy — agent mode becomes unrestricted again'
complete -c murk -n "__fish_murk_using_subcommand policy; and not __fish_seen_subcommand_from show set clear help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from show" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from show" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from set" -l allow-tag -d 'Tag agents are allowed to receive (repeatable, required)' -r
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from set" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from clear" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from clear" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show the agent access policy (works without a key)'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "clear" -d 'Remove the policy — agent mode becomes unrestricted again'
complete -c murk -n "__fish_murk_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -f -a "authorize" -d 'Add a recipient to the vault'
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -f -a "revoke" -d 'Remove a recipient from the vault'
complete -c murk -n "__fish_murk_using_subcommand circle; and not __fish_seen_subcommand_from authorize revoke help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -l name -d 'Display name for this recipient' -r
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -l group -d 'Also add the new recipient to this group' -r
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -l force -d 'Accept changed GitHub keys without confirmation'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -l allow-ssh-rsa -d 'Allow ssh-rsa recipients (rejected by default — use ed25519)'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from authorize" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from revoke" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from revoke" -l rotate -d 'Rotate the secrets they had access to in the same session'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from revoke" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from help" -f -a "authorize" -d 'Add a recipient to the vault'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from help" -f -a "revoke" -d 'Remove a recipient from the vault'
complete -c murk -n "__fish_murk_using_subcommand circle; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand authorize" -l name -d 'Display name for this recipient' -r
complete -c murk -n "__fish_murk_using_subcommand authorize" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand authorize" -l force -d 'Accept changed GitHub keys without confirmation'
complete -c murk -n "__fish_murk_using_subcommand authorize" -l allow-ssh-rsa -d 'Allow ssh-rsa recipients (rejected by default — use ed25519)'
complete -c murk -n "__fish_murk_using_subcommand authorize" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand revoke" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand revoke" -l rotate -d 'Rotate the secrets they had access to in the same session'
complete -c murk -n "__fish_murk_using_subcommand revoke" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -f -a "create" -d 'Create a new recipient group (you become its first member)'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -f -a "ls" -d 'List groups and their members'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -f -a "add" -d 'Add a member to a group'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -f -a "rm" -d 'Remove a member from a group, or delete the group entirely'
complete -c murk -n "__fish_murk_using_subcommand group; and not __fish_seen_subcommand_from create ls add rm help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from create" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from create" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from ls" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from ls" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from ls" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from add" -l member -d 'Recipient pubkey or display name to add' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from add" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from rm" -l member -d 'Recipient pubkey or display name to remove (omit to delete the group)' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from rm" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from rm" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from help" -f -a "create" -d 'Create a new recipient group (you become its first member)'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from help" -f -a "ls" -d 'List groups and their members'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a member to a group'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from help" -f -a "rm" -d 'Remove a member from a group, or delete the group entirely'
complete -c murk -n "__fish_murk_using_subcommand group; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand verify" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand verify" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand doctor" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand doctor" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand scan" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand scan" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand diff" -l vault -d 'Vault filename' -r
complete -c murk -n "__fish_murk_using_subcommand diff" -l show-values -d 'Show actual values (not just key names)'
complete -c murk -n "__fish_murk_using_subcommand diff" -l json -d 'Output as JSON'
complete -c murk -n "__fish_murk_using_subcommand diff" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand setup-merge-driver" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand merge-driver" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand completion; and not __fish_seen_subcommand_from generate install help" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand completion; and not __fish_seen_subcommand_from generate install help" -f -a "generate" -d 'Print completions to stdout'
complete -c murk -n "__fish_murk_using_subcommand completion; and not __fish_seen_subcommand_from generate install help" -f -a "install" -d 'Install completions to the standard path'
complete -c murk -n "__fish_murk_using_subcommand completion; and not __fish_seen_subcommand_from generate install help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand completion; and __fish_seen_subcommand_from generate" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand completion; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help'
complete -c murk -n "__fish_murk_using_subcommand completion; and __fish_seen_subcommand_from help" -f -a "generate" -d 'Print completions to stdout'
complete -c murk -n "__fish_murk_using_subcommand completion; and __fish_seen_subcommand_from help" -f -a "install" -d 'Install completions to the standard path'
complete -c murk -n "__fish_murk_using_subcommand completion; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "init" -d 'Initialize a new vault and generate a keypair'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "env" -d 'Write a .envrc for direnv integration'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "restore" -d 'Restore MURK_KEY from a BIP39 recovery phrase'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "recover" -d 'Re-derive recovery phrase from current MURK_KEY'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "add" -d 'Add or update a secret'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "generate" -d 'Generate a random secret and store it'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "rotate" -d 'Rotate secrets with new values'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "rm" -d 'Remove a secret'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "get" -d 'Get a single decrypted value'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "edit" -d 'Edit secrets in $EDITOR'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "ls" -d 'List all key names'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "export" -d 'Export all secrets as shell export statements'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "import" -d 'Import secrets from a .env file'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "describe" -d 'Add or update a key description'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "info" -d 'Show public schema and key info'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "skeleton" -d 'Export schema-only vault with no secrets or recipients'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "exec" -d 'Run a command with secrets injected as environment variables'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "agent" -d 'Agent-oriented commands (schema-only output for AI agent prompts)'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "mcp" -d 'Run an MCP (Model Context Protocol) stdio server for AI agents'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "policy" -d 'Manage the agent access policy'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "circle" -d 'Manage recipients'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "authorize" -d 'Add a recipient to the vault'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "revoke" -d 'Remove a recipient from the vault'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "group" -d 'Manage recipient groups'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "verify" -d 'Verify vault integrity without exporting secrets'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "doctor" -d 'Check the surrounding repo for hygiene issues'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "scan" -d 'Scan files for leaked secret values'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "diff" -d 'Show secret changes vs a git ref'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "setup-merge-driver" -d 'Configure git to use murk\'s merge driver for .murk files'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "merge-driver" -d 'Git merge driver for .murk vault files (called by git)'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "completion" -d 'Generate or install shell completions'
complete -c murk -n "__fish_murk_using_subcommand help; and not __fish_seen_subcommand_from init env restore recover add generate rotate rm get edit ls export import describe info skeleton exec agent mcp policy circle authorize revoke group verify doctor scan diff setup-merge-driver merge-driver completion help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "plan" -d 'Emit schema-only context safe to paste into an AI agent prompt'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "exec" -d 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "grant" -d 'Mint a short-lived ephemeral key that can read only the named secrets'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "init" -d 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "ls" -d 'List active agent grants and their TTLs'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "revoke" -d 'Revoke an agent grant and rotate the keys it could read'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "connect" -d 'Wire `murk mcp` into an AI editor\'s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "disconnect" -d 'Remove murk\'s entry from an AI editor\'s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "show" -d 'Show the agent access policy (works without a key)'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "set" -d 'Set the agent allow-list: agents may only receive secrets carrying one of these tags'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "clear" -d 'Remove the policy — agent mode becomes unrestricted again'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from circle" -f -a "authorize" -d 'Add a recipient to the vault'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from circle" -f -a "revoke" -d 'Remove a recipient from the vault'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from group" -f -a "create" -d 'Create a new recipient group (you become its first member)'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from group" -f -a "ls" -d 'List groups and their members'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from group" -f -a "add" -d 'Add a member to a group'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from group" -f -a "rm" -d 'Remove a member from a group, or delete the group entirely'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from completion" -f -a "generate" -d 'Print completions to stdout'
complete -c murk -n "__fish_murk_using_subcommand help; and __fish_seen_subcommand_from completion" -f -a "install" -d 'Install completions to the standard path'
