
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'murk' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'murk'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'murk' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a new vault and generate a keypair')
            [CompletionResult]::new('env', 'env', [CompletionResultType]::ParameterValue, 'Write a .envrc for direnv integration')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore MURK_KEY from a BIP39 recovery phrase')
            [CompletionResult]::new('recover', 'recover', [CompletionResultType]::ParameterValue, 'Re-derive recovery phrase from current MURK_KEY')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add or update a secret')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a random secret and store it')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate secrets with new values')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a single decrypted value')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Edit secrets in $EDITOR')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List all key names')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export all secrets as shell export statements')
            [CompletionResult]::new('import', 'import', [CompletionResultType]::ParameterValue, 'Import secrets from a .env file')
            [CompletionResult]::new('describe', 'describe', [CompletionResultType]::ParameterValue, 'Add or update a key description')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Show public schema and key info')
            [CompletionResult]::new('skeleton', 'skeleton', [CompletionResultType]::ParameterValue, 'Export schema-only vault with no secrets or recipients')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with secrets injected as environment variables')
            [CompletionResult]::new('agent', 'agent', [CompletionResultType]::ParameterValue, 'Agent-oriented commands (schema-only output for AI agent prompts)')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Run an MCP (Model Context Protocol) stdio server for AI agents')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the agent access policy')
            [CompletionResult]::new('circle', 'circle', [CompletionResultType]::ParameterValue, 'Manage recipients')
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('group', 'group', [CompletionResultType]::ParameterValue, 'Manage recipient groups')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify vault integrity without exporting secrets')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Check the surrounding repo for hygiene issues')
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan files for leaked secret values')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Show secret changes vs a git ref')
            [CompletionResult]::new('setup-merge-driver', 'setup-merge-driver', [CompletionResultType]::ParameterValue, 'Configure git to use murk''s merge driver for .murk files')
            [CompletionResult]::new('merge-driver', 'merge-driver', [CompletionResultType]::ParameterValue, 'Git merge driver for .murk vault files (called by git)')
            [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate or install shell completions')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;init' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;env' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;restore' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename, for the restored-identity recipient check')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;recover' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;add' {
            [CompletionResult]::new('--desc', '--desc', [CompletionResultType]::ParameterName, 'Description for this key')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value')
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Who can read it: a group name, `everyone` (default), or `me`')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--scoped', '--scoped', [CompletionResultType]::ParameterName, 'Deprecated alias for `--group me`')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;generate' {
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Length in bytes (default 32)')
            [CompletionResult]::new('--desc', '--desc', [CompletionResultType]::ParameterName, 'Description for this key')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value')
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Who can read it: a group name, `everyone` (default), or `me`')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--hex', '--hex', [CompletionResultType]::ParameterName, 'Output as hex instead of base64')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;rotate' {
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Length in bytes for generated values (default 32)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--all', '--all', [CompletionResultType]::ParameterName, 'Rotate all secrets in the vault')
            [CompletionResult]::new('--generate', '--generate', [CompletionResultType]::ParameterName, 'Generate random values instead of prompting')
            [CompletionResult]::new('--hex', '--hex', [CompletionResultType]::ParameterName, 'Output generated values as hex instead of base64')
            [CompletionResult]::new('--list', '--list', [CompletionResultType]::ParameterName, 'List keys needing rotation instead of rotating (exits 1 if any)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output the listing as JSON (with --list, always exits 0)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;rm' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;get' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;edit' {
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Edit values for this group instead of shared secrets')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--scoped', '--scoped', [CompletionResultType]::ParameterName, 'Edit scoped overrides instead of shared secrets')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;ls' {
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;export' {
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;import' {
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Assign imported secrets to this group (default: everyone)')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value applied to every imported key')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Overwrite existing secrets without prompting')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;describe' {
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable, replaces existing tags)')
            [CompletionResult]::new('--rotate-every', '--rotate-every', [CompletionResultType]::ParameterName, 'Rotation interval, e.g. `90d` or `90` (days). `never` clears it')
            [CompletionResult]::new('--expires', '--expires', [CompletionResultType]::ParameterName, 'Hard expiry date, e.g. `2026-09-01`. `never` clears it')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;info' {
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;skeleton' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file (prints to stdout if omitted)')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file (prints to stdout if omitted)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;exec' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Only inject these specific keys (repeatable)')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--clean-env', '--clean-env', [CompletionResultType]::ParameterName, 'Strip inherited environment (only murk secrets + PATH)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant and rotate the keys it could read')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;agent;plan' {
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file (prints to stdout if omitted)')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file (prints to stdout if omitted)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;exec' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Inject these specific keys (required — agent mode fails closed)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;grant' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to revoke it later)')
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys this grant can read (required — fails closed)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Where to write the agent key: a path, or `-` for stdout')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--renew', '--renew', [CompletionResultType]::ParameterName, 'Replace a live grant with this name: revoke its key, mint a fresh one')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;init' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to revoke it later)')
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys the agent can read (required — fails closed)')
            [CompletionResult]::new('--allow-tag', '--allow-tag', [CompletionResultType]::ParameterName, 'Set the agent allow-list to these tags before granting (repeatable)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Where to write the agent key: a path, or `-` for stdout')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;ls' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;revoke' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the keys it could read in the same session')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;connect' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys the agent may read (required — fails closed)')
            [CompletionResult]::new('--allow-tag', '--allow-tag', [CompletionResultType]::ParameterName, 'Set the agent allow-list to these tags before granting (repeatable)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Grant time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to disconnect/revoke it later)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--allow-exec', '--allow-exec', [CompletionResultType]::ParameterName, 'Also expose `murk agent exec` to the agent (adds --allow-exec)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;disconnect' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name to revoke with --rotate')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Revoke the grant and rotate the keys it could read')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;help' {
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant and rotate the keys it could read')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;agent;help;plan' {
            break
        }
        'murk;agent;help;exec' {
            break
        }
        'murk;agent;help;grant' {
            break
        }
        'murk;agent;help;init' {
            break
        }
        'murk;agent;help;ls' {
            break
        }
        'murk;agent;help;revoke' {
            break
        }
        'murk;agent;help;connect' {
            break
        }
        'murk;agent;help;disconnect' {
            break
        }
        'murk;agent;help;help' {
            break
        }
        'murk;mcp' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--allow-exec', '--allow-exec', [CompletionResultType]::ParameterName, 'Enable the murk_exec tool (run commands with scoped secrets injected). Off by default: it runs arbitrary commands as this user — the injected secrets are grant-scoped, but the command itself is not sandboxed')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;policy' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the agent access policy (works without a key)')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set the agent allow-list: agents may only receive secrets carrying one of these tags')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Remove the policy — agent mode becomes unrestricted again')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;policy;show' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;policy;set' {
            [CompletionResult]::new('--allow-tag', '--allow-tag', [CompletionResultType]::ParameterName, 'Tag agents are allowed to receive (repeatable, required)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;policy;clear' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;policy;help' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the agent access policy (works without a key)')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set the agent allow-list: agents may only receive secrets carrying one of these tags')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Remove the policy — agent mode becomes unrestricted again')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;policy;help;show' {
            break
        }
        'murk;policy;help;set' {
            break
        }
        'murk;policy;help;clear' {
            break
        }
        'murk;policy;help;help' {
            break
        }
        'murk;circle' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;circle;authorize' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Display name for this recipient')
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Also add the new recipient to this group')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Accept changed GitHub keys without confirmation')
            [CompletionResult]::new('--allow-ssh-rsa', '--allow-ssh-rsa', [CompletionResultType]::ParameterName, 'Allow ssh-rsa recipients (rejected by default — use ed25519)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;circle;revoke' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the secrets they had access to in the same session')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;circle;help' {
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;circle;help;authorize' {
            break
        }
        'murk;circle;help;revoke' {
            break
        }
        'murk;circle;help;help' {
            break
        }
        'murk;authorize' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Display name for this recipient')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Accept changed GitHub keys without confirmation')
            [CompletionResult]::new('--allow-ssh-rsa', '--allow-ssh-rsa', [CompletionResultType]::ParameterName, 'Allow ssh-rsa recipients (rejected by default — use ed25519)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;revoke' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the secrets they had access to in the same session')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;group' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new recipient group (you become its first member)')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List groups and their members')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a member to a group')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a member from a group, or delete the group entirely')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;group;create' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;group;ls' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;group;add' {
            [CompletionResult]::new('--member', '--member', [CompletionResultType]::ParameterName, 'Recipient pubkey or display name to add')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;group;rm' {
            [CompletionResult]::new('--member', '--member', [CompletionResultType]::ParameterName, 'Recipient pubkey or display name to remove (omit to delete the group)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;group;help' {
            [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new recipient group (you become its first member)')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List groups and their members')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a member to a group')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a member from a group, or delete the group entirely')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;group;help;create' {
            break
        }
        'murk;group;help;ls' {
            break
        }
        'murk;group;help;add' {
            break
        }
        'murk;group;help;rm' {
            break
        }
        'murk;group;help;help' {
            break
        }
        'murk;verify' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;doctor' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;scan' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;diff' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--show-values', '--show-values', [CompletionResultType]::ParameterName, 'Show actual values (not just key names)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;setup-merge-driver' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;merge-driver' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;completion' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions to stdout')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install completions to the standard path')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;completion;generate' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;completion;install' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;completion;help' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions to stdout')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install completions to the standard path')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;completion;help;generate' {
            break
        }
        'murk;completion;help;install' {
            break
        }
        'murk;completion;help;help' {
            break
        }
        'murk;help' {
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a new vault and generate a keypair')
            [CompletionResult]::new('env', 'env', [CompletionResultType]::ParameterValue, 'Write a .envrc for direnv integration')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore MURK_KEY from a BIP39 recovery phrase')
            [CompletionResult]::new('recover', 'recover', [CompletionResultType]::ParameterValue, 'Re-derive recovery phrase from current MURK_KEY')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add or update a secret')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a random secret and store it')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate secrets with new values')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a single decrypted value')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Edit secrets in $EDITOR')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List all key names')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export all secrets as shell export statements')
            [CompletionResult]::new('import', 'import', [CompletionResultType]::ParameterValue, 'Import secrets from a .env file')
            [CompletionResult]::new('describe', 'describe', [CompletionResultType]::ParameterValue, 'Add or update a key description')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Show public schema and key info')
            [CompletionResult]::new('skeleton', 'skeleton', [CompletionResultType]::ParameterValue, 'Export schema-only vault with no secrets or recipients')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with secrets injected as environment variables')
            [CompletionResult]::new('agent', 'agent', [CompletionResultType]::ParameterValue, 'Agent-oriented commands (schema-only output for AI agent prompts)')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Run an MCP (Model Context Protocol) stdio server for AI agents')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the agent access policy')
            [CompletionResult]::new('circle', 'circle', [CompletionResultType]::ParameterValue, 'Manage recipients')
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('group', 'group', [CompletionResultType]::ParameterValue, 'Manage recipient groups')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify vault integrity without exporting secrets')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Check the surrounding repo for hygiene issues')
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan files for leaked secret values')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Show secret changes vs a git ref')
            [CompletionResult]::new('setup-merge-driver', 'setup-merge-driver', [CompletionResultType]::ParameterValue, 'Configure git to use murk''s merge driver for .murk files')
            [CompletionResult]::new('merge-driver', 'merge-driver', [CompletionResultType]::ParameterValue, 'Git merge driver for .murk vault files (called by git)')
            [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate or install shell completions')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;help;init' {
            break
        }
        'murk;help;env' {
            break
        }
        'murk;help;restore' {
            break
        }
        'murk;help;recover' {
            break
        }
        'murk;help;add' {
            break
        }
        'murk;help;generate' {
            break
        }
        'murk;help;rotate' {
            break
        }
        'murk;help;rm' {
            break
        }
        'murk;help;get' {
            break
        }
        'murk;help;edit' {
            break
        }
        'murk;help;ls' {
            break
        }
        'murk;help;export' {
            break
        }
        'murk;help;import' {
            break
        }
        'murk;help;describe' {
            break
        }
        'murk;help;info' {
            break
        }
        'murk;help;skeleton' {
            break
        }
        'murk;help;exec' {
            break
        }
        'murk;help;agent' {
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant and rotate the keys it could read')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Wire `murk mcp` into an AI editor''s MCP config, minting a scoped grant. No CLIENT auto-detects installed editors. Give one (claude, cursor, vscode, zed, gemini, omp, codex) to target it')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config. No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
            break
        }
        'murk;help;agent;plan' {
            break
        }
        'murk;help;agent;exec' {
            break
        }
        'murk;help;agent;grant' {
            break
        }
        'murk;help;agent;init' {
            break
        }
        'murk;help;agent;ls' {
            break
        }
        'murk;help;agent;revoke' {
            break
        }
        'murk;help;agent;connect' {
            break
        }
        'murk;help;agent;disconnect' {
            break
        }
        'murk;help;mcp' {
            break
        }
        'murk;help;policy' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show the agent access policy (works without a key)')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Set the agent allow-list: agents may only receive secrets carrying one of these tags')
            [CompletionResult]::new('clear', 'clear', [CompletionResultType]::ParameterValue, 'Remove the policy — agent mode becomes unrestricted again')
            break
        }
        'murk;help;policy;show' {
            break
        }
        'murk;help;policy;set' {
            break
        }
        'murk;help;policy;clear' {
            break
        }
        'murk;help;circle' {
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            break
        }
        'murk;help;circle;authorize' {
            break
        }
        'murk;help;circle;revoke' {
            break
        }
        'murk;help;authorize' {
            break
        }
        'murk;help;revoke' {
            break
        }
        'murk;help;group' {
            [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new recipient group (you become its first member)')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List groups and their members')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add a member to a group')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a member from a group, or delete the group entirely')
            break
        }
        'murk;help;group;create' {
            break
        }
        'murk;help;group;ls' {
            break
        }
        'murk;help;group;add' {
            break
        }
        'murk;help;group;rm' {
            break
        }
        'murk;help;verify' {
            break
        }
        'murk;help;doctor' {
            break
        }
        'murk;help;scan' {
            break
        }
        'murk;help;diff' {
            break
        }
        'murk;help;setup-merge-driver' {
            break
        }
        'murk;help;merge-driver' {
            break
        }
        'murk;help;completion' {
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Print completions to stdout')
            [CompletionResult]::new('install', 'install', [CompletionResultType]::ParameterValue, 'Install completions to the standard path')
            break
        }
        'murk;help;completion;generate' {
            break
        }
        'murk;help;completion;install' {
            break
        }
        'murk;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
