
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
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a vault or reuse its existing key')
            [CompletionResult]::new('env', 'env', [CompletionResultType]::ParameterValue, 'Write a .envrc for direnv integration')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore MURK_KEY from a BIP39 recovery phrase')
            [CompletionResult]::new('recover', 'recover', [CompletionResultType]::ParameterValue, 'Re-derive recovery phrase from current MURK_KEY')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add or update a secret')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a random secret and store it')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate secrets with new values')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a single decrypted value')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Edit secrets in $EDITOR (experimental)')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List all key names')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export all secrets as shell export statements')
            [CompletionResult]::new('import', 'import', [CompletionResultType]::ParameterValue, 'Import secrets from a .env file')
            [CompletionResult]::new('describe', 'describe', [CompletionResultType]::ParameterValue, 'Set a key''s description, example, tags and rotation or expiry policy')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Show public schema and key info')
            [CompletionResult]::new('skeleton', 'skeleton', [CompletionResultType]::ParameterValue, 'Export schema-only vault with no secrets or recipients')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with secrets injected as environment variables')
            [CompletionResult]::new('agent', 'agent', [CompletionResultType]::ParameterValue, 'Give AI agents scoped, time-limited access to secrets (experimental)')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Run an MCP (Model Context Protocol) stdio server for AI agents (experimental)')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the agent access policy (experimental)')
            [CompletionResult]::new('circle', 'circle', [CompletionResultType]::ParameterValue, 'Manage recipients')
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('group', 'group', [CompletionResultType]::ParameterValue, 'Manage recipient groups (experimental)')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify vault integrity without exporting secrets')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Review who signed the vault and what changed, then trust it on this machine')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Check the surrounding repo for hygiene issues')
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan files for leaked secret values')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Show secret and access changes vs a git ref (experimental)')
            [CompletionResult]::new('setup-merge-driver', 'setup-merge-driver', [CompletionResultType]::ParameterValue, 'Configure git to use murk''s merge driver for .murk files (experimental)')
            [CompletionResult]::new('merge-driver', 'merge-driver', [CompletionResultType]::ParameterValue, 'Git merge driver for .murk vault files (called by git; experimental)')
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
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Who can read it: a group name (experimental), `everyone`, or `me`. Omit to keep an existing key''s tier; a new key is shared with everyone')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--scoped', '--scoped', [CompletionResultType]::ParameterName, 'Deprecated alias for `--group me`')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;generate' {
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Length in bytes')
            [CompletionResult]::new('--desc', '--desc', [CompletionResultType]::ParameterName, 'Description for this key')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value')
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Who can read it: a group name (experimental), `everyone`, or `me`. Omit to keep an existing key''s tier; a new key is shared with everyone')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--hex', '--hex', [CompletionResultType]::ParameterName, 'Encode the value as hex instead of URL-safe base64')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;rotate' {
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Length in bytes for generated values')
            [CompletionResult]::new('--values-from', '--values-from', [CompletionResultType]::ParameterName, 'Read new values from a dotenv file of KEY=value lines (`-` for stdin), matched by key name')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--all', '--all', [CompletionResultType]::ParameterName, 'Rotate all secrets in the vault')
            [CompletionResult]::new('--generate', '--generate', [CompletionResultType]::ParameterName, 'Generate random values instead of prompting')
            [CompletionResult]::new('--hex', '--hex', [CompletionResultType]::ParameterName, 'Encode generated values as hex instead of URL-safe base64')
            [CompletionResult]::new('--list', '--list', [CompletionResultType]::ParameterName, 'List keys needing rotation instead of rotating (exits 1 if any)')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output the listing as JSON, an object with `verified` and `issues` (with --list, exits 0 even when keys need rotating)')
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
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Edit values for this group instead of shared secrets (experimental)')
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
            [CompletionResult]::new('--allow-reserved', '--allow-reserved', [CompletionResultType]::ParameterName, 'Allow keys named like loader/shell/tool variables (PATH, LD_*, GIT_*, MURK_*, ...)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;import' {
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Assign imported secrets to this group (`everyone`, `me`, or a group name, which is experimental). Omit to keep each existing key''s tier; new keys are shared with everyone')
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value applied to every imported key')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Overwrite existing secrets. Without it, import stops if any key already exists')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;describe' {
            [CompletionResult]::new('--example', '--example', [CompletionResultType]::ParameterName, 'Example value. Omitting it clears the current example')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Tag for grouping (repeatable, replaces existing tags)')
            [CompletionResult]::new('--rotate-every', '--rotate-every', [CompletionResultType]::ParameterName, 'Rotation interval, e.g. `90d` or `90` (days). `never` clears it')
            [CompletionResult]::new('--expires', '--expires', [CompletionResultType]::ParameterName, 'Hard expiry date, e.g. `2026-09-01`. `never` clears it')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
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
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'New output file; refuses an existing path (prints to stdout if omitted)')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'New output file; refuses an existing path (prints to stdout if omitted)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;exec' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Only inject these specific keys (repeatable)')
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--clean-env', '--clean-env', [CompletionResultType]::ParameterName, 'Start the command with only murk secrets plus PATH, HOME and TERM on Unix (on Windows, PATH and a fixed set of system variables)')
            [CompletionResult]::new('--allow-reserved', '--allow-reserved', [CompletionResultType]::ParameterName, 'Allow keys named like loader/shell/tool variables (PATH, LD_*, GIT_*, MURK_*, ...)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt (experimental)')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (experimental; keeps only PATH, HOME and TERM from the inherited environment on Unix, or PATH and a fixed set of system variables on Windows, strips MURK_KEY, requires --only, masks injected values in the output)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets (experimental)')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding (experimental): optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs (experimental)')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant (experimental)')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add `murk mcp` to an AI client''s MCP config and mint a scoped grant for it (experimental)')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config (experimental). No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'murk;agent;plan' {
            [CompletionResult]::new('--tag', '--tag', [CompletionResultType]::ParameterName, 'Filter by tag (repeatable)')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'New output file; refuses an existing path (prints to stdout if omitted)')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'New output file; refuses an existing path (prints to stdout if omitted)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output as JSON')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;exec' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Inject these specific keys (required — agent mode fails closed)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--allow-operator-key', '--allow-operator-key', [CompletionResultType]::ParameterName, 'Decrypt with your own stored key from ~/.config/murk/keys. Without this, agent exec needs an explicit MURK_KEY or MURK_KEY_FILE')
            [CompletionResult]::new('--allow-reserved', '--allow-reserved', [CompletionResultType]::ParameterName, 'Allow keys named like loader/shell/tool variables (PATH, LD_*, GIT_*, MURK_*, ...)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;grant' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to revoke it later)')
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys this grant can read (required — fails closed)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Time to live, e.g. 30m, 2h, 7d; at most 365d (reads fail closed after expiry)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Where to write the agent key: a path, or `-` for stdout')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--renew', '--renew', [CompletionResultType]::ParameterName, 'Replace a live grant with this name: revoke its key, mint a fresh one')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Replace a file already at --out (refused by default)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;agent;init' {
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to revoke it later)')
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys the agent can read (required — fails closed)')
            [CompletionResult]::new('--allow-tag', '--allow-tag', [CompletionResultType]::ParameterName, 'Set the agent allow-list to these tags before granting (repeatable)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Time to live, e.g. 30m, 2h, 7d; at most 365d (reads fail closed after expiry)')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Where to write the agent key: a path, or `-` for stdout')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Replace a file already at --out (refused by default)')
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
            [CompletionResult]::new('--values-from', '--values-from', [CompletionResultType]::ParameterName, 'With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the secrets the grant could read, in the same run. murk stores a new value for each. It does not rotate them at the provider')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'murk;agent;connect' {
            [CompletionResult]::new('--only', '--only', [CompletionResultType]::ParameterName, 'Keys the agent may read (required — fails closed)')
            [CompletionResult]::new('--allow-tag', '--allow-tag', [CompletionResultType]::ParameterName, 'Set the agent allow-list to these tags before granting (repeatable)')
            [CompletionResult]::new('--ttl', '--ttl', [CompletionResultType]::ParameterName, 'Grant time to live, e.g. 30m, 2h, 7d; at most 365d (reads fail closed after expiry)')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Grant name (used to disconnect/revoke it later)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--allow-exec', '--allow-exec', [CompletionResultType]::ParameterName, 'Also enable the `murk_exec` tool in the MCP server (writes `--allow-exec` into the client config)')
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
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt (experimental)')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (experimental; keeps only PATH, HOME and TERM from the inherited environment on Unix, or PATH and a fixed set of system variables on Windows, strips MURK_KEY, requires --only, masks injected values in the output)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets (experimental)')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding (experimental): optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs (experimental)')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant (experimental)')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add `murk mcp` to an AI client''s MCP config and mint a scoped grant for it (experimental)')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config (experimental). No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
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
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Also add the new recipient to this group (experimental)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Accept changed GitHub keys. Without it, authorize stops when a user''s keys differ from the pinned set')
            [CompletionResult]::new('--allow-ssh-rsa', '--allow-ssh-rsa', [CompletionResultType]::ParameterName, 'Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;circle;revoke' {
            [CompletionResult]::new('--values-from', '--values-from', [CompletionResultType]::ParameterName, 'With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the secrets they had access to in the same session')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Revoke every key of a multi-key GitHub user without confirmation')
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
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Accept changed GitHub keys. Without it, authorize stops when a user''s keys differ from the pinned set')
            [CompletionResult]::new('--allow-ssh-rsa', '--allow-ssh-rsa', [CompletionResultType]::ParameterName, 'Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'murk;revoke' {
            [CompletionResult]::new('--values-from', '--values-from', [CompletionResultType]::ParameterName, 'With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)')
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--rotate', '--rotate', [CompletionResultType]::ParameterName, 'Rotate the secrets they had access to in the same session')
            [CompletionResult]::new('--force', '--force', [CompletionResultType]::ParameterName, 'Revoke every key of a multi-key GitHub user without confirmation')
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
        'murk;trust' {
            [CompletionResult]::new('--vault', '--vault', [CompletionResultType]::ParameterName, 'Vault filename')
            [CompletionResult]::new('--yes', '--yes', [CompletionResultType]::ParameterName, 'Accept without asking (for scripts; review first)')
            [CompletionResult]::new('--print-key', '--print-key', [CompletionResultType]::ParameterName, 'Print your own trusted-signer entry (for MURK_TRUSTED_SIGNERS) and signing-key fingerprint (for teammates to confirm), then exit')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
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
            [CompletionResult]::new('--json', '--json', [CompletionResultType]::ParameterName, 'Output JSON: {"secrets": [...], "changes": [...]} (values only with --show-values)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
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
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize a vault or reuse its existing key')
            [CompletionResult]::new('env', 'env', [CompletionResultType]::ParameterValue, 'Write a .envrc for direnv integration')
            [CompletionResult]::new('restore', 'restore', [CompletionResultType]::ParameterValue, 'Restore MURK_KEY from a BIP39 recovery phrase')
            [CompletionResult]::new('recover', 'recover', [CompletionResultType]::ParameterValue, 'Re-derive recovery phrase from current MURK_KEY')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Add or update a secret')
            [CompletionResult]::new('generate', 'generate', [CompletionResultType]::ParameterValue, 'Generate a random secret and store it')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate secrets with new values')
            [CompletionResult]::new('rm', 'rm', [CompletionResultType]::ParameterValue, 'Remove a secret')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a single decrypted value')
            [CompletionResult]::new('edit', 'edit', [CompletionResultType]::ParameterValue, 'Edit secrets in $EDITOR (experimental)')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List all key names')
            [CompletionResult]::new('export', 'export', [CompletionResultType]::ParameterValue, 'Export all secrets as shell export statements')
            [CompletionResult]::new('import', 'import', [CompletionResultType]::ParameterValue, 'Import secrets from a .env file')
            [CompletionResult]::new('describe', 'describe', [CompletionResultType]::ParameterValue, 'Set a key''s description, example, tags and rotation or expiry policy')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Show public schema and key info')
            [CompletionResult]::new('skeleton', 'skeleton', [CompletionResultType]::ParameterValue, 'Export schema-only vault with no secrets or recipients')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with secrets injected as environment variables')
            [CompletionResult]::new('agent', 'agent', [CompletionResultType]::ParameterValue, 'Give AI agents scoped, time-limited access to secrets (experimental)')
            [CompletionResult]::new('mcp', 'mcp', [CompletionResultType]::ParameterValue, 'Run an MCP (Model Context Protocol) stdio server for AI agents (experimental)')
            [CompletionResult]::new('policy', 'policy', [CompletionResultType]::ParameterValue, 'Manage the agent access policy (experimental)')
            [CompletionResult]::new('circle', 'circle', [CompletionResultType]::ParameterValue, 'Manage recipients')
            [CompletionResult]::new('authorize', 'authorize', [CompletionResultType]::ParameterValue, 'Add a recipient to the vault')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Remove a recipient from the vault')
            [CompletionResult]::new('group', 'group', [CompletionResultType]::ParameterValue, 'Manage recipient groups (experimental)')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify vault integrity without exporting secrets')
            [CompletionResult]::new('trust', 'trust', [CompletionResultType]::ParameterValue, 'Review who signed the vault and what changed, then trust it on this machine')
            [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Check the surrounding repo for hygiene issues')
            [CompletionResult]::new('scan', 'scan', [CompletionResultType]::ParameterValue, 'Scan files for leaked secret values')
            [CompletionResult]::new('diff', 'diff', [CompletionResultType]::ParameterValue, 'Show secret and access changes vs a git ref (experimental)')
            [CompletionResult]::new('setup-merge-driver', 'setup-merge-driver', [CompletionResultType]::ParameterValue, 'Configure git to use murk''s merge driver for .murk files (experimental)')
            [CompletionResult]::new('merge-driver', 'merge-driver', [CompletionResultType]::ParameterValue, 'Git merge driver for .murk vault files (called by git; experimental)')
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
            [CompletionResult]::new('plan', 'plan', [CompletionResultType]::ParameterValue, 'Emit schema-only context safe to paste into an AI agent prompt (experimental)')
            [CompletionResult]::new('exec', 'exec', [CompletionResultType]::ParameterValue, 'Run a command with strict agent-safe defaults (experimental; keeps only PATH, HOME and TERM from the inherited environment on Unix, or PATH and a fixed set of system variables on Windows, strips MURK_KEY, requires --only, masks injected values in the output)')
            [CompletionResult]::new('grant', 'grant', [CompletionResultType]::ParameterValue, 'Mint a scoped ephemeral key that can read only the named secrets (experimental)')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'One-shot onboarding (experimental): optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely')
            [CompletionResult]::new('ls', 'ls', [CompletionResultType]::ParameterValue, 'List active agent grants and their TTLs (experimental)')
            [CompletionResult]::new('revoke', 'revoke', [CompletionResultType]::ParameterValue, 'Revoke an agent grant (experimental)')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add `murk mcp` to an AI client''s MCP config and mint a scoped grant for it (experimental)')
            [CompletionResult]::new('disconnect', 'disconnect', [CompletionResultType]::ParameterValue, 'Remove murk''s entry from an AI editor''s MCP config (experimental). No CLIENT clears every configured editor. `--rotate` also revokes the grant and rotates its keys')
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
        'murk;help;trust' {
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
