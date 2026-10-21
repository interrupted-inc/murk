// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI command model: the clap `Parser`/`Subcommand` types.
//!
//! Defined in the library (not `main.rs`) so both the `murk` binary and the
//! `doc-gen` tool build the exact same command tree from `Cli::command()`.

use clap::{Parser, Subcommand};

/// Encrypted secrets manager for developers.
#[derive(Parser)]
#[command(name = "murk", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    // Setup & recovery
    /// Initialize a new vault and generate a keypair
    Init {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Write a .envrc for direnv integration
    Env {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Restore MURK_KEY from a BIP39 recovery phrase
    Restore {
        /// Vault filename, for the restored-identity recipient check
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Re-derive recovery phrase from current MURK_KEY
    Recover,

    // Secrets
    /// Add or update a secret
    Add {
        /// Secret key name
        key: String,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Example value
        #[arg(long)]
        example: Option<String>,
        /// Who can read it: a group name, `everyone` (default), or `me`
        #[arg(long)]
        group: Option<String>,
        /// Deprecated alias for `--group me`
        #[arg(long, hide = true)]
        scoped: bool,
        /// Tag for grouping (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Generate a random secret and store it
    Generate {
        /// Secret key name
        key: String,
        /// Length in bytes
        #[arg(long, default_value = "32")]
        length: usize,
        /// Encode the value as hex instead of URL-safe base64
        #[arg(long)]
        hex: bool,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Example value
        #[arg(long)]
        example: Option<String>,
        /// Who can read it: a group name, `everyone` (default), or `me`
        #[arg(long)]
        group: Option<String>,
        /// Tag for grouping (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Rotate secrets with new values
    Rotate {
        /// Secret key name (omit for --all)
        key: Option<String>,
        /// Rotate all secrets in the vault
        #[arg(long)]
        all: bool,
        /// Generate random values instead of prompting
        #[arg(long)]
        generate: bool,
        /// Length in bytes for generated values
        #[arg(long, default_value = "32")]
        length: usize,
        /// Encode generated values as hex instead of URL-safe base64
        #[arg(long)]
        hex: bool,
        /// List keys needing rotation instead of rotating (exits 1 if any)
        #[arg(long, conflicts_with_all = ["key", "all", "generate", "hex"])]
        list: bool,
        /// Output the listing as JSON (with --list, always exits 0)
        #[arg(long, requires = "list", conflicts_with_all = ["key", "all", "generate", "hex"])]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a secret
    Rm {
        /// Secret key name
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Get a single decrypted value
    Get {
        /// Secret key name
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Edit secrets in $EDITOR
    Edit {
        /// Edit a single key (omit to edit all)
        key: Option<String>,
        /// Edit scoped overrides instead of shared secrets
        #[arg(long)]
        scoped: bool,
        /// Edit values for this group instead of shared secrets
        #[arg(long)]
        group: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List all key names
    Ls {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export all secrets as shell export statements
    Export {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Import secrets from a .env file
    Import {
        /// Path to the .env file to import
        #[arg(default_value = ".env")]
        file: String,
        /// Overwrite existing secrets. Without it, import stops if any key already exists
        #[arg(long)]
        force: bool,
        /// Assign imported secrets to this group (default: everyone)
        #[arg(long)]
        group: Option<String>,
        /// Example value applied to every imported key
        #[arg(long)]
        example: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Metadata & inspection
    /// Set a key's description, example, tags and rotation or expiry policy
    ///
    /// Each call replaces the description. It also replaces the example:
    /// omitting `--example` clears it. `--tag` replaces the tags only when
    /// given. `--rotate-every` and `--expires` change only when given.
    Describe {
        /// Secret key name
        key: String,
        /// Description text (replaces the current one)
        description: String,
        /// Example value. Omitting it clears the current example
        #[arg(long)]
        example: Option<String>,
        /// Tag for grouping (repeatable, replaces existing tags)
        #[arg(long)]
        tag: Vec<String>,
        /// Rotation interval, e.g. `90d` or `90` (days). `never` clears it
        #[arg(long, value_name = "DAYS")]
        rotate_every: Option<String>,
        /// Hard expiry date, e.g. `2026-09-01`. `never` clears it
        #[arg(long, value_name = "DATE")]
        expires: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Show public schema and key info
    Info {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export schema-only vault with no secrets or recipients
    Skeleton {
        /// Output file (prints to stdout if omitted)
        #[arg(long, short)]
        output: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Run
    /// Run a command with secrets injected as environment variables
    #[command(trailing_var_arg = true)]
    Exec {
        /// Only inject these specific keys (repeatable)
        #[arg(long)]
        only: Vec<String>,
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Start the command with only murk secrets plus PATH, HOME and TERM on Unix (on Windows, PATH and a fixed set of system variables)
        #[arg(long)]
        clean_env: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Command and arguments to execute
        #[arg(required = true)]
        command: Vec<String>,
    },

    // Agents
    /// Give AI agents scoped, time-limited access to secrets
    Agent {
        #[command(subcommand)]
        sub: AgentCommand,
    },

    /// Run an MCP (Model Context Protocol) stdio server for AI agents
    Mcp {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Enable the murk_exec tool (run commands with scoped secrets injected).
        /// Off by default: it runs arbitrary commands as this user — the injected
        /// secrets are grant-scoped, but the command itself is not sandboxed.
        #[arg(long = "allow-exec")]
        allow_exec: bool,
    },

    /// Manage the agent access policy
    Policy {
        #[command(subcommand)]
        sub: PolicyCommand,
    },

    // Recipients & groups
    /// Manage recipients
    #[command(alias = "recipients")]
    Circle {
        #[command(subcommand)]
        sub: Option<CircleCommand>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add a recipient to the vault
    #[command(hide = true)]
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
        /// Accept changed GitHub keys. Without it, authorize stops when a user's keys differ from the pinned set
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a recipient from the vault
    #[command(hide = true)]
    Revoke {
        /// Recipient pubkey or display name
        recipient: String,
        /// Rotate the secrets they had access to in the same session
        #[arg(long)]
        rotate: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Manage recipient groups
    Group {
        #[command(subcommand)]
        sub: GroupCommand,
    },

    // Checks
    /// Verify vault integrity without exporting secrets
    Verify {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Check the surrounding repo for hygiene issues
    Doctor {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Scan files for leaked secret values
    Scan {
        /// Files or directories to scan (defaults to current directory)
        paths: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Git integration
    /// Show secret changes vs a git ref
    ///
    /// The old revision is decrypted without checking its MAC or signature, so
    /// treat its values as unverified.
    Diff {
        /// Git ref to compare against
        #[arg(default_value = "HEAD")]
        git_ref: String,
        /// Show actual values (not just key names)
        #[arg(long)]
        show_values: bool,
        /// Output as JSON. Always includes the old and new values
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Configure git to use murk's merge driver for .murk files
    #[command(name = "setup-merge-driver")]
    SetupMergeDriver,

    /// Git merge driver for .murk vault files (called by git)
    #[command(name = "merge-driver", hide = true)]
    MergeDriver {
        /// Path to base version (%O)
        base: String,
        /// Path to ours version (%A) — result is written here
        ours: String,
        /// Path to theirs version (%B)
        theirs: String,
    },

    // Shell
    /// Generate or install shell completions
    Completion {
        #[command(subcommand)]
        action: CompletionAction,
    },
}

#[derive(Subcommand)]
pub enum CompletionAction {
    /// Print completions to stdout
    Generate {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Install completions to the standard path
    Install {
        /// Shell to install completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Emit schema-only context safe to paste into an AI agent prompt
    Plan {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Output file (prints to stdout if omitted)
        #[arg(long, short)]
        output: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Run a command with strict agent-safe defaults (keeps only PATH, HOME and
    /// TERM from the inherited environment on Unix, or PATH and a fixed set of
    /// system variables on Windows, strips MURK_KEY, requires --only, masks
    /// injected values in the output)
    #[command(trailing_var_arg = true)]
    Exec {
        /// Inject these specific keys (required — agent mode fails closed)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Decrypt with your own stored key from ~/.config/murk/keys. Without
        /// this, agent exec needs an explicit MURK_KEY or MURK_KEY_FILE
        #[arg(long)]
        allow_operator_key: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Command and arguments to execute
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Mint a scoped ephemeral key that can read only the named secrets
    Grant {
        /// Grant name (used to revoke it later)
        #[arg(long)]
        name: String,
        /// Keys this grant can read (required — fails closed)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Replace a live grant with this name: revoke its key, mint a fresh one
        #[arg(long)]
        renew: bool,
        /// Where to write the agent key: a path, or `-` for stdout
        #[arg(long)]
        out: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// One-shot onboarding: optionally set the agent allow-list, mint a scoped
    /// grant, and print how to run the agent safely
    Init {
        /// Grant name (used to revoke it later)
        #[arg(long)]
        name: String,
        /// Keys the agent can read (required — fails closed)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Set the agent allow-list to these tags before granting (repeatable)
        #[arg(long = "allow-tag")]
        allow_tag: Vec<String>,
        /// Time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Where to write the agent key: a path, or `-` for stdout
        #[arg(long)]
        out: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List active agent grants and their TTLs
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Revoke an agent grant
    ///
    /// The grant's key can still decrypt old versions of the vault from git
    /// history, so rotate the secrets it could read: pass `--rotate`, or answer
    /// the prompt on a terminal.
    Revoke {
        /// Grant name
        name: String,
        /// Rotate the secrets the grant could read, in the same run. murk stores
        /// a new value for each. It does not rotate them at the provider
        #[arg(long)]
        rotate: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add `murk mcp` to an AI client's MCP config and mint a scoped grant for it
    Connect {
        /// Client to configure: claude, cursor, vscode, zed, gemini, omp or codex.
        /// Omit it to configure every client that already has a config file or
        /// marker directory (such as `.cursor/`) next to the vault
        client: Option<String>,
        /// Keys the agent may read (required — fails closed)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Set the agent allow-list to these tags before granting (repeatable)
        #[arg(long = "allow-tag")]
        allow_tag: Vec<String>,
        /// Also enable the `murk_exec` tool in the MCP server (writes `--allow-exec` into the client config)
        #[arg(long)]
        allow_exec: bool,
        /// Grant time to live, e.g. 30m, 2h, 7d (reads fail closed after expiry)
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Grant name (used to disconnect/revoke it later)
        #[arg(long, default_value = "mcp")]
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove murk's entry from an AI editor's MCP config. No CLIENT clears every
    /// configured editor. `--rotate` also revokes the grant and rotates its keys.
    Disconnect {
        /// Editor to disconnect. Omit for every configured editor
        client: Option<String>,
        /// Revoke the grant and rotate the keys it could read
        #[arg(long)]
        rotate: bool,
        /// Grant name to revoke with --rotate
        #[arg(long, default_value = "mcp")]
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum CircleCommand {
    /// Add a recipient to the vault
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
        /// Also add the new recipient to this group
        #[arg(long)]
        group: Option<String>,
        /// Accept changed GitHub keys. Without it, authorize stops when a user's keys differ from the pinned set
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a recipient from the vault
    Revoke {
        /// Recipient pubkey or display name
        recipient: String,
        /// Rotate the secrets they had access to in the same session
        #[arg(long)]
        rotate: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a new recipient group (you become its first member)
    Create {
        /// Group name
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List groups and their members
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add a member to a group
    Add {
        /// Group name
        name: String,
        /// Recipient pubkey or display name to add
        #[arg(long)]
        member: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a member from a group, or delete the group entirely
    Rm {
        /// Group name
        name: String,
        /// Recipient pubkey or display name to remove (omit to delete the group)
        #[arg(long)]
        member: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Show the agent access policy (works without a key)
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Set the agent allow-list: agents may only receive secrets carrying one of these tags
    Set {
        /// Tag agents are allowed to receive (repeatable, required)
        #[arg(long = "allow-tag", required = true)]
        allow_tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove the policy — agent mode becomes unrestricted again
    Clear {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}
