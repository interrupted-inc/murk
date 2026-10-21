# murk CLI style guide

Internal reference for how murk commands present output. Follow this when
adding a new command so the CLI feels consistent.

## Prefixes

Every user-facing line starts with a one-word status prefix — no colons,
no punctuation, lowercase, bold-colored, one space before the message.

| Prefix  | Color          | Use                                             |
|---------|----------------|-------------------------------------------------|
| `ok`    | green bold     | check passed / operation succeeded              |
| `warn`  | yellow bold    | non-fatal issue the user should see             |
| `error` | red bold       | fatal, printed right before exit(1)             |
| `hint`  | cyan bold      | next-action suggestion under a warn or error    |
| `◆`     | magenta        | action-completed branding mark (not a status)   |

Examples:

```
ok vault integrity verified
warn 1 ssh-rsa key authorized — ed25519 is recommended
error MURK_KEY not set
hint run `murk init` to generate a key
◆ authorized alice
```

Never write `ok:`, `warn:`, `Error:`, `OK` etc. Prefixes are lowercase and
colon-free.

## Inline markers

| Marker | Color   | Use                                           |
|--------|---------|-----------------------------------------------|
| `◆`    | magenta | completed action / branding dot               |
| `✦`    | yellow  | scoped (mote) variant of `◆` — scoped add/update, scoped recipients in info |
| `⚠`    | yellow  | inline warning inside a list item             |
| `✕`    | red     | failed check inside a list item               |
| `*`    | plain   | "this entry is you" marker in `circle` / info |

Use `◆` for "something happened" lines, not for status. Use `ok` / `warn` /
`error` prefixes for status lines. A finding list under a `warn` header
should use `✕` for each failing item, not repeated `warn` prefixes.

## Formatting

- **Recipient display names** — green bold
- **Pubkeys** — dimmed, truncated to 10–12 chars + `…` when displayed next to
  a name (full pubkey acceptable when it's the primary subject of a line)
- **File paths, key names** — `bold()`
- **Fix hints / follow-ups** — two-space indent under the parent line,
  dimmed color
- **Errors from external causes** — include the raw message in dimmed style
  at the end of the line

## Layout

- No trailing period on status lines.
- No decorative horizontal rules or ASCII art.
- Empty lines only between logical sections — never between consecutive
  status lines of the same kind.
- Totals/summaries on their own line, not inline with item lists.
- Right-align counts when printing tables of counts. Otherwise use plain
  left-aligned output.

## Exit codes

- `0` — success, no findings
- `1` — any fatal error, or any unresolved `warn` from a check command
  (`verify`, `doctor`, `scan`, etc.)
- `2` — usage error: the arguments themselves are invalid, so nothing was
  attempted. clap exits 2 for unknown flags and missing arguments; a command
  that validates an argument value itself (`describe --rotate-every`/`--expires`,
  an unknown editor in `agent connect`/`disconnect`) uses 2 as well. Failures
  while doing the work (I/O, parse, crypto) are runtime errors and exit 1.

Check commands must be fail-closed by default: a finding that the user
should act on exits 1, even if the vault itself is readable.

## Colors

The demo theme is Catppuccin Mocha but the CLI should degrade gracefully
on any terminal. Always use the `colored` crate's semantic helpers
(`.green().bold()`, `.dimmed()`) — never raw ANSI escapes.

See [brand.md](./brand.md) for the canonical palette (ANSI slots and brand
hex), the brand purple `#8760FF`, and the rule that the CLI stays
theme-adaptive while fixed assets use the locked hex.

Use semantic colors for new CLI output. The `murk info` nameplate currently
uses a fixed RGB color and is an exception.

## Examples from the codebase

```rust
// status line
eprintln!("{} vault integrity verified", "ok".green().bold());

// warning with a count
eprintln!(
    "{} {} ssh-rsa key{} skipped — ed25519 is strongly recommended",
    "warn".yellow().bold(),
    rsa_count,
    if rsa_count == 1 { "" } else { "s" }
);

// action-completed branding
eprintln!("{} authorized {}", "◆".magenta(), display.bold());

// finding list under a warn header
eprintln!("{} {} findings", "warn".yellow().bold(), findings.len());
for f in &findings {
    eprintln!("  {} {} — {}", "✕".red(), f.category.bold(), f.message);
    if let Some(fix) = &f.fix {
        eprintln!("      {}", fix.dimmed());
    }
}
```
