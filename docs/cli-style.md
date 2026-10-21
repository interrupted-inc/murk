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
| `✕`     | red            | fatal error, printed right before exit. Each further line of the message prints as an indented `hint` line |
| `hint`  | cyan bold      | next-action suggestion under a warn or `✕` line |
| `◆`     | magenta        | action-completed branding mark (not a status)   |

Fatal errors go through `die()`, which prints the `✕` form. The `error`
word prefix (red bold) appears in four places only: `scan`, the merge
driver and the two strict-mode guards.

Examples:

```
ok vault integrity verified
warn 1 ssh-rsa key authorized — ed25519 is recommended
✕ MURK_KEY not set
  hint run `murk init` to generate a key
  hint or point MURK_KEY_FILE at an existing key file
◆ authorized alice
```

Never write `ok:`, `warn:`, `Error:`, `OK` etc. Prefixes are lowercase and
colon-free. Current exceptions: clap's own usage errors print `error:`, and
the warning about a `.env` readable by others prints `warning:`.

## Inline markers

| Marker | Color   | Use                                           |
|--------|---------|-----------------------------------------------|
| `◆`    | magenta | completed action / branding dot               |
| `✦`    | faint   | scoped (mote) variant of `◆`, used for scoped recipients in `info` |
| `⚠`    | yellow  | warning, as the lead of a line or inside a list item |
| `✕`    | red     | fatal error line (see Prefixes), or a failed check inside a list item |
| `*`    | plain   | "this entry is you" marker in `info` and `group ls`. `circle` marks you with a magenta `◆` |
| `▸`    | dimmed  | bullet in a list of secret names (revoke and grant output) |
| `✓`    | green   | rotation summary line |
| `+` `-` `~` | magenta, red, yellow (bold) | added, removed and changed secrets in `murk diff` |

Use `◆` for "something happened" lines, not for status. Use `ok` / `warn` /
`error` prefixes for status lines. A finding list under a `warn` header
should use `✕` for each failing item, not repeated `warn` prefixes.

## Formatting

- **Recipient display names** — green bold
- **Pubkeys**: dimmed, shown as the first 8 and last 4 characters joined by
  `…` (for example `age1ps8p…a26p`) when displayed next to a name. Strings of
  13 characters or fewer are shown whole. A full key is fine when it is the
  subject of the line.
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
(`.green().bold()`, `.dimmed()`). Do not use raw ANSI escapes. The `.env`
permission warning in the library is a current exception.

See [brand.md](./brand.md) for the canonical palette (ANSI slots and brand
hex), the brand purple `#8760FF`, and the rule that the CLI stays
theme-adaptive while fixed assets use the locked hex.

## Output examples

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
eprintln!(
    "{} {} issue{} in {}",
    "warn".yellow().bold(),
    findings.len(),
    if findings.len() == 1 { "" } else { "s" },
    header
);
for f in &findings {
    eprintln!("  {} {} — {}", "✕".red(), f.category.bold(), f.message);
    if let Some(fix) = &f.fix {
        eprintln!("      {}", fix.dimmed());
    }
}
```
