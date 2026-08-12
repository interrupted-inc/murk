# murk brand guide

The single source of truth for murk's color, mark, and voice. The live CLI and
the fixed brand assets follow *different* color rules — read the split below
before changing either.

## The one purple

murk's brand purple is **`#8760FF`** — the project's one canonical purple.
Every fixed-color surface — logo, lockup, favicon, social card, website accent,
recorded demo GIFs — uses this exact hex.

UI accent ramps may derive tints *from* it — the site's Starlight theme uses a
dark low (`#241a4d`), a light high (`#d3c8ff`), and alpha glows (`#8760ff40`,
the brand purple at 25%). Those are sanctioned derivations of the one purple,
not new brand colors. A second, standalone base purple anywhere is drift; fix
it, don't add to it.

## CLI color vs. asset color

Two surfaces, two rules:

- **The live CLI emits semantic ANSI, never a fixed hex.** The mark and every
  status color go through the `colored` crate's semantic helpers (see
  [cli-style.md](./cli-style.md)). The `◆` mark is ANSI magenta (SGR 35); the
  *terminal* decides the actual RGB from the user's theme. That's intentional —
  murk adapts to the user's terminal instead of fighting it.
- **Fixed-color assets standardize on `#8760FF`.** Anything murk ships as a
  rendered image — logos, favicon, social card, recorded demo GIFs — is drawn
  in the brand purple, not left to a theme.

The demo GIFs bridge the two: the CLI still emits ANSI magenta, but the VHS
recording theme overrides magenta to `#8760FF`, so the recorded mark shows the
brand color rather than the terminal palette's magenta.

## Palette

The CLI emits ANSI slots (universal, theme-decided). The hex column is how those
slots render in brand/demo contexts — Catppuccin Mocha, with magenta overridden
to the brand purple.

| Role             | Glyph | CLI emits (ANSI)    | Brand hex             |
|------------------|-------|---------------------|-----------------------|
| brand mark       | ◆     | magenta (SGR 35)    | `#8760FF` (fixed)     |
| scoped mote      | ✦     | yellow (SGR 33)     | `#f9e2af`             |
| ok / recipient   |       | green bold (1;32)   | `#a6e3a1`             |
| warn             | ⚠     | yellow bold (1;33)  | `#f9e2af`             |
| error            | ✕     | red bold (1;31)     | `#f38ba8`             |
| hint             |       | cyan bold (1;36)    | `#94e2d5`             |
| dimmed           |       | faint (SGR 2)       | `#6c7086` (assets only) |
| foreground       |       | default fg (39)     | `#cdd6f4`             |
| background       |       | default bg (49)     | `#1e1e2e`             |

`dimmed` has no palette slot — it's the SGR 2 faint attribute over the
foreground, so its rendered color varies by terminal. `#6c7086` is only for
drawing dimmed text in static assets.

## The mark

The murk mark is a **diamond (`◆`)** — a rotated square, drawn as a vector path,
never a font glyph (a glyph renders differently across platforms and fonts). The
lockup is the diamond followed by the lowercase wordmark: **◆ murk**.

## Contrast

`#8760FF` measured against common backgrounds:

| Background             | Ratio  |
|------------------------|--------|
| Mocha base `#1e1e2e`   | 4.02:1 |
| White                  | 4.08:1 |
| GitHub dark            | 4.64:1 |

All clear the **3:1** bar for graphics and large marks (safe on light and dark
READMEs), but fall under the **4.5:1** bar for small body text. Use the purple
as a **mark or accent only** — never for small text on a dark background.

## Voice

murk is **"an encrypted secrets manager for developers."** Plain, technical, no
marketing gloss: say what it does, then what it doesn't.

Pair a public claim with the honesty line — murk is **pre-1.0 and has not been
independently audited**; use good judgment with production secrets. That caveat
is part of the voice, not a disclaimer to bury: it's what makes the security
claims credible.

## Agent positioning

Reusable copy for the agent-safe story, in the plain voice above. Pull from
these for the README, docs, and launch materials so the claim stays consistent
and precise. The full narrative and the security boundary live in the AI agents
& MCP guide on the docs site.

**Headline:** Let coding agents use your secrets without giving them your key.

**Subhead:** Agents read the vault's schema (names and descriptions, no values)
to write code and config. When they need to run something, you mint a grant
scoped to only the secrets you name. They never get the key that decrypts
everything.

**One-liner:** Scoped, revocable secret access for coding agents.

**Two-sentence pitch:** murk lets coding agents work with your secrets without
handing over the key to your vault. They read the schema to plan, then run
against a grant scoped to only the secrets you name.

**Boundary line** (include wherever the claim appears): This reduces where
secrets are exposed; it doesn't prevent a commanded process from printing one.
A grant's TTL is a reminder to revoke, not an expiry. It's least-privilege, not
a sandbox.
