# murk_lints

Type-aware secret-handling lints for the murk codebase.
`tests/invariants.rs` scans source text and cannot express type-level rules;
these are [dylint](https://github.com/trailofbits/dylint) lints built on real
rustc type information instead.

## Lints

- `secret_field_missing_zeroize` — the crate's *known* plaintext
  secret-holding fields (see `SECRET_FIELDS` in `src/lib.rs`) must resolve —
  possibly through `HashMap`/`BTreeMap`/`Option`/`Vec` — to
  `zeroize::Zeroizing<_>`, `age::secrecy::SecretString`, or a type
  implementing `zeroize::ZeroizeOnDrop`.
- `secret_debug_leak` — no `Debug` impl (derived, or the standard
  `Formatter::debug_struct(..).field(name, value)` manual builder pattern)
  may print a field whose type is/contains `Zeroizing<_>` or another
  `ZeroizeOnDrop` type that (like `Zeroizing`) doesn't redact its own
  `Debug` output. `age::secrecy::SecretString` is deliberately *not* in this
  marker set — see "Marker strategy" below.
- `secret_uncontrolled_escape` — `.clone()`/`.to_string()` may not escape a
  secret wrapper into a plain, never-zeroized value (`(*v).clone()` or
  `v.to_string()` where `v: Zeroizing<_>`/`SecretString`).

## Marker strategy

The murk codebase wraps every piece of decrypted plaintext in
`zeroize::Zeroizing<_>` (or, in `env.rs`, `age::secrecy::SecretString`) —
verified by grepping the crate before writing these lints; there are no
hand-rolled `impl Zeroize` types today. So "correctly handled" is checked
with real trait/ADT resolution against those two wrapper types, plus a
generic fallback that accepts any type implementing `zeroize::ZeroizeOnDrop`
(not plain `Zeroize` — see the note in `src/lib.rs` on why `ZeroizeOnDrop` is
the trait that matters: `String`/`Vec<u8>` implement `Zeroize` but nothing
calls it for you, so treating bare `Zeroize` as sufficient would be unsound).

`secret_field_missing_zeroize` additionally needs a way to know *which*
fields are secret-holding in the first place — it can't require a wrapper
that isn't there yet to prove a field should have one. There is no marker
trait/attribute for this in murk_cli today, so rather than guess from field
names (which produces false positives — `Murk::recipients`,
`Murk::groups`, `MurkIdentity::Plugin::pubkey`, etc. hold non-secret
metadata right alongside the secret fields, in the *same* structs), this
lint uses a **verified allowlist**: the exact `(type path, field name)`
pairs identified by reading the source (`SECRET_FIELDS` in `src/lib.rs`).
It is a regression guard for those known-sensitive fields, not a discovery
tool — extend the list by hand when a new field starts holding decrypted
plaintext.

`secret_debug_leak` doesn't need an allowlist either: the wrapper type
itself, resolved from real field types (not text), *is* the marker. But it
deliberately uses a **narrower** marker set than the other two lints:
`Zeroizing<_>` and any other `ZeroizeOnDrop` type count, but
`age::secrecy::SecretString` (`secrecy::SecretBox<str>`) does not, even
though it also implements `ZeroizeOnDrop`. `SecretBox`'s own `Debug` impl
unconditionally prints `SecretBox<str>([REDACTED])` (verified in the
`secrecy` crate source) — deriving `Debug` over a `SecretString` field is
already safe. Treating it as unsafe produced a real false positive during
development (`init::DiscoveredKey`, which derives `Debug` over a
`secret_key: SecretString` field) before this exclusion was added.

## Known limitations (scoped down deliberately)

- `secret_debug_leak`'s manual-impl check only recognizes the standard
  `.field(name, &self.field)` builder pattern, not `write!`/`format!`
  interpolation of a secret field. Reliably matching macro-desugared
  argument sinks is fragile across rustc versions; every manual `Debug` impl
  in murk_cli today (`MurkIdentity`, `MurkRecipient`, `Murk`, `DiffEntry`)
  either uses the builder pattern or never references a secret field, so
  this covers every real call site as of this writing.
- `secret_field_missing_zeroize` only covers the fields in its allowlist.

## Running

```sh
lints/murk_lints/run-dylint.sh
```

This is the single verified, reproducible command: it builds `murk_lints`
in release mode, then runs it over the murk workspace's lib, tests, and
bins via `cargo dylint --lib-path`. It requires the pinned nightly toolchain
and `cargo-dylint`/`dylint-link` to already be installed (see the script's
header comment for the one-time setup commands) — both are external tool
installs, not part of the murk workspace's own build.

UI tests:

```sh
cd lints/murk_lints
export PATH="$HOME/.cargo/bin:$PATH"
rustup run nightly-2026-05-28 cargo test
```

## Follow-up (not done in this pass)

- CI wiring.
- `secret_field_missing_zeroize` is a hand-maintained allowlist; if murk
  grows a general "this holds a secret" marker (attribute or trait) in the
  future, this lint should switch to discovering fields from it instead.
