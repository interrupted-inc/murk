// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `.env` format: what `murk import` reads and what `murk edit` writes to
//! its scratch file and reads back.
//!
//! Each entry is `KEY=VALUE`, optionally prefixed with `export `. Blank lines
//! and lines starting with `#` are skipped. A value is one of:
//!
//! - **Bare**: the rest of the line after `=`, trimmed, taken literally (a
//!   `#` in it is part of the value).
//! - **Double-quoted**: the escapes `\\`, `\"`, `\n`, `\r`, `\t` and
//!   `\u{HEX}` are decoded and any other backslash is kept as is. The value
//!   may span lines.
//! - **Single-quoted**: literal, and may span lines.
//!
//! After a closing quote, only whitespace and a `# comment` may follow. A
//! quote that is never closed is an error for the whole input, so the lines
//! after it never become entries of their own.
//!
//! [`push_value`] writes a value bare when that is unambiguous and
//! double-quoted otherwise, with every newline, control character and
//! whitespace other than a space escaped, so it reads back byte for byte even
//! after an editor rewrites line endings or strips trailing whitespace.
//!
//! Errors and skip notices carry line numbers, never the input's text, which
//! holds plaintext secrets.

use std::fmt;

use zeroize::Zeroizing;

use crate::is_valid_key_name;

/// Why the input as a whole was refused. Holds a line number and a
/// description, never input text.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line the problem starts on.
    pub line: usize,
    pub reason: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ParseError {}

fn error(line: usize, reason: impl Into<String>) -> ParseError {
    ParseError {
        line,
        reason: reason.into(),
    }
}

/// One non-blank, non-comment line (or quoted run of lines) of the input.
pub enum Item {
    /// `KEY=VALUE`. `key` is the trimmed text before `=`, not yet validated.
    Entry {
        line: usize,
        key: String,
        value: Zeroizing<String>,
        /// Whether the value was written without quotes.
        bare: bool,
    },
    /// A line with no `=`.
    NotAnEntry { line: usize },
}

/// Whether `value` reads back unchanged when written bare.
fn is_bare(value: &str) -> bool {
    let (Some(first), Some(last)) = (value.chars().next(), value.chars().next_back()) else {
        return false;
    };
    first != ' '
        && last != ' '
        && !matches!(first, '"' | '\'' | '#')
        && value
            .chars()
            .all(|c| c == ' ' || !(c.is_whitespace() || c.is_control() || crate::is_deceptive(c)))
}

/// Append `value` to `out`: bare if unambiguous, else double-quoted with
/// escapes. Reads back exactly through [`parse`] and [`parse_single`].
pub fn push_value(out: &mut String, value: &str) {
    if is_bare(value) {
        out.push_str(value);
        return;
    }
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c != ' ' && (c.is_whitespace() || c.is_control() || crate::is_deceptive(c)) => {
                use fmt::Write;
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The input's lines, numbered from 1, with a `\r` before each `\n` dropped
/// so CRLF files parse like LF ones.
struct Lines<'a> {
    inner: std::iter::Enumerate<std::str::Split<'a, char>>,
}

impl<'a> Lines<'a> {
    fn new(text: &'a str) -> Self {
        Lines {
            inner: text.split('\n').enumerate(),
        }
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = (usize, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let (i, line) = self.inner.next()?;
        Some((i + 1, line.strip_suffix('\r').unwrap_or(line)))
    }
}

/// Whether a line holds no value: blank, or a `#` comment.
fn is_skippable(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with('#')
}

/// Decode `\u{HEX}` at the start of `tail` (just after `\u`): the character
/// and how many bytes of `tail` it used.
fn unicode_escape(tail: &str) -> Option<(char, usize)> {
    let (hex, _) = tail.strip_prefix('{')?.split_once('}')?;
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let c = char::from_u32(u32::from_str_radix(hex, 16).ok()?)?;
    Some((c, hex.len() + 2))
}

/// Parse the value that starts at `rest` (the text after `=`, or a whole line
/// in single-key mode) on line `line_no`. A quoted value may continue onto
/// further lines, which are taken from `lines`.
fn parse_value(
    rest: &str,
    line_no: usize,
    lines: &mut Lines<'_>,
) -> Result<Zeroizing<String>, ParseError> {
    let rest = rest.trim_start();
    let Some(quote @ ('"' | '\'')) = rest.chars().next() else {
        return Ok(Zeroizing::new(rest.trim_end().to_string()));
    };

    let mut value = Zeroizing::new(String::new());
    let mut current = &rest[1..];
    let mut current_no = line_no;
    loop {
        let mut chars = current.char_indices();
        while let Some((i, c)) = chars.next() {
            if c == quote {
                let after = current[i + 1..].trim_start();
                if !(after.is_empty() || after.starts_with('#')) {
                    return Err(error(current_no, "unexpected text after the closing quote"));
                }
                return Ok(value);
            }
            if c != '\\' || quote == '\'' {
                value.push(c);
                continue;
            }
            let decoded = match current[i + 1..].chars().next() {
                Some('\\') => Some(('\\', 1)),
                Some('"') => Some(('"', 1)),
                Some('n') => Some(('\n', 1)),
                Some('r') => Some(('\r', 1)),
                Some('t') => Some(('\t', 1)),
                Some('u') => unicode_escape(&current[i + 2..]).map(|(c, used)| (c, used + 1)),
                _ => None,
            };
            match decoded {
                Some((c, used)) => {
                    value.push(c);
                    // `used` counts ASCII bytes after the backslash.
                    for _ in 0..used {
                        chars.next();
                    }
                }
                // Not an escape murk knows: keep the backslash.
                None => value.push('\\'),
            }
        }
        let Some((no, next)) = lines.next() else {
            return Err(error(
                line_no,
                format!("the {quote} opened here is never closed"),
            ));
        };
        value.push('\n');
        current = next;
        current_no = no;
    }
}

/// Parse `.env` text into its entries and the lines that are not entries, in
/// order. Keys are not validated. A malformed quoted value refuses the whole
/// input.
pub fn parse(text: &str) -> Result<Vec<Item>, ParseError> {
    let mut items = Vec::new();
    let mut lines = Lines::new(text);
    while let Some((line, raw)) = lines.next() {
        if is_skippable(raw) {
            continue;
        }
        let trimmed = raw.trim_start();
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((key, rest)) = trimmed.split_once('=') else {
            items.push(Item::NotAnEntry { line });
            continue;
        };
        let bare = !rest.trim_start().starts_with(['"', '\'']);
        let value = parse_value(rest, line, &mut lines)?;
        items.push(Item::Entry {
            line,
            key: key.trim().to_string(),
            value,
            bare,
        });
    }
    Ok(items)
}

/// A line `murk import` leaves out, and why. Its text is never kept.
#[derive(Debug, PartialEq, Eq)]
pub enum Skipped {
    /// The line has no `=`.
    NotAnEntry { line: usize },
    /// The key is not a shell identifier.
    InvalidKey { line: usize },
    /// The key is a `MURK_*` variable, which configures murk itself.
    MurkVariable { line: usize, key: String },
}

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Skipped::NotAnEntry { line } => write!(f, "line {line}: not KEY=VALUE"),
            Skipped::InvalidKey { line } => write!(f, "line {line}: invalid key name"),
            Skipped::MurkVariable { line, key } => {
                write!(f, "{key} (line {line}): murk variables cannot be imported")
            }
        }
    }
}

/// A bare value with ` #` in it, imported whole. Many `.env` loaders treat
/// that `#` as the start of a comment; murk keeps it, since cutting a value
/// silently is worse. Names the line, never the value.
#[derive(Debug, PartialEq, Eq)]
pub struct HashInBareValue {
    pub line: usize,
}

impl fmt::Display for HashInBareValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: value contains \" #\"; quote the value if the # is part of it, or remove the comment",
            self.line
        )
    }
}

/// A key set again later in the file. Import keeps the later value;
/// `rotate --values-from` refuses the batch. Key names are shell identifiers,
/// never values.
#[derive(Debug, PartialEq, Eq)]
pub struct DuplicateKey {
    pub key: String,
    /// The line that set it before.
    pub previous_line: usize,
    /// The line that sets it again.
    pub line: usize,
}

impl fmt::Display for DuplicateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: {} is already set on line {}",
            self.line, self.key, self.previous_line
        )
    }
}

/// A `.env` file as `murk import` takes it.
pub struct EnvImport {
    /// The entries to import, in file order. A key given twice keeps its
    /// last value (see [`EnvImport::duplicates`]).
    pub pairs: Vec<(String, Zeroizing<String>)>,
    /// What was left out, in file order.
    pub skipped: Vec<Skipped>,
    /// Imported bare values that look like they carry a comment.
    pub hash_notices: Vec<HashInBareValue>,
    /// Keys set more than once, in file order.
    pub duplicates: Vec<DuplicateKey>,
}

/// Parse a `.env` file for `murk import` (and `rotate --values-from`):
/// entries with valid, non-`MURK_*` key names are kept and every other line is
/// reported in [`EnvImport::skipped`].
pub fn parse_env(contents: &str) -> Result<EnvImport, ParseError> {
    let mut import = EnvImport {
        pairs: Vec::new(),
        skipped: Vec::new(),
        hash_notices: Vec::new(),
        duplicates: Vec::new(),
    };
    let mut set_on: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in parse(contents)? {
        match item {
            Item::NotAnEntry { line } => import.skipped.push(Skipped::NotAnEntry { line }),
            Item::Entry { line, key, .. } if !is_valid_key_name(&key) => {
                import.skipped.push(Skipped::InvalidKey { line });
            }
            Item::Entry { line, key, .. } if key.starts_with("MURK_") => {
                import.skipped.push(Skipped::MurkVariable { line, key });
            }
            Item::Entry {
                line,
                key,
                value,
                bare,
            } => {
                if bare && value.contains(" #") {
                    import.hash_notices.push(HashInBareValue { line });
                }
                if let Some(previous_line) = set_on.insert(key.clone(), line) {
                    import.duplicates.push(DuplicateKey {
                        key: key.clone(),
                        previous_line,
                        line,
                    });
                }
                import.pairs.retain(|(k, _)| *k != key);
                import.pairs.push((key, value));
            }
        }
    }
    Ok(import)
}

/// Parse a bulk `murk edit` buffer. Stricter than [`parse_env`]: a line that
/// is not an entry, an invalid key name, or a key given twice refuses it all.
pub fn parse_edit_buffer(text: &str) -> Result<Vec<(String, Zeroizing<String>)>, ParseError> {
    let mut entries: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut seen_on: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in parse(text)? {
        let (line, key, value) = match item {
            Item::NotAnEntry { line } => return Err(error(line, "expected KEY=VALUE")),
            Item::Entry {
                line, key, value, ..
            } => (line, key, value),
        };
        if !is_valid_key_name(&key) {
            return Err(error(
                line,
                "invalid key name: use letters, digits and _, not starting with a digit",
            ));
        }
        if let Some(first) = seen_on.insert(key.clone(), line) {
            return Err(error(line, format!("{key} is already set on line {first}")));
        }
        entries.push((key, value));
    }
    Ok(entries)
}

/// The last line of the header murk writes above a single-key value. Lines up
/// to and including it are ignored; everything after it is the value, lines
/// starting with `#` included.
pub const VALUE_MARKER: &str = "# ---- the value starts below this line ----";

/// Parse a single-key `murk edit` buffer: the header, then the value. `None`
/// when there is no value at all (the user emptied the buffer to abort).
///
/// The header runs to the first [`VALUE_MARKER`] line. If the user deleted
/// that line, every leading blank and `#` line counts as header instead.
///
/// A value starting with a quote is read like an entry's right-hand side, and
/// only blank lines and `#` comments may follow it. Any other value is taken
/// verbatim from its first line to the end of the buffer, trimmed, so a
/// multi-line value can be pasted in as is. [`push_value`] writes a value
/// that way only when it is one line with nothing to trim, so it reads back
/// exactly.
pub fn parse_single(text: &str) -> Result<Option<Zeroizing<String>>, ParseError> {
    let has_marker = Lines::new(text).any(|(_, l)| l.trim_end() == VALUE_MARKER);
    let mut in_header = has_marker;
    let mut lines = Lines::new(text);
    while let Some((no, line)) = lines.next() {
        if in_header {
            in_header = line.trim_end() != VALUE_MARKER;
            continue;
        }
        let is_header = if has_marker {
            line.trim().is_empty()
        } else {
            is_skippable(line)
        };
        if is_header {
            continue;
        }
        if line.trim_start().starts_with(['"', '\'']) {
            let value = parse_value(line, no, &mut lines)?;
            if let Some((extra, _)) = lines.find(|(_, l)| !is_skippable(l)) {
                return Err(error(extra, "text after the closing quote"));
            }
            return Ok(Some(value));
        }
        // `line` is a subslice of `text`, so this is where it starts.
        let start = line.as_ptr() as usize - text.as_ptr() as usize;
        let raw = text[start..].trim();
        let mut value = Zeroizing::new(String::with_capacity(raw.len()));
        for (i, part) in raw.split("\r\n").enumerate() {
            if i > 0 {
                value.push('\n');
            }
            value.push_str(part);
        }
        return Ok(Some(value));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: &str) -> String {
        let mut out = String::new();
        push_value(&mut out, value);
        out
    }

    fn pairs(entries: Vec<(String, Zeroizing<String>)>) -> Vec<(String, String)> {
        entries
            .into_iter()
            .map(|(k, v)| (k, v.as_str().to_string()))
            .collect()
    }

    fn edit_buffer(text: &str) -> Vec<(String, String)> {
        pairs(parse_edit_buffer(text).unwrap())
    }

    fn env(text: &str) -> Vec<(String, String)> {
        pairs(parse_env(text).unwrap().pairs)
    }

    fn single(text: &str) -> Option<String> {
        parse_single(text).unwrap().map(|v| v.as_str().to_string())
    }

    fn owned(expected: &[(&str, &str)]) -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// Values that each need a different rule to survive the buffer.
    const AWKWARD: &[&str] = &[
        "",
        "plain",
        "has spaces inside",
        "-----BEGIN KEY-----\nMIIB\n-----END KEY-----\n",
        "line\r\nwindows",
        "\n\nleading and trailing newlines\n\n",
        "trailing spaces   ",
        "   leading spaces",
        "\"fully quoted\"",
        "'single quoted'",
        "say \"hi\" and 'bye'",
        "a=b==c=",
        "#starts with a hash",
        "inner # hash",
        "back\\slash\\",
        "tab\there",
        "nul\0and bell\x07",
        "nbsp\u{a0}and line sep\u{2028}",
        "\\u{41} looks like an escape",
    ];

    #[test]
    fn every_value_round_trips_through_a_bulk_buffer() {
        let mut buffer = String::from("# header\n\n");
        for (i, v) in AWKWARD.iter().enumerate() {
            buffer.push('K');
            buffer.push_str(&i.to_string());
            buffer.push('=');
            push_value(&mut buffer, v);
            buffer.push('\n');
        }
        let expected: Vec<(String, String)> = AWKWARD
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("K{i}"), (*v).to_string()))
            .collect();
        assert_eq!(edit_buffer(&buffer), expected);
        assert_eq!(env(&buffer), expected);
    }

    #[test]
    fn every_value_round_trips_through_a_single_key_buffer() {
        for v in AWKWARD {
            for header in ["# Editing KEY\n# more header\n", "# Editing KEY\n"] {
                let marked = format!("{header}{VALUE_MARKER}\n{}", encoded(v));
                assert_eq!(single(&marked).as_deref(), Some(*v), "{marked:?}");
                let unmarked = format!("{header}{}", encoded(v));
                assert_eq!(single(&unmarked).as_deref(), Some(*v), "{unmarked:?}");
            }
        }
    }

    #[test]
    fn after_the_marker_hash_lines_are_part_of_the_value() {
        let text =
            format!("# Editing KEY\n# notes\n{VALUE_MARKER}\n#!/bin/sh\n# say hi\necho hi\n");
        assert_eq!(
            single(&text).as_deref(),
            Some("#!/bin/sh\n# say hi\necho hi")
        );
        let text = format!("# Editing KEY\n{VALUE_MARKER}\n#Passw0rd\n");
        assert_eq!(single(&text).as_deref(), Some("#Passw0rd"));
        // Only blank lines after the marker: no value.
        assert_eq!(single(&format!("# h\n{VALUE_MARKER}\n\n")), None);
    }

    #[test]
    fn encoded_values_never_span_lines() {
        for v in AWKWARD {
            assert!(!encoded(v).contains(['\n', '\r']), "{v:?}");
        }
    }

    #[test]
    fn crlf_line_endings_do_not_change_values() {
        let text = format!("A=plain\r\nB={}\r\n", encoded("two\nlines"));
        assert_eq!(
            edit_buffer(&text),
            owned(&[("A", "plain"), ("B", "two\nlines")])
        );
    }

    #[test]
    fn a_quoted_pem_spans_lines_and_its_body_never_becomes_keys() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\nZm9vYmFy=\n-----END RSA PRIVATE KEY-----";
        let text = format!("API=x\nTLS_KEY=\"{pem}\"\nexport NEXT='a\nb'  # trailing comment\n");
        assert_eq!(
            env(&text),
            owned(&[("API", "x"), ("TLS_KEY", pem), ("NEXT", "a\nb")])
        );
        assert_eq!(parse_env(&text).unwrap().skipped, []);
    }

    #[test]
    fn literal_lines_inside_quotes_keep_their_whitespace() {
        let text = "K=\"a  \n  b \t\nc\"\n";
        assert_eq!(env(text), owned(&[("K", "a  \n  b \t\nc")]));
        assert_eq!(edit_buffer(text), owned(&[("K", "a  \n  b \t\nc")]));
        assert_eq!(single("# h\n\"a  \n  b\"\n").as_deref(), Some("a  \n  b"));
        assert_eq!(single("# h\n'a  \n  b'\n").as_deref(), Some("a  \n  b"));
    }

    #[test]
    fn bare_values_are_trimmed_and_taken_literally() {
        assert_eq!(
            edit_buffer("  K = a \"b\" 'c' \\n # not a comment  \nE=\n"),
            owned(&[("K", "a \"b\" 'c' \\n # not a comment"), ("E", "")])
        );
    }

    #[test]
    fn unknown_escapes_keep_their_backslash() {
        assert_eq!(
            env("P=\"C:\\path\\u{zz}\\u{d800}\\\"q\"\n"),
            owned(&[("P", "C:\\path\\u{zz}\\u{d800}\"q")])
        );
    }

    #[test]
    fn an_unclosed_quote_refuses_everything() {
        for text in [
            "A=1\nTLS=\"-----BEGIN-----\nMIIEow==\nB=2\n",
            "A='open\n",
            "A=\"hello'\n",
        ] {
            let err = parse_env(text).err().expect(text);
            assert!(err.reason.contains("never closed"), "{err}");
            assert!(parse_edit_buffer(text).is_err());
        }
        let err = parse_env("A=1\nB=\"x\nC=y\n").err().unwrap();
        assert_eq!(err.line, 2);
    }

    #[test]
    fn a_hash_in_a_bare_value_is_kept_and_noted() {
        let parsed = parse_env("A=pa ss #1\nB=\"q #2\"\nC=x#y\nD='z #3'\n").unwrap();
        assert_eq!(
            pairs(parsed.pairs),
            owned(&[
                ("A", "pa ss #1"),
                ("B", "q #2"),
                ("C", "x#y"),
                ("D", "z #3")
            ])
        );
        assert_eq!(parsed.hash_notices, [HashInBareValue { line: 1 }]);
        assert!(!parsed.hash_notices[0].to_string().contains("pa ss"));
    }

    #[test]
    fn import_skips_lines_by_number_and_murk_variables() {
        let parsed = parse_env(
            "MURK_KEY=a\nMURK_FOO=b\n1BAD=c\nnot a pair\n=empty\nexport GOOD=yes\nGOOD=again\n",
        )
        .unwrap();
        assert_eq!(pairs(parsed.pairs), owned(&[("GOOD", "again")]));
        assert_eq!(
            parsed.skipped,
            [
                Skipped::MurkVariable {
                    line: 1,
                    key: "MURK_KEY".into()
                },
                Skipped::MurkVariable {
                    line: 2,
                    key: "MURK_FOO".into()
                },
                Skipped::InvalidKey { line: 3 },
                Skipped::NotAnEntry { line: 4 },
                Skipped::InvalidKey { line: 5 },
            ]
        );
        assert_eq!(
            parsed.duplicates,
            [DuplicateKey {
                key: "GOOD".into(),
                previous_line: 6,
                line: 7
            }]
        );
    }

    #[test]
    fn an_empty_single_key_buffer_is_no_value() {
        assert_eq!(single("# only comments\n\n"), None);
        assert_eq!(single(""), None);
        assert_eq!(single("\"\"").as_deref(), Some(""));
    }

    #[test]
    fn malformed_edit_buffers_are_refused_with_the_line() {
        let refused = |text: &str, line: usize, reason: &str| {
            let err = parse_edit_buffer(text).unwrap_err();
            assert_eq!(err.line, line, "{text:?}: {err}");
            assert!(err.reason.contains(reason), "{text:?}: {err}");
        };
        refused("A=1\nno equals sign\n", 2, "expected KEY=VALUE");
        refused("1BAD=x\n", 1, "invalid key name");
        refused("A=1\nA=2\n", 2, "already set on line 1");
        refused("A=\"open\nstill open\n", 1, "never closed");
        refused("A=\"x\" trailing\n", 1, "after the closing quote");
    }

    #[test]
    fn an_unquoted_single_value_is_the_rest_of_the_buffer_verbatim() {
        let pasted = "# h\n\n-----BEGIN-----\r\n# kept: not a comment\n\nabc==\n-----END-----\n\n";
        assert_eq!(
            single(pasted).as_deref(),
            Some("-----BEGIN-----\n# kept: not a comment\n\nabc==\n-----END-----")
        );
        let err = parse_single("# h\n\"quoted\"\nmore\n").unwrap_err();
        assert_eq!(err.line, 3, "{err}");
    }

    proptest::proptest! {
        /// Whatever the value, the buffer reads back exactly what was written.
        #[test]
        fn any_value_round_trips(v in proptest::prelude::any::<String>()) {
            let mut buffer = String::from("# header\nA=");
            push_value(&mut buffer, &v);
            buffer.push_str("\nB=x\n");
            let parsed = edit_buffer(&buffer);
            proptest::prop_assert_eq!(&parsed[0].1, &v);
            proptest::prop_assert_eq!(&env(&buffer)[0].1, &v);
            proptest::prop_assert_eq!(single(&format!("# header\n{}\n", encoded(&v))), Some(v));
        }
    }

    #[test]
    fn errors_never_quote_the_input() {
        for text in [
            "A=\"SECRETTEXT\" SECRETTEXT\n",
            "A=\"SECRETTEXT\n",
            "SECRETTEXT\n",
        ] {
            if let Err(err) = parse_edit_buffer(text) {
                assert!(!err.to_string().contains("SECRETTEXT"), "{err}");
            }
            match parse_env(text) {
                Err(err) => assert!(!err.to_string().contains("SECRETTEXT"), "{err}"),
                Ok(import) => {
                    for s in import.skipped {
                        assert!(!s.to_string().contains("SECRETTEXT"), "{s}");
                    }
                }
            }
        }
    }
}
