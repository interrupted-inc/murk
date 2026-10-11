//! Edit buffer parsing and diff logic for `murk edit`.

use std::collections::BTreeMap;

/// Result of parsing an edited buffer and diffing against the original.
#[derive(Debug, PartialEq, Eq)]
pub struct EditDiff {
    /// Keys that were added (not in original).
    pub added: BTreeMap<String, String>,
    /// Keys that were updated (value changed).
    pub updated: BTreeMap<String, String>,
    /// Keys that were removed (in original but not in edited).
    pub removed: Vec<String>,
}

impl EditDiff {
    /// True if nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty()
    }
}

/// Malformed lines encountered during parsing.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseWarning {
    pub line: String,
    pub reason: &'static str,
}

/// Parse a KEY=VALUE edit buffer, filtering comments and blank lines.
/// Returns parsed entries and any warnings for malformed lines.
pub fn parse_edit_buffer(
    content: &str,
    validate_key: fn(&str) -> bool,
) -> (BTreeMap<String, String>, Vec<ParseWarning>) {
    let mut entries = BTreeMap::new();
    let mut warnings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            warnings.push(ParseWarning {
                line: trimmed.to_string(),
                reason: "malformed (no = sign)",
            });
            continue;
        };
        let k = k.trim();
        if !validate_key(k) {
            warnings.push(ParseWarning {
                line: trimmed.to_string(),
                reason: "invalid key name",
            });
            continue;
        }
        entries.insert(k.to_string(), v.to_string());
    }

    (entries, warnings)
}

/// Diff edited entries against the original set.
pub fn diff_edits(
    original: &BTreeMap<String, String>,
    edited: &BTreeMap<String, String>,
) -> EditDiff {
    let mut added = BTreeMap::new();
    let mut updated = BTreeMap::new();
    let mut removed = Vec::new();

    for (k, v) in edited {
        match original.get(k) {
            Some(old_v) if old_v == v => {} // unchanged
            Some(_) => {
                updated.insert(k.clone(), v.clone());
            }
            None => {
                added.insert(k.clone(), v.clone());
            }
        }
    }

    for k in original.keys() {
        if !edited.contains_key(k) {
            removed.push(k.clone());
        }
    }

    EditDiff {
        added,
        updated,
        removed,
    }
}

/// Parse a single-key edit result, stripping comment lines.
pub fn parse_single_value(content: &str) -> String {
    content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end_matches('\n')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_valid(_: &str) -> bool {
        true
    }

    fn alpha_only(k: &str) -> bool {
        k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    #[test]
    fn parse_basic() {
        let (entries, warnings) = parse_edit_buffer("FOO=bar\nBAZ=qux\n", always_valid);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["FOO"], "bar");
        assert_eq!(entries["BAZ"], "qux");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let input = "# comment\n\nFOO=bar\n# another\n";
        let (entries, _) = parse_edit_buffer(input, always_valid);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries["FOO"], "bar");
    }

    #[test]
    fn parse_warns_on_malformed() {
        let input = "FOO=bar\nbad line\nBAZ=qux\n";
        let (entries, warnings) = parse_edit_buffer(input, always_valid);
        assert_eq!(entries.len(), 2);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].line, "bad line");
    }

    #[test]
    fn parse_warns_on_invalid_key() {
        let input = "GOOD=yes\nbad-key=no\n";
        let (entries, warnings) = parse_edit_buffer(input, alpha_only);
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key("GOOD"));
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_value_with_equals() {
        let input = "URL=postgres://host:5432/db?sslmode=require\n";
        let (entries, _) = parse_edit_buffer(input, always_valid);
        assert_eq!(entries["URL"], "postgres://host:5432/db?sslmode=require");
    }

    #[test]
    fn diff_no_changes() {
        let orig: BTreeMap<_, _> = [("A".into(), "1".into())].into();
        let edited = orig.clone();
        let diff = diff_edits(&orig, &edited);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_added() {
        let orig: BTreeMap<String, String> = BTreeMap::new();
        let edited: BTreeMap<_, _> = [("NEW".into(), "val".into())].into();
        let diff = diff_edits(&orig, &edited);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.updated.is_empty());
        assert!(diff.removed.is_empty(), "{:?}", diff.removed);
    }

    #[test]
    fn diff_updated() {
        let orig: BTreeMap<_, _> = [("KEY".into(), "old".into())].into();
        let edited: BTreeMap<_, _> = [("KEY".into(), "new".into())].into();
        let diff = diff_edits(&orig, &edited);
        assert!(diff.added.is_empty());
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.updated["KEY"], "new");
        assert!(diff.removed.is_empty(), "{:?}", diff.removed);
    }

    #[test]
    fn diff_removed() {
        let orig: BTreeMap<_, _> = [("GONE".into(), "val".into())].into();
        let edited: BTreeMap<String, String> = BTreeMap::new();
        let diff = diff_edits(&orig, &edited);
        assert!(diff.added.is_empty());
        assert!(diff.updated.is_empty());
        assert_eq!(diff.removed, vec!["GONE"]);
    }

    #[test]
    fn diff_mixed() {
        let orig: BTreeMap<_, _> = [
            ("KEEP".into(), "same".into()),
            ("CHANGE".into(), "old".into()),
            ("DELETE".into(), "gone".into()),
        ]
        .into();
        let edited: BTreeMap<_, _> = [
            ("KEEP".into(), "same".into()),
            ("CHANGE".into(), "new".into()),
            ("ADD".into(), "fresh".into()),
        ]
        .into();
        let diff = diff_edits(&orig, &edited);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.removed, vec!["DELETE"]);
    }

    #[test]
    fn parse_single_value_strips_comments() {
        let input = "# Editing KEY\n# Save and quit.\nsecret_value";
        assert_eq!(parse_single_value(input), "secret_value");
    }

    #[test]
    fn parse_single_value_empty() {
        let input = "# comment only\n";
        assert_eq!(parse_single_value(input), "");
    }

    #[test]
    fn parse_single_value_multiline() {
        let input = "# header\nline1\nline2";
        assert_eq!(parse_single_value(input), "line1\nline2");
    }
}
