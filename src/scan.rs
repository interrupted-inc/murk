// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scan files for leaked secret values.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

/// A single scan finding: a secret key was found in a file.
#[derive(Debug)]
pub struct ScanFinding {
    /// The secret key name that was found.
    pub key: String,
    /// The file path where the value was found.
    pub path: String,
}

/// Scan files under the given paths for leaked secret values.
///
/// Skips hidden directories, `target/`, `node_modules/`, `.murk` files,
/// `.lock` files, and binary/unreadable files. Values shorter than
/// `min_length` are skipped to reduce false positives.
pub fn scan_for_leaks(
    paths: &[&str],
    secrets: &BTreeMap<String, Zeroizing<String>>,
    min_length: usize,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for base in paths {
        let walker = walkdir::WalkDir::new(base)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                if e.file_type().is_dir() && e.depth() > 0 {
                    return !name.starts_with('.') && name != "target" && name != "node_modules";
                }
                true
            });

        for entry in walker.flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();

            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(".murk") || name.ends_with(".lock") {
                continue;
            }

            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };

            for (key, value) in secrets {
                if value.len() < min_length {
                    continue;
                }
                if content.contains(value.as_str()) {
                    findings.push(ScanFinding {
                        key: key.clone(),
                        path: path.display().to_string(),
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn scan_finds_leaked_value() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.yml"),
            "db_password: supersecretvalue123",
        )
        .unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "DB_PASSWORD".into(),
            Zeroizing::new("supersecretvalue123".to_string()),
        );

        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "DB_PASSWORD");
    }

    #[test]
    fn scan_skips_short_values() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "abc").unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert("SHORT".into(), Zeroizing::new("abc".to_string()));

        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_murk_files() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("test.murk"), "supersecretvalue123").unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "KEY".into(),
            Zeroizing::new("supersecretvalue123".to_string()),
        );

        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_hidden_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let hidden = dir.path().join(".hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(hidden.join("leaked.txt"), "supersecretvalue123").unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "KEY".into(),
            Zeroizing::new("supersecretvalue123".to_string()),
        );

        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_no_secrets_returns_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "some content").unwrap();

        let secrets = BTreeMap::new();
        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_multiple_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("a.env"),
            "KEY1=secretvalue1\nKEY2=secretvalue2",
        )
        .unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert("K1".into(), Zeroizing::new("secretvalue1".to_string()));
        secrets.insert("K2".into(), Zeroizing::new("secretvalue2".to_string()));

        let findings = scan_for_leaks(&[dir.path().to_str().unwrap()], &secrets, 8);
        assert_eq!(findings.len(), 2);
    }
}
