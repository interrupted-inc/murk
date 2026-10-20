//! GitHub SSH key fetching for `murk authorize github:username`.

use std::fmt::Write;
use std::time::Duration;

use base64::Engine;

use crate::crypto::{self, MurkRecipient};

/// Errors that can occur when fetching GitHub SSH keys.
#[derive(Debug)]
pub enum GitHubError {
    /// HTTP request failed.
    Fetch(String),
    /// No supported SSH keys found for this user.
    NoKeys(String),
}

impl std::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubError::Fetch(msg) => write!(f, "GitHub key fetch failed: {msg}"),
            GitHubError::NoKeys(user) => write!(
                f,
                "no supported SSH keys found for GitHub user {user} (need ed25519 or rsa)"
            ),
        }
    }
}

/// GitHub usernames: alphanumeric + hyphens, 1-39 chars (no path traversal).
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 39
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Fetch all SSH public keys for a GitHub user.
///
/// Hits `https://github.com/{username}.keys` (no auth needed) and parses
/// each line as an SSH public key. Returns all valid keys as recipients
/// paired with the key type string (e.g., "ssh-ed25519").
///
/// Filters to supported types only (ed25519 and rsa). Unsupported key
/// types (ecdsa, sk-ssh-*) are silently skipped.
pub fn fetch_keys(username: &str) -> Result<Vec<(MurkRecipient, String)>, GitHubError> {
    if !is_valid_username(username) {
        return Err(GitHubError::Fetch(format!(
            "invalid GitHub username: {username}"
        )));
    }

    let url = format!("https://github.com/{username}.keys");

    // Defense-in-depth against a compromised or MITM'd upstream:
    // - max_redirects(0) refuses redirects so we cannot be steered to an
    //   internal host or cloud metadata service via a 30x response.
    // - timeout_global caps the whole exchange.
    // - proxy(None) ignores HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars. ureq v3
    //   honours them by default via Config::default(); a malicious proxy in the
    //   user's environment could otherwise MITM key fetches before TOFU pinning
    //   takes effect on first authorize.
    // - ureq v3 does not retry transient errors by default, so a network
    //   failure fails closed without quietly hammering the network.
    // - body limit caps memory; GitHub allows up to 256 keys per user, ~2 KB
    //   each in the worst case, so 1 MB is generous but bounded.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .proxy(None)
        .build()
        .into();

    let body = agent
        .get(&url)
        .call()
        .map_err(|e| GitHubError::Fetch(format!("{url}: {e}")))?
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|e| GitHubError::Fetch(format!("reading response: {e}")))?;

    if body.trim().is_empty() {
        return Err(GitHubError::NoKeys(username.into()));
    }

    parse_github_keys(&body, username)
}

/// Parse SSH keys from a GitHub `.keys` response body.
///
/// Filters to ed25519 and rsa only. Normalizes by stripping comments.
pub fn parse_github_keys(
    body: &str,
    username: &str,
) -> Result<Vec<(MurkRecipient, String)>, GitHubError> {
    let mut keys = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let key_type = line.split_whitespace().next().unwrap_or("");

        if key_type != "ssh-ed25519" && key_type != "ssh-rsa" {
            continue;
        }

        if let Ok(recipient) = crypto::parse_recipient(line) {
            let normalized = match &recipient {
                MurkRecipient::Ssh(r) => r.to_string(),
                MurkRecipient::Age(_) => unreachable!("SSH key parsed as age key"),
                MurkRecipient::Plugin(_) => unreachable!("SSH key parsed as plugin recipient"),
            };
            keys.push((recipient, normalized));
        }
    }

    if keys.is_empty() {
        return Err(GitHubError::NoKeys(username.into()));
    }

    Ok(keys)
}

/// Compute a SHA-256 fingerprint of an SSH public key string.
///
/// Returns a string like `SHA256:abc123...` (base64, no padding).
pub fn fingerprint(key_string: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(key_string.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{encoded}")
}

/// Check fetched keys against pinned fingerprints.
///
/// Returns Ok(()) if pins match or no pins exist (TOFU).
/// Returns Err with a description of what changed if pins don't match.
pub fn check_pins(
    username: &str,
    fetched_keys: &[(MurkRecipient, String)],
    pinned: &[String],
) -> Result<(), String> {
    if pinned.is_empty() {
        return Ok(()); // First use — trust on first use.
    }

    let fetched_fps: Vec<String> = fetched_keys.iter().map(|(_, k)| fingerprint(k)).collect();

    // Added keys are present in the fetch but not pinned. We still hold the full
    // key string, so label each with its SSH type — that lets a user tell a
    // routine rotation (ed25519 added) from a suspicious downgrade (ssh-rsa
    // added) at a glance.
    let mut added: Vec<String> = Vec::new();
    for ((_, key), fp) in fetched_keys.iter().zip(&fetched_fps) {
        if !pinned.contains(fp) {
            added.push(format!("{} {fp}", key_type_label(key)));
        }
    }
    // Removed keys were pinned but are no longer fetched. We only stored the
    // fingerprint, not the original key string, so these stay unlabeled.
    let mut removed: Vec<&str> = Vec::new();
    for fp in pinned {
        if !fetched_fps.contains(fp) {
            removed.push(fp);
        }
    }

    if added.is_empty() && removed.is_empty() {
        return Ok(());
    }

    let mut msg = format!("github:{username} keys changed since last authorization\n");
    for entry in &added {
        let _ = writeln!(msg, "  + {entry}");
    }
    for fp in &removed {
        let _ = writeln!(msg, "  - {fp}");
    }
    msg.push_str("use --force to accept the new keys");
    Err(msg)
}

/// Classify an SSH key type for human-readable display.
///
/// Returns a short label like "ssh-ed25519" or "ssh-rsa" from
/// the full key string.
pub fn key_type_label(key_string: &str) -> &str {
    key_string.split_whitespace().next().unwrap_or("ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_label_ed25519() {
        assert_eq!(
            key_type_label("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."),
            "ssh-ed25519"
        );
    }

    #[test]
    fn key_type_label_rsa() {
        assert_eq!(key_type_label("ssh-rsa AAAAB3NzaC1yc2EAAAA..."), "ssh-rsa");
    }

    #[test]
    fn key_type_label_empty() {
        assert_eq!(key_type_label(""), "ssh");
    }

    const TEST_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI7KsDGxx+I8XZQwtbgoEYDfuNd9fQ4MzcHHUmtIau9";

    #[test]
    fn parse_keys_ed25519() {
        let body = format!("{TEST_ED25519_KEY}\n");
        let keys = parse_github_keys(&body, "testuser").unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].1.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn parse_keys_skips_ecdsa() {
        let body = "ecdsa-sha2-nistp256 AAAAE2VjZHNh...\n";
        let result = parse_github_keys(body, "testuser");
        assert!(result.is_err());
    }

    #[test]
    fn parse_keys_skips_blank_lines() {
        let body = format!("\n\n{TEST_ED25519_KEY}\n\n");
        let keys = parse_github_keys(&body, "testuser").unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn parse_keys_empty_body() {
        let result = parse_github_keys("", "testuser");
        assert!(result.is_err());
    }

    #[test]
    fn parse_keys_strips_comment() {
        let body = format!("{TEST_ED25519_KEY} user@host\n");
        let keys = parse_github_keys(&body, "testuser").unwrap();
        assert!(!keys[0].1.contains("user@host"));
    }

    #[test]
    fn fetch_rejects_empty_username() {
        let result = fetch_keys("");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid GitHub username")
        );
    }

    #[test]
    fn fetch_rejects_long_username() {
        let long = "a".repeat(40);
        let result = fetch_keys(&long);
        assert!(result.is_err());
    }

    #[test]
    fn fetch_rejects_path_traversal() {
        let result = fetch_keys("../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn github_error_display() {
        let e = GitHubError::Fetch("connection refused".into());
        assert!(e.to_string().contains("connection refused"));

        let e = GitHubError::NoKeys("alice".into());
        assert!(e.to_string().contains("alice"));
    }

    // ── check_pins tests ──

    #[test]
    fn check_pins_tofu_accepts_any_keys() {
        let body = format!("{TEST_ED25519_KEY}\n");
        let keys = parse_github_keys(&body, "alice").unwrap();
        assert!(check_pins("alice", &keys, &[]).is_ok());
    }

    #[test]
    fn check_pins_matching_passes() {
        let body = format!("{TEST_ED25519_KEY}\n");
        let keys = parse_github_keys(&body, "alice").unwrap();
        let pins: Vec<String> = keys.iter().map(|(_, k)| fingerprint(k)).collect();
        assert!(check_pins("alice", &keys, &pins).is_ok());
    }

    #[test]
    fn check_pins_detects_added_key() {
        let body = format!("{TEST_ED25519_KEY}\n");
        let keys = parse_github_keys(&body, "alice").unwrap();
        // Pinned list is empty (but not TOFU — simulate having had a different key).
        let old_pins = vec!["SHA256:fakefakefake".to_string()];
        let result = check_pins("alice", &keys, &old_pins);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        // Added keys are labeled with their SSH type; removed ones are not
        // (only the fingerprint was pinned).
        assert!(msg.contains("+ ssh-ed25519 SHA256:"), "msg: {msg}");
        assert!(msg.contains("- SHA256:fakefakefake"), "msg: {msg}");
    }

    #[test]
    fn check_pins_detects_removed_key() {
        // No keys fetched, but we had a pin.
        let old_pins = vec!["SHA256:oldkey".to_string()];
        let result = check_pins("alice", &[], &old_pins);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("- SHA256:oldkey"));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let fp1 = fingerprint(TEST_ED25519_KEY);
        let fp2 = fingerprint(TEST_ED25519_KEY);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
    }
}
