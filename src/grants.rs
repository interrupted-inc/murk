// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Short-lived agent grants: ephemeral, narrowly-scoped read credentials.
//!
//! A grant mints an ephemeral age identity, hands it to an agent, and gives it
//! read access to a fixed set of keys — without ever exposing the operator's own
//! key. The agent's pubkey is a vault recipient (so it can verify integrity and
//! decrypt the meta blob) but is excluded from the shared "everyone" layer; its
//! access is exactly the set of scoped ciphertexts encrypted to it. Grant
//! metadata (scope, TTL, issuer) lives in the encrypted meta (see
//! [`crate::types::Meta::grants`]) and is covered by the keyed MAC, so it cannot
//! be tampered with undetected.
//!
//! The TTL is enforced at read time by the murk binary: an expired grant fails
//! closed at every entry point (CLI, MCP, bindings — see
//! [`crate::enforce_agent_policy`]). That is a guardrail, not cryptography:
//! age keys cannot self-destruct and old `.murk` versions stay readable in
//! git, so a leaked grant key works against history until `agent revoke` +
//! rotate. `agent ls` flags grants that are past their TTL.

use chrono::{DateTime, Duration, Utc};

use crate::error::MurkError;
use crate::types;

/// Validate a short identifier: 1–64 chars of `[A-Za-z0-9_-]`. Shared by grant
/// and group name validation (`noun` customizes the error text, e.g. "grant"
/// or "group").
pub(crate) fn validate_short_name(name: &str, noun: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{noun} name cannot be empty"));
    }
    if name.len() > 64 {
        return Err(format!("{noun} name too long (max 64 characters)"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "invalid {noun} name \"{}\" — use letters, digits, dashes, underscores",
            crate::validate::show(name)
        ));
    }
    Ok(())
}

/// Validate a grant name: 1–64 chars of `[A-Za-z0-9_-]`.
pub fn validate_grant_name(name: &str) -> Result<(), MurkError> {
    validate_short_name(name, "grant").map_err(MurkError::Grant)
}

/// Longest accepted grant TTL. Grants are meant to be short-lived; this bound
/// also keeps `issued_at + ttl` far inside chrono's date range.
const MAX_TTL_DAYS: i64 = 365;

/// Parse a TTL like `90s`, `30m`, `2h`, or `7d` into a [`Duration`]. A bare
/// number is rejected — the unit must be explicit so `2` is never ambiguous.
/// TTLs longer than [`MAX_TTL_DAYS`] are refused.
pub fn parse_ttl(s: &str) -> Result<Duration, MurkError> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| MurkError::Grant(format!("ttl \"{s}\" needs a unit: s, m, h, or d")))?,
    );
    let too_long =
        || MurkError::Grant(format!("ttl \"{s}\" is too long — at most {MAX_TTL_DAYS}d"));
    let n: i64 = num.parse().map_err(|e: std::num::ParseIntError| {
        if matches!(e.kind(), std::num::IntErrorKind::PosOverflow) {
            too_long()
        } else {
            MurkError::Grant(format!("invalid ttl \"{s}\" — use e.g. 30m, 2h, 7d"))
        }
    })?;
    if n <= 0 {
        return Err(MurkError::Grant("ttl must be positive".into()));
    }
    let dur = match unit {
        "s" => Duration::try_seconds(n),
        "m" => Duration::try_minutes(n),
        "h" => Duration::try_hours(n),
        "d" => Duration::try_days(n),
        other => {
            return Err(MurkError::Grant(format!(
                "unknown ttl unit \"{other}\" — use s, m, h, or d"
            )));
        }
    };
    match dur {
        Some(d) if d <= Duration::days(MAX_TTL_DAYS) => Ok(d),
        _ => Err(too_long()),
    }
}

/// Create an agent grant in the working state. The caller mints the ephemeral
/// identity, adds `agent_pubkey` to the vault recipients, and registers its
/// display name *before* calling this. Encrypts a private copy of each scope
/// key's shared value to the agent and records the grant metadata.
///
/// Errors if the name is invalid or already used, the scope is empty, or a scope
/// key has no shared value the operator can read (e.g. an unknown key, or one
/// that is group/scoped-only). Returns the recorded [`types::GrantEntry`].
pub fn create_grant(
    current: &mut types::Murk,
    name: &str,
    agent_pubkey: &str,
    scope: &[String],
    issuer_pubkey: &str,
    issued_at: DateTime<Utc>,
    ttl: Duration,
) -> Result<types::GrantEntry, MurkError> {
    validate_grant_name(name)?;
    if current.grants.contains_key(name) {
        return Err(MurkError::Grant(format!(
            "grant already exists: {name} — pass --renew to replace it"
        )));
    }
    // One key, one grant: a pubkey shared across grants would make read-time
    // expiry ambiguous (which TTL applies?), so refuse before mutating anything.
    if let Some(existing) = current
        .grants
        .iter()
        .find_map(|(n, g)| (g.pubkey == agent_pubkey).then_some(n))
    {
        return Err(MurkError::Grant(format!(
            "agent key is already bound to grant {existing} — mint a fresh identity per grant"
        )));
    }
    if scope.is_empty() {
        return Err(MurkError::Grant(
            "a grant needs at least one key — pass --only KEY".into(),
        ));
    }

    // Sort + de-dup so the scope is deterministic (it's MAC-covered) and a key
    // passed twice doesn't double-encrypt.
    let mut scope_sorted = scope.to_vec();
    scope_sorted.sort();
    scope_sorted.dedup();

    for key in &scope_sorted {
        let value = current.values.get(key).ok_or_else(|| {
            MurkError::Grant(format!(
                "cannot grant {key}: no shared value to grant (unknown key, or it is group/scoped-only)"
            ))
        })?;
        current
            .private
            .entry(key.clone())
            .or_default()
            .insert(agent_pubkey.to_string(), value.clone());
    }

    let entry = types::GrantEntry {
        pubkey: agent_pubkey.to_string(),
        scope: scope_sorted,
        issued_at: fmt_ts(issued_at),
        expires_at: fmt_ts(issued_at + ttl),
        issuer: issuer_pubkey.to_string(),
    };
    current.grants.insert(name.to_string(), entry.clone());
    Ok(entry)
}

/// Remove a grant by name, returning its metadata so the caller can revoke the
/// agent recipient (which clears its private entries) and rotate the scope.
pub fn remove_grant(current: &mut types::Murk, name: &str) -> Result<types::GrantEntry, MurkError> {
    current
        .grants
        .remove(name)
        .ok_or_else(|| MurkError::Grant(format!("grant not found: {name}")))
}

/// Format a timestamp the same way as the rest of the vault (ISO-8601 UTC,
/// second precision).
fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn murk_with(keys: &[(&str, &str)]) -> types::Murk {
        let mut m = types::Murk::default();
        for (k, v) in keys {
            m.values
                .insert((*k).to_string(), Zeroizing::new((*v).to_string()));
        }
        m
    }

    #[test]
    fn parse_ttl_units() {
        assert_eq!(parse_ttl("90s").unwrap(), Duration::seconds(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::hours(2));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::days(7));
    }

    #[test]
    fn parse_ttl_rejects_bad_input() {
        assert!(parse_ttl("2").is_err()); // no unit
        assert!(parse_ttl("0h").is_err()); // not positive
        assert!(parse_ttl("-1h").is_err()); // sign is not a digit
        assert!(parse_ttl("2y").is_err()); // unknown unit
        assert!(parse_ttl("abc").is_err());
    }

    #[test]
    fn parse_ttl_caps_length_at_the_boundary() {
        assert_eq!(parse_ttl("365d").unwrap(), Duration::days(365));
        assert_eq!(parse_ttl("8760h").unwrap(), Duration::days(365));
        assert!(parse_ttl("366d").is_err());
        assert!(parse_ttl("8761h").is_err());
    }

    #[test]
    fn validate_grant_name_rules() {
        assert!(validate_grant_name("codex-debug").is_ok());
        assert!(validate_grant_name("").is_err());
        assert!(validate_grant_name("has space").is_err());
        // Boundary: 64 chars is the max accepted; 65 is rejected.
        assert!(validate_grant_name(&"x".repeat(64)).is_ok());
        assert!(validate_grant_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn name_errors_escape_control_characters() {
        // Group names reach this validator from CLI args and from vaults.
        for err in [
            validate_grant_name("\u{1b}[31mx").unwrap_err().to_string(),
            crate::groups::validate_group_name("\u{1b}[31mx")
                .unwrap_err()
                .to_string(),
        ] {
            assert!(err.contains("\\u{1b}[31mx"), "{err:?}");
            assert!(
                !err.chars().any(char::is_control),
                "raw control char in {err:?}"
            );
        }
    }

    #[test]
    fn create_grant_encrypts_scope_and_records_metadata() {
        let mut current = murk_with(&[("STRIPE_KEY", "sk_live_1"), ("OTHER", "v")]);
        let issued = DateTime::parse_from_rfc3339("2026-06-16T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = create_grant(
            &mut current,
            "codex",
            "age1agent",
            &["STRIPE_KEY".into()],
            "age1owner",
            issued,
            Duration::hours(2),
        )
        .unwrap();

        assert_eq!(entry.pubkey, "age1agent");
        assert_eq!(entry.scope, vec!["STRIPE_KEY".to_string()]);
        assert_eq!(entry.issued_at, "2026-06-16T00:00:00Z");
        assert_eq!(entry.expires_at, "2026-06-16T02:00:00Z");
        assert_eq!(entry.issuer, "age1owner");

        // A private copy is staged for the agent on the granted key only.
        assert_eq!(
            current.private["STRIPE_KEY"]["age1agent"].as_str(),
            "sk_live_1"
        );
        assert!(!current.private.contains_key("OTHER"));
        assert!(current.grants.contains_key("codex"));
    }

    #[test]
    fn create_grant_rejects_unknown_key() {
        let mut current = murk_with(&[("STRIPE_KEY", "sk")]);
        let issued = Utc::now();
        let err = create_grant(
            &mut current,
            "codex",
            "age1agent",
            &["NOPE".into()],
            "age1owner",
            issued,
            Duration::hours(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("NOPE"));
        // Nothing recorded on failure.
        assert!(current.grants.is_empty());
    }

    #[test]
    fn create_grant_rejects_pubkey_already_bound_to_another_grant() {
        let mut current = murk_with(&[("STRIPE_KEY", "sk"), ("DB_URL", "pg")]);
        let issued = Utc::now();
        create_grant(
            &mut current,
            "codex",
            "age1agent",
            &["STRIPE_KEY".into()],
            "age1owner",
            issued,
            Duration::hours(1),
        )
        .unwrap();

        let err = create_grant(
            &mut current,
            "other-bot",
            "age1agent",
            &["DB_URL".into()],
            "age1owner",
            issued,
            Duration::hours(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already bound to grant codex"));
        // Refused before mutating: no private copy staged for the second scope.
        assert!(!current.private.contains_key("DB_URL"));
        assert!(!current.grants.contains_key("other-bot"));
    }

    #[test]
    fn create_grant_rejects_duplicate_name() {
        let mut current = murk_with(&[("K", "v")]);
        let issued = Utc::now();
        create_grant(
            &mut current,
            "dup",
            "age1a",
            &["K".into()],
            "age1owner",
            issued,
            Duration::hours(1),
        )
        .unwrap();
        assert!(
            create_grant(
                &mut current,
                "dup",
                "age1b",
                &["K".into()],
                "age1owner",
                issued,
                Duration::hours(1),
            )
            .is_err()
        );
    }

    #[test]
    fn remove_grant_returns_metadata() {
        let mut current = murk_with(&[("K", "v")]);
        create_grant(
            &mut current,
            "g",
            "age1a",
            &["K".into()],
            "age1owner",
            Utc::now(),
            Duration::hours(1),
        )
        .unwrap();
        let removed = remove_grant(&mut current, "g").unwrap();
        assert_eq!(removed.pubkey, "age1a");
        assert!(current.grants.is_empty());
        assert!(remove_grant(&mut current, "g").is_err());
    }
}
