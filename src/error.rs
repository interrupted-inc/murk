//! Unified error type for the murk library.

use crate::crypto::CryptoError;
use crate::github::GitHubError;
use crate::vault::VaultError;

/// Top-level error type for murk operations.
#[derive(Debug)]
pub enum MurkError {
    /// Vault file I/O or parsing.
    Vault(VaultError),
    /// Cryptographic operation (encrypt/decrypt/key parse).
    Crypto(CryptoError),
    /// Integrity check failed (MAC mismatch, tampering).
    Integrity(String),
    /// Key resolution or environment configuration.
    Key(String),
    /// Recipient management (authorize, revoke).
    Recipient(String),
    /// Secret management (add, remove, describe).
    Secret(String),
    /// Recipient group management (create, add/remove member, assign).
    Group(String),
    /// Agent grant management (grant, revoke, list).
    Grant(String),
    /// Agent access policy violation or management error.
    Policy(String),
    /// External editor/client MCP config file is malformed (`agent connect`/`disconnect`).
    Config(String),
    /// GitHub key fetch.
    GitHub(GitHubError),
    /// General I/O.
    Io(std::io::Error),
}

impl std::fmt::Display for MurkError {
    #[allow(clippy::match_same_arms)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MurkError::Vault(e) => write!(f, "{e}"),
            MurkError::Crypto(e) => write!(f, "{e}"),
            MurkError::Integrity(msg) => write!(f, "integrity check failed: {msg}"),
            MurkError::Key(msg) => write!(f, "{msg}"),
            MurkError::Recipient(msg) => write!(f, "{msg}"),
            MurkError::Secret(msg) => write!(f, "{msg}"),
            MurkError::Group(msg) => write!(f, "{msg}"),
            MurkError::Grant(msg) => write!(f, "{msg}"),
            MurkError::Policy(msg) => write!(f, "{msg}"),
            MurkError::Config(msg) => write!(f, "{msg}"),
            MurkError::GitHub(e) => write!(f, "{e}"),
            MurkError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for MurkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MurkError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VaultError> for MurkError {
    fn from(e: VaultError) -> Self {
        MurkError::Vault(e)
    }
}

impl From<CryptoError> for MurkError {
    fn from(e: CryptoError) -> Self {
        MurkError::Crypto(e)
    }
}

impl From<GitHubError> for MurkError {
    fn from(e: GitHubError) -> Self {
        MurkError::GitHub(e)
    }
}

impl From<std::io::Error> for MurkError {
    fn from(e: std::io::Error) -> Self {
        MurkError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_integrity() {
        let e = MurkError::Integrity("mac mismatch".into());
        assert_eq!(e.to_string(), "integrity check failed: mac mismatch");
    }

    #[test]
    fn display_key() {
        let e = MurkError::Key("MURK_KEY not set".into());
        assert_eq!(e.to_string(), "MURK_KEY not set");
    }

    #[test]
    fn display_recipient() {
        let e = MurkError::Recipient("not found".into());
        assert_eq!(e.to_string(), "not found");
    }

    #[test]
    fn display_secret() {
        let e = MurkError::Secret("invalid".into());
        assert_eq!(e.to_string(), "invalid");
    }

    #[test]
    fn display_config() {
        let e = MurkError::Config("config is not a JSON object".into());
        assert_eq!(e.to_string(), "config is not a JSON object");
    }

    #[test]
    fn display_io() {
        let e = MurkError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(e.to_string().contains("I/O error"));
    }

    #[test]
    fn from_vault_error() {
        let ve = VaultError::Parse("bad json".into());
        let e: MurkError = ve.into();
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn from_crypto_error() {
        let ce = CryptoError::Decrypt("failed".into());
        let e: MurkError = ce.into();
        assert!(e.to_string().contains("failed"));
    }

    #[test]
    fn from_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e: MurkError = io.into();
        assert!(e.to_string().contains("denied"));
    }

    #[test]
    fn error_source_io() {
        let e = MurkError::Io(std::io::Error::other("test"));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn error_source_non_io() {
        let e = MurkError::Key("test".into());
        assert!(std::error::Error::source(&e).is_none());
    }
}
