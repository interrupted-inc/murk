// aux-build:zeroize.rs
extern crate zeroize;

use zeroize::Zeroizing;

// Violation: derived `Debug` forwards the wrapped plaintext transparently.
#[derive(Debug)]
struct LeakyToken {
    token: Zeroizing<String>,
}

// Violation: manual impl, but still passes the secret field straight through
// `.field(name, value)`.
struct DirectToken {
    token: Zeroizing<String>,
}

impl std::fmt::Debug for DirectToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectToken")
            .field("token", &self.token)
            .finish()
    }
}

// Pass: manual impl redacts the secret field instead of passing it through.
struct RedactedToken {
    token: Zeroizing<String>,
}

impl std::fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactedToken")
            .field("token", &"<redacted>")
            .finish()
    }
}

fn main() {
    let a = LeakyToken {
        token: Zeroizing::new("sekrit-a".to_string()),
    };
    let b = DirectToken {
        token: Zeroizing::new("sekrit-b".to_string()),
    };
    let c = RedactedToken {
        token: Zeroizing::new("sekrit-c".to_string()),
    };
    println!("{a:?} {b:?} {c:?}");
}
