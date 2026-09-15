// aux-build:secrecy.rs

// Regression test: `secrecy::SecretBox` (what `age::secrecy::SecretString`
// resolves to) redacts its own `Debug` output, so deriving `Debug` over a
// struct that only holds one is safe and must not be flagged — unlike
// `Zeroizing`, which forwards `Debug` transparently. See the
// `SECRET_STRING_PATH` exclusion in `is_debug_leaking_wrapper_ty`.
extern crate secrecy;

use secrecy::SecretString;

#[derive(Debug)]
struct DiscoveredKey {
    secret_key: SecretString,
    pubkey: String,
}

fn main() {
    let k = DiscoveredKey {
        secret_key: SecretString::from("sekrit".to_string()),
        pubkey: "age1...".to_string(),
    };
    println!("{k:?}");
}
