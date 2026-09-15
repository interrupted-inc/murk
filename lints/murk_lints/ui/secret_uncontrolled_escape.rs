// aux-build:zeroize.rs
extern crate zeroize;

use zeroize::Zeroizing;

fn main() {
    let v: Zeroizing<String> = Zeroizing::new("sekrit".to_string());

    // Pass: `Zeroizing<Z: Clone>` implements `Clone` directly and returns
    // another `Zeroizing` — nothing escapes.
    let safe_clone: Zeroizing<String> = v.clone();

    // Violation: explicit deref past the wrapper, then clone the bare value.
    let leaked_deref: String = (*v).clone();

    // Violation: `to_string()` always returns a bare, never-zeroized `String`.
    let leaked_to_string: String = v.to_string();

    println!(
        "{} {} {}",
        safe_clone.len(),
        leaked_deref.len(),
        leaked_to_string.len()
    );
}
