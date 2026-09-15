// aux-build:zeroize.rs

// `secret_field_missing_zeroize` is a verified allowlist keyed on the real
// murk_cli type paths (see `SECRET_FIELDS` in src/lib.rs). Declare this
// crate's own name as `murk_cli` so the fixture matches
// `murk_cli::types::Murk::values` exactly, without needing the real crate.
#![crate_name = "murk_cli"]

extern crate zeroize;

use std::collections::HashMap;

mod types {
    // Pass: `values` is correctly wrapped in `Zeroizing` — must produce no
    // warning.
    pub struct Murk {
        pub values: std::collections::HashMap<String, ::zeroize::Zeroizing<String>>,
    }
}

fn main() {
    let _ = types::Murk {
        values: HashMap::new(),
    };
}
