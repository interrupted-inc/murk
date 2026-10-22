// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A vault path inside a private, empty `HOME`, set up once per process.
///
/// The driver reads this machine's trust pin (under `$HOME`) and resolves a
/// key from the environment or `$HOME`. Pointing `HOME` at an empty temp dir
/// and dropping the key variables keeps a local run away from the developer's
/// real pins and keys, while the pin lookup itself still runs (and finds none),
/// unlike `MURK_NO_SIGNER_PIN`, which would skip it.
static VAULT_PATH: LazyLock<String> = LazyLock::new(|| {
    let home = std::env::temp_dir().join(format!("murk-fuzz-merge-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create fuzz HOME");
    // SAFETY: set once, before the first merge, while no other thread runs.
    unsafe {
        std::env::set_var("HOME", &home);
        for var in [
            "MURK_KEY",
            "MURK_KEY_FILE",
            "MURK_NO_SIGNER_PIN",
            "USERPROFILE",
        ] {
            std::env::remove_var(var);
        }
    }
    home.join(".murk").to_string_lossy().into_owned()
});

fuzz_target!(|data: &[u8]| {
    let vault_path = VAULT_PATH.as_str();
    // Split fuzzer input into three chunks for base/ours/theirs.
    if data.len() < 3 {
        return;
    }
    let chunk = data.len() / 3;
    let base = std::str::from_utf8(&data[..chunk]).unwrap_or("");
    let ours = std::str::from_utf8(&data[chunk..chunk * 2]).unwrap_or("");
    let theirs = std::str::from_utf8(&data[chunk * 2..]).unwrap_or("");

    // Merge driver must never panic on arbitrary vault-like input.
    let _ = murk_cli::run_merge_driver(base, ours, theirs, vault_path);
});
