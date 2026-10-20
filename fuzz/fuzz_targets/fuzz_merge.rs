// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split fuzzer input into three chunks for base/ours/theirs.
    if data.len() < 3 {
        return;
    }
    let chunk = data.len() / 3;
    let base = std::str::from_utf8(&data[..chunk]).unwrap_or("");
    let ours = std::str::from_utf8(&data[chunk..chunk * 2]).unwrap_or("");
    let theirs = std::str::from_utf8(&data[chunk * 2..]).unwrap_or("");

    // Merge driver must never panic on arbitrary vault-like input.
    let _ = murk_cli::run_merge_driver(base, ours, theirs);
});
