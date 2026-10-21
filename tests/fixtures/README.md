# Test fixtures

Files the integration tests load with `include_str!`. Nothing here is a secret.

## Test-only keys

| File | What it is for |
|------|----------------|
| `v0_13_signed.test-only.key` | The age identity that wrote and signed `v0_13_signed.murk`. `tests/adversarial.rs` uses it to check that a vault from murk 0.13.0 still verifies and decrypts, and is upgraded on the next write. |

This key is published on purpose and is not secret. No real vault lists its public key (`age13kngcf8z5z2eql0qvk7d4pfz42tvl2swmwlwzap5zvphuy6yzf4qn5e8pe`) as a recipient, and none must: anyone can read a vault encrypted to it. Do not use it, or copy it, for anything except these tests.

## Vaults

| File | What it is |
|------|------------|
| `v0_13_signed.murk` | A vault written by the murk 0.13.0 release binary: header version `2.0`, an older MAC scheme, and a signed-view-1 signature inside the meta. One secret, `API_KEY`, with the value `fixture-secret-value-0123`. |
