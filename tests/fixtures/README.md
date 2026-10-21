# Test fixtures

Files the integration tests load with `include_str!`. Nothing here is a secret.

## Test-only keys

| File | What it is for |
|------|----------------|
| `v0_13_signed.test-only.key` | The age identity that wrote and signed `v0_13_signed.murk`. `tests/adversarial.rs` uses it to check that a vault from murk 0.13.0 still verifies and decrypts, and is upgraded on the next write. |
| `v0_13_duplicate_ssh.test-only.key` | The age identity ("alice") that wrote and signed `v0_13_duplicate_ssh.murk`. |
| `v0_13_duplicate_ssh_bob.test-only.key` | An OpenSSH ed25519 private key ("bob"), listed twice in `v0_13_duplicate_ssh.murk`. It wrote bob's own override there. `tests/cli_recipients.rs` uses both keys to check that such a vault still loads, that the next save lists bob once, and that revoking him by either spelling removes every copy. |

These keys are published on purpose and are not secret. No real vault lists their public keys (`age13kngcf8z5z2eql0qvk7d4pfz42tvl2swmwlwzap5zvphuy6yzf4qn5e8pe`, `age1jqsm85gqqeuq6tf20xem06z6kpjgkqygwvqny7r8uxad6zvzcvaqd7yfg8`, `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFMXjwwBOjk5V0rYD2Di9tLG0xGudp2h/CJHkhIPi6Y`) as recipients, and none must: anyone can read a vault encrypted to them. Do not use them, or copy them, for anything except these tests.

## Vaults

| File | What it is |
|------|------------|
| `v0_13_signed.murk` | A vault written by the murk 0.13.0 release binary: header version `2.0`, an older MAC scheme, and a signed-view-1 signature inside the meta. One secret, `API_KEY`, with the value `fixture-secret-value-0123`. |
| `v0_13_duplicate_ssh.murk` | A vault written by a murk 0.13.0 build (v0.13.0, `97e5002`): header version `2.0`, with bob's SSH key listed twice, once with its `bob@laptop` comment and once without (0.13 compared keys as exact strings). Secrets: `API_KEY` (shared `fixture-shared-value`, and bob's own override `bob-override`) and `SECOND` (`fixture-second-value`). |
