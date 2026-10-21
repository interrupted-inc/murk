# Fuzz targets

`fuzz_targets/` holds the cargo-fuzz targets. `seeds/<target>/` holds the
committed starting inputs for each target: `.github/workflows/fuzz.yaml` copies
them into the corpus, and `.github/workflows/fuzz-coverage.yaml` measures
coverage from them. Every file in a seed directory is fed to the target as it
is, so these directories hold only inputs: keep notes here, not next to the
seeds.

```bash
cargo fuzz run fuzz_identity_parse fuzz/seeds/fuzz_identity_parse -- -runs=1000
```

## Test keys in the seeds

`seeds/fuzz_identity_parse/` contains private keys, so that the identity parser
is fuzzed from valid inputs. They are public test keys, not secrets:

- `test-only-age-key` is a throwaway age key made for this seed. No vault,
  test or recipient list uses it; its public key
  (`age1ll33jay5ppls8xx2cv5elfx7wlg27eq2ehjcdd85rxcvkd2la5lqtt6acr`) appears
  nowhere else in the repository but here.
- `test-only-openssh-key` is the published ssh-ed25519 test key from the rage test suite
  (comment `str4d@carbon`). murk's own tests use its public key as a recipient.

Never authorize either public key on a real vault.
