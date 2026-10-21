// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node.js/TypeScript bindings for murk via napi-rs.
//!
//! ```typescript
//! import { load, get, exportAll, hasIdentity } from '@interrupted/murk-secrets'
//!
//! const vault = load()              // reads MURK_KEY from env, .murk from cwd
//! vault.get('DATABASE_URL')         // decrypt a single value
//! vault.export()                    // Record<string, string> of all secrets
//! get('DATABASE_URL')               // one-liner convenience
//! vault.add('NEW_KEY', 'value')     // store a secret (encrypted to everyone)
//! ```
//!
//! Every call that reads the vault applies the same trust rules as the CLI
//! (`murk_cli::load_vault`): a vault this machine does not trust throws an
//! `Error` with `code` `'MURK_TRUST'` and the message the CLI prints.

use std::collections::HashMap;
use std::path::Path;

use murk_cli::{MurkError, SecretTier};
use napi_derive::napi;

/// `code` of the error thrown when the vault itself is refused: not trusted
/// on this machine, or tampered with.
const TRUST_ERROR: &str = "MURK_TRUST";

/// `code` of every other error (napi's default).
const GENERIC_ERROR: &str = "GenericFailure";

/// What the bindings throw: an `Error` whose `code` is a string we choose.
type Result<T, E = napi::Error<String>> = std::result::Result<T, E>;

fn fail(reason: impl std::fmt::Display) -> napi::Error<String> {
    napi::Error::new(GENERIC_ERROR.to_string(), reason)
}

/// A refusal of the vault (trust or integrity) gets [`TRUST_ERROR`].
fn murk_error(e: MurkError) -> napi::Error<String> {
    let code = match e {
        MurkError::Trust(_) | MurkError::Integrity(_) => TRUST_ERROR,
        _ => GENERIC_ERROR,
    };
    napi::Error::new(code.to_string(), e)
}

/// A loaded and decrypted murk vault.
#[napi]
pub struct Vault {
    vault: murk_cli::types::Vault,
    murk: murk_cli::types::Murk,
    pubkey: String,
    path: String,
}

/// Options for [`Vault::add`]. All fields are optional; an omitted `tier`
/// keeps an existing key in its tier and makes a new key shared (`everyone`).
#[napi(object)]
#[derive(Default)]
pub struct AddOptions {
    /// `"everyone"`, `"me"` (personal scoped), or a group name. Omit it to keep
    /// an existing key where it is; a new key is then shared (`everyone`).
    pub tier: Option<String>,
    /// Human-readable description recorded in the vault schema.
    pub desc: Option<String>,
    /// Tags recorded on the key — the unit the agent allow-tag policy gates on.
    pub tags: Option<Vec<String>>,
}

/// Options for [`Vault::describe`]. All fields are optional.
#[napi(object)]
#[derive(Default)]
pub struct DescribeOptions {
    /// Tags to set on the key (replaces existing tags when non-empty).
    pub tags: Option<Vec<String>>,
    /// Example value recorded in the schema (for `.env.example`-style docs).
    pub example: Option<String>,
}

#[napi]
impl Vault {
    /// Get a single decrypted secret value. Resolution order: a personal scoped
    /// override, then a named-group value we can read, then the shared value.
    ///
    /// Internally, vault state stores values in `Zeroizing<String>` so plaintext
    /// is wiped from memory when dropped. Crossing the napi boundary into a
    /// JavaScript `String` requires copying the plaintext into a regular Rust
    /// `String`; the V8 garbage collector owns it from there and zeroize cannot
    /// follow. This is a known leak in the JS bindings — see THREAT_MODEL.md.
    ///
    /// When the loaded identity is a granted agent, the vault's agent policy is
    /// enforced before the value is returned — the same gate the CLI applies at
    /// `agent exec`. Throws if policy forbids the key. For an operator identity
    /// this is a no-op.
    #[napi]
    pub fn get(&self, key: String) -> Result<Option<String>> {
        let value = murk_cli::get_secret(&self.murk, &key, &self.pubkey).map(str::to_string);
        // Only enforce when there is a value to hand back: a key the agent
        // cannot decrypt is already inaccessible, so policy is moot.
        if value.is_some() {
            murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &[key])
                .map_err(fail)?;
        }
        Ok(value)
    }

    /// Export all secrets as an object. Scoped values override shared values.
    ///
    /// See `get` for the zeroize caveat — the returned `HashMap` holds plain
    /// `String` plaintext, not `Zeroizing<String>`.
    ///
    /// For a granted agent, the vault's agent policy is enforced over the full
    /// key set first (mirroring `murk agent exec`): if any resolvable key is
    /// outside the policy, the whole export throws rather than returning a
    /// partial object. For an operator identity this is a no-op.
    #[napi]
    // Controlled boundary: NAPI export hands plaintext back to JavaScript by
    // design (see the doc comment above) (murk-lints secret_uncontrolled_escape).
    #[cfg_attr(dylint_lib = "murk_lints", allow(secret_uncontrolled_escape))]
    pub fn export(&self) -> Result<HashMap<String, String>> {
        let resolved = murk_cli::resolve_secrets(&self.vault, &self.murk, &self.pubkey, &[]);
        let keys: Vec<String> = resolved.keys().cloned().collect();
        murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &keys)
            .map_err(fail)?;
        Ok(resolved
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect())
    }

    /// List all key names.
    #[napi]
    pub fn keys(&self) -> Vec<String> {
        self.vault.schema.keys().cloned().collect()
    }

    /// Number of secrets in the vault.
    #[napi(getter)]
    pub fn length(&self) -> u32 {
        self.vault.schema.len() as u32
    }

    /// Check if a key exists.
    #[napi]
    pub fn has(&self, key: String) -> bool {
        self.vault.schema.contains_key(&key)
    }

    /// Warnings about this vault that did not stop the load — the ones the
    /// CLI prints as `warn …` (an unsigned vault read by a key that cannot
    /// sign, a legacy MAC, a trust pin that could not be written).
    #[napi(getter)]
    pub fn warnings(&self) -> Vec<String> {
        self.murk.warnings.clone()
    }

    /// Store a secret. Mirrors `murk add`: the value is encrypted to the tier's
    /// recipients and the vault is re-signed and written back to disk under an
    /// exclusive lock, so it is safe against concurrent writers.
    ///
    /// `tier` selects the destination — `"everyone"` (shared to all recipients),
    /// `"me"` (a personal value encrypted to the caller only), or a group name
    /// (encrypted to that group's members; the caller must be a member). Giving
    /// a tier moves an existing key there. Without one, an existing key keeps its
    /// tier: a group value stays in its group and a personal override stays the
    /// caller's own. Only a new key defaults to `"everyone"`. A key held by a
    /// group the caller is not a member of can't be written (except as a `"me"`
    /// override), and a key holding only other recipients' overrides needs an
    /// explicit tier: otherwise the call throws.
    ///
    /// PLAINTEXT CAVEAT: unlike the read path — where plaintext only ever appears
    /// *after* decryption — a write means the caller already holds the secret as a
    /// JavaScript `String` before this call. That string lives in V8's heap, is
    /// copied across the napi boundary into a Rust `String`, and is not zeroized on
    /// either side. See `get` and THREAT_MODEL.md.
    ///
    /// An agent grant can't write: the call throws "agent grants are read-only"
    /// and nothing is saved. When the operator has opted into self-scope, the
    /// resulting key must satisfy the vault's agent allow-tag policy, otherwise
    /// the write throws and nothing is saved. For a plain operator identity
    /// the policy check is a no-op.
    #[napi]
    pub fn add(&mut self, key: String, value: String, options: Option<AddOptions>) -> Result<()> {
        if !murk_cli::is_valid_key_name(&key) {
            return Err(fail(format!(
                "invalid key name: {key}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]"
            )));
        }
        let opts = options.unwrap_or_default();
        let tier = opts.tier.as_deref().map(SecretTier::parse);
        let desc = opts.desc.as_deref();
        let tags = opts.tags.unwrap_or_default();

        // Lock, then load fresh from disk so a concurrent write isn't clobbered —
        // the same read-modify-write discipline the CLI's `cmd_add` follows.
        let _lock = murk_cli::vault::lock(Path::new(&self.path)).map_err(fail)?;
        let (mut vault, murk, identity) = murk_cli::load_vault(&self.path).map_err(murk_error)?;
        murk_cli::ensure_writable(&murk).map_err(fail)?;
        let pubkey = identity.pubkey_string().map_err(fail)?;
        let original = murk.clone();
        let mut current = murk;

        murk_cli::set_secret(
            &mut vault,
            &mut current,
            &key,
            &value,
            desc,
            None,
            tier.as_ref(),
            &tags,
            &pubkey,
        )
        .map_err(fail)?;

        // Enforce the agent policy over the resulting key *before* persisting, so a
        // forbidden write fails closed and leaves the on-disk vault untouched. The
        // schema now carries the intended tags, so the tag check sees the real
        // post-write state.
        murk_cli::enforce_agent_policy(&vault, &current, &pubkey, &[key]).map_err(fail)?;

        murk_cli::save_vault(&self.path, &mut vault, &original, &current).map_err(murk_error)?;

        // Refresh the in-memory snapshot so subsequent reads on this handle see
        // the write (and any concurrent changes the fresh load picked up).
        self.vault = vault;
        self.murk = current;
        self.pubkey = pubkey;
        Ok(())
    }

    /// Update a secret's description (and optionally its tags/example) in the
    /// vault schema. Mirrors `murk describe`. Does not touch the secret value;
    /// a key with no value becomes a documented-but-unset entry.
    ///
    /// Agent policy is enforced over the key exactly as in `add`.
    #[napi]
    pub fn describe(
        &mut self,
        key: String,
        description: String,
        options: Option<DescribeOptions>,
    ) -> Result<()> {
        let opts = options.unwrap_or_default();
        let tags = opts.tags.unwrap_or_default();

        let _lock = murk_cli::vault::lock(Path::new(&self.path)).map_err(fail)?;
        let (mut vault, murk, identity) = murk_cli::load_vault(&self.path).map_err(murk_error)?;
        murk_cli::ensure_writable(&murk).map_err(fail)?;
        let pubkey = identity.pubkey_string().map_err(fail)?;
        let original = murk.clone();
        let current = murk;

        murk_cli::require_group_access(&vault, &current, &key, &pubkey).map_err(murk_error)?;

        murk_cli::describe_key(
            &mut vault,
            &key,
            &description,
            opts.example.as_deref(),
            &tags,
            None,
            None,
        );

        murk_cli::enforce_agent_policy(&vault, &current, &pubkey, &[key]).map_err(fail)?;

        murk_cli::save_vault(&self.path, &mut vault, &original, &current).map_err(murk_error)?;

        self.vault = vault;
        self.murk = current;
        self.pubkey = pubkey;
        Ok(())
    }
}

/// Load a murk vault. Reads MURK_KEY from the environment.
#[napi]
pub fn load(vault_path: Option<String>) -> Result<Vault> {
    let path = vault_path.as_deref().unwrap_or(".murk");
    let (vault, murk, identity) = murk_cli::load_vault(path).map_err(murk_error)?;
    let pubkey = identity.pubkey_string().map_err(fail)?;
    Ok(Vault {
        vault,
        murk,
        pubkey,
        path: path.to_string(),
    })
}

/// One-liner: load the vault and get a single key.
#[napi]
pub fn get(key: String, vault_path: Option<String>) -> Result<Option<String>> {
    load(vault_path)?.get(key)
}

/// One-liner: load the vault and export all secrets as an object.
#[napi]
pub fn export_all(vault_path: Option<String>) -> Result<HashMap<String, String>> {
    load(vault_path)?.export()
}

/// One-liner: load the vault and store a secret. See `Vault.add`.
#[napi]
pub fn add(
    key: String,
    value: String,
    options: Option<AddOptions>,
    vault_path: Option<String>,
) -> Result<()> {
    load(vault_path)?.add(key, value, options)
}

/// Whether a decryption identity (`MURK_KEY` / `MURK_KEY_FILE`) is available in
/// the environment — i.e. whether `load` can decrypt. This does not check
/// whether a secret exists; use `Vault.has` / `Vault.keys` for that.
#[napi]
pub fn has_identity() -> bool {
    murk_cli::resolve_key().is_ok()
}
