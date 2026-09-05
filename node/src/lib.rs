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

use std::collections::HashMap;
use std::path::Path;

use napi_derive::napi;

/// A loaded and decrypted murk vault.
#[napi]
pub struct Vault {
    vault: murk_cli::types::Vault,
    murk: murk_cli::types::Murk,
    pubkey: String,
    path: String,
}

/// Destination tier for a written secret, mirroring the CLI's `--group` value.
///
/// The reserved names route to the shared/scoped tiers; anything else is a named
/// group. This is the same mapping the CLI applies in `resolve_secret_tier`.
enum Tier {
    /// The shared value, encrypted to all recipients (the default).
    Everyone,
    /// A personal scoped value, encrypted to the caller only.
    Me,
    /// A named group, encrypted to that group's members.
    Group(String),
}

fn resolve_tier(tier: Option<&str>) -> Tier {
    match tier {
        None => Tier::Everyone,
        Some("everyone" | "all" | "shared") => Tier::Everyone,
        Some("me" | "self" | "mine") => Tier::Me,
        Some(name) => Tier::Group(name.to_string()),
    }
}

/// Options for [`Vault::add`]. All fields are optional; an omitted `tier`
/// defaults to `everyone` (the shared value).
#[napi(object)]
#[derive(Default)]
pub struct AddOptions {
    /// `"everyone"` (default), `"me"` (personal scoped), or a group name.
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
    pub fn get(&self, key: String) -> napi::Result<Option<String>> {
        let value = murk_cli::get_secret(&self.murk, &key, &self.pubkey).map(str::to_string);
        // Only enforce when there is a value to hand back: a key the agent
        // cannot decrypt is already inaccessible, so policy is moot.
        if value.is_some() {
            murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &[key])
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;
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
    pub fn export(&self) -> napi::Result<HashMap<String, String>> {
        let resolved = murk_cli::resolve_secrets(&self.vault, &self.murk, &self.pubkey, &[]);
        let keys: Vec<String> = resolved.keys().cloned().collect();
        murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &keys)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
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

    /// Store a secret. Mirrors `murk add`: the value is encrypted to the tier's
    /// recipients and the vault is re-signed and written back to disk under an
    /// exclusive lock, so it is safe against concurrent writers.
    ///
    /// `tier` selects the destination — `"everyone"` (default, shared to all
    /// recipients), `"me"` (a personal value encrypted to the caller only), or a
    /// group name (encrypted to that group's members; the caller must be a
    /// member). An existing key is overwritten in place.
    ///
    /// PLAINTEXT CAVEAT: unlike the read path — where plaintext only ever appears
    /// *after* decryption — a write means the caller already holds the secret as a
    /// JavaScript `String` before this call. That string lives in V8's heap, is
    /// copied across the napi boundary into a Rust `String`, and is not zeroized on
    /// either side. See `get` and THREAT_MODEL.md.
    ///
    /// Agent policy is enforced exactly as on the read path: if the loaded
    /// identity is a granted agent (or the operator has opted into self-scope),
    /// the resulting key must satisfy the vault's agent allow-tag policy and the
    /// grant must be unexpired — otherwise the write throws and nothing is saved.
    /// For a plain operator identity this is a no-op.
    #[napi]
    pub fn add(
        &mut self,
        key: String,
        value: String,
        options: Option<AddOptions>,
    ) -> napi::Result<()> {
        if !murk_cli::is_valid_key_name(&key) {
            return Err(napi::Error::from_reason(format!(
                "invalid key name: {key}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]"
            )));
        }
        let opts = options.unwrap_or_default();
        let tier = resolve_tier(opts.tier.as_deref());
        let desc = opts.desc.as_deref();
        let tags = opts.tags.unwrap_or_default();

        // Lock, then load fresh from disk so a concurrent write isn't clobbered —
        // the same read-modify-write discipline the CLI's `cmd_add` follows.
        let _lock = murk_cli::vault::lock(Path::new(&self.path))
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let (mut vault, murk, identity) = murk_cli::load_vault(&self.path)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let pubkey = identity
            .pubkey_string()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let original = murk.clone();
        let mut current = murk;

        match &tier {
            Tier::Everyone => {
                murk_cli::add_secret(
                    &mut vault,
                    &mut current,
                    &key,
                    &value,
                    desc,
                    None,
                    false,
                    &tags,
                    Some(&pubkey),
                );
            }
            Tier::Me => {
                murk_cli::add_secret(
                    &mut vault,
                    &mut current,
                    &key,
                    &value,
                    desc,
                    None,
                    true,
                    &tags,
                    Some(&pubkey),
                );
            }
            Tier::Group(name) => {
                murk_cli::add_grouped_secret(
                    &mut vault,
                    &mut current,
                    &key,
                    &value,
                    desc,
                    None,
                    name,
                    &tags,
                    &pubkey,
                )
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;
            }
        }

        // Enforce the agent policy over the resulting key *before* persisting, so a
        // forbidden write fails closed and leaves the on-disk vault untouched. The
        // schema now carries the intended tags, so the tag check sees the real
        // post-write state.
        murk_cli::enforce_agent_policy(&vault, &current, &pubkey, &[key])
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        murk_cli::save_vault(&self.path, &mut vault, &original, &current)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

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
    ) -> napi::Result<()> {
        let opts = options.unwrap_or_default();
        let tags = opts.tags.unwrap_or_default();

        let _lock = murk_cli::vault::lock(Path::new(&self.path))
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let (mut vault, murk, identity) = murk_cli::load_vault(&self.path)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let pubkey = identity
            .pubkey_string()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let original = murk.clone();
        let current = murk;

        murk_cli::describe_key(
            &mut vault,
            &key,
            &description,
            opts.example.as_deref(),
            &tags,
            None,
            None,
        );

        murk_cli::enforce_agent_policy(&vault, &current, &pubkey, &[key])
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        murk_cli::save_vault(&self.path, &mut vault, &original, &current)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        self.vault = vault;
        self.murk = current;
        self.pubkey = pubkey;
        Ok(())
    }
}

/// Load a murk vault. Reads MURK_KEY from the environment.
#[napi]
pub fn load(vault_path: Option<String>) -> napi::Result<Vault> {
    let path = vault_path.as_deref().unwrap_or(".murk");
    let (vault, murk, identity) =
        murk_cli::load_vault(path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(Vault {
        vault,
        murk,
        pubkey,
        path: path.to_string(),
    })
}

/// One-liner: load the vault and get a single key.
#[napi]
pub fn get(key: String, vault_path: Option<String>) -> napi::Result<Option<String>> {
    load(vault_path)?.get(key)
}

/// One-liner: load the vault and export all secrets as an object.
#[napi]
pub fn export_all(vault_path: Option<String>) -> napi::Result<HashMap<String, String>> {
    load(vault_path)?.export()
}

/// One-liner: load the vault and store a secret. See `Vault.add`.
#[napi]
pub fn add(
    key: String,
    value: String,
    options: Option<AddOptions>,
    vault_path: Option<String>,
) -> napi::Result<()> {
    load(vault_path)?.add(key, value, options)
}

/// Whether a decryption identity (`MURK_KEY` / `MURK_KEY_FILE`) is available in
/// the environment — i.e. whether `load` can decrypt. This does not check
/// whether a secret exists; use `Vault.has` / `Vault.keys` for that.
#[napi]
pub fn has_identity() -> bool {
    murk_cli::resolve_key().is_ok()
}
