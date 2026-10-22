// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Python bindings for murk via PyO3.
//!
//! ```python
//! import murk
//!
//! vault = murk.load()              # finds your key like the CLI, .murk from cwd
//! vault.get("DATABASE_URL")        # decrypt a single value
//! vault.export()                   # dict of all key/values
//! murk.get("DATABASE_URL")         # one-liner convenience
//! ```
//!
//! `load()` applies the same trust rules as the CLI (`crate::load_vault`): a
//! vault this machine does not trust raises `murk.TrustError`, with the
//! message the CLI prints.

use std::collections::HashMap;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::{MurkError, env, export, policy, types};

pyo3::create_exception!(
    murk,
    TrustError,
    PyRuntimeError,
    "The vault was refused: not trusted on this machine, or tampered with."
);

/// A refusal of the vault itself (trust or integrity) raises `TrustError`;
/// anything else `RuntimeError`.
fn load_error(e: &MurkError) -> PyErr {
    match e {
        MurkError::Trust(_) | MurkError::Integrity(_) => TrustError::new_err(e.to_string()),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}

/// A loaded and decrypted murk vault.
#[pyclass]
struct Vault {
    inner: types::Vault,
    decrypted: types::Murk,
    pubkey: String,
}

#[pymethods]
impl Vault {
    /// Get a single decrypted secret value. Resolution order: a personal scoped
    /// override, then a named-group value we can read, then the shared value.
    ///
    /// The returned `String` is a plain Python-owned copy — once it crosses
    /// the FFI boundary the plaintext is outside murk's zeroization.
    ///
    /// When the loaded identity is a granted agent, the vault's agent policy is
    /// enforced before the value is returned — the same gate the CLI applies at
    /// `agent exec`. Raises `RuntimeError` if policy forbids the key. For an
    /// operator identity this is a no-op.
    fn get(&self, key: &str) -> PyResult<Option<String>> {
        let value = crate::get_secret(&self.decrypted, key, &self.pubkey).map(str::to_string);
        // Only enforce when there is a value to hand back: a key the agent
        // cannot decrypt is already inaccessible, so policy is moot.
        if value.is_some() {
            policy::enforce_agent_policy(
                &self.inner,
                &self.decrypted,
                &self.pubkey,
                &[key.to_string()],
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        }
        Ok(value)
    }

    /// Export all secrets as a dict. Scoped values override shared values.
    ///
    /// For a granted agent, the vault's agent policy is enforced over the full
    /// key set first (mirroring `murk agent exec`): if any resolvable key is
    /// outside the policy, the whole export raises `RuntimeError` rather than
    /// returning a partial dict. For an operator identity this is a no-op.
    fn export(&self) -> PyResult<HashMap<String, String>> {
        let resolved = export::resolve_secrets(&self.inner, &self.decrypted, &self.pubkey, &[]);
        let keys: Vec<String> = resolved.keys().cloned().collect();
        policy::enforce_agent_policy(&self.inner, &self.decrypted, &self.pubkey, &keys)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        // Python dicts own plain Strings — zeroization ends at the FFI boundary.
        Ok(resolved
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect())
    }

    /// List all key names.
    fn keys(&self) -> Vec<String> {
        self.inner.schema.keys().cloned().collect()
    }

    /// Number of secrets in the vault.
    fn __len__(&self) -> usize {
        self.inner.schema.len()
    }

    /// Get a value by key (dict-style access).
    fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.get(key)?
            .ok_or_else(|| PyRuntimeError::new_err(format!("key not found: {key}")))
    }

    /// Check if a key exists.
    fn __contains__(&self, key: &str) -> bool {
        self.inner.schema.contains_key(key)
    }

    fn __repr__(&self) -> String {
        format!(
            "Vault({} secrets, {} recipients)",
            self.inner.schema.len(),
            self.inner.recipients.len()
        )
    }

    /// Warnings about this vault that did not stop the load — the ones the
    /// CLI prints as `warn …` (an unsigned vault read by a key that cannot
    /// sign, a legacy MAC, a trust pin that could not be written).
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.decrypted.warnings.clone()
    }
}

/// Load a murk vault. Finds the key the same way the CLI does: `MURK_KEY`,
/// `MURK_KEY_FILE`, or the key file `murk init` stored. Raises `TrustError`
/// when this machine does not trust the vault.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn load(vault_path: &str) -> PyResult<Vault> {
    let (vault, murk, identity) = crate::load_vault(vault_path).map_err(|e| load_error(&e))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(Vault {
        inner: vault,
        decrypted: murk,
        pubkey,
    })
}

/// One-liner: load the vault and get a single key.
#[pyfunction]
#[pyo3(signature = (key, vault_path=".murk"))]
fn get(key: &str, vault_path: &str) -> PyResult<Option<String>> {
    let v = load(vault_path)?;
    v.get(key)
}

/// One-liner: load the vault and export all secrets as a dict.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn export_all(vault_path: &str) -> PyResult<HashMap<String, String>> {
    let v = load(vault_path)?;
    v.export()
}

/// Whether murk can find a key for `./.murk`: MURK_KEY, MURK_KEY_FILE or the key
/// file `murk init` stored. This does not read the vault, so True does not mean
/// load() succeeds. It does not check whether a secret exists; use
/// `key in vault` / Vault.keys for that.
#[pyfunction]
fn has_identity() -> bool {
    env::resolve_key().is_ok()
}

/// Python module definition.
#[pymodule]
fn murk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Vault>()?;
    m.add("TrustError", m.py().get_type::<TrustError>())?;
    m.add_function(wrap_pyfunction!(load, m)?)?;
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_function(wrap_pyfunction!(export_all, m)?)?;
    m.add_function(wrap_pyfunction!(has_identity, m)?)?;
    Ok(())
}
