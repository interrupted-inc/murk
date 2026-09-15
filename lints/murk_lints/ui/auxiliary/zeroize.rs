//! Minimal stand-in for the real `zeroize` crate, compiled as an auxiliary
//! crate so ui test fixtures can exercise a real external `zeroize::Zeroizing`
//! `DefId` (matching what `SECRET_FIELDS`/`ZEROIZING_PATH` in the lint check
//! for) without depending on the real crate.

use std::ops::Deref;

#[derive(Clone, Debug)]
pub struct Zeroizing<Z>(Z);

impl<Z> Zeroizing<Z> {
    pub fn new(z: Z) -> Self {
        Zeroizing(z)
    }
}

impl<Z> Deref for Zeroizing<Z> {
    type Target = Z;
    fn deref(&self) -> &Z {
        &self.0
    }
}

impl<Z: std::fmt::Display> std::fmt::Display for Zeroizing<Z> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
