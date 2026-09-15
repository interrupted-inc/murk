//! Minimal stand-in for the real `secrecy` crate (what `age::secrecy`
//! re-exports), compiled as an auxiliary crate so ui test fixtures can
//! exercise a real `secrecy::SecretBox` `DefId` — the type
//! `age::secrecy::SecretString` actually resolves to — without depending on
//! the real crate.
//!
//! Mirrors the real crate's key property (verified against
//! `secrecy-0.10.3`'s source): `SecretBox`'s own `Debug` impl always prints
//! a redacted placeholder, never the wrapped value, and it implements
//! `ZeroizeOnDrop`.

use std::fmt;
use std::ops::Deref;

pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl Zeroize for str {
    fn zeroize(&mut self) {
        // SAFETY: overwriting with the zero byte, still valid UTF-8 (NUL is
        // a valid single-byte code point), so length/validity are preserved.
        unsafe {
            for b in self.as_bytes_mut() {
                *b = 0;
            }
        }
    }
}

pub trait ZeroizeOnDrop {}

pub struct SecretBox<S: Zeroize + ?Sized> {
    inner_secret: Box<S>,
}

impl<S: Zeroize + ?Sized> SecretBox<S> {
    pub fn new(secret: Box<S>) -> Self {
        Self {
            inner_secret: secret,
        }
    }
}

impl<S: Zeroize + ?Sized> Deref for SecretBox<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.inner_secret
    }
}

impl<S: Zeroize + ?Sized> Drop for SecretBox<S> {
    fn drop(&mut self) {
        self.inner_secret.zeroize();
    }
}

impl<S: Zeroize + ?Sized> ZeroizeOnDrop for SecretBox<S> {}

impl<S: Zeroize + ?Sized> fmt::Debug for SecretBox<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBox([REDACTED])")
    }
}

pub type SecretString = SecretBox<str>;

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        SecretBox::new(s.into_boxed_str())
    }
}
