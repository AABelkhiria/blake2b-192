//! BLAKE2b with a fixed 24-byte (192-bit) digest.
//!
//! This crate's headline API implements exactly one primitive: **unkeyed,
//! sequential BLAKE2b parameterized with a digest length of 24 bytes**, as
//! defined by RFC 7693 and the BLAKE2 specification.
//!
//! The digest length is part of BLAKE2b's parameterization (it is mixed into
//! the initial state), so this is **not** BLAKE2b-512 truncated to 24 bytes;
//! the two functions produce unrelated outputs. The implemented function is
//! byte-for-byte compatible with libsodium's
//! `crypto_generichash(out, 24, msg, len, NULL, 0)`, CPython's
//! `hashlib.blake2b(msg, digest_size=24)`, and RustCrypto's
//! `Blake2b::<U24>`.
//!
//! Properties:
//!
//! - `no_std`, no heap allocation, zero dependencies;
//! - no `unsafe` code (enforced by `#![forbid(unsafe_code)]`);
//! - keyed hashing, salts, personalization, and tree mode are deliberately
//!   out of scope. Other digest lengths are out of scope for the headline
//!   API; the [`engine`] module exposes the validated engine at 1..=64 bytes
//!   for crates that build on it.
//!
//! A 24-byte digest provides at most ~96-bit collision resistance (and
//! ~192-bit preimage resistance); use a longer digest where general-purpose
//! collision resistance matters.
//!
//! # Examples
//!
//! One-shot:
//!
//! ```
//! let digest: [u8; 24] = blake2b_192::hash(b"abc");
//! assert_eq!(
//!     digest[..4],
//!     [0x56, 0xa1, 0x7e, 0x38],
//! );
//! ```
//!
//! Streaming:
//!
//! ```
//! let mut hasher = blake2b_192::Blake2b192::new();
//! hasher.update(b"ab");
//! hasher.update(b"c");
//! assert_eq!(hasher.finalize(), blake2b_192::hash(b"abc"));
//! ```

// Provenance: written from RFC 7693 and the BLAKE2 specification, reviewed
// against RustCrypto `blake2` 0.11.0-rc.6 (RustCrypto/hashes @ tag
// blake2-v0.11.0-rc.6) and treated as a derivative of it for licensing
// purposes; upstream notices are retained in LICENSE-MIT and COPYRIGHT.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod engine;

use crate::engine::Blake2bCore;

/// Digest length in bytes (24 bytes = 192 bits).
pub const DIGEST_LEN: usize = 24;

/// Streaming BLAKE2b-192 hasher.
///
/// Feed input with [`update`](Self::update) in any number of chunks;
/// [`finalize`](Self::finalize) consumes the hasher and returns the digest.
/// The result is identical to [`hash`] of the concatenated input.
///
/// ```
/// let mut hasher = blake2b_192::Blake2b192::new();
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// assert_eq!(hasher.finalize(), blake2b_192::hash(b"hello world"));
/// ```
pub struct Blake2b192 {
    state: Blake2bCore,
}

impl Blake2b192 {
    /// Creates a hasher for a new message.
    #[must_use]
    pub fn new() -> Self {
        Blake2b192 {
            state: Blake2bCore::init(DIGEST_LEN as u64),
        }
    }

    /// Absorbs more message bytes.
    pub fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Completes hashing and returns the 24-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let out = self.state.finalize();
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&out[..DIGEST_LEN]);
        digest
    }
}

impl Default for Blake2b192 {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the BLAKE2b-192 digest of `input` in one call.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Blake2b192::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests;
