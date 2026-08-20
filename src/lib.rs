//! BLAKE2b with a fixed 24-byte (192-bit) digest.
//!
//! This crate implements exactly one primitive: **unkeyed, sequential BLAKE2b
//! parameterized with a digest length of 24 bytes**, as defined by RFC 7693
//! and the BLAKE2 specification.
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
//! - keyed hashing, salts, personalization, tree mode, and other digest
//!   lengths are deliberately out of scope.
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

/// Digest length in bytes (24 bytes = 192 bits).
pub const DIGEST_LEN: usize = 24;

/// BLAKE2b block size in bytes (RFC 7693 §2.1, "bb").
const BLOCK_LEN: usize = 128;

/// BLAKE2b initialization vector (RFC 7693 §2.6): the same constants as the
/// SHA-512 IV.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Message word schedule (RFC 7693 §2.7). BLAKE2b runs 12 rounds; round `i`
/// uses row `SIGMA[i % 10]`.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The G mixing function (RFC 7693 §3.1): rotations 32, 24, 16, 63; all
/// additions mod 2^64.
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The compression function F (RFC 7693 §3.2).
///
/// `t_lo`/`t_hi` are the 128-bit byte counter including the bytes of this
/// block; `last` sets the final-block flag f0 (f1 is always zero: sequential
/// mode only).
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN], t_lo: u64, t_hi: u64, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        // Message words are read little-endian (RFC 7693 §2.3).
        let bytes = &block[8 * i..8 * i + 8];
        *word = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
    }

    let mut v = [
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], IV[0], IV[1], IV[2], IV[3], IV[4], IV[5],
        IV[6], IV[7],
    ];
    v[12] ^= t_lo;
    v[13] ^= t_hi;
    if last {
        v[14] = !v[14];
    }

    for round in 0..12 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Internal hashing state, parameterized over the digest length so tests can
/// exercise the shared core at other lengths against official vectors. The
/// public API fixes the digest length at 24.
struct State {
    h: [u64; 8],
    /// 128-bit counter of message bytes fed to `compress` (low/high words).
    t_lo: u64,
    t_hi: u64,
    /// Lazy block buffer: may hold a full 128-byte block, which is only
    /// compressed once further input proves it is not the final block.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
}

impl State {
    /// Initial state for unkeyed sequential BLAKE2b with `digest_len` output
    /// bytes: the parameter block has digest_length = `digest_len`,
    /// key_length = 0, fanout = 1, depth = 1, and every other field zero, so
    /// only the first parameter word `0x0101_0000 | digest_len` is nonzero.
    fn new(digest_len: usize) -> Self {
        debug_assert!((1..=64).contains(&digest_len));
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ digest_len as u64;
        State {
            h,
            t_lo: 0,
            t_hi: 0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
        }
    }

    /// Adds `n` to the 128-bit byte counter.
    fn count(&mut self, n: usize) {
        let n = n as u64;
        self.t_lo = self.t_lo.wrapping_add(n);
        if self.t_lo < n {
            self.t_hi += 1;
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }
        // Top up a partially filled buffer first.
        if self.buf_len < BLOCK_LEN {
            let take = usize::min(BLOCK_LEN - self.buf_len, input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
        // While more input remains, the buffered block is full and provably
        // not the final one, so it can be compressed.
        while !input.is_empty() {
            self.count(BLOCK_LEN);
            compress(&mut self.h, &self.buf, self.t_lo, self.t_hi, false);
            let take = usize::min(BLOCK_LEN, input.len());
            self.buf[..take].copy_from_slice(&input[..take]);
            self.buf_len = take;
            input = &input[take..];
        }
    }

    /// Compresses the held final block (zero-padded, counter advanced by the
    /// exact number of buffered bytes, final-block flag set) and returns the
    /// full 64-byte little-endian serialization of the state; a digest of
    /// length `nn` is its first `nn` bytes. An empty message compresses one
    /// all-zero block with the counter at zero (RFC 7693 §3.3, dd = 1).
    fn finalize(mut self) -> [u8; 64] {
        self.count(self.buf_len);
        self.buf[self.buf_len..].fill(0);
        compress(&mut self.h, &self.buf, self.t_lo, self.t_hi, true);

        let mut out = [0u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

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
    state: State,
}

impl Blake2b192 {
    /// Creates a hasher for a new message.
    #[must_use]
    pub fn new() -> Self {
        Blake2b192 {
            state: State::new(DIGEST_LEN),
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
