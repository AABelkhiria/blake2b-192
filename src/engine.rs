//! The validated BLAKE2b engine, exposed for crates that build on it.
//!
//! This module makes the crate's internal hashing state public as [`Blake2bCore`]:
//! unkeyed, sequential BLAKE2b with a runtime digest length of 1 to 64 bytes.
//! It exists for crates that build other constructions on the engine and need the
//! validated core at digest lengths other than 24.
//! It is the same engine, not a second implementation: [`Blake2b192`](crate::Blake2b192)
//! is built on this type, and the KAT suites that validate it at 64 bytes
//! (RFC 7693 Appendix A and the 256 official BLAKE2b-512 vectors) and at other
//! lengths run through this public type.
//!
//! For general-purpose hashing, use RustCrypto's [`blake2`](https://docs.rs/blake2) instead;
//! this module carries only what those crates consume. There is still no keyed hashing, salt,
//! personalization, or tree mode.
//!
//! # Examples
//!
//! ```
//! # fn demo() -> Option<()> {
//! use blake2b_192::engine::Blake2bCore;
//!
//! // BLAKE2b-512("abc"), the RFC 7693 Appendix A vector.
//! let mut core = Blake2bCore::new(64)?;
//! core.update(b"abc");
//! let full: [u8; 64] = core.finalize();
//! assert_eq!(full[..4], [0xba, 0x80, 0xa5, 0x3f]);
//!
//! // A digest of length `n` is the first `n` bytes of `finalize`; at 24 it
//! // is exactly the headline API.
//! let mut short = Blake2bCore::new(24)?;
//! short.update(b"abc");
//! assert_eq!(short.finalize()[..24], blake2b_192::hash(b"abc"));
//! # Some(())
//! # }
//! # assert!(demo().is_some());
//! ```

/// BLAKE2b block size in bytes (RFC 7693 §2.1, "bb").
const BLOCK_LEN: usize = 128;

/// BLAKE2b initialization vector (RFC 7693 §2.6): the same constants as the
/// SHA-512 IV.
pub(crate) const IV: [u64; 8] = [
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

/// Unkeyed sequential BLAKE2b, parameterized at construction over the digest
/// length.
///
/// [`finalize`](Self::finalize) always returns the full 64-byte state
/// serialization; a digest of the length passed to [`new`](Self::new) is its
/// first `digest_len` bytes. Feed input with [`update`](Self::update) in any
/// number of chunks; empty calls are no-ops.
pub struct Blake2bCore {
    pub(crate) h: [u64; 8],
    /// 128-bit counter of message bytes fed to `compress` (low/high words).
    pub(crate) t_lo: u64,
    pub(crate) t_hi: u64,
    /// Lazy block buffer: may hold a full 128-byte block, which is only
    /// compressed once further input proves it is not the final block.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
}

impl Blake2bCore {
    /// Creates a hasher producing `digest_len` output bytes.
    ///
    /// Returns `Some` iff `digest_len` is 1..=64, the range BLAKE2b's
    /// parameter block admits.
    #[must_use]
    pub fn new(digest_len: usize) -> Option<Self> {
        if (1..=64).contains(&digest_len) {
            Some(Self::init(digest_len as u64))
        } else {
            None
        }
    }

    /// Initial state for unkeyed sequential BLAKE2b with `digest_len` output
    /// bytes: the parameter block has digest_length = `digest_len`,
    /// key_length = 0, fanout = 1, depth = 1, and every other field zero, so
    /// only the first parameter word `0x0101_0000 | digest_len` is nonzero.
    ///
    /// Crate-internal so the fixed-length [`Blake2b192`](crate::Blake2b192)
    /// constructor stays infallible without a panic path; `digest_len` must
    /// already be valid.
    pub(crate) fn init(digest_len: u64) -> Self {
        debug_assert!((1..=64).contains(&digest_len));
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ digest_len;
        Blake2bCore {
            h,
            t_lo: 0,
            t_hi: 0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
        }
    }

    /// Adds `n` to the 128-bit byte counter, carrying into the high word.
    pub(crate) fn count(&mut self, n: usize) {
        let n = n as u64;
        self.t_lo = self.t_lo.wrapping_add(n);
        if self.t_lo < n {
            self.t_hi = self.t_hi.wrapping_add(1);
        }
    }

    /// Absorbs more message bytes.
    pub fn update(&mut self, mut input: &[u8]) {
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
    #[must_use]
    pub fn finalize(mut self) -> [u8; 64] {
        let buf_len = self.buf_len.min(BLOCK_LEN);
        self.count(buf_len);
        self.buf[buf_len..].fill(0);
        compress(&mut self.h, &self.buf, self.t_lo, self.t_hi, true);

        let mut out = [0u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}
