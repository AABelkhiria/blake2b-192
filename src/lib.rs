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
//! # Status
//!
//! **Work in progress.** The public API is not yet implemented; do not use
//! this crate yet.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
