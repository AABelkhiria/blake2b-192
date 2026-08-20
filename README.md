# blake2b-192

BLAKE2b with a fixed 24-byte (192-bit) digest.

> **Status: work in progress — not yet implemented, not yet released. Do not
> use.**

## What this is

A deliberately small Rust crate implementing exactly one primitive: unkeyed,
sequential **BLAKE2b parameterized with `digest_length = 24`** (RFC 7693 /
the BLAKE2 specification).

- The digest length is part of BLAKE2b's parameterization: this is **not**
  BLAKE2b-512 truncated to 24 bytes — those are unrelated functions.
- Byte-for-byte compatible with libsodium's
  `crypto_generichash(out, 24, …)`, CPython's
  `hashlib.blake2b(digest_size=24)`, and RustCrypto's `Blake2b::<U24>`.
- `#![no_std]`, zero runtime dependencies, no heap allocation, no `unsafe`
  (`#![forbid(unsafe_code)]`).
- No prerelease dependencies anywhere in the tree (enforced in CI).
- Out of scope: keyed hashing/MAC, salt/personalization, other digest
  lengths, BLAKE2s, tree mode, XOFs.

## Planned API

```rust
pub fn hash(input: &[u8]) -> [u8; 24];

pub struct Blake2b192 { /* … */ }
impl Blake2b192 {
    pub fn new() -> Self;
    pub fn update(&mut self, input: &[u8]);
    pub fn finalize(self) -> [u8; 24];
}
```

## Verification

The implementation is written from RFC 7693 and the BLAKE2 specification and
is differentially verified against independent implementations (libsodium,
CPython `hashlib`, RustCrypto `blake2`), including official BLAKE2b test
vectors, block-boundary and streaming-equivalence tests. A 24-byte digest
provides at most ~96-bit collision resistance; choose a longer digest where
general-purpose collision resistance matters.

## Provenance

The implementation was written from RFC 7693 and the BLAKE2 specification,
using [RustCrypto's `blake2`] crate (`0.11.0-rc.6`) as its review reference
and libsodium as a verification oracle. Out of caution it is treated as a
derivative of RustCrypto `blake2` for licensing purposes: the upstream
copyright notices (The RustCrypto Project Developers, Artyom Pavlov, and the
`blake2-rfc` Developers) are retained in [LICENSE-MIT](LICENSE-MIT), and
original contributions are covered by [COPYRIGHT](COPYRIGHT).

Not affiliated with or endorsed by the RustCrypto, BLAKE2, or libsodium
projects.

[RustCrypto's `blake2`]: https://github.com/RustCrypto/hashes/tree/master/blake2

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
