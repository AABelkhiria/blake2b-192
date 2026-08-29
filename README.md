# blake2b-192

BLAKE2b with the digest length fixed at 24 bytes (192 bits).

BLAKE2b takes its output length as a parameter, and that parameter is mixed into the initial state before a single
message byte is processed.
So BLAKE2b-192 is its own function rather than the first 24 bytes of BLAKE2b-512; the two share an algorithm and produce
unrelated output.

This crate implements the 24-byte parameterization and nothing else.

[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

> [!WARNING]
> The implementation's output is checked byte for byte against libsodium, CPython, and RustCrypto,
> but agreement between four implementations says nothing about a mistake all four could share.

## Scope

One function, offering one-shot and streaming. There is no keyed hashing or MAC, no salt or personalization, no tree
mode, no BLAKE2s, no XOF, and, in the headline API, no runtime-selectable digest length.
The `engine` module exposes the same validated engine at digest lengths 1 to 64 for crates that build other
constructions on it; general-purpose users still belong with [`blake2`][rustcrypto-blake2].
What's left is small on purpose: eight `u64` of chaining state, a 128-byte block buffer, and a 128-bit counter.
No `unsafe` (`#![forbid(unsafe_code)]`), no allocation, no dependencies.

[`blake2`][rustcrypto-blake2] and [`blake2b_simd`][blake2b_simd] are more general (this crate isn't replacing them).

## Usage

```rust
use blake2b_192::{Blake2b192, hash};

let digest: [u8; 24] = hash(b"abc");

let mut hasher = Blake2b192::new();
hasher.update(b"ab");
hasher.update(b"c");
assert_eq!(hasher.finalize(), digest);
```

That digest is `56a17e38cc371a46b12c32f18e0c61de2a84e9c2555b114e`.
`update` takes any number of chunks and empty calls are no-ops.
`finalize` consumes the hasher, so reusing one after finishing it is a compile error rather than a subtle bug.

## Not a truncation

This is the one thing worth being sure about before using the crate:

```text
BLAKE2b-192("abc")        56a17e38cc371a46b12c32f18e0c61de2a84e9c2555b114e
BLAKE2b-512("abc")[..24]  ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b7
```

The digest length lives in BLAKE2b's parameter block, which is XORed into the IV at initialization, so at 24 bytes the
state starts from `h[0] = IV[0] ^ 0x0101_0018` instead of `IV[0]`.
Every subsequent round diverges.
The test suite asserts these two values differ, so the distinction can't quietly regress.

The same parameterization is what libsodium's `crypto_generichash(out, 24, msg, len, NULL, 0)`, CPython's
`hashlib.blake2b(msg, digest_size=24)`, and RustCrypto's `Blake2b::<U24>` compute.
This crate matches all three byte for byte.

## How it's tested

There are no published test vectors for unkeyed BLAKE2b with a 24-byte output, so correctness is tested in layers.

The core is tested at 64 bytes against RFC 7693 Appendix A and the official BLAKE2b-512 vectors.
This covers the core algorithm, including the IV, message schedule, counter, finalization, and endianness.

The 24-byte API is tested against 410-message corpus generated with libsodium and cross-checked with CPython's hashlib.
RustCrypto hashes the same corpus independently, and both fixtures must match.

Streaming is tested with chunk sizes from 1 to 256, including exact block boundaries.
Miri checks the implementation on little- and big-endian targets.
A bare-metal build verifies that the optimized library has no panic paths.

`python3 vectors/generate/gen_vectors.py` regenerates fixtures, and CI re-runs it on every push and diffs the result.
Vectors this crate generated for itself would be worth nothing.

## Platforms

No features to choose from. The crate is `no_std` and never allocates, so it doesn't need `alloc` either.
Minimum supported Rust version is 1.85, checked in [Checks](.github/workflows/checks.yml).
Compile checks for `thumbv7em-none-eabi`, `wasm32-unknown-unknown`, and `x86_64-unknown-linux-musl`.

## Security notes

[SECURITY.md](SECURITY.md) records the scope, assumptions, limitations, and what has been reviewed.

## Provenance

Written from RFC 7693 and the BLAKE2 paper, with RustCrypto's [`blake2`][rustcrypto-blake2] as a review reference:
Each component was checked against it rather than copied from it.
The upstream notices, The RustCrypto Project Developers, Artyom Pavlov,
and the `blake2-rfc` Developers are kept in [LICENSE-MIT](LICENSE-MIT).

Not affiliated with or endorsed by the RustCrypto, BLAKE2, or libsodium projects.

[rustcrypto-blake2]: https://github.com/RustCrypto/hashes/tree/master/blake2
[blake2b_simd]: https://github.com/oconnor663/blake2_simd

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
