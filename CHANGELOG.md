# Changelog

> Following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
> and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-21

First release.
This is one portion of what RustCrypto's `blake2` covers: BLAKE2b-192, and nothing else.

### Added

- `hash`, which takes a byte slice and returns `[u8; 24]` in one call.
- `Blake2b192`, the streaming form, with `new`, `update` and `finalize`. `update` accepts any chunking and treats an
  empty slice as a no-op; `finalize` consumes the hasher, so reusing one after finishing it is a compile error rather
  than a wrong answer. `Default` is equivalent to `new`.
- `DIGEST_LEN`, which is 24. The digest length is fixed at compile time.

### Security

- No `unsafe` anywhere, enforced by `#![forbid(unsafe_code)]`, and no dependency that could introduce any.
  The crate is `no_std`, never allocates.
  It holds its whole state in `[u64; 8]`, a 128-byte block buffer and a 128-bit counter.
- The API cannot panic on any input, and this is checked rather than asserted.
  CI builds the lib optimized for `thumbv7em-none-eabi` and fails if the object references any panicking entry point.
- Every component was read against RFC 7693 and RustCrypto `blake2 0.11.0-rc.6` before release, independently of the
  test suite (See `SECURITY.md`).
- A 24-byte digest carries roughly 96-bit collision resistance, below the customary 128-bit level.
  It belongs where 24 bytes is structurally required, not where a general-purpose hash is wanted.
- Hashing is data-independent by construction, but no constant-time digest comparison is provided.
  The state is not zeroized on drop.

### Compatibility

- Byte-for-byte agreement with libsodium 1.0.22 `crypto_generichash(out, 24, msg, len, NULL, 0)`, CPython
  `hashlib.blake2b(msg, digest_size=24)` and RustCrypto `Blake2b::<U24>` at 0.11.0-rc.6, across a 410-message corpus
  covering every length from 0 to 257, inputs up to a megabyte, and seeded pseudo-random data.
- The shared core reproduces RFC 7693 Appendix A and all 256 official unkeyed BLAKE2b-512 known answers when run at a
  64-byte digest length, which is what pins the IV, message schedule, G function, counter, finalization and endianness.
  No authoritative vectors exist for unkeyed BLAKE2b at 24 bytes, so agreement between independent implementations
  carries the rest.
- This is not BLAKE2b-512 truncated.
- `no_std` with no `alloc` requirement.
  Compile-checked for `thumbv7em-none-eabi`, `wasm32-unknown-unknown` and `x86_64-unknown-linux-musl`.
  Minimum supported Rust version is 1.85.

[0.1.0]: https://github.com/AABelkhiria/blake2b-192/releases/tag/v0.1.0
