# Security Policy

## Status

> [!WARNING]
> This crate is unaudited.

What the tests cover:
- The output matches libsodium 1.0.22, CPython's `hashlib`, and RustCrypto's `blake2` byte for byte across a 410-message corpus.
- The shared core reproduces the official BLAKE2b-512 known-answer vectors.

That is evidence about which function is being computed.
But four implementations agreeing cannot rule out a mistake all inherited from the same reading of the specification.

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include:
- The crate version
- The target
- An input that reproduces the problem or code that generates one
- What you think the impact is

## What this crate computes

Exactly one primitive:

```text
BLAKE2b, unkeyed, sequential mode, digest_length = 24 bytes (192 bits)
```

parameterized as:

```text
digest_length = 24    key_length = 0    fanout = 1    depth = 1
leaf_length = node_offset = node_depth = inner_length = 0
salt = personal = all-zero
```

That is the same function as libsodium's `crypto_generichash(out, 24, msg, len, NULL, 0)`, CPython's
`hashlib.blake2b(msg, digest_size=24)`, and RustCrypto's `Blake2b::<U24>`.

It is not BLAKE2b-512 truncated.
The digest length is XORed into the initial state before any message byte is processed, the two are unrelated functions.

The `engine` module additionally exposes the same engine at digest lengths 1 to 64 (`engine::Blake2bCore`), for crates
that build other constructions on it; every parameter other than digest_length stays fixed as above.

Not provided, and not a supported use:
Keyed hashing or MAC, salt and personalization, tree modes, BLAKE2s, BLAKE2X and other XOFs, and runtime-variable
output length outside the `engine` module.

This crate implements no password hashing or key derivation itself, but it no longer gets to disclaim the topic
entirely: such constructions can be built on `engine::Blake2bCore`, and that is what the module is for.
Whether a construction is assembled correctly is the building crate's problem; a defect in the engine underneath it
is this crate's, and belongs in a report here.

## Implementation assumptions

Pure safe Rust: `#![forbid(unsafe_code)]`, `#![no_std]`, no heap allocation, no dependencies.
The state is `[u64; 8]`, a 128-byte block buffer, and a 128-bit counter, all fixed size.

Arithmetic is explicitly wrapping and every message and output conversion is explicitly little-endian, so correctness
doesn't depend on host endianness.

The unit tests, the 256 official 64-byte known-answer vectors included, pass under Miri cross-interpreted for big-endian
`s390x-unknown-linux-gnu`.

Input is an untrusted byte slice with no length limit and nothing to validate.
The message counter cannot overflow for any input that can physically exist, and `finalize` consumes the hasher,
so reusing one after finishing it is a compile error rather than a silent wrong answer.

## Known limitations

Hashing is data-independent by construction, a fixed round count, no secret-dependent branches, and no table lookups
indexed by input.
That property is what lets the exported engine sit under constructions that do see secret input; the 24-byte API itself
is still meant for hashing non-secret data.
Comparing digests is yours to do.
If the digests are secret, use a constant-time comparison; this crate doesn't provide one.

State is not zeroized on drop. If you hash something sensitive, this crate will not erase it, and that holds for
`engine::Blake2bCore` too: a construction feeding secret material through the engine, as a password hash does, has to
do its own scrubbing.

RustCrypto's BLAKE2b keeps a 64-bit byte counter and hard-codes the high word to zero, where this crate carries into it
as RFC 7693 specifies.
The two agree for every message below 2^64 bytes, which is every message that will ever be hashed, but the divergence is
recorded rather than papered over.

## Dependencies

There are none, and CI reads `cargo metadata` on every push to confirm that no prerelease version appears anywhere in the resolved graph.
The rule is unconditional: this crate's own releases are stable versions.
