extern crate std;

use std::string::String;
use std::vec::Vec;

use super::{Blake2b192, IV, State, hash};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| std::format!("{b:02x}")).collect()
}

/// h[0] after initialization must be IV[0] ^ 0x0101_0018 for
/// digest_length = 24, key_length = 0, fanout = 1, depth = 1.
#[test]
fn init_parameter_word() {
    let state = State::new(24);
    assert_eq!(state.h[0], 0x6a09_e667_f2bd_c910);
    assert_eq!(state.h[0], IV[0] ^ 0x0101_0018);
    assert_eq!(state.h[1..], IV[1..]);
}

/// Anchor digests established from two independent oracles (libsodium 1.0.22
/// and CPython hashlib.blake2b(digest_size=24)), which agree byte-for-byte.
#[test]
fn anchors_24() {
    assert_eq!(
        hex(&hash(b"")),
        "ab3b5331a7135ed50d0f182d026e60abdb3646fd51bcf8a3"
    );
    assert_eq!(
        hex(&hash(b"abc")),
        "56a17e38cc371a46b12c32f18e0c61de2a84e9c2555b114e"
    );
    assert_eq!(
        hex(&hash(&[0u8; 128])),
        "9ff4abe3fc3c8006f8a2922a9ded93c51fcf063f0eccf365"
    );
    let inc: Vec<u8> = (0..129).map(|i| i as u8).collect();
    assert_eq!(
        hex(&hash(&inc)),
        "921c466b582e135fab21c8e052fe3715d9113bcd864276ba"
    );
}

/// RFC 7693 Appendix A: BLAKE2b-512("abc"), through the internal core at
/// digest length 64 — the authoritative spec vector.
#[test]
fn rfc7693_appendix_a_blake2b512_abc() {
    let mut state = State::new(64);
    state.update(b"abc");
    assert_eq!(
        hex(&state.finalize()),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );
}

/// Unkeyed BLAKE2b-512 of the empty message, from the official BLAKE2 KATs
/// (blake2-kat.json, unkeyed entry for the empty input).
#[test]
fn official_kat_blake2b512_empty() {
    let state = State::new(64);
    assert_eq!(
        hex(&state.finalize()),
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    );
}

/// BLAKE2b-192 is parameterized, not truncated: its digests must differ from
/// prefixes of the corresponding BLAKE2b-512 digests.
#[test]
fn not_a_truncation_of_blake2b512() {
    for msg in [&b""[..], b"abc"] {
        let mut state = State::new(64);
        state.update(msg);
        let full = state.finalize();
        assert_ne!(hash(msg), full[..24]);
    }
}

/// The streaming API over every split of a short message equals the one-shot
/// digest (exhaustive two-chunk splits across the first block boundary).
#[test]
fn streaming_two_chunk_splits() {
    let msg: Vec<u8> = (0..300).map(|i| (i * 7) as u8).collect();
    let expected = hash(&msg);
    for split in 0..=msg.len() {
        let mut hasher = Blake2b192::new();
        hasher.update(&msg[..split]);
        hasher.update(&msg[split..]);
        assert_eq!(hasher.finalize(), expected, "split at {split}");
    }
}

/// Empty updates are no-ops anywhere in the stream.
#[test]
fn empty_updates_are_noops() {
    let mut hasher = Blake2b192::new();
    hasher.update(b"");
    hasher.update(b"ab");
    hasher.update(b"");
    hasher.update(b"c");
    hasher.update(b"");
    assert_eq!(hasher.finalize(), hash(b"abc"));
}
