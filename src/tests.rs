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

/// All 256 official unkeyed BLAKE2b-512 KATs (inputs 00 01 02 ... of lengths
/// 0..=255), through the internal core at digest length 64. See the data
/// file's provenance header.
#[test]
fn official_unkeyed_kat64() {
    let data = include_str!("../tests/data/official_blake2b_kat64.txt");
    let mut count = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        let (len, digest) = line.split_once(' ').expect("malformed line");
        let len: usize = len.parse().expect("bad length");
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut state = State::new(64);
        state.update(&msg);
        assert_eq!(hex(&state.finalize()), digest, "input length {len}");
        count += 1;
    }
    assert_eq!(count, 256);
}

/// Digest-length parameterization at 20, 32, 48, and 64 bytes (the RFC 7693
/// self-test lengths), dual-endorsed fixtures from libsodium and hashlib.
#[test]
fn multi_length_parameterization() {
    let data = include_str!("../tests/data/multilen_kat.txt");
    let mut count = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split(' ');
        let outlen: usize = fields.next().unwrap().parse().unwrap();
        let msglen: usize = fields.next().unwrap().parse().unwrap();
        let digest = fields.next().unwrap();
        let msg: Vec<u8> = (0..msglen).map(|i| i as u8).collect();
        let mut state = State::new(outlen);
        state.update(&msg);
        assert_eq!(
            hex(&state.finalize()[..outlen]),
            digest,
            "outlen {outlen}, msglen {msglen}"
        );
        count += 1;
    }
    assert_eq!(count, 28);
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

/// The low→high carry of the 128-bit byte counter. No test can reach it
/// through the public API (it needs 2^64 bytes of input), so the counter is
/// driven directly; the carry branch would otherwise go unexercised.
#[test]
fn counter_carry() {
    let mut state = State::new(24);

    // No carry below 2^64.
    state.count(128);
    assert_eq!((state.t_lo, state.t_hi), (128, 0));

    // Exactly reaching 2^64 wraps the low word to zero and carries once.
    state.t_lo = u64::MAX;
    state.t_hi = 0;
    state.count(1);
    assert_eq!((state.t_lo, state.t_hi), (0, 1));

    // Crossing 2^64 keeps the remainder in the low word.
    state.t_lo = u64::MAX - 2;
    state.t_hi = 7;
    state.count(10);
    assert_eq!((state.t_lo, state.t_hi), (7, 8));

    // The boundary case just below the wrap must not carry.
    state.t_lo = u64::MAX - 128;
    state.t_hi = 0;
    state.count(128);
    assert_eq!((state.t_lo, state.t_hi), (u64::MAX, 0));

    // The high word wraps rather than panicking (unreachable: 2^128 bytes).
    state.t_lo = u64::MAX;
    state.t_hi = u64::MAX;
    state.count(1);
    assert_eq!((state.t_lo, state.t_hi), (0, 0));
}

/// `Default` must construct the same hasher as `new`.
#[test]
fn default_matches_new() {
    let mut hasher = Blake2b192::default();
    hasher.update(b"abc");
    assert_eq!(hasher.finalize(), hash(b"abc"));
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
