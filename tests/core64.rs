//! Public-API twin of the 64-byte core suites (0.1.1 core export): RFC 7693
//! Appendix A and the 256 official BLAKE2b-512 known answers, through
//! `engine::Blake2bCore::new(64)`. The unit tests already run these vectors
//! in-crate; this file pins them to the *exported* type, so the surface
//! other crates consume is validated by the same vectors that justified it.

mod common;

use blake2b_192::engine::Blake2bCore;

fn blake2b512(msg: &[u8]) -> [u8; 64] {
    let mut core = Blake2bCore::new(64).expect("64 is a valid digest length");
    core.update(msg);
    core.finalize()
}

/// RFC 7693 Appendix A: BLAKE2b-512("abc") — the authoritative spec vector.
#[test]
fn rfc7693_appendix_a_blake2b512_abc() {
    let expected = common::hex_decode(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
    assert_eq!(blake2b512(b"abc")[..], expected[..]);
}

/// All 256 official unkeyed BLAKE2b-512 KATs (inputs 00 01 02 ... of lengths
/// 0..=255) through the public core. See the data file's provenance header.
#[test]
fn official_unkeyed_kat64() {
    let data = include_str!("data/official_blake2b_kat64.txt");
    let mut count = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        let (len, digest) = line.split_once(' ').expect("malformed line");
        let len: usize = len.parse().expect("bad length");
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let expected = common::hex_decode(digest);
        assert_eq!(blake2b512(&msg)[..], expected[..], "input length {len}");
        count += 1;
    }
    assert_eq!(count, 256);
}

/// Chunked updates through the public core equal the one-shot digest
/// (split across the first block boundary, like the headline API's test).
#[test]
fn streaming_matches_one_shot() {
    let msg: Vec<u8> = (0..300).map(|i| (i * 7) as u8).collect();
    let expected = blake2b512(&msg);
    for split in [0, 1, 127, 128, 129, 255, 256, 300] {
        let mut core = Blake2bCore::new(64).expect("64 is a valid digest length");
        core.update(&msg[..split]);
        core.update(&msg[split..]);
        assert_eq!(core.finalize()[..], expected[..], "split at {split}");
    }
}
