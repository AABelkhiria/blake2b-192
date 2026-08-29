//! Public-API twin of the multi-length parameterization suite (0.1.1 core export):
//! the dual-endorsed `multilen_kat.txt` vectors through `engine::Blake2bCore::new(len)`
//! for every length the file covers. Variable 1..=64-byte final digests are exactly the
//! contract downstream constructions build on.

mod common;

use std::collections::BTreeSet;

use blake2b_192::engine::Blake2bCore;

/// Digest-length parameterization at 20, 32, 48, and 64 bytes (the RFC 7693
/// self-test lengths), dual-endorsed fixtures from libsodium and hashlib,
/// through the public core. A digest of length `nn` is the first `nn` bytes
/// of `finalize`.
#[test]
fn multi_length_parameterization() {
    let data = include_str!("data/multilen_kat.txt");
    let mut count = 0;
    let mut lengths = BTreeSet::new();
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split(' ');
        let outlen: usize = fields.next().unwrap().parse().unwrap();
        let msglen: usize = fields.next().unwrap().parse().unwrap();
        let expected = common::hex_decode(fields.next().unwrap());
        let msg: Vec<u8> = (0..msglen).map(|i| i as u8).collect();
        let mut core = Blake2bCore::new(outlen).expect("KAT digest lengths are valid");
        core.update(&msg);
        assert_eq!(
            core.finalize()[..outlen],
            expected[..],
            "outlen {outlen}, msglen {msglen}"
        );
        lengths.insert(outlen);
        count += 1;
    }
    assert_eq!(count, 28);
    assert_eq!(lengths, BTreeSet::from([20, 32, 48, 64]));
}

/// `new` is total over the digest length: `Some` iff 1..=64.
#[test]
fn digest_length_bounds() {
    assert!(Blake2bCore::new(0).is_none());
    assert!(Blake2bCore::new(65).is_none());
    assert!(Blake2bCore::new(usize::MAX).is_none());
    assert!(Blake2bCore::new(1).is_some());
    assert!(Blake2bCore::new(24).is_some());
    assert!(Blake2bCore::new(64).is_some());
}

/// The core at digest length 24 computes the headline function: the
/// reimplementation of `Blake2b192` over the exported type changed nothing.
#[test]
fn core_at_24_is_the_headline_api() {
    for msg in [
        &b""[..],
        b"abc",
        &[0u8; 128],
        &(0..300).map(|i| (i * 7) as u8).collect::<Vec<u8>>(),
    ] {
        let mut core = Blake2bCore::new(24).expect("24 is a valid digest length");
        core.update(msg);
        assert_eq!(core.finalize()[..24], blake2b_192::hash(msg)[..]);
    }
}
