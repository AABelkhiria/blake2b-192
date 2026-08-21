//! The committed BLAKE2b-192 corpus, dual-endorsed at generation time by
//! libsodium and CPython hashlib (see the data file's provenance header):
//! every length 0..=257, multi-block boundaries, large messages, all-zero,
//! all-0xff, repeating and seeded pseudo-random patterns.

mod common;

#[test]
fn dual_endorsed_kat24_corpus() {
    let data = include_str!("data/blake2b192_kat.txt");
    let fixtures = common::parse_fixtures(data);
    assert_eq!(fixtures.len(), 410);
    for (spec, expected) in fixtures {
        let msg = common::build_message(spec);
        assert_eq!(&blake2b_192::hash(&msg)[..], &expected[..], "spec {spec}");
    }
}
