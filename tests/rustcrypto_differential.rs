//! Differential fixtures produced by RustCrypto blake2 0.11.0-rc.6
//! (`Blake2b::<U24>::digest`) — the exact implementation this crate replaces
//! — over the same corpus as the dual-endorsed KAT file. Generated
//! out-of-tree from the pinned reference/hashes submodule so the prerelease
//! crate never enters this crate's dependency graph.

mod common;

#[test]
fn rustcrypto_differential_corpus() {
    let data = include_str!("data/rustcrypto_blake2b192.txt");
    let fixtures = common::parse_fixtures(data);
    assert_eq!(fixtures.len(), 410);
    for (spec, expected) in fixtures {
        let msg = common::build_message(spec);
        assert_eq!(&blake2b_192::hash(&msg)[..], &expected[..], "spec {spec}");
    }
}

/// The two independently produced fixture files must themselves agree —
/// oracle consistency across libsodium, hashlib, and RustCrypto.
#[test]
fn fixture_files_agree() {
    let kat = common::parse_fixtures(include_str!("data/blake2b192_kat.txt"));
    let rc = common::parse_fixtures(include_str!("data/rustcrypto_blake2b192.txt"));
    assert_eq!(kat, rc);
}
