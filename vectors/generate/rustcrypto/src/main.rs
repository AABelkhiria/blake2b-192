//! Reads the corpus specs from tests/data/blake2b192_kat.txt (ignoring the
//! digests there), hashes each message with RustCrypto
//! `Blake2b::<U24>::digest` at the pinned reference version, and writes
//! tests/data/rustcrypto_blake2b192.txt.
//!
//! Message building must match vectors/generate/gen_vectors.py and
//! tests/common/mod.rs; any mismatch shows up as a digest disagreement in the
//! differential test, so it cannot pass silently.

use blake2::{Blake2b, Digest, digest::consts::U24};
use std::fmt::Write as _;
use std::path::Path;

struct SplitMix64 {
    x: u64,
}

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.x = self.x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn build_message(spec: &str) -> Vec<u8> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        ["kat", n] => {
            let n: usize = n.parse().unwrap();
            (0..n).map(|i| i as u8).collect()
        }
        ["zero", n] => vec![0u8; n.parse().unwrap()],
        ["ff", n] => vec![0xffu8; n.parse().unwrap()],
        ["rep", pat, n] => {
            let n: usize = n.parse().unwrap();
            let pat: Vec<u8> = (0..pat.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&pat[i..i + 2], 16).unwrap())
                .collect();
            pat.iter().copied().cycle().take(n).collect()
        }
        ["rng", seed, n] => {
            let mut rng = SplitMix64 {
                x: seed.parse().unwrap(),
            };
            let n: usize = n.parse().unwrap();
            let mut out = Vec::with_capacity(n + 8);
            while out.len() < n {
                out.extend_from_slice(&rng.next_u64().to_le_bytes());
            }
            out.truncate(n);
            out
        }
        _ => panic!("bad message spec: {spec}"),
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let corpus = std::fs::read_to_string(root.join("tests/data/blake2b192_kat.txt")).unwrap();

    let mut out = String::from(
        "# Unkeyed BLAKE2b-192 differential fixtures from RustCrypto\n\
         # blake2 0.11.0 (Blake2b::<U24>::digest), built from the pinned\n\
         # submodule reference/hashes @ tag blake2-v0.11.0.\n\
         # Same corpus as blake2b192_kat.txt. Regenerate with:\n\
         #   cargo run --release --manifest-path vectors/generate/rustcrypto/Cargo.toml\n\
         # Format: <message-spec> <blake2b-192-hex-digest>\n",
    );
    let mut count = 0;
    for line in corpus
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (spec, _) = line.split_once(' ').unwrap();
        let digest = Blake2b::<U24>::digest(build_message(spec));
        let mut hex = String::with_capacity(48);
        for byte in digest {
            write!(hex, "{byte:02x}").unwrap();
        }
        writeln!(out, "{spec} {hex}").unwrap();
        count += 1;
    }

    let path = root.join("tests/data/rustcrypto_blake2b192.txt");
    std::fs::write(&path, out).unwrap();
    println!("wrote {count} fixtures to {}", path.display());
}
