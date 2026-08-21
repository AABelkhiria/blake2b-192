//! Shared helpers for fixture-driven integration tests: message-spec parsing
//! matching vectors/generate/gen_vectors.py, and the SplitMix64 PRNG used for
//! `rng:` specs (any implementation mismatch fails the digest comparison, so
//! it cannot silently weaken the tests).

#![allow(dead_code)]

pub struct SplitMix64 {
    x: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { x: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.x = self.x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Rebuilds a corpus message from its spec (see gen_vectors.py for the
/// grammar).
pub fn build_message(spec: &str) -> Vec<u8> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        ["kat", n] => {
            let n: usize = n.parse().unwrap();
            (0..n).map(|i| i as u8).collect()
        }
        ["zero", n] => vec![0u8; n.parse().unwrap()],
        ["ff", n] => vec![0xffu8; n.parse().unwrap()],
        ["rep", pat, n] => {
            let pat = hex_decode(pat);
            let n: usize = n.parse().unwrap();
            pat.iter().copied().cycle().take(n).collect()
        }
        ["rng", seed, n] => {
            let mut rng = SplitMix64::new(seed.parse().unwrap());
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

pub fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Parses "<spec> <hex-digest>" fixture lines, skipping '#' comments.
pub fn parse_fixtures(text: &str) -> Vec<(&str, Vec<u8>)> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (spec, digest) = l.split_once(' ').expect("malformed fixture line");
            (spec, hex_decode(digest))
        })
        .collect()
}
