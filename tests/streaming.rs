//! Streaming equivalence: hashing a message through the streaming API in any
//! chunking must equal the one-shot digest — fixed chunk sizes around the
//! 128-byte block boundary, seeded random chunkings, and explicit final-block
//! patterns.

mod common;

use blake2b_192::{Blake2b192, hash};
use common::SplitMix64;

const CHUNK_SIZES: &[usize] = &[1, 2, 3, 7, 8, 16, 31, 32, 63, 64, 127, 128, 129, 255, 256];

/// Message lengths spanning empty, sub-block, exact-block, and multi-block
/// cases, including every boundary the corpus singles out.
const MSG_LENS: &[usize] = &[
    0, 1, 2, 63, 64, 65, 126, 127, 128, 129, 130, 254, 255, 256, 257, 383, 384, 385, 511, 512, 513,
    1024, 4096, 65536,
];

fn message(len: usize) -> Vec<u8> {
    let mut rng = SplitMix64::new(len as u64 + 0xB2B);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn fixed_chunk_sizes() {
    for &len in MSG_LENS {
        let msg = message(len);
        let expected = hash(&msg);
        for &chunk in CHUNK_SIZES {
            let mut hasher = Blake2b192::new();
            for part in msg.chunks(chunk.max(1)) {
                hasher.update(part);
            }
            assert_eq!(hasher.finalize(), expected, "len {len}, chunk size {chunk}");
        }
    }
}

#[test]
fn randomized_chunk_boundaries() {
    let mut rng = SplitMix64::new(0x5EED);
    for &len in MSG_LENS {
        let msg = message(len);
        let expected = hash(&msg);
        for round in 0..20 {
            let mut hasher = Blake2b192::new();
            let mut pos = 0;
            while pos < msg.len() {
                // Chunk sizes biased toward the block size so boundaries are
                // crossed in many different phases.
                let take = 1 + (rng.next_u64() as usize) % 200;
                let take = take.min(msg.len() - pos);
                hasher.update(&msg[pos..pos + take]);
                pos += take;
            }
            assert_eq!(hasher.finalize(), expected, "len {len}, round {round}");
        }
    }
}

/// Final-block edge patterns: updates ending exactly on block boundaries, a
/// full block followed by nothing, a full block followed by one byte, and
/// interleaved empty updates.
#[test]
fn final_block_patterns() {
    let msg = message(4 * 128 + 1);

    for &cut in &[128usize, 256, 384, 512, 513] {
        let mut hasher = Blake2b192::new();
        hasher.update(&msg[..cut]);
        hasher.update(&msg[cut..]);
        assert_eq!(hasher.finalize(), hash(&msg), "cut at {cut}");
    }

    let block = &msg[..128];
    let mut hasher = Blake2b192::new();
    hasher.update(block);
    assert_eq!(hasher.finalize(), hash(block), "exactly one block");

    let mut hasher = Blake2b192::new();
    hasher.update(block);
    hasher.update(&msg[128..129]);
    assert_eq!(hasher.finalize(), hash(&msg[..129]), "block plus one byte");

    let mut hasher = Blake2b192::new();
    hasher.update(&[]);
    hasher.update(block);
    hasher.update(&[]);
    hasher.update(&[]);
    hasher.update(&msg[128..256]);
    hasher.update(&[]);
    assert_eq!(
        hasher.finalize(),
        hash(&msg[..256]),
        "empty updates around full blocks"
    );
}
