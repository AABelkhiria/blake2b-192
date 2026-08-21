#!/usr/bin/env python3
"""Generate BLAKE2b vector fixtures dual-endorsed by two independent
implementations: libsodium (via ctypes) and CPython's hashlib.blake2b.
Generation aborts on any disagreement, so every committed line is endorsed by
both.

Outputs (committed to the repository):

- tests/data/blake2b192_kat.txt — unkeyed BLAKE2b with digest_length=24 over
  a deterministic corpus. Format: "<spec> <48-hex-digest>", where <spec>
  describes how to rebuild the message:
      kat:<len>            bytes 00 01 02 ... (i % 256)
      zero:<len>           0x00 repeated
      ff:<len>             0xff repeated
      rep:<hexpat>:<len>   <hexpat> bytes repeated, truncated to <len>
      rng:<seed>:<len>     SplitMix64(seed) output, little-endian u64 stream
- tests/data/multilen_kat.txt — unkeyed BLAKE2b at digest lengths
  {20, 32, 48, 64} over kat-pattern messages, pinning digest-length
  parameterization at other lengths (the RFC 7693 Appendix E self-test
  lengths). Format: "<outlen> <msglen> <hex-digest>".

Usage: python3 vectors/generate/gen_vectors.py
"""

import ctypes
import ctypes.util
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA = ROOT / "tests" / "data"


def load_sodium():
    candidates = [
        "/opt/homebrew/lib/libsodium.dylib",
        "/usr/local/lib/libsodium.dylib",
        ctypes.util.find_library("sodium"),
    ]
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
        except OSError:
            continue
        if lib.sodium_init() < 0:
            sys.exit("sodium_init failed")
        lib.sodium_version_string.restype = ctypes.c_char_p
        lib.crypto_generichash_blake2b.restype = ctypes.c_int
        lib.crypto_generichash_blake2b.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,  # outlen
            ctypes.c_char_p,
            ctypes.c_ulonglong,  # inlen
            ctypes.c_char_p,
            ctypes.c_size_t,  # keylen
        ]
        return lib
    sys.exit("libsodium not found")


SODIUM = load_sodium()


def sodium_blake2b(msg, outlen):
    out = ctypes.create_string_buffer(outlen)
    rc = SODIUM.crypto_generichash_blake2b(out, outlen, msg, len(msg), None, 0)
    if rc != 0:
        sys.exit("crypto_generichash_blake2b failed")
    return out.raw


def dual_digest(msg, outlen):
    """Digest endorsed by both libsodium and hashlib, or abort."""
    a = sodium_blake2b(msg, outlen)
    b = hashlib.blake2b(msg, digest_size=outlen).digest()
    if a != b:
        sys.exit(f"oracle disagreement at outlen={outlen}, len={len(msg)}")
    return a.hex()


class SplitMix64:
    def __init__(self, seed):
        self.x = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self):
        self.x = (self.x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.x
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)


def build_message(spec):
    parts = spec.split(":")
    kind = parts[0]
    if kind == "kat":
        n = int(parts[1])
        return bytes(i & 0xFF for i in range(n))
    if kind == "zero":
        return bytes(int(parts[1]))
    if kind == "ff":
        return b"\xff" * int(parts[1])
    if kind == "rep":
        pat, n = bytes.fromhex(parts[1]), int(parts[2])
        return (pat * (n // len(pat) + 1))[:n]
    if kind == "rng":
        seed, n = int(parts[1]), int(parts[2])
        rng = SplitMix64(seed)
        out = bytearray()
        while len(out) < n:
            out += rng.next_u64().to_bytes(8, "little")
        return bytes(out[:n])
    sys.exit(f"bad spec {spec}")


BOUNDARIES = [0, 1, 2, 63, 64, 65, 126, 127, 128, 129, 130, 254, 255, 256, 257, 384, 1024]


def corpus():
    specs = []
    # Every length through two blocks, then multi-block boundaries and large.
    for n in list(range(258)) + [383, 384, 385, 511, 512, 513, 1024, 4096, 65536, 1048576]:
        specs.append(f"kat:{n}")
    for n in BOUNDARIES:
        specs.append(f"zero:{n}")
        specs.append(f"ff:{n}")
    for n in [5, 127, 128, 129, 300, 1000]:
        specs.append(f"rep:deadbeef:{n}")
    # Seeded pseudo-random messages across diverse lengths.
    for seed in range(1, 101):
        specs.append(f"rng:{seed}:{1 + (seed * 97) % 700}")
    specs.append("rng:1000:10000")
    specs.append("rng:1001:100000")
    return specs


def provenance_header(what, fmt):
    sodium_version = SODIUM.sodium_version_string().decode()
    py = "%d.%d.%d" % sys.version_info[:3]
    return (
        f"# {what}\n"
        f"# Dual-endorsed at generation time by libsodium {sodium_version}\n"
        f"# (crypto_generichash_blake2b via ctypes) and CPython {py}\n"
        "# hashlib.blake2b; generation aborts on any disagreement.\n"
        "# Regenerate with: python3 vectors/generate/gen_vectors.py\n"
        f"# Format: {fmt}\n"
    )


def main():
    DATA.mkdir(parents=True, exist_ok=True)

    specs = corpus()
    with open(DATA / "blake2b192_kat.txt", "w") as f:
        f.write(provenance_header(
            "Unkeyed BLAKE2b, digest_length = 24 (parameterized, not truncated).",
            "<message-spec> <blake2b-192-hex-digest>",
        ))
        for spec in specs:
            f.write(f"{spec} {dual_digest(build_message(spec), 24)}\n")
    print(f"wrote {len(specs)} vectors to {DATA / 'blake2b192_kat.txt'}")

    outlens = [20, 32, 48, 64]
    msglens = [0, 3, 64, 128, 129, 255, 1024]
    with open(DATA / "multilen_kat.txt", "w") as f:
        f.write(provenance_header(
            "Unkeyed BLAKE2b at other digest lengths, over kat-pattern messages.",
            "<outlen> <msglen> <hex-digest>",
        ))
        for outlen in outlens:
            for msglen in msglens:
                digest = dual_digest(build_message(f"kat:{msglen}"), outlen)
                f.write(f"{outlen} {msglen} {digest}\n")
    print(f"wrote {len(outlens) * len(msglens)} vectors to {DATA / 'multilen_kat.txt'}")


if __name__ == "__main__":
    main()
