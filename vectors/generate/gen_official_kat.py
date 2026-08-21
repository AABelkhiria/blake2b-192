#!/usr/bin/env python3
"""Extract the unkeyed BLAKE2b (64-byte digest) vectors from the official
BLAKE2 KAT JSON into tests/data/official_blake2b_kat64.txt.

Source: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
(entries with hash == "blake2b" and an empty key). The official inputs are the
byte sequence 00 01 02 ... of lengths 0..255; this is verified, so the output
file only stores "<len> <128-hex-digest>" lines. Every digest is additionally
cross-checked against CPython's independent hashlib.blake2b implementation
before being written.

Usage: python3 vectors/generate/gen_official_kat.py
"""

import hashlib
import json
import pathlib
import sys
import urllib.request

URL = "https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json"
OUT = pathlib.Path(__file__).resolve().parents[2] / "tests" / "data" / "official_blake2b_kat64.txt"


def main():
    with urllib.request.urlopen(URL) as resp:
        data = json.load(resp)

    entries = [e for e in data if e["hash"] == "blake2b" and e["key"] == ""]
    if len(entries) != 256:
        sys.exit(f"expected 256 unkeyed blake2b entries, found {len(entries)}")

    lines = []
    for i, entry in enumerate(entries):
        msg = bytes.fromhex(entry["in"])
        if msg != bytes(range(i)):
            sys.exit(f"entry {i}: input is not the expected 00 01 02 ... pattern")
        digest = entry["out"]
        if len(digest) != 128:
            sys.exit(f"entry {i}: not a 64-byte digest")
        if hashlib.blake2b(msg).hexdigest() != digest:
            sys.exit(f"entry {i}: official digest disagrees with hashlib.blake2b")
        lines.append(f"{len(msg)} {digest}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as f:
        f.write(
            "# Official unkeyed BLAKE2b-512 known-answer tests.\n"
            f"# Source: {URL}\n"
            "# Inputs are the byte sequence 00 01 02 ... of the given length.\n"
            "# Each digest was cross-checked against CPython hashlib.blake2b at\n"
            "# extraction time. Regenerate with: python3 vectors/generate/gen_official_kat.py\n"
            "# Format: <input-len> <blake2b-512-hex-digest>\n"
        )
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} vectors to {OUT}")


if __name__ == "__main__":
    main()
