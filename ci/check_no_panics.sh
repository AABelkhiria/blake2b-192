#!/usr/bin/env bash
#
# `SECURITY.md` claims the API cannot panic on any input.

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=thumbv7em-none-eabi

cargo build --release --lib --locked --target "$TARGET"

RLIB=$(ls target/"$TARGET"/release/libblake2b_192.rlib)

FOUND=$(nm -u "$RLIB" 2>/dev/null | grep -Ei 'panic|_fail|unwrap|expect_failed' || true)

if [ -n "$FOUND" ]; then
    echo "ERROR: the optimized no_std build retains panicking paths:"
    echo "$FOUND"
    exit 1
fi

echo "OK: no panicking paths in the optimized $TARGET build"
