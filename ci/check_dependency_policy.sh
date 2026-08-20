#!/usr/bin/env bash
# Dependency policy, checked from cargo metadata (never from eyeballing
# `cargo tree`), over every dependency kind — normal, dev, build, transitive:
#
#   1. the resolved graph must contain exactly this crate (zero
#      dependencies); relaxing this is a deliberate decision that includes
#      updating this script;
#   2. defense in depth: no semver prerelease version may appear anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo metadata --format-version 1 --locked |
python3 -c '
import json, sys

meta = json.load(sys.stdin)
names = sorted(p["name"] for p in meta["packages"])

bad = []
for pkg in meta["packages"]:
    # semver: prerelease is the "-..." part, which precedes any "+build" part
    core = pkg["version"].split("+", 1)[0]
    if "-" in core:
        bad.append(pkg["name"] + " " + pkg["version"])

if bad:
    print("ERROR: prerelease versions in the dependency graph:")
    for b in sorted(bad):
        print("  " + b)
    sys.exit(1)

if names != ["blake2b-192"]:
    print("ERROR: the dependency graph must contain only blake2b-192, found: "
          + ", ".join(names))
    sys.exit(1)

print("OK: dependency graph is exactly blake2b-192; zero dependencies, none prerelease")
'
