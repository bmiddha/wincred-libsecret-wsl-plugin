#!/usr/bin/env bash
set -euo pipefail

git fetch --tags --force
python3 scripts/release/test-release-change.py
cargo metadata --locked --format-version 1 --no-deps >/dev/null
