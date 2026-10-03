#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/cargo.sh clean
python3 scripts/clean.py
