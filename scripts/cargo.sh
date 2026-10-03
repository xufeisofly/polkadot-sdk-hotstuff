#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_HOME="$PWD/.cache/cargo"
export CARGO_TARGET_DIR="$PWD/target"
if [[ $(uname -s) == Darwin && -d /opt/homebrew/opt/llvm/lib ]]; then
  export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib
  export DYLD_LIBRARY_PATH="/opt/homebrew/opt/llvm/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi
exec cargo "$@"
