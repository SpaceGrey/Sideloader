#!/bin/bash
# Build a Sideloader CLI that actually runs on macOS 15+.
# Official 1.0-pre4 and LDC 1.34/1.40 static binaries SIGSEGV in pthread_getspecific
# before main. LDC 1.41 + shared druntime works. LDC 1.42 hits an LDC ICE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
LDC_ACTIVATE="${LDC_ACTIVATE:-$HOME/dlang/ldc-1.41.0/activate}"
if [[ ! -f "$LDC_ACTIVATE" ]]; then
  echo "Install LDC 1.41.0 first:"
  echo "  curl -fsS https://dlang.org/install.sh | bash -s ldc-1.41.0"
  exit 1
fi
# shellcheck disable=SC1090
source "$LDC_ACTIVATE"
cd "$ROOT/frontends/cli"
dub build --compiler=ldc2 --build=release
BIN="$ROOT/bin/sideloader"
chmod +x "$BIN" "$ROOT/sideloader"
echo "built $BIN (run via $ROOT/sideloader)"
otool -L "$BIN"
"$ROOT/sideloader" --help
