#!/usr/bin/env bash
set -euo pipefail

BIN="./target/debug/{{APP_NAME}}"
if [ ! -x "$BIN" ]; then
  echo "Building {{APP_NAME}} (debug)"
  cargo build
fi

exec "$BIN" --config config.toml "$@"
