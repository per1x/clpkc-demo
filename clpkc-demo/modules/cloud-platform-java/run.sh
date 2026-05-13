#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
bash "$SCRIPT_DIR/build.sh"
cd "$SCRIPT_DIR"
exec java -cp out demo.clpkc.cloud.CloudPlatformServer "$@"
