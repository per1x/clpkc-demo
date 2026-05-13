#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$SCRIPT_DIR/out"
javac -encoding UTF-8 -d "$SCRIPT_DIR/out" $(find "$SCRIPT_DIR/src" -name "*.java" | sort)
