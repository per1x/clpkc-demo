#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
MODULES_DIR="$ROOT_DIR/modules"

echo "[构建] 检查当前环境依赖版本。"
bash "$SCRIPT_DIR/check-deps.sh"

echo "[构建] 生成 KGC 开发证书。"
bash "$MODULES_DIR/kgc-java/gen-dev-cert.sh"
echo "[构建] 编译 KGC Java 模块。"
bash "$MODULES_DIR/kgc-java/build.sh"
echo "[构建] 编译 Cloud Java 模块。"
bash "$MODULES_DIR/cloud-platform-java/build.sh"
echo "[构建] 编译 Charging Pile C++ 模块。"
bash "$MODULES_DIR/charging-pile-cpp/build.sh"

echo "[构建] 全部模块构建完成。"
