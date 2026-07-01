#!/usr/bin/env bash
# 构建三端：KGC / Cloud 各自独立的 Maven 工程 + C++ 充电桩。
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"

# JDK 17
if [ -z "${JAVA_HOME:-}" ]; then
  if [ -x /opt/homebrew/opt/openjdk@17/bin/java ]; then
    export JAVA_HOME=/opt/homebrew/opt/openjdk@17
  fi
fi
echo "[构建] JAVA_HOME=${JAVA_HOME:-(system)}"

echo "[构建] 打包 KGC（含单测）..."
mvn -f "$ROOT/kgc-service/pom.xml" clean package

echo "[构建] 打包 Cloud ..."
mvn -f "$ROOT/cloud-service/pom.xml" clean package

echo "[构建] CMake 构建充电桩..."
cmake -S "$ROOT/charging-pile" -B "$ROOT/charging-pile/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/charging-pile/build"

echo "[构建] 完成。"
echo "  KGC   jar: $ROOT/kgc-service/target/kgc-service.jar"
echo "  Cloud jar: $ROOT/cloud-service/target/cloud-service.jar"
echo "  Pile  bin: $ROOT/charging-pile/build/charging_pile"
