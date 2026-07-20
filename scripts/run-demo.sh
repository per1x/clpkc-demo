#!/usr/bin/env bash
# 一键联调：启动 KGC(HTTP) + Cloud(Socket) 并运行充电桩客户端一次。
# 需要：JDK17 (JAVA_HOME)、已 mvn package、已 cmake 构建 charging-pile。
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
RUN_DIR="${RUN_DIR:-${TMPDIR:-/tmp}/clpkc-run}"
# JDK17 定位（跨平台，不写死路径）：按候选顺序取第一个主版本 >= 17 的 java。
# 注意 macOS 的 `java_home -v 17` 在没有 17 时会回退到其它版本，故一律实测版本号。
java_major() {  # <java-bin> -> 主版本号（Java 8 输出 "1.8.0_x" 归一化为 8）
  [ -x "$1" ] || return 1
  "$1" -version 2>&1 | head -1 \
    | sed -E 's/.*version "([0-9]+)\.?([0-9]*).*/\1 \2/' \
    | awk '{print ($1==1)?$2:$1}'
}
JAVA=""
for cand in \
  "${JAVA_HOME:-}/bin/java" \
  "$([ -x /usr/libexec/java_home ] && /usr/libexec/java_home -v 17 2>/dev/null)/bin/java" \
  /opt/homebrew/opt/openjdk@17/bin/java \
  /usr/lib/jvm/java-17-openjdk-*/bin/java \
  "$(command -v java || true)"; do
  m="$(java_major "$cand" 2>/dev/null || true)"
  if [ -n "$m" ] && [ "$m" -ge 17 ] 2>/dev/null; then JAVA="$cand"; break; fi
done
if [ -z "$JAVA" ]; then
  echo "[脚本] 未找到 JDK 17+（本项目 jar 需要 JDK 17+）。请设置 JAVA_HOME 指向 JDK17 后重试。"
  exit 1
fi
echo "[脚本] 使用 JDK: $JAVA (major $(java_major "$JAVA"))"
mkdir -p "$RUN_DIR"

KGC_JAR="$ROOT/kgc-service/target/kgc-service.jar"
CLOUD_JAR="$ROOT/cloud-service/target/cloud-service.jar"
PILE_BIN="$ROOT/charging-pile/build/charging_pile"

KGC_PID=""; CLOUD_PID=""
cleanup() {
  [ -n "$CLOUD_PID" ] && kill "$CLOUD_PID" 2>/dev/null
  [ -n "$KGC_PID" ] && kill "$KGC_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_for() {  # <file> <pattern> <timeout_s>
  local f="$1" p="$2" t="${3:-40}" i=0
  while [ "$i" -lt "$t" ]; do
    grep -q "$p" "$f" 2>/dev/null && return 0
    sleep 1; i=$((i+1))
  done
  echo "[脚本] 等待超时: $p"; tail -20 "$f"; return 1
}

echo "[脚本] 启动 KGC ..."
"$JAVA" -jar "$KGC_JAR" > "$RUN_DIR/kgc.log" 2>&1 &
KGC_PID=$!
wait_for "$RUN_DIR/kgc.log" "Started KgcApplication" 40 || exit 1
echo "[脚本] KGC 就绪。"

echo "[脚本] 启动 Cloud ..."
"$JAVA" -jar "$CLOUD_JAR" > "$RUN_DIR/cloud.log" 2>&1 &
CLOUD_PID=$!
wait_for "$RUN_DIR/cloud.log" "TCP Socket 服务已启动" 40 || exit 1
echo "[脚本] Cloud 就绪。"

echo "[脚本] 运行充电桩客户端 ..."
( cd "$ROOT/charging-pile" && "$PILE_BIN" config/pile.conf ) 2>&1 | tee "$RUN_DIR/pile.log"

echo; echo "===== Cloud 关键日志 ====="
grep -E "HMAC|会话密钥|签名|KGC|身份就绪" "$RUN_DIR/cloud.log" | tail -20
echo; echo "===== KGC 关键日志 ====="
grep -E "颁发|主公钥|部分私钥" "$RUN_DIR/kgc.log" | tail -20
