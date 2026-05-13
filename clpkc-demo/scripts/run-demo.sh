#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
MODULES_DIR="$ROOT_DIR/modules"
LOGS_DIR="$ROOT_DIR/logs"
KGC_DIR="$MODULES_DIR/kgc-java"
CLOUD_DIR="$MODULES_DIR/cloud-platform-java"
PILE_DIR="$MODULES_DIR/charging-pile-cpp"

KGC_LOG="$LOGS_DIR/kgc.log"
CLOUD_LOG="$LOGS_DIR/cloud.log"
PILE_LOG="$LOGS_DIR/pile.log"
KEEP_SERVICES_RUNNING=0

cleanup() {
  if [ "${KEEP_SERVICES_RUNNING:-0}" = "1" ]; then
    echo "[脚本] 按用户选择保留 KGC 和 Cloud 进程继续运行。"
    return 0
  fi
  local closed_any=0
  if [ -n "${CLOUD_PID:-}" ] && kill -0 "$CLOUD_PID" 2>/dev/null; then
    kill "$CLOUD_PID" 2>/dev/null || true
    wait "$CLOUD_PID" 2>/dev/null || true
    closed_any=1
  fi
  if [ -n "${KGC_PID:-}" ] && kill -0 "$KGC_PID" 2>/dev/null; then
    kill "$KGC_PID" 2>/dev/null || true
    wait "$KGC_PID" 2>/dev/null || true
    closed_any=1
  fi
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :8443 )" 2>/dev/null | tail -n +2 | grep -q .; then
      echo "[脚本] 检测到 8443 端口仍被占用，尝试按主类名补充关闭 KGC。"
      pkill -f demo.clpkc.kgc.KgcServer 2>/dev/null || true
      closed_any=1
    fi
    if ss -ltn "( sport = :9000 )" 2>/dev/null | tail -n +2 | grep -q .; then
      echo "[脚本] 检测到 9000 端口仍被占用，尝试按主类名补充关闭 Cloud。"
      pkill -f demo.clpkc.cloud.CloudPlatformServer 2>/dev/null || true
      closed_any=1
    fi
  else
    # 无法检测端口时，仍尝试按主类名兜底关闭，避免外层 shell 退出但 Java 进程残留。
    pkill -f demo.clpkc.kgc.KgcServer 2>/dev/null || true
    pkill -f demo.clpkc.cloud.CloudPlatformServer 2>/dev/null || true
  fi
  if [ "$closed_any" = "1" ]; then
    echo "[脚本] 已关闭 KGC 和 Cloud 服务进程。"
  fi
}

ask_stop_services() {
  local answer="${AUTO_STOP_SERVICES:-}"
  if [ -n "$answer" ]; then
    case "$answer" in
      y|Y|yes|YES|true|TRUE|1)
        echo "[脚本] 检测到 AUTO_STOP_SERVICES=$answer，脚本结束后将自动关闭 KGC 和 Cloud。"
        KEEP_SERVICES_RUNNING=0
        return 0
        ;;
      n|N|no|NO|false|FALSE|0)
        echo "[脚本] 检测到 AUTO_STOP_SERVICES=$answer，脚本结束后将保留 KGC 和 Cloud。"
        KEEP_SERVICES_RUNNING=1
        return 0
        ;;
      *)
        echo "[脚本] 无法识别 AUTO_STOP_SERVICES=$answer，将进入交互式确认。"
        ;;
    esac
  fi

  if [ ! -t 0 ]; then
    echo "[脚本] 当前不是交互终端，默认关闭 KGC 和 Cloud。"
    KEEP_SERVICES_RUNNING=0
    return 0
  fi

  echo
  echo "[脚本] 联调已完成。"
  printf "[脚本] 是否关闭 KGC 和 Cloud 进程？[Y/n]: "
  read -r answer
  case "${answer:-Y}" in
    y|Y|yes|YES|"")
      KEEP_SERVICES_RUNNING=0
      echo "[脚本] 将在脚本退出时关闭所有服务进程。"
      ;;
    n|N|no|NO)
      KEEP_SERVICES_RUNNING=1
      echo "[脚本] 将保留服务进程继续运行。"
      echo "[脚本] KGC 端口: 8443"
      echo "[脚本] Cloud 端口: 9000"
      ;;
    *)
      KEEP_SERVICES_RUNNING=0
      echo "[脚本] 输入无法识别，默认关闭所有服务进程。"
      ;;
  esac
}

check_port() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :$port )" | tail -n +2 | grep -q .; then
      echo "[脚本] 端口 $port 已被占用，请先停止占用该端口的进程。" >&2
      return 1
    fi
  fi
  return 0
}

wait_for_process_or_log() {
  local pid="$1"
  local file="$2"
  local pattern="$3"
  local timeout="${4:-20}"
  local i=0
  while [ "$i" -lt "$timeout" ]; do
    if [ -f "$file" ] && grep -q "$pattern" "$file"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[脚本] 进程提前退出，启动失败。日志如下:" >&2
      if [ -f "$file" ]; then
        cat "$file" >&2
      fi
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "[脚本] 等待日志超时: 未在 $file 中看到关键字 [$pattern]" >&2
  if [ -f "$file" ]; then
    echo "[脚本] 当前日志内容:" >&2
    cat "$file" >&2
  fi
  return 1
}

trap cleanup EXIT INT TERM

mkdir -p "$LOGS_DIR"

check_port 8443
check_port 9000

echo "[脚本] 检查当前环境依赖版本。"
bash "$SCRIPT_DIR/check-deps.sh"

echo "[脚本] 开始构建三端 Demo。"
bash "$SCRIPT_DIR/build-all.sh"
echo "[脚本] 构建完成，开始启动 KGC、Cloud 和 Charging Pile。"

: >"$KGC_LOG"
: >"$CLOUD_LOG"
: >"$PILE_LOG"

(
  cd "$KGC_DIR"
  bash ./run.sh
) >"$KGC_LOG" 2>&1 &
KGC_PID=$!
wait_for_process_or_log "$KGC_PID" "$KGC_LOG" "HTTPS 服务已启动"
echo "[脚本] KGC 已启动。"

(
  cd "$CLOUD_DIR"
  bash ./run.sh
) >"$CLOUD_LOG" 2>&1 &
CLOUD_PID=$!
wait_for_process_or_log "$CLOUD_PID" "$CLOUD_LOG" "TCP Socket 服务已启动"
echo "[脚本] Cloud 已启动。"

(
  cd "$PILE_DIR"
  bash ./run.sh
) | tee "$PILE_LOG"

sleep 1

echo
echo "===== KGC 日志 ====="
cat "$KGC_LOG"
echo
echo "===== Cloud 日志 ====="
cat "$CLOUD_LOG"
echo
echo "===== Charging Pile 日志 ====="
cat "$PILE_LOG"

ask_stop_services
