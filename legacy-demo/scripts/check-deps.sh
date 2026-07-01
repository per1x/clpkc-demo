#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
MODULES_DIR="$ROOT_DIR/modules"

status=0

print_title() {
  echo
  echo "===== $1 ====="
}

check_cmd() {
  local name="$1"
  local cmd="$2"
  local version_cmd="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[依赖] 已找到 $name: $(command -v "$cmd")"
    bash -lc "$version_cmd" 2>&1 | head -n 2 | sed 's/^/[版本] /'
  else
    echo "[依赖] 未找到 $name ($cmd)" >&2
    status=1
  fi
}

check_file() {
  local label="$1"
  local path="$2"
  if [ -f "$path" ]; then
    echo "[依赖] 已找到 $label: $path"
  else
    echo "[依赖] 未找到 $label: $path" >&2
    status=1
  fi
}

print_title "基础命令"
check_cmd "Java 运行时" java "java -version"
check_cmd "Java 编译器" javac "javac -version"
check_cmd "证书工具" keytool "keytool -help | head -n 1"
check_cmd "CMake" cmake "cmake --version"

if command -v c++ >/dev/null 2>&1; then
  echo "[依赖] 已找到 C++ 编译器: $(command -v c++)"
  c++ --version 2>&1 | head -n 2 | sed 's/^/[版本] /'
elif command -v g++ >/dev/null 2>&1; then
  echo "[依赖] 已找到 g++ 编译器: $(command -v g++)"
  g++ --version 2>&1 | head -n 2 | sed 's/^/[版本] /'
else
  echo "[依赖] 未找到 C++ 编译器 (c++/g++)" >&2
  status=1
fi

print_title "OpenSSL 运行时"
if command -v openssl >/dev/null 2>&1; then
  echo "[依赖] 已找到 openssl: $(command -v openssl)"
  openssl version 2>&1 | sed 's/^/[版本] /'
else
  echo "[依赖] 未找到 openssl 命令" >&2
  status=1
fi

openssl_include_dir="${OPENSSL_INCLUDE_DIR:-}"
openssl_ssl_lib="${OPENSSL_SSL_LIBRARY:-}"
openssl_crypto_lib="${OPENSSL_CRYPTO_LIBRARY:-}"

if [ -z "$openssl_include_dir" ]; then
  for dir in /usr/include /usr/local/include /usr/include/node; do
    if [ -f "$dir/openssl/ssl.h" ]; then
      openssl_include_dir="$dir"
      break
    fi
  done
fi

if [ -z "$openssl_ssl_lib" ]; then
  openssl_ssl_lib="$(find /usr/lib /usr/local/lib /lib -name 'libssl.so' -o -name 'libssl.so.*' 2>/dev/null | sort | head -n 1 || true)"
fi

if [ -z "$openssl_crypto_lib" ]; then
  openssl_crypto_lib="$(find /usr/lib /usr/local/lib /lib -name 'libcrypto.so' -o -name 'libcrypto.so.*' 2>/dev/null | sort | head -n 1 || true)"
fi

if [ -n "$openssl_include_dir" ]; then
  echo "[依赖] OpenSSL 头文件目录: $openssl_include_dir"
else
  echo "[依赖] 未找到 OpenSSL 头文件目录，可设置 OPENSSL_INCLUDE_DIR" >&2
  status=1
fi

if [ -n "$openssl_ssl_lib" ]; then
  echo "[依赖] OpenSSL SSL 库路径: $openssl_ssl_lib"
else
  echo "[依赖] 未找到 libssl，可设置 OPENSSL_SSL_LIBRARY" >&2
  status=1
fi

if [ -n "$openssl_crypto_lib" ]; then
  echo "[依赖] OpenSSL Crypto 库路径: $openssl_crypto_lib"
else
  echo "[依赖] 未找到 libcrypto，可设置 OPENSSL_CRYPTO_LIBRARY" >&2
  status=1
fi

print_title "项目关键文件"
check_file "KGC 证书脚本" "$MODULES_DIR/kgc-java/gen-dev-cert.sh"
check_file "Cloud 启动脚本" "$MODULES_DIR/cloud-platform-java/run.sh"
check_file "Pile 构建脚本" "$MODULES_DIR/charging-pile-cpp/build.sh"

print_title "检查结果"
if [ "$status" -eq 0 ]; then
  echo "[依赖] 当前环境依赖检查通过，可以继续构建和运行。"
else
  echo "[依赖] 当前环境存在缺失项，请先根据上面的提示补齐依赖。" >&2
fi

exit "$status"
