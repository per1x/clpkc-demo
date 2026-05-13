#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
MULTIARCH_TRIPLET="$(gcc -print-multiarch 2>/dev/null || true)"

OPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR:-}"
OPENSSL_SSL_LIBRARY="${OPENSSL_SSL_LIBRARY:-}"
OPENSSL_CRYPTO_LIBRARY="${OPENSSL_CRYPTO_LIBRARY:-}"

find_openssl_library() {
  local libname="$1"
  local candidate=""

  if command -v ldconfig >/dev/null 2>&1; then
    candidate="$(
      ldconfig -p 2>/dev/null \
        | grep -E "[[:space:]]${libname}\.so([[:space:]]|\.)" \
        | grep -v '/lib32/' \
        | { if [ -n "$MULTIARCH_TRIPLET" ]; then grep "/$MULTIARCH_TRIPLET/" || true; else cat; fi; } \
        | head -n 1 \
        | awk '{print $NF}'
    )"
    if [ -n "$candidate" ] && [ -e "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  fi

  if [ -n "$MULTIARCH_TRIPLET" ]; then
    for base in "/usr/lib/$MULTIARCH_TRIPLET" "/lib/$MULTIARCH_TRIPLET" "/usr/local/lib"; do
      for file in "$base/${libname}.so" "$base/${libname}.so."*; do
        if [ -e "$file" ]; then
          echo "$file"
          return 0
        fi
      done
    done
  fi

  candidate="$(
    find /usr/lib /usr/local/lib /lib \
      \( -path '*/lib32/*' -o -path '*/i386-linux-gnu/*' \) -prune -o \
      \( -name "${libname}.so" -o -name "${libname}.so.*" \) -print 2>/dev/null \
      | head -n 1
  )"
  if [ -n "$candidate" ] && [ -e "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

if [ -z "$OPENSSL_INCLUDE_DIR" ]; then
  for dir in /usr/include /usr/local/include /usr/include/node; do
    if [ -f "$dir/openssl/ssl.h" ]; then
      OPENSSL_INCLUDE_DIR="$dir"
      break
    fi
  done
fi

if [ -z "$OPENSSL_SSL_LIBRARY" ]; then
  OPENSSL_SSL_LIBRARY="$(find_openssl_library libssl || true)"
fi

if [ -z "$OPENSSL_CRYPTO_LIBRARY" ]; then
  OPENSSL_CRYPTO_LIBRARY="$(find_openssl_library libcrypto || true)"
fi

mkdir -p "$BUILD_DIR"

if [ -f "$BUILD_DIR/CMakeCache.txt" ] && ! grep -q "$SCRIPT_DIR" "$BUILD_DIR/CMakeCache.txt"; then
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
fi

CMAKE_ARGS=("-S" "$SCRIPT_DIR" "-B" "$BUILD_DIR")
if [ -n "$OPENSSL_INCLUDE_DIR" ] && [ -n "$OPENSSL_SSL_LIBRARY" ] && [ -n "$OPENSSL_CRYPTO_LIBRARY" ]; then
  echo "[构建] 使用 OpenSSL 头文件目录: $OPENSSL_INCLUDE_DIR"
  echo "[构建] 使用 libssl: $OPENSSL_SSL_LIBRARY"
  echo "[构建] 使用 libcrypto: $OPENSSL_CRYPTO_LIBRARY"
  CMAKE_ARGS+=(
    "-DOPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_DIR"
    "-DOPENSSL_SSL_LIBRARY=$OPENSSL_SSL_LIBRARY"
    "-DOPENSSL_CRYPTO_LIBRARY=$OPENSSL_CRYPTO_LIBRARY"
  )
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR"
