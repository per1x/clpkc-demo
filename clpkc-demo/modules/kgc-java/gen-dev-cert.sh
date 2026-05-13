#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
KEYSTORE="$CERT_DIR/kgc-keystore.p12"
CERT_PEM="$CERT_DIR/kgc-cert.pem"

mkdir -p "$CERT_DIR"

if ! command -v keytool >/dev/null 2>&1; then
  echo "未找到 keytool，请先安装 JDK 再生成 KGC 证书。" >&2
  exit 1
fi

if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair \
    -alias kgc \
    -keyalg EC \
    -groupname secp256r1 \
    -storetype PKCS12 \
    -keystore "$KEYSTORE" \
    -storepass changeit \
    -keypass changeit \
    -dname "CN=localhost, OU=Demo, O=CLPKC, L=SZ, ST=GD, C=CN"
fi

keytool -exportcert \
  -alias kgc \
  -rfc \
  -keystore "$KEYSTORE" \
  -storepass changeit \
  -file "$CERT_PEM" >/dev/null

echo "[证书] 已生成或更新开发证书。"
echo "[证书] Keystore 路径: $KEYSTORE"
echo "[证书] PEM 证书路径: $CERT_PEM"
