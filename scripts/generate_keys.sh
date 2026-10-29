#!/usr/bin/env bash
#
# Generate ECDSA P-256 signing keys for MCUboot & B0 dual-stage bootloader
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${WORKSPACE_ROOT}/keys"

mkdir -p "${KEYS_DIR}"

PRIV_KEY="${KEYS_DIR}/root-ec-p256.pem"
PUB_KEY="${KEYS_DIR}/root-ec-p256-pub.pem"
PUB_C="${KEYS_DIR}/root-ec-p256-pub.c"

if [ -f "${PRIV_KEY}" ]; then
    echo "[INFO] Signing key already exists at: ${PRIV_KEY}"
else
    echo "[INFO] Generating ECDSA P-256 private key at: ${PRIV_KEY}..."
    openssl ecparam -name prime256v1 -genkey -noout -out "${PRIV_KEY}"
    chmod 600 "${PRIV_KEY}"
    echo "[SUCCESS] Generated private key."
fi

if [ ! -f "${PUB_KEY}" ]; then
    echo "[INFO] Extracting public key to: ${PUB_KEY}..."
    openssl ec -in "${PRIV_KEY}" -pubout -out "${PUB_KEY}" 2>/dev/null
    echo "[SUCCESS] Extracted public key."
fi

echo "[INFO] Keys in ${KEYS_DIR}:"
ls -la "${KEYS_DIR}"
