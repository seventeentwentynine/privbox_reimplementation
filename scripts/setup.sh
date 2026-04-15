#!/usr/bin/env bash
set -euo pipefail

: "${KEY_DIR:?KEY_DIR not set}"
: "${CERT_DIR:?CERT_DIR not set}"
: "${LOG_DIR:?LOG_DIR not set}"

mkdir -p "${KEY_DIR}" "${CERT_DIR}" "${LOG_DIR}"

echo "[setup] generating signature keys (SigRG + SigMB) into ${KEY_DIR}"
python /app/src/init_keys.py

echo "[setup] generating local CA + receiver TLS cert into ${CERT_DIR}"
bash /app/scripts/gen_certs.sh "${CERT_DIR}"

echo "[setup] done"
