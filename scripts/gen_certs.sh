#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/data/certs}"
mkdir -p "${OUT_DIR}"

CA_KEY="${OUT_DIR}/ca.key"
CA_CRT="${OUT_DIR}/ca.crt"
SVR_KEY="${OUT_DIR}/receiver.key"
SVR_CSR="${OUT_DIR}/receiver.csr"
SVR_CRT="${OUT_DIR}/receiver.crt"

if [[ -f "${CA_KEY}" && -f "${CA_CRT}" && -f "${SVR_KEY}" && -f "${SVR_CRT}" ]]; then
  echo "[gen_certs] certs already exist in ${OUT_DIR}; skipping"
  exit 0
fi

echo "[gen_certs] creating CA"
openssl genrsa -out "${CA_KEY}" 4096
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
  -subj "/C=US/ST=Demo/L=Demo/O=PrivBoxDemo/OU=CA/CN=privbox-demo-ca" \
  -out "${CA_CRT}"

echo "[gen_certs] creating receiver key + CSR"
openssl genrsa -out "${SVR_KEY}" 2048

# OpenSSL SAN config
SAN_CONF="$(mktemp)"
cat > "${SAN_CONF}" << 'EOF'
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = US
ST = Demo
L  = Demo
O  = PrivBoxDemo
OU = Receiver
CN = receiver

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = receiver
EOF

openssl req -new -key "${SVR_KEY}" -out "${SVR_CSR}" -config "${SAN_CONF}"

echo "[gen_certs] signing receiver cert with CA"
openssl x509 -req -in "${SVR_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SVR_CRT}" -days 825 -sha256 -extensions req_ext -extfile "${SAN_CONF}"

rm -f "${SAN_CONF}" "${SVR_CSR}" "${OUT_DIR}/ca.srl"

chmod 600 "${CA_KEY}" "${SVR_KEY}"
chmod 644 "${CA_CRT}" "${SVR_CRT}"

echo "[gen_certs] wrote:"
ls -l "${OUT_DIR}"
