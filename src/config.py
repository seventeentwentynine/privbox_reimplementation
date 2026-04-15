from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else default


# Network defaults (can be overridden by docker-compose env)
MB_HOST = _env("MB_HOST", "mb")
MB_RULE_PREP_PORT = _env_int("MB_RULE_PREP_PORT", 9000)
MB_ENDPOINT_PORT = _env_int("MB_ENDPOINT_PORT", 9001)

LISTEN_HOST = _env("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = _env_int("LISTEN_PORT", 8443)


TLS_PROXY_HOST = _env("TLS_PROXY_HOST", "mb")
TLS_PROXY_PORT = _env_int("TLS_PROXY_PORT", 8443)
TLS_SERVER_NAME = _env("TLS_SERVER_NAME", "receiver")

RECEIVER_HOST = _env("RECEIVER_HOST", "receiver")
RECEIVER_TLS_PORT = _env_int("RECEIVER_TLS_PORT", 8443)

# Tokenization parameters
TOKEN_SIZE = _env_int("TOKEN_SIZE", 8)

# Token ciphertext size output (RS_BYTES)
RS_BYTES = _env_int("RS_BYTES", 16)

# TLS exporter
TLS_EXPORT_LABEL = _env("TLS_EXPORT_LABEL", "EXPORTER-PRIVBOX-V1").encode("ascii", "strict")
TLS_EXPORT_LEN = _env_int("TLS_EXPORT_LEN", 64)

# Paths (mounted via volumes)
KEY_DIR = _env("KEY_DIR", "/data/keys")
CERT_DIR = _env("CERT_DIR", "/data/certs")
MB_STATE_DIR = _env("MB_STATE_DIR", "/data/mb_state")
LOG_DIR = _env("LOG_DIR", "/data/logs")

CA_CERT_PATH = f"{CERT_DIR}/ca.crt"
RECEIVER_CERT_PATH = f"{CERT_DIR}/receiver.crt"
RECEIVER_KEY_PATH = f"{CERT_DIR}/receiver.key"

# Demo ruleset
DEFAULT_RULESET_TEXT = """\
# Minimal ruleset for demo
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"UNION SELECT";)
"""
