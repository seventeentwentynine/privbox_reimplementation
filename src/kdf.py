from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from crypto import group, ZR


@dataclass(frozen=True)
class EndpointSecrets:
    k_s1: Any  # ZR
    k_s2: Any  # ZR
    S_salt: int  # integer salt


def derive_endpoint_secrets(exporter_bytes: bytes) -> EndpointSecrets:
    """
    Derive endpoint secrets from TLS exporter bytes.

    Engineering note:
    - The paper conceptually derives secrets from the TLS session keying material.
    - We use HKDF-SHA256 over exported keying material (EKM) to get stable bytes, then
      map to ZR using group.hash for k_s1/k_s2, and an integer S_salt.
    """
    if not isinstance(exporter_bytes, (bytes, bytearray)) or len(exporter_bytes) < 16:
        raise ValueError("exporter_bytes must be bytes, reasonably long")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=None,
        info=b"privbox-demo-kdf-v1",
    )
    okm = hkdf.derive(bytes(exporter_bytes))

    k_s1 = group.hash(okm[0:32], ZR)
    k_s2 = group.hash(okm[32:64], ZR)

    # 64-bit salt (non-negative)
    S_salt = int.from_bytes(okm[64:72], "big") & 0x7FFFFFFFFFFFFFFF

    return EndpointSecrets(k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)


def session_id_from_exporter(exporter_bytes: bytes) -> bytes:
    """16-byte stable session id derived from exporter bytes."""
    return hashlib.sha256(exporter_bytes).digest()[:16]
