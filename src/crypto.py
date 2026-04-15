from __future__ import annotations

import hashlib
import os
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import RS_BYTES

try:
    from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "Charm is required (charm-crypto-framework). "
        "In Docker, this should be installed via requirements.txt and system prereqs."
    ) from e


# Pairing group for demo. This is for correctness demo, not production security tuning.
group = PairingGroup("SS512")

# Deterministic generator in G1.
G_BASE = group.hash(b"PrivBox|g", G1)


def serialize_element(x: Any) -> bytes:
    return group.serialize(x)


def deserialize_element(b: bytes) -> Any:
    return group.deserialize(b)


def H1(X: Any) -> bytes:
    """H1: group element -> 16B key for DEM (AES-GCM)."""
    return hashlib.sha256(serialize_element(X)).digest()[:16]


def H2(token: bytes) -> Any:
    """H2: token-bytes -> ZR."""
    return group.hash(token, ZR)


def H3(X: Any) -> Any:
    """H3: group element -> ZR."""
    return group.hash(serialize_element(X), ZR)


def H4(salt: int, X: Any) -> bytes:
    """
    H4: AES-based random function (PRF-like), output RS_BYTES.
    Engineering instantiation: AES-ECB over one block, keyed by SHA256(ser(X))[:16].
    """
    key = hashlib.sha256(serialize_element(X)).digest()[:16]
    # 16-byte block: salt||0
    block = struct.pack("!Q", salt & 0xFFFFFFFFFFFFFFFF) + b"\x00" * 8
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = encryptor.update(block) + encryptor.finalize()
    return out[:RS_BYTES]


def dem_encrypt(key16: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    DEM encryption for Y in rule preparation:
    output = nonce(12) || ciphertext+tag
    """
    if len(key16) != 16:
        raise ValueError("DEM key must be 16 bytes")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key16)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def dem_decrypt(key16: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(key16) != 16:
        raise ValueError("DEM key must be 16 bytes")
    if len(blob) < 12 + 16:
        raise ValueError("DEM blob too short")
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key16)
    return aesgcm.decrypt(nonce, ct, aad)
