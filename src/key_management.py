from __future__ import annotations

from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from config import KEY_DIR
from signatures import (
    generate_ed25519_keypair,
    private_key_to_pem,
    public_key_to_pem,
    load_private_key_from_pem,
    load_public_key_from_pem,
)


def _paths(role: str) -> Tuple[Path, Path]:
    base = Path(KEY_DIR)
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{role}_private.pem", base / f"{role}_public.pem"


def ensure_keypair(role: str) -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv_path, pub_path = _paths(role)

    if priv_path.exists() and pub_path.exists():
        sk = load_private_key_from_pem(priv_path.read_bytes())
        pk = load_public_key_from_pem(pub_path.read_bytes())
        return sk, pk

    kp = generate_ed25519_keypair()
    priv_path.write_bytes(private_key_to_pem(kp.private))
    pub_path.write_bytes(public_key_to_pem(kp.public))
    return kp.private, kp.public


def load_public_key(role: str) -> Ed25519PublicKey:
    _priv_path, pub_path = _paths(role)
    if not pub_path.exists():
        raise FileNotFoundError(f"public key missing for role={role}, expected {pub_path}")
    return load_public_key_from_pem(pub_path.read_bytes())


def load_private_key(role: str) -> Ed25519PrivateKey:
    priv_path, _pub_path = _paths(role)
    if not priv_path.exists():
        raise FileNotFoundError(f"private key missing for role={role}, expected {priv_path}")
    return load_private_key_from_pem(priv_path.read_bytes())
