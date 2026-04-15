from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from crypto import serialize_element


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey


def generate_ed25519_keypair() -> KeyPair:
    priv = Ed25519PrivateKey.generate()
    return KeyPair(private=priv, public=priv.public_key())


def private_key_to_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_from_pem(pem: bytes) -> Ed25519PrivateKey:
    k = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise TypeError("not ed25519 private key")
    return k


def load_public_key_from_pem(pem: bytes) -> Ed25519PublicKey:
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise TypeError("not ed25519 public key")
    return k


def sign_element(sk: Ed25519PrivateKey, element: Any) -> bytes:
    return sk.sign(serialize_element(element))


def verify_element(pk: Ed25519PublicKey, element: Any, sig: bytes) -> bool:
    try:
        pk.verify(sig, serialize_element(element))
        return True
    except Exception:
        return False
