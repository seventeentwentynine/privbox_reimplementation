"""
crypto.py

Encapsulates Charm-Crypto operations for the PrivBox architecture.
Instantiates the symmetric bilinear pairing group ('SS512') to provide
the algebraic structures G1, G2, GT, and Z_p.
Implements specific cryptographic hashing functions and the CPA-secure
Data Encapsulation Mechanism (DEM).
"""

import hashlib
import os
from typing import Tuple, Any
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Instantiate the Symmetric Bilinear Pairing Group
# Corresponds to a prime order p supporting efficient pairings.
group = PairingGroup('SS512')

def serialize_element(element: Any) -> bytes:
    """
    Serializes a Charm-Crypto group element (G1, GT, or ZR) to a base64 byte string.
    Essential for transmitting complex multi-dimensional elements over raw TCP sockets.
    """
    if element is None:
        return b""
    return objectToBytes(element, group)

def deserialize_element(data: bytes) -> Any:
    """
    Deserializes a byte string back into an active Charm-Crypto group element.
    """
    if not data:
        return None
    return bytesToObject(data, group)

def H1(element: Any) -> bytes:
    """
    H1: G -> K. Hashes a group element to a symmetric key (bytes).
    Utilized during Rule Preparation to derive the AES-GCM key for DEM.
    """
    element_bytes = serialize_element(element)
    return hashlib.sha256(element_bytes).digest()

def H2(data: bytes) -> Any:
    """
    H2: R -> Z_p. Hashes detection string rules into a mathematical scalar.
    """
    return group.hash(data, ZR)

def H3(element: Any) -> Any:
    """
    H3: G -> Z_p. Hashes an elliptic curve group element into a scalar.
    Provides the secondary masking factor for the dual double-masking structure.
    """
    element_bytes = serialize_element(element)
    return group.hash(element_bytes, ZR)

def H4(salt: int, element: Any) -> bytes:
    """
    H4: Operates as a pseudorandom oracle taking a dynamic salt and an element in G.
    Outputs a randomized byte string to resist frequency analysis during Token Encryption.
    """
    element_bytes = serialize_element(element)
    salt_bytes = salt.to_bytes(16, byteorder='big', signed=False)
    hasher = hashlib.sha256()
    hasher.update(salt_bytes)
    hasher.update(element_bytes)
    return hasher.digest()

def dem_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    CPA-Secure Data Encapsulation Mechanism (DEM) Encryption.
    Transfers middlebox secrets y and y_tilde securely to the Rule Generator.
    Utilizes AES-GCM for authenticated encryption.
    """
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def dem_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    """
    CPA-Secure Data Encapsulation Mechanism (DEM) Decryption.
    """
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_keypair() -> Tuple[Any, Any]:
    """
    Generates a standard public/private keypair over the elliptic curve for signature logic.
    """
    sk = group.random(ZR)
    pk = (group.random(G1) ** 1) ** sk  # pk = g^sk
    return pk, sk