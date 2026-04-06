"""
crypto.py
Encapsulates Charm-Crypto operations for the PrivBox architecture.
"""
import hashlib
import os
from typing import Tuple, Any

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

group = PairingGroup('SS512')

def serialize_element(element: Any) -> bytes:
    if element is None:
        return b""
    return objectToBytes(element, group)

def deserialize_element(data: bytes) -> Any:
    if not data:
        return None
    return bytesToObject(data, group)

def H1(element: Any) -> bytes:
    element_bytes = serialize_element(element)
    return hashlib.sha256(element_bytes).digest()

def H2(data: bytes) -> Any:
    return group.hash(data, ZR)

def H3(element: Any) -> Any:
    element_bytes = serialize_element(element)
    return group.hash(element_bytes, ZR)

def H4(salt: int, element: Any) -> bytes:
    element_bytes = serialize_element(element)
    salt_bytes = salt.to_bytes(16, byteorder='big', signed=False)
    hasher = hashlib.sha256()
    hasher.update(salt_bytes)
    hasher.update(element_bytes)
    return hasher.digest()

def dem_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def dem_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()