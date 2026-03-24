import base64
import hashlib
import os
import coincurve
from Crypto.Cipher import AES

class PrivBoxCrypto:
    def __init__(self):
        self.g = coincurve.PublicKey.from_secret(b'\x01' * 32)   # generator
        self.order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def _hash_to_scalar(self, data: bytes) -> int:
        h = hashlib.sha256(data).digest()
        return int.from_bytes(h, 'big') % self.order

    def H2(self, s: str) -> int:
        return self._hash_to_scalar(s.encode())

    def H3(self, point: coincurve.PublicKey) -> int:
        return self._hash_to_scalar(point.format())

    def random_scalar(self) -> int:
        # Return a non‑zero scalar in [1, order-1]
        while True:
            x = int.from_bytes(os.urandom(32), 'big') % self.order
            if x != 0:
                return x

    def random_bytes(self, n: int = 32) -> bytes:
        return os.urandom(n)

    def exp(self, base: coincurve.PublicKey, exponent: int) -> coincurve.PublicKey:
        # Reduce exponent modulo group order
        exponent_mod = exponent % self.order
        scalar = exponent_mod.to_bytes(32, 'big')
        return base.multiply(scalar)

    def mul(self, a: coincurve.PublicKey, b: coincurve.PublicKey) -> coincurve.PublicKey:
        # Add two public keys using the combine method
        return coincurve.PublicKey.combine(public_keys=[a, b])

    def is_equal(self, a: coincurve.PublicKey, b: coincurve.PublicKey) -> bool:
        return a.format() == b.format()

    def get_generator(self) -> coincurve.PublicKey:
        return self.g

    def H4(self, salt: int, value: coincurve.PublicKey) -> bytes:
        val_bytes = value.format()
        key = hashlib.sha256(val_bytes).digest()[:16]
        salt_bytes = salt.to_bytes(16, 'big')
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(salt_bytes)

    def serialize(self, point: coincurve.PublicKey) -> str:
        return base64.b64encode(point.format()).decode()

    def deserialize_g1(self, data: str) -> coincurve.PublicKey:
        return coincurve.PublicKey(base64.b64decode(data))

crypto = PrivBoxCrypto()