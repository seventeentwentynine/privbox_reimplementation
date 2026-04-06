import base64
import hashlib
import os
from coincurve import PublicKey
from Crypto.Cipher import AES

class PrivBoxCrypto:
    def __init__(self):
        # Generator point (secp256k1)
        self.g = PublicKey.from_secret(b'\x01' * 32)
        self.order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def _hash_to_scalar(self, data: bytes) -> int:
        h = hashlib.sha256(data).digest()
        return int.from_bytes(h, 'big') % self.order

    def H2(self, data: bytes) -> int:
        return self._hash_to_scalar(data)

    def H3(self, point: PublicKey) -> int:
        return self._hash_to_scalar(point.format())

    def random_scalar(self) -> int:
        while True:
            x = int.from_bytes(os.urandom(32), 'big') % self.order
            if x != 0:
                return x

    def random_bytes(self, n: int = 32) -> bytes:
        return os.urandom(n)

    def generate_salt(self) -> bytes:
        """Generate random salt S_salt for token encryption"""
        return os.urandom(16)

    def hash_to_key(self, data: bytes) -> bytes:
        """Hash to 32-byte key for token encryption"""
        return hashlib.sha256(data).digest()[:32]

    def exp(self, base: PublicKey, exponent: int) -> PublicKey:
        exponent_mod = exponent % self.order
        scalar = exponent_mod.to_bytes(32, 'big')
        return base.multiply(scalar)

    def mul(self, a: PublicKey, b: PublicKey) -> PublicKey:
        # Use the generator's combine method (instance method) to add points
        return self.g.combine([a, b])

    def is_equal(self, a: PublicKey, b: PublicKey) -> bool:
        return a.format() == b.format()

    def get_generator(self) -> PublicKey:
        return self.g

    def H4(self, salt: int, value: PublicKey) -> bytes:
        val_bytes = value.format()
        key = hashlib.sha256(val_bytes).digest()[:16]
        salt_bytes = salt.to_bytes(16, 'big')
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(salt_bytes)

    def serialize(self, point: PublicKey) -> str:
        return base64.b64encode(point.format()).decode()

    def deserialize_g1(self, data: str) -> PublicKey:
        return PublicKey(base64.b64decode(data))

crypto = PrivBoxCrypto()
