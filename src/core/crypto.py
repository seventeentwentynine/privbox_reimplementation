from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import hashlib
import hmac

class PrivBoxCrypto:
    def __init__(self):
        # using NIST P-256 (prime256v1) as in the paper
        self.curve = ec.SECP256R1()
        self.curve_name = "prime256v1"
        
    def generate_keypair(self):
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return private_key, public_key
    
    def compute_shared_secret(self, private_key, peer_public_key):
        return private_key.exchange(ec.ECDH(), peer_public_key)
    
    def hash_to_group(self, value: bytes) -> int:
        # TODO: This is a pretty braindead H2G implementation. Should use a proper hash-to-curve method.
        digest = hashlib.sha256(value).digest()
        return int.from_bytes(digest, 'big')
    
    def hash_to_key(self, value: bytes) -> bytes:
        # will prob have to migrate to a more standard KDF in production, but this is fine for now
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'privbox-h4',
        )
        return hkdf.derive(value)
    
    def generate_salt(self) -> bytes:
        return os.urandom(16)
    
    def aes_encrypt(self, key: bytes, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct
    
    def aes_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ct), AES.block_size)

# singleton instance
crypto = PrivBoxCrypto()