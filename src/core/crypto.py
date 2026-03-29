import base64
import hashlib
import os
from typing import Tuple, List, Optional, Dict, Any
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from charm.toolbox.pairinggroup import PairingGroup, G1, ZR, pair
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False

@dataclass
class RGSecrets:
    """RG's secrets a, r from Section IV-B"""
    a: Any  # ZR element
    r: Any  # ZR element
    
@dataclass
class MBSecrets:
    """MB's secrets b, s, y, ỹ from Section IV-B"""
    b: Any  # ZR
    s: Any  # ZR
    y: Any  # ZR
    y_tilde: Any  # ZR (ỹ in paper)

@dataclass
class EndpointSecrets:
    """Endpoint secrets k_s1, k_s2 from Section IV-B"""
    k_s1: Any  # ZR
    k_s2: Any  # ZR
    k_r: bytes  # for randomness
    k_ssl: bytes  # regular SSL key

@dataclass 
class RuleTuple:
    """Rule tuple from Fig. 2: (R̂_i, Sig_RG(R̂_i), Sig_MB(R̂_i), R̃_i, ...)"""
    R: Any  # g^{a·b·s·r}
    R_i: Any  # g^{a·b·s·r·H₂(r_i)}
    tilde_R_i: Any  # R̃_i = g^{y·a·b·s·r·H₂(r_i) + y·ỹ·H₃(g^{a·b·s·r·H₂(r_i)})}
    hat_R_i: Any  # R̂_i = g^{y·H₃(g^{a·b·s·r·H₂(r_i)})}
    sig_rg_R: bytes
    sig_rg_tilde: bytes
    sig_rg_hat: bytes
    sig_mb_R: bytes
    sig_mb_tilde: bytes
    sig_mb_hat: bytes

class PrivBoxCrypto:
    def __init__(self, curve: str = "BN254"):
        # The paper uses prime256v1 but we'll use BN254; the math is the exact same.
        if CHARM_AVAILABLE:
            self.group = PairingGroup(curve)
            self.g = self.group.random(G1)  # generator g
        else:
            self.group = None
            self.g = b"generator_placeholder"
        
        # Hash functions as defined in paper
        self.H1 = self.hash_to_key  # H1: G -> K (keyspace)
        self.H2 = self._hash_to_zr   # H2: R -> Z_p
        self.H3 = self._hash_to_zr   # H3: G -> Z_p
        # H4 implemented with AES in token encryption
        
    def _hash_to_zr(self, data: Any) -> Any:
        """H2, H3: Hash to ZR (exponent space)"""
        if CHARM_AVAILABLE:
            if isinstance(data, str):
                data = data.encode()
            elif hasattr(data, '__str__'):
                data = str(data).encode()
            return self.group.hash(data, ZR)
        else:
            # Simulation mode
            h = hashlib.sha256(str(data).encode()).digest()
            return int.from_bytes(h, 'big')
    
    def hash_to_key(self, element: Any) -> bytes:
        """H1: Hash group element to AES key"""
        if CHARM_AVAILABLE:
            serialized = self.group.serialize(element)
            return hashlib.sha256(serialized).digest()[:32]
        else:
            return hashlib.sha256(str(element).encode()).digest()[:32]
    
    def random_zr(self) -> Any:
        """Generate random ZR element"""
        if CHARM_AVAILABLE:
            return self.group.random(ZR)
        else:
            return int.from_bytes(os.urandom(32), 'big')
    
    def random_bytes(self, n: int = 32) -> bytes:
        """Generate random bytes"""
        return os.urandom(n)

    def generate_salt(self) -> bytes:
        """Generate random salt for token encryption"""
        return os.urandom(16)

    # === Group Operations ===
    
    def exp(self, base: Any, exponent: Any) -> Any:
        """Exponentiation in group: base^exponent"""
        if CHARM_AVAILABLE:
            return base ** exponent
        else:
            # Simulation: just return bytes
            return base
    
    def mul(self, a: Any, b: Any) -> Any:
        """Group multiplication: a * b"""
        if CHARM_AVAILABLE:
            return a * b
        else:
            return a + b  # Placeholder
    
    def pair(self, a: Any, b: Any) -> Any:
        """Pairing operation e(a, b)"""
        if CHARM_AVAILABLE:
            return pair(a, b)
        else:
            return b"pairing_placeholder"
    
    # === Data Encapsulation Mechanism (DEM) ===
    
    def dem_encrypt(self, key: bytes, data: bytes) -> bytes:
        """DEM encryption with AES-CBC"""
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, AES.block_size))
        return iv + ct
    
    def dem_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """DEM decryption"""
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    
    # === H4: Random function with AES ===
    
    def H4(self, salt: int, value: Any) -> bytes:
        """
        H4(salt, value) implemented with AES as in BlindBox
        Used for final token encryption
        """
        if CHARM_AVAILABLE:
            # Serialize value to bytes
            val_bytes = self.group.serialize(value)
        else:
            val_bytes = str(value).encode()
        
        # Create AES key from value (as in BlindBox: AES_{AES_k(t)}(salt))
        # Here value is T_t, we use it directly as key material
        key = hashlib.sha256(val_bytes).digest()[:16]
        
        # Encrypt salt with AES
        salt_bytes = salt.to_bytes(16, 'big')
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(salt_bytes)
    
    # === Serialization Helpers ===
    
    def serialize(self, element: Any) -> str:
        """Serialize group element to string"""
        if CHARM_AVAILABLE:
            return base64.b64encode(self.group.serialize(element)).decode()
        else:
            return base64.b64encode(str(element).encode()).decode()
    
    def deserialize_g1(self, data: str) -> Any:
        """Deserialize G1 element"""
        if CHARM_AVAILABLE:
            return self.group.deserialize(base64.b64decode(data))
        else:
            return data

# Singleton instance
crypto = PrivBoxCrypto()