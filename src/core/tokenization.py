# src/core/tokenization.py
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

from .crypto import crypto

@dataclass
class TokenEntry:
    count: int
    T_t: Any
    token_str: str

class TokenEncryption:
    """
    Implements Fig. 6: Token Encryption Algorithm
    """

    def __init__(self):
        self.counter_table: Dict[str, TokenEntry] = {}   # CT
        self.salt: int = 0                               # S_salt
        self.R: Optional[Any] = None                     # g^{a·b·s·r}
        self.k_s1: Optional[Any] = None
        self.k_s2: Optional[Any] = None
        self.K_s: Optional[Any] = None                   # for subsequent sessions

    def initialize_first_session(self, R: Any, k_s1: Any, k_s2: Any, k_r: bytes):
        self.R = R
        self.k_s1 = k_s1
        self.k_s2 = k_s2
        # Derive initial salt from k_r (Section IV-E)
        self.salt = int.from_bytes(hashlib.sha256(k_r).digest()[:8], 'big')
        self.counter_table.clear()

    def initialize_subsequent_session(self, R: Any, k_s1: Any, k_s2: Any, K_s: Any):
        self.R = R
        self.k_s1 = k_s1
        self.k_s2 = k_s2
        self.K_s = K_s
        # Keep counter table for token reuse

    def _compute_T_t_first_session(self, token: str) -> Any:
        h2 = crypto.H2(token)
        R_h2 = crypto.exp(self.R, h2)
        term1 = crypto.exp(R_h2, self.k_s1)
        # FIX: pass the point, not its serialization
        h3 = crypto.H3(R_h2)                     # <-- change here
        term2 = crypto.exp(crypto.get_generator(), self.k_s2 * h3)
        return crypto.mul(term1, term2)

    def _compute_T_t_subsequent_session(self, token: str) -> Any:
        base_T_t = self._compute_T_t_first_session(token)
        return crypto.mul(base_T_t, self.K_s)         # multiply by K_s

    def encrypt_token(self, token: str) -> Tuple[bytes, int]:
        """Returns (D_t, count)"""
        if self.K_s is not None:
            T_t = self._compute_T_t_subsequent_session(token)
        else:
            T_t = self._compute_T_t_first_session(token)

        # Look up in counter table
        if token in self.counter_table:
            entry = self.counter_table[token]
            # If T_t changed (new session), reset count
            if not crypto.is_equal(entry.T_t, T_t):
                entry.count = 0
                entry.T_t = T_t
            else:
                entry.count += 1
            count = entry.count
            T_t_to_use = entry.T_t
        else:
            count = 0
            self.counter_table[token] = TokenEntry(count=0, T_t=T_t, token_str=token)
            T_t_to_use = T_t

        D_t = crypto.H4(self.salt + count, T_t_to_use)
        return D_t, count

    def encrypt_payload(self, payload: bytes) -> List[Tuple[bytes, int, int]]:
        """
        Sliding window tokenization (8 bytes). Returns list of (D_t, count, offset).
        """
        window_size = 8
        results = []
        for offset in range(len(payload) - window_size + 1):
            token_bytes = payload[offset:offset+window_size]
            token_str = token_bytes.hex()   # convert to string for counter
            D_t, count = self.encrypt_token(token_str)
            results.append((D_t, count, offset))
        return results

    def reset_counter_table(self):
        max_count = max([e.count for e in self.counter_table.values()] or [0])
        self.salt = self.salt + max_count + 1
        self.counter_table.clear()

    def get_salt(self) -> int:
        return self.salt

token_encryption = TokenEncryption()