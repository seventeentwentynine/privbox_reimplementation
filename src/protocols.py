"""
protocols.py

Implements the *vanilla* PrivBox algorithms from Section IV of the paper:

- Rule preparation protocol (Fig. 2): RG <-> MB
- Preprocessing protocol (Fig. 3): endpoints <-> MB
- Session rule preparation (Fig. 5): endpoints <-> MB (included for completeness)
- Token encryption (Fig. 6): sender-side algorithm (reused by receiver for validation)

This module contains only the mathematical state machines; network messages are handled in scripts.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from crypto import (
    G_BASE,
    H1,
    H2,
    H3,
    ZR,
    dem_decrypt,
    dem_encrypt,
    group,
    pair,
    serialize_element,
)
from signatures import sign_element, verify_element
from storage import RuleTuple, SetupState, SignedValue


def encode_y_pair(y: Any, y_tilde: Any) -> bytes:
    """
    Encode (y, y_tilde) as a length-delimited blob:
        len(y)||y||len(y_tilde)||y_tilde
    where each len is uint32_be.

    This is purely an engineering detail (does not change the cryptographic algorithm).
    """
    y_b = serialize_element(y)
    yt_b = serialize_element(y_tilde)
    return struct.pack("!I", len(y_b)) + y_b + struct.pack("!I", len(yt_b)) + yt_b


def decode_y_pair(blob: bytes) -> Tuple[Any, Any]:
    off = 0
    if len(blob) < 8:
        raise ValueError("Invalid y-pair blob")
    (y_len,) = struct.unpack("!I", blob[off : off + 4])
    off += 4
    y_b = blob[off : off + y_len]
    off += y_len
    (yt_len,) = struct.unpack("!I", blob[off : off + 4])
    off += 4
    yt_b = blob[off : off + yt_len]
    from crypto import deserialize_element

    return deserialize_element(y_b), deserialize_element(yt_b)


@dataclass
class RGOutboundFig2Step5:
    R_hat: Any
    sig_rg_R: bytes
    items: List[Tuple[Any, Any, bytes, Any, bytes]]  # (R_i, tildeR_i, sig_tilde, hatR_i, sig_hat)


class RulePreparationRG:
    """
    Rule Generator side of Fig. 2.
    """

    def __init__(self, rules: List[bytes], sk_sig_rg: Any):
        if not rules:
            raise ValueError("rules must be non-empty")
        self.rules = rules
        self.sk_sig_rg = sk_sig_rg

        # RG secrets (a, r) ∈ Zp
        self.a = group.random(ZR)
        self.r = group.random(ZR)

        # Commitments
        self.S_A = G_BASE ** self.a  # g^a
        self.L = G_BASE ** self.r  # g^r

        # Will be set once we'd gotten MB messages
        self.tilde_S_B = None

    def step1_commitments(self) -> Tuple[Any, Any]:
        return self.S_A, self.L

    def step3_compute_V(self, S_B: Any, S: Any) -> List[Any]:
        """
        RG receives S_B and S, then sends V_i = (S_B^a)^{H2(r_i)}.
        """
        tilde_S_B = S_B ** self.a
        self.tilde_S_B = tilde_S_B

        V_list = []
        for r_i in self.rules:
            V_list.append((tilde_S_B) ** H2(r_i))
        return V_list

    def step5_compute_and_sign(self, Y: bytes, R_tilde: Any, S_i_list: List[Any]) -> RGOutboundFig2Step5:
        if self.tilde_S_B is None:
            raise RuntimeError("step3 must run before step5")

        dem_key = H1(self.tilde_S_B)
        y, y_tilde = decode_y_pair(dem_decrypt(dem_key, Y))

        # R_tilde = g^(abs), so R must be g^(absr)
        R = R_tilde ** self.r
        R_hat = R * self.tilde_S_B

        sig_rg_R = sign_element(self.sk_sig_rg, R)

        items: List[Tuple[Any, Any, bytes, Any, bytes]] = []
        for S_i in S_i_list:
            R_i = S_i ** self.r
            tilde_R_i = (R_i ** y) * (G_BASE ** (y * y_tilde * H3(R_i)))
            hat_R_i = G_BASE ** (y * H3(R_i))

            sig_tilde = sign_element(self.sk_sig_rg, tilde_R_i)
            sig_hat = sign_element(self.sk_sig_rg, hat_R_i)
            items.append((R_i, tilde_R_i, sig_tilde, hat_R_i, sig_hat))

        return RGOutboundFig2Step5(R_hat=R_hat, sig_rg_R=sig_rg_R, items=items)


class RulePreparationMB:
    """
    Middlebox side of Fig. 2.
    """

    def __init__(self, rules: List[bytes], sk_sig_mb: Any, pk_sig_rg: Any):
        if not rules:
            raise ValueError("rules must be non-empty")
        self.rules = rules
        self.sk_sig_mb = sk_sig_mb
        self.pk_sig_rg = pk_sig_rg

        # MB secrets (b, s, y, y_tilde)
        self.b = group.random(ZR)
        self.s = group.random(ZR)
        self.y = group.random(ZR)
        self.y_tilde = group.random(ZR)

        # MB commitments
        self.S_B = G_BASE ** self.b  # g^b
        self.S = G_BASE ** self.s  # g^s

        self.S_A = None
        self.L = None
        self.tilde_S_B = None  # (S_A)^b = g^{ab}
        self.R_tilde = None
        self.S_i_list: List[Any] = []

    def step2_commitments(self, S_A: Any, L: Any) -> Tuple[Any, Any]:
        self.S_A = S_A
        self.L = L
        return self.S_B, self.S

    def step4_verify_and_mask(self, V_list: List[Any]) -> Tuple[bytes, Any, List[Any]]:
        if self.S_A is None or self.L is None:
            raise RuntimeError("step2 must run before step4")
        if len(V_list) != len(self.rules):
            raise ValueError("V_list length mismatch")

        self.tilde_S_B = self.S_A ** self.b  # g^{ab}

        for i, r_i in enumerate(self.rules):
            expected = self.tilde_S_B ** H2(r_i)
            if V_list[i] != expected:
                raise ValueError("Verification failed: V_i != (tilde_S_B)^{H2(r_i)}")

        # Build Y = Enc_{H1(tilde_S_B)}(y||y_tilde)
        dem_key = H1(self.tilde_S_B)
        Y = dem_encrypt(dem_key, encode_y_pair(self.y, self.y_tilde))

        # # Compute R_tilde = L^s = (g^r)^s = g^{rs}
        # self.R_tilde = self.L ** self.s
        #
        # # Compute per-rule S_i = g^{s * H2(r_i)}
        # self.S_i_list = [G_BASE ** (self.s * H2(r_i)) for r_i in self.rules]

        self.tilde_S_B = self.S_A ** self.b
        self.R_tilde = self.tilde_S_B ** self.s
        self.S_i_list = [V_i ** self.s for V_i in V_list]

        return Y, self.R_tilde, self.S_i_list

    def step6_verify_and_store(self, msg: RGOutboundFig2Step5) -> SetupState:
        if self.R_tilde is None or self.L is None:
            raise RuntimeError("step4 must run before step6")

        # Compute R = R_hat / tilde_S_B
        if self.tilde_S_B is None:
            raise RuntimeError("Missing tilde_S_B")
        R = msg.R_hat / self.tilde_S_B

        # Verify SigRG(R)
        if not verify_element(self.pk_sig_rg, R, msg.sig_rg_R):
            raise ValueError("Invalid SigRG(R)")

        # pairing check: e(R, g) == e(R_tilde, L)
        if pair(R, G_BASE) != pair(self.R_tilde, self.L):
            raise ValueError("Pairing check failed: e(R,g) != e(R_tilde, L)")

        rule_tuples: List[RuleTuple] = []
        for i, (R_i, tilde_R_i, sig_tilde, hat_R_i, sig_hat) in enumerate(msg.items):
            if not verify_element(self.pk_sig_rg, tilde_R_i, sig_tilde):
                raise ValueError(f"Invalid SigRG(tilde_R_{i})")
            if not verify_element(self.pk_sig_rg, hat_R_i, sig_hat):
                raise ValueError(f"Invalid SigRG(hat_R_{i})")

            S_i = self.S_i_list[i]
            if pair(self.L, S_i) != pair(G_BASE, R_i):
                raise ValueError(f"Pairing check failed for rule {i}: e(L,S_i) != e(g,R_i)")

            expected_tilde = (R_i ** self.y) * (G_BASE ** (self.y * self.y_tilde * H3(R_i)))
            if tilde_R_i != expected_tilde:
                raise ValueError(f"Invalid tilde_R_{i}")

            expected_hat = G_BASE ** (self.y * H3(R_i))
            if hat_R_i != expected_hat:
                raise ValueError(f"Invalid hat_R_{i}")

            sig_mb_tilde = sign_element(self.sk_sig_mb, tilde_R_i)
            sig_mb_hat = sign_element(self.sk_sig_mb, hat_R_i)

            rule_tuples.append(
                RuleTuple(
                    R_i=R_i,
                    tilde_R_i=SignedValue(value=tilde_R_i, sig_rg=sig_tilde, sig_mb=sig_mb_tilde),
                    hat_R_i=SignedValue(value=hat_R_i, sig_rg=sig_hat, sig_mb=sig_mb_hat),
                )
            )

        sig_mb_R = sign_element(self.sk_sig_mb, R)

        return SetupState(
            y=self.y,
            y_tilde=self.y_tilde,
            R=SignedValue(value=R, sig_rg=msg.sig_rg_R, sig_mb=sig_mb_R),
            rule_tuples=rule_tuples,
        )


class PreprocessingEndpoint:
    """
    Endpoint-side logic for Fig. 3.

    Inputs: (k_s1, k_s2) in Zp; public keys pkSigRG and pkSigMB.
    """

    def __init__(self, k_s1: Any, k_s2: Any, pk_sig_rg: Any, pk_sig_mb: Any):
        self.k_s1 = k_s1
        self.k_s2 = k_s2
        self.pk_sig_rg = pk_sig_rg
        self.pk_sig_mb = pk_sig_mb

        self.K_s1 = G_BASE ** self.k_s1
        self.R: Any | None = None

    def verify_and_compute_tildeK(self, R_signed: SignedValue, rule_tuples: List[RuleTuple]) -> List[Any]:
        if not verify_element(self.pk_sig_rg, R_signed.value, R_signed.sig_rg):
            raise ValueError("Endpoint: invalid SigRG(R)")
        if not verify_element(self.pk_sig_mb, R_signed.value, R_signed.sig_mb):
            raise ValueError("Endpoint: invalid SigMB(R)")

        self.R = R_signed.value

        tildeK_list: List[Any] = []
        for i, rt in enumerate(rule_tuples):
            tilde_signed = rt.tilde_R_i
            hat_signed = rt.hat_R_i

            if not verify_element(self.pk_sig_rg, tilde_signed.value, tilde_signed.sig_rg):
                raise ValueError(f"Endpoint: invalid SigRG(tildeR_{i})")
            if not verify_element(self.pk_sig_mb, tilde_signed.value, tilde_signed.sig_mb):
                raise ValueError(f"Endpoint: invalid SigMB(tildeR_{i})")
            if not verify_element(self.pk_sig_rg, hat_signed.value, hat_signed.sig_rg):
                raise ValueError(f"Endpoint: invalid SigRG(hatR_{i})")
            if not verify_element(self.pk_sig_mb, hat_signed.value, hat_signed.sig_mb):
                raise ValueError(f"Endpoint: invalid SigMB(hatR_{i})")

            tildeK_i = (tilde_signed.value ** self.k_s1) * (hat_signed.value ** self.k_s2)
            tildeK_list.append(tildeK_i)

        return tildeK_list


class PreprocessingMB:
    """
    MB-side computation in Fig. 3 step 4:
      K_i = (tildeK_i / (K_s1)^{y*y_tilde*H3(R_i)})^{1/y}
    """

    def __init__(self, y: Any, y_tilde: Any):
        self.y = y
        self.y_tilde = y_tilde

    def finalize_K(self, K_s1: Any, tildeK_list: List[Any], R_i_list: List[Any]) -> List[Any]:
        if len(tildeK_list) != len(R_i_list):
            raise ValueError("Length mismatch in finalize_K")

        y_inv = self.y ** -1
        out: List[Any] = []
        for tildeK_i, R_i in zip(tildeK_list, R_i_list):
            denom = (K_s1 ** (self.y * self.y_tilde * H3(R_i)))
            K_i = (tildeK_i / denom) ** y_inv
            out.append(K_i)
        return out


def session_rules_first_session(K_list: List[Any]) -> List[Any]:
    """Fig. 5: first session sets I_i = K_i."""
    return list(K_list)


def session_rules_subsequent_session(K_list: List[Any], K_s: Any) -> List[Any]:
    """Fig. 5: subsequent session sets I_i = K_i * K_s."""
    return [K_i * K_s for K_i in K_list]


@dataclass
class CTEntry:
    count: int
    T_tilde: Any
    T: Any


class TokenEncryptor:
    """
    Implements Fig. 6 token encryption algorithm (sender-side, and reused by receiver for validation).
    """

    def __init__(self, R: Any, k_s1: Any, k_s2: Any, S_salt: int, K_s: Any | None = None):
        self.R = R
        self.k_s1 = k_s1
        self.k_s2 = k_s2
        self.S_salt = S_salt
        self.K_s = K_s  # None for first session, else g^{k_s'}

        self.CT: Dict[bytes, CTEntry] = {}

    def encrypt_token(self, token: bytes) -> bytes:
        from crypto import H4

        T_tilde = self.R ** H2(token)
        T = (T_tilde ** self.k_s1) * (G_BASE ** (self.k_s2 * H3(T_tilde)))

        if self.K_s is not None:
            T = T * self.K_s

        entry = self.CT.get(token)
        if entry is None:
            self.CT[token] = CTEntry(count=0, T_tilde=T_tilde, T=T)
            return H4(self.S_salt, T)

        if entry.T != T:
            entry.count = 0
            entry.T_tilde = T_tilde
            entry.T = T
            return H4(self.S_salt, T)

        entry.count += 1
        return H4(self.S_salt + entry.count, T)
