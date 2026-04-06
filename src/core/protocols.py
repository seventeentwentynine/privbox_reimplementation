"""
protocols.py
Implements the explicit mathematical state machines.
"""
from typing import List, Tuple, Any
from crypto import group, G1, ZR, pair, H1, H2, H3, dem_encrypt, dem_decrypt

class RulePreparationRG:
    def __init__(self, rules: List[bytes]):
        self.rules = rules
        self.a = group.random(ZR)
        self.r = group.random(ZR)
        self.S_A = (group.random(G1) ** 1) ** self.a
        self.L = (group.random(G1) ** 1) ** self.r

    def step1_get_commitments(self) -> Tuple[Any, Any]:
        return self.S_A, self.L

    def step3_process_mb_commitments(self, S_B: Any, S: Any) -> List[Any]:
        self.S_B = S_B
        self.S = S
        self.S_A_tilde = S_B ** self.a

        V_list = []
        for r_i in self.rules:
            V_i = self.S_A_tilde ** H2(r_i)
            V_list.append(V_i)
        return V_list

    def step5_generate_obfuscated_rules(self, Y: bytes, R_tilde: Any, S_i_list: List[Any]) -> Tuple[Any, List[Tuple[Any, Any, Any]]]:
        dem_key = H1(self.S_A_tilde)
        decrypted_y_ytilde = dem_decrypt(dem_key, Y)

        y_len = len(decrypted_y_ytilde) // 2
        y = group.deserialize(decrypted_y_ytilde[:y_len])
        y_tilde = group.deserialize(decrypted_y_ytilde[y_len:])

        self.R = R_tilde ** self.r
        self.R_hat = self.R * self.S_A_tilde

        rule_tuples = []
        for S_i in S_i_list:
            R_i = S_i ** self.r
            g_base = group.random(G1) ** 1

            R_i_hat = g_base ** (y * H3(R_i))
            R_i_tilde = (R_i ** y) * (g_base ** (y * y_tilde * H3(R_i)))

            rule_tuples.append((R_i, R_i_tilde, R_i_hat))

        return self.R, rule_tuples

class RulePreparationMB:
    def __init__(self):
        self.b = group.random(ZR)
        self.s = group.random(ZR)
        self.y = group.random(ZR)
        self.y_tilde = group.random(ZR)

        g_base = group.random(G1) ** 1
        self.S_B = g_base ** self.b
        self.S = g_base ** self.s

    def step2_get_commitments(self) -> Tuple[Any, Any]:
        return self.S_B, self.S

    def step4_verify_and_mask(self, S_A: Any, V_list: List[Any], rules: List[bytes]) -> Tuple[bytes, Any, List[Any]]:
        self.S_B_tilde = S_A ** self.b

        for i, r_i in enumerate(rules):
            expected_V_i = self.S_B_tilde ** H2(r_i)
            if V_list[i] != expected_V_i:
                raise ValueError("Mathematical verification of V_i failed.")

        y_bytes = group.serialize(self.y)
        y_tilde_bytes = group.serialize(self.y_tilde)
        dem_key = H1(self.S_B_tilde)
        Y = dem_encrypt(dem_key, y_bytes + y_tilde_bytes)

        R_tilde = self.S_B_tilde ** self.s
        S_i_list = [V_i ** self.s for V_i in V_list]

        return Y, R_tilde, S_i_list

    def step6_finalize_rules(self, R: Any, R_hat: Any, rule_tuples: List[Tuple[Any, Any, Any]], L: Any):
        R_calc = R_hat / self.S_B_tilde
        g = group.random(G1) ** 1

        if pair(R_calc, g) != pair(self.S_B_tilde ** self.s, L):
            raise ValueError("Pairing constraint e(R, g) = e(R_tilde, L) failed.")

        return R_calc, rule_tuples

class PreprocessingEndpoint:
    def __init__(self, k_s1: Any, k_s2: Any):
        self.k_s1 = k_s1
        self.k_s2 = k_s2
        self.K_s1 = (group.random(G1) ** 1) ** self.k_s1

    def compute_K_tilde(self, R_i_tilde: Any, R_i_hat: Any) -> Any:
        return (R_i_tilde ** self.k_s1) * (R_i_hat ** self.k_s2)

class PreprocessingMB:
    def __init__(self, y: Any, y_tilde: Any):
        self.y = y
        self.y_tilde = y_tilde

    def finalize_K_i(self, K_tilde_i: Any, K_s1: Any, R_i: Any) -> Any:
        exponent = self.y * self.y_tilde * H3(R_i)
        denominator = K_s1 ** exponent
        base = K_tilde_i / denominator
        y_inv = self.y ** -1
        return base ** y_inv