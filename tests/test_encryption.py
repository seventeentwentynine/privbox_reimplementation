import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.crypto import crypto
from src.core.tokenization import token_encryption
from src.core.inspection import traffic_inspection

def test_encryption():
    print("=" * 60)
    print("Testing PrivBox Encryption (coincurve backend)")
    print("=" * 60)

    # Generate synthetic parameters
    a = crypto.random_scalar()
    b = crypto.random_scalar()
    s = crypto.random_scalar()
    r = crypto.random_scalar()
    g = crypto.get_generator()
    g_a = crypto.exp(g, a)
    g_ab = crypto.exp(g_a, b)
    g_abs = crypto.exp(g_ab, s)
    R = crypto.exp(g_abs, r)  # g^{a·b·s·r}

    # Endpoint secrets
    k_s1 = crypto.random_scalar()
    k_s2 = crypto.random_scalar()
    k_r = crypto.random_bytes(16)

    # Initialize token encryption
    token_encryption.initialize_first_session(R, k_s1, k_s2, k_r)
    print(f"Initial salt: {token_encryption.get_salt()}")

    # Create a test rule "attack" and compute its session rule I_i
    rule_keyword = "attack"
    h2 = crypto.H2(rule_keyword)
    R_h2 = crypto.exp(R, h2)
    term1 = crypto.exp(R_h2, k_s1)
    h3 = crypto.H3(R_h2)                 # now takes a point
    term2 = crypto.exp(g, k_s2 * h3)    # product reduced inside exp
    I_i = crypto.mul(term1, term2)

    # Initialize inspection with this rule
    traffic_inspection.initialize_session({"attack_rule": I_i}, token_encryption.get_salt())

    # Payload containing the keyword
    payload = b"This is a test payload containing the word attack"
    print(f"\nPayload: {payload}")
    encrypted_tokens = token_encryption.encrypt_payload(payload)
    print(f"Generated {len(encrypted_tokens)} tokens")
    matches = traffic_inspection.inspect_payload([t[0] for t in encrypted_tokens])
    print(f"Matches: {matches}")

    # Payload without keyword
    payload2 = b"Benign payload with no suspicious words"
    print(f"\nPayload2: {payload2}")
    token_encryption.reset_counter_table()
    encrypted_tokens2 = token_encryption.encrypt_payload(payload2)
    matches2 = traffic_inspection.inspect_payload([t[0] for t in encrypted_tokens2])
    print(f"Matches2: {matches2}")

    if matches:
        print("\n✓ Correct: attack payload matched")
    else:
        print("\n✗ Error: attack payload did not match")
    if not matches2:
        print("✓ Correct: benign payload did not match")
    else:
        print("✗ Error: benign payload matched unexpectedly")

if __name__ == "__main__":
    test_encryption()