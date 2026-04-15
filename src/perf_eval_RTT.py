"""
Evaluate Performance of a Round Trip

perf_eval_RTT.py
"""
import time
import os
import csv
from pathlib import Path

# From the Project Files.
from crypto import group, ZR, G_BASE
from signatures import generate_ed25519_keypair
from protocols import (
    RulePreparationRG,
    RulePreparationMB,
    PreprocessingMB,
    PreprocessingEndpoint,
    TokenEncryptor,
    session_rules_first_session,
    session_rules_subsequent_session
)
from inspection import TrafficInspector


#####################
#                   #
# --- Constants --- #
#                   #
#####################


# Create Directory to hold CSV Files.
RESULTS_DIR = Path("eval_performance_rt")
RESULTS_DIR.mkdir(exist_ok=True)


# CSV Files.
FIGURE_12A = "figure_12a.csv"
FIGURE_12B = "figure_12b.csv"
HEADER_12AB = ["Number of Rules", "Round Trip Time (s)"]
FIGURE_12C = "figure_12c.csv"
FIGURE_12D = "figure_12d.csv"
HEADER_12CD = ["Number of Tokens (x 10^2)", "Round Trip Time (s)"]
TABLE_VI = "table_vi.csv"
HEADER_VI = ["No. of Repeated Tokens (for 4 times)", "Round Trip Time (s)"]
TABLE_VII = "table_vii.csv"
HEADER_VII = ["Percentage of One Token Repeating", "Round Trip Time (s)"]
TABLE_VIII = "table_viii.csv"
HEADER_VIII = ["Percentage of Repeated Tokens", "Round Trip Time (s)"]


# (1) Counts for Number of Rules.
RULE_COUNTS = [1, 1000, 2000, 3000]
TOKEN_CONSTANT_8000 = 8000  # Would be used for (3), (4), and (5).

# (2) Counts for Number of Tokens.
TOKEN_COUNTS_HUNDREDS = [5, 10, 50, 100]
RULE_CONSTANT_3000 = 3000

# (3) Counts for Number of Repeated Tokens for 4 Times.
REPEATED_TOKEN_COUNT = [500, 1000, 1500, 2000]

# (4) Percentage of 1 Token Repeating.
PERCENTAGES_ONE_TOKEN_REPEATING = [0.05, 0.5, 0.85, 1.0]

# (5) Percentage of Repeated Tokens in Subsequent Session.
PERCENTAGES_REPEATED_TOKENS = [0.05, 0.5, 0.91, 0.92, 1.0]


#################
#               #
# --- Setup --- #
#               #
#################


def generate_dummy_rules(n: int) -> list[bytes]:
    """
    Generate `n` random 8-byte rules.

    :param n: Number of random 8-byte rules.
    :type n: `int`
    :return: List of `n` random 8-byte rules.
    :rtype: `list[bytes]`
    """
    return [os.urandom(8) for _ in range(n)]


def setup_test_environment(n: int) -> tuple:
    """
    Simulate the RG and MB Setup phase.
    Generate the required cryptographic fixtures (`SetupState`) so we can benchmark the endpoints.
    
    :param n: Number of random 8-byte rules.
    :type n: `int`
    :return: Tuple of the environment variables.
    :rtype: `tuple`
    """
    print(f"[*] Generating {n} rules and keys...")
    
    # Generate Keys.
    rg_keys = generate_ed25519_keypair()
    mb_keys = generate_ed25519_keypair()

    # Generate Rules.
    rules = generate_dummy_rules(n)

    # Set up RG and MB.
    rg = RulePreparationRG(rules=rules, sk_sig_rg=rg_keys.private)
    mb = RulePreparationMB(rules=rules, sk_sig_mb=mb_keys.private, pk_sig_rg=rg_keys.public)

    # 5-step Handshake.
    s_a, l = rg.step1_commitments()  # RG Commits.
    s_b, s = mb.step2_commitments(s_a, l)  # MB Commits.
    v_list = rg.step3_compute_V(s_b, s)  # RG Proves with Zero Knowledge.
    y, r_tilde, s_i_list = mb.step4_verify_and_mask(v_list)  # MB Verifies and Masks.
    msg = rg.step5_compute_and_sign(y, r_tilde, s_i_list)  # RG Signs and Finalizes.
    setup_state = mb.step6_verify_and_store(msg)  # MB Verifies and Stores.

    # Generate Endpoint Secrets.
    k_s1 = group.random(ZR)
    k_s2 = group.random(ZR)
    s_salt = 12345

    return setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, rg, mb


#########################
#                       #
# --- Token Helpers --- #
#                       #
#########################


def generate_dummy_tokens(m: int) -> list[bytes]:
    """
    Generate `m` random 8-byte tokens.

    :param m: Number of random 8-byte tokens.
    :type m: `int`
    :return: List of `n` random 8-byte tokens.
    :rtype: `list[bytes]`
    """
    return [os.urandom(8) for _ in range(m)]


def generate_tokens_repeating_4_times(tokens_repeating: int, total_token_constant: int = TOKEN_CONSTANT_8000) -> list[bytes]:
    """
    Generate a token list where `tokens_repeating` distinct tokens repeating 4 times each.

    :param tokens_repeating: Number of tokens repeating 4 times.
    :type tokens_repeating: `int`
    :param total_token_constant: Number of tokens in the set (8000 by default).
    :type total_token_constant: `int`
    :return: List of `tokens_repeating` distinct tokens repeating 4 times each.
    :rtype: `list[bytes]`
    """
    tokens = []
    for _ in range(tokens_repeating):
        tok = os.urandom(8)
        tokens.extend([tok] * 4)
    remaining = total_token_constant - len(tokens)
    if remaining > 0:
        tokens.extend(generate_dummy_tokens(remaining))
    return tokens


def generate_tokens_one_repeating(pct: float, total_token_constant: int = TOKEN_CONSTANT_8000) -> list[bytes]:
    """
    Generate a token list, where 1 token makes up `pct`\% of the list.

    :param pct: Percentage of one token repeating.
    :type pct: `float`
    :param total_token_constant: Number of tokens in the set (8000 by default).
    :type total_token_constant: `int`
    :return: List of tokens, where 1 token makes up `pct`\% of the list.
    :rtype: `list[bytes]`
    """
    repeating_count = int(total_token_constant * pct)
    special_token = os.urandom(8)
    tokens = [special_token] * repeating_count
    remaining = total_token_constant - repeating_count
    if remaining > 0:
        tokens.extend(generate_dummy_tokens(remaining))
    return tokens


def generate_subsequent_tokens(prev_tokens: list[bytes], pct: float, total_token_constant: int = TOKEN_CONSTANT_8000) -> list[bytes]:
    """
    Takes a percentage of tokens from a previous session and fills the rest with new unique tokens.
    """
    reuse_count = int(total_token_constant * pct)
    # Deduplicate previous tokens to get unique candidates for reuse.
    unique_prev = list(set(prev_tokens))

    # Repeat the reused tokens to fill the reuse count.
    reused_subset = [unique_prev[i % len(unique_prev)] for i in range(reuse_count)]
    remaining = total_token_constant - reuse_count
    new_tokens = generate_dummy_tokens(remaining)

    return reused_subset + new_tokens


######################
#                    #
# --- Evaluation --- #
#                    #
######################


def eval_d1_performance_different_rules(rule_counts: list[int]):
    """
    Evaluate the Performance of a Round Trip with Different Rules.

    :param rule_counts: List of rule counts.
    :type rule_counts: `list[int]`
    """
    print("\n[*] Evaluating Performance of a Round Trip with Different Rules...")

    # Generate unique tokens.
    tokens = generate_dummy_tokens(TOKEN_CONSTANT_8000)

    # CSV.
    csv_12a = RESULTS_DIR / FIGURE_12A
    csv_12b = RESULTS_DIR / FIGURE_12B

    with open(csv_12a, "w", newline="") as f1, open(csv_12b, "w", newline="") as f2:
        writer_12a = csv.writer(f1)
        writer_12b = csv.writer(f2)
        writer_12a.writerow(HEADER_12AB)
        writer_12b.writerow(HEADER_12CD)

        for n in rule_counts:

            # FIRST SESSION
            setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(n)

            # Preprocessing
            t0_preprocessing = time.perf_counter()
            ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
            tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
            mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
            k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])
            inspector = TrafficInspector(session_rules_first_session(k_list), s_salt)
            t1_preprocessing = time.perf_counter() - t0_preprocessing

            # Token Encryption
            t0_token_encryption = time.perf_counter()
            enc = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            d_toks = [enc.encrypt_token(t) for t in tokens]
            t1_token_encryption = time.perf_counter() - t0_token_encryption

            # Traffic Inspection
            t0_traffic_inspection = time.perf_counter()
            for pos, ct in enumerate(d_toks):
                inspector.inspect(ct, pos)
            t1_traffic_inspection = time.perf_counter() - t0_traffic_inspection

            # RTT (First Session)
            rtt_first = t1_preprocessing + t1_token_encryption + t1_traffic_inspection
            writer_12a.writerow([n, round(rtt_first, 4)])


            # SUBSEQUENT SESSIONS
            new_tokens = generate_dummy_tokens(TOKEN_CONSTANT_8000)

            # Session Rule Preparation
            t0_session_rule_prep = time.perf_counter()
            new_k_s_val = group.random(ZR)
            new_k_s = G_BASE ** new_k_s_val
            session_rules = session_rules_subsequent_session(k_list, new_k_s)
            new_inspector = TrafficInspector(session_rules, s_salt)
            t2_session_rule_prep = time.perf_counter() - t0_session_rule_prep

            # Token Encryption
            t0_tok_encrypt = time.perf_counter()
            enc = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            new_d_toks = [enc.encrypt_token(t) for t in new_tokens]
            t2_tok_encrypt = time.perf_counter() - t0_tok_encrypt

            # Traffic Inspection
            t0_traffic_inspect = time.perf_counter()
            for pos, ct in enumerate(new_d_toks):
                new_inspector.inspect(ct, pos)
            t2_traffic_inspect = time.perf_counter() - t0_traffic_inspect


            rtt_subsequent = t2_session_rule_prep + t2_tok_encrypt + t2_traffic_inspect
            writer_12b.writerow([n, round(rtt_subsequent, 4)])
    print(f"[+] Saved to `{csv_12a}` and `{csv_12b}`!")


def eval_d2_performance_different_tokens(token_counts_hundreds: list[int]):
    """
    Evaluate the Performance of a Round Trip with Different Tokens.

    :param rule_counts: List of token counts in hundreds.
    :type rule_counts: `list[int]`
    """
    print("\n[*] Evaluating Performance of a Round Trip with Different Tokens...")

    # Set up test environment once with 3000 rules.
    setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(RULE_CONSTANT_3000)

    # Pre-compute baseline k_list.
    ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
    tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
    mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
    k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])

    # CSV.
    csv_12c = RESULTS_DIR / FIGURE_12C
    csv_12d = RESULTS_DIR / FIGURE_12D

    with open(csv_12c, "w", newline="") as f1, open(csv_12d, "w", newline="") as f2:
        writer_12c = csv.writer(f1)
        writer_12d = csv.writer(f2)
        writer_12c.writerow(HEADER_12CD)
        writer_12d.writerow(HEADER_12CD)

        for mh in token_counts_hundreds:
            
            # FIRST SESSION
            token_count = mh * 100
            tokens = generate_dummy_tokens(token_count)

            # Prepare Inspector
            t0_prepare_inspector = time.perf_counter()
            inspector = TrafficInspector(session_rules_first_session(k_list), s_salt)
            t1_prepare_inspector = time.perf_counter() - t0_prepare_inspector

            # Token Encryption
            t0_token_encryption = time.perf_counter()
            enc = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            d_toks = [enc.encrypt_token(t) for t in tokens]
            t1_token_encryption = time.perf_counter() - t0_token_encryption

            # Traffic Inspection
            t0_traffic_inspection = time.perf_counter()
            for pos, ct in enumerate(d_toks):
                inspector.inspect(ct, pos)
            t1_traffic_inspection = time.perf_counter() - t0_traffic_inspection

            # RTT (First Session)
            rtt_first = t1_prepare_inspector + t1_token_encryption + t1_traffic_inspection
            writer_12c.writerow([mh, round(rtt_first, 4)])


            # SUBSEQUENT SESSIONS
            new_tokens = generate_dummy_tokens(token_count)

            # Session Rule Preparation
            t0_session_rule_prep = time.perf_counter()
            new_k_s_val = group.random(ZR)
            new_k_s = G_BASE ** new_k_s_val
            session_rules = session_rules_subsequent_session(k_list, new_k_s)
            new_inspector = TrafficInspector(session_rules, s_salt)
            t2_session_rule_prep = time.perf_counter() - t0_session_rule_prep

            # Token Encryption
            t0_tok_encrypt = time.perf_counter()
            enc.K_s = new_k_s
            new_d_toks = [enc.encrypt_token(t) for t in new_tokens]
            t2_tok_encrypt = time.perf_counter() - t0_tok_encrypt

            # Traffic Inspection
            t0_traffic_inspect = time.perf_counter()
            for pos, ct in enumerate(new_d_toks):
                new_inspector.inspect(ct, pos)
            t2_traffic_inspect = time.perf_counter() - t0_traffic_inspect

            rtt_subsequent = t2_session_rule_prep + t2_tok_encrypt + t2_traffic_inspect
            writer_12d.writerow([mh, round(rtt_subsequent, 4)])
    print(f"[+] Saved to `{csv_12c}` and `{csv_12d}`!")
    

def eval_d3_table_vi_repeating_4_times(repeating_counts: list[int]):
    """
    Evaluate the Performance of a Round Trip with 8000 Tokens (changing the number of tokens that repeat 4 times).

    :param repeating_counts: List of token counts that repeat 4 times.
    :type repeating_counts: `list[int]`
    """
    print("\n[*] Evaluating Performance of a Round Trip with 8000 Tokens (changing the number of tokens that repeat 4 times)...")

    # Set up test environment once with 3000 rules.
    setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(RULE_CONSTANT_3000)

    # Pre-compute baseline k_list.
    ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
    tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
    mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
    k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])

    # CSV.
    csv_table_vi = RESULTS_DIR / TABLE_VI

    with open(csv_table_vi, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER_VI)

        for num_repeating in repeating_counts:
            
            # Generate tokens.
            tokens = generate_tokens_repeating_4_times(num_repeating, TOKEN_CONSTANT_8000)

            # Prepare Inspector
            t0_prep = time.perf_counter()
            traffic_inspector = TrafficInspector(session_rules_first_session(k_list), s_salt)
            t1_prep = time.perf_counter() - t0_prep

            # Token Encryption
            t0_enc = time.perf_counter()
            token_encryptor = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            d_toks = [token_encryptor.encrypt_token(t) for t in tokens]
            t1_enc = time.perf_counter() - t0_enc

            # Traffic Inspection
            t0_insp = time.perf_counter()
            for pos, ct in enumerate(d_toks):
                traffic_inspector.inspect(ct, pos)
            t1_insp = time.perf_counter() - t0_insp

            writer.writerow([num_repeating, round(t1_prep + t1_enc + t1_insp, 4)])
    print(f"[+] Saved to `{csv_table_vi}`!")


def eval_d4_table_vii_one_token_repeating(percentages: list[float]):
    """
    Evaluate the Performance of a Round Trip with 8000 Tokens (changing the percentage of one token repeating).

    :param percentages: List of percentages of one token repeating.
    :type percentages: `list[float]`
    """
    print("\n[*] Evaluating Performance of a Round Trip with 8000 Tokens (changing the percentage of one token repeating)...")

    # Set up test environment once with 3000 rules.
    setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(RULE_CONSTANT_3000)

    # Pre-compute baseline k_list.
    ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
    tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
    mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
    k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])

    # CSV.
    csv_table_vii = RESULTS_DIR / TABLE_VII

    with open(csv_table_vii, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER_VII)

        for pct in percentages:
            
            # Generate tokens.
            tokens = generate_tokens_one_repeating(pct, TOKEN_CONSTANT_8000)

            # Prepare Inspector
            t0_prep = time.perf_counter()
            traffic_inspector = TrafficInspector(session_rules_first_session(k_list), s_salt)
            t1_prep = time.perf_counter() - t0_prep

            # Token Encryption
            t0_enc = time.perf_counter()
            token_encryptor = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            d_toks = [token_encryptor.encrypt_token(t) for t in tokens]
            t1_enc = time.perf_counter() - t0_enc

            # Traffic Inspection
            t0_insp = time.perf_counter()
            for pos, ct in enumerate(d_toks):
                traffic_inspector.inspect(ct, pos)
            t1_insp = time.perf_counter() - t0_insp

            writer.writerow([int(pct * 100), round(t1_prep + t1_enc + t1_insp, 4)])
    print(f"[+] Saved to `{csv_table_vii}`!")


def eval_d5_table_viii_subsequent_session_reuse(percentages: list[float]):
    """
    Evaluate the Performance of a Round Trip with 8000 Tokens (changing the percentage of repeated tokens in subsequent sessions).

    :param percentages: List of percentages of repeated tokens in subsequent sessions.
    :type percentages: `list[float]`
    """
    print("\n[*] Evaluating Performance of a Round Trip with 8000 Tokens (changing the percentage of repeated tokens in subsequent sessions)...")

    # Set up test environment once with 3000 rules.
    setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(RULE_CONSTANT_3000)

    # Pre-compute baseline k_list.
    ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
    tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
    mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
    k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])

    # CSV.
    csv_table_viii = RESULTS_DIR / TABLE_VIII

    with open(csv_table_viii, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER_VIII)

        for pct in percentages:

            # Generate Session 1 tokens.
            previous_tokens = generate_dummy_tokens(TOKEN_CONSTANT_8000)
            token_encryptor = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            _ = [token_encryptor.encrypt_token(t) for t in previous_tokens]

            # Generate Session 2 tokens.
            current_tokens = generate_subsequent_tokens(previous_tokens, pct, TOKEN_CONSTANT_8000)

            # Prepare Inspector
            t0_prep = time.perf_counter()
            new_k_s = G_BASE ** group.random(ZR)
            traffic_inspector = TrafficInspector(session_rules_subsequent_session(k_list, new_k_s), s_salt)
            t1_prep = time.perf_counter() - t0_prep

            # Token Encryption
            t0_enc = time.perf_counter()
            token_encryptor.K_s = new_k_s  # Maintain CT state for Session 1.
            d_toks = [token_encryptor.encrypt_token(t) for t in current_tokens]
            t1_enc = time.perf_counter() - t0_enc

            # Traffic Inspection
            t0_insp = time.perf_counter()
            for pos, ct in enumerate(d_toks):
                traffic_inspector.inspect(ct, pos)
            t1_insp = time.perf_counter() - t0_insp

            writer.writerow([int(pct * 100), round(t1_prep + t1_enc + t1_insp, 4)])
    print(f"[+] Saved to `{csv_table_viii}`")


if __name__ == "__main__":
    print("[*] Starting PrivBox Performance Evaluation (Part D)...")
    eval_d1_performance_different_rules(RULE_COUNTS)
    eval_d2_performance_different_tokens(TOKEN_COUNTS_HUNDREDS)
    eval_d3_table_vi_repeating_4_times(REPEATED_TOKEN_COUNT)
    eval_d4_table_vii_one_token_repeating(PERCENTAGES_ONE_TOKEN_REPEATING)
    eval_d5_table_viii_subsequent_session_reuse(PERCENTAGES_REPEATED_TOKENS)
    print("\n[+] PrivBox Performance Evaluation (Part D) Completed!")
