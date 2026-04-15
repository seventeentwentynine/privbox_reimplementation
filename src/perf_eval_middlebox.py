"""
Evaluate Performance of Middlebox

perf_eval_middlebox.py
"""
import time
import os
import csv
from pathlib import Path

# From the Project Files.
from crypto import group, ZR, G_BASE, serialize_element
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
RESULTS_DIR = Path("eval_performance_mb")
RESULTS_DIR.mkdir(exist_ok=True)


# CSV Files.
FIGURE_09A = "figure_09a.csv"
FIGURE_09B = "figure_09b.csv"
TABLE_III = "table_iii.csv"
FIGURE_10A = "figure_10a.csv"
FIGURE_10B = "figure_10b.csv"


# Counts.
RULE_COUNTS = [1, 1000, 2000, 3000]
SESSION_COUNTS = [1, 5, 10, 20]
RULES_3000 = 3000


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


######################
#                    #
# --- Evaluation --- #
#                    #
######################


def eval_b1a_performance_preprocessing_phase_time(rule_counts: list[int]):
    """
    Evaluate the Performance of the Preprocessing Phase Time.

    :param rule_counts: List of rule counts.
    :type rule_counts: `list[int]`
    """
    print("\n[*] Evaluating MB Preprocessing Time...")

    # CSV.
    csv_path = RESULTS_DIR / FIGURE_09A
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Number of Rules", "Time Cost (ms)"])

        # Iterate through each rule count.
        for rule_count in rule_counts:
            _, _, _, _, _, _, _, mb = setup_test_environment(rule_count)

            # Time Preprocess MB.
            start_time = time.perf_counter()
            _ = PreprocessingMB(mb.y, mb.y_tilde)
            time_preprocess_mb = (time.perf_counter() - start_time) * (10 ** 3)

            # Write Row.
            writer.writerow([rule_count, round(time_preprocess_mb, 4)])
    print(f"[+] Saved to `{csv_path}`!")


def eval_b1b_performance_preprocessing_phase_bandwidth(rule_counts: list[int]):
    """
    Evaluate the Performance of the Preprocessing Phase Bandwidth.

    :param rule_counts: List of rule counts.
    :type rule_counts: `list[int]`
    """
    print("\n[*] Evaluating MB Preprocessing Bandwidth...")

    # CSV.
    csv_path = RESULTS_DIR / FIGURE_09B
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Number of Rules", "Bandwidth Cost (KB)"])

        # Iterate through each rule count.
        for rule_count in rule_counts:
            setup_state, rg_keys, mb_keys, k_s1, k_s2, _, _, _ = setup_test_environment(rule_count)

            # Preprocess Endpoint.
            ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
            tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

            # Set Total Bytes of Bandwidth
            total_bytes = 0

            # MB → Endpoint (PREP_SETUP)
            total_bytes += 4 + len(b"PREP_SETUP")
            total_bytes += 8 + 4  # Rule count 'n'

            # Signed R
            total_bytes += 4 + len(serialize_element(setup_state.R.value))
            total_bytes += 4 + len(setup_state.R.sig_rg)
            total_bytes += 4 + len(setup_state.R.sig_mb)

            # Rule Tuples
            for rt in setup_state.rule_tuples:
                total_bytes += 4 + len(serialize_element(rt.R_i))
                total_bytes += 4 + len(serialize_element(rt.tilde_R_i.value))
                total_bytes += 4 + len(rt.tilde_R_i.sig_rg)
                total_bytes += 4 + len(rt.tilde_R_i.sig_mb)
                total_bytes += 4 + len(serialize_element(rt.hat_R_i.value))
                total_bytes += 4 + len(rt.hat_R_i.sig_rg)
                total_bytes += 4 + len(rt.hat_R_i.sig_mb)
            
            # Endpoint → MB (PREP_RESPONSE)
            total_bytes += 4 + len(b"PREP_RESPONSE")
            total_bytes += 4 + len(serialize_element(ep_prep.K_s1))
            total_bytes += 8 + 4  # Length of tildeK_list
            for tk in tilde_k_list:
                total_bytes += 4 + len(serialize_element(tk))
            total_bytes += 8 + 4  # s_salt

            # Convert to KB
            bandwidth_kb = total_bytes / 1024.0
            writer.writerow([rule_count, round(bandwidth_kb, 4)])
    print(f"[+] Saved to `{csv_path}`!")


def eval_b2_performance_traffic_inspection_phase(rule_counts: list[int]):
    """
    Evaluate the Performance of the Traffic Inspection Phase.

    :param rule_counts: List of rule counts.
    :type rule_counts: `list[int]`
    """
    print("\n[*] Evaluating Traffic Inspection...")

    # CSV.
    csv_path = RESULTS_DIR / TABLE_III
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["No. of Rules", "Time (μs)"])

        # Iterate through each rule count.
        for rule_count in rule_counts:
            setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(rule_count)

            # Preprocess Endpoint.
            ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
            tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

            # Preprocess MB.
            mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
            k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])
            inspector = TrafficInspector(session_rules_first_session(k_list), s_salt)

            # Encrypt Token.
            enc = TokenEncryptor(ep_prep.R, k_s1, k_s2, s_salt)
            sample_token = enc.encrypt_token(b"UNION SELECT")

            # Time Traffic Inspection.
            start_time = time.perf_counter()
            _ = inspector.inspect(sample_token, 0)
            time_traffic_inspection = (time.perf_counter() - start_time) * (10 ** 6)

            # Write Row.
            writer.writerow([rule_count, round(time_traffic_inspection, 4)])
    print(f"[+] Saved to `{csv_path}`!")


def eval_b3_performance_preparation_of_session_rule(session_counts: list[int]):
    """
    Evaluate the Performance of the Preparation of Session Rule in Subsequent Sessions

    :param session_counts: List of session counts.
    :type session_counts: `list[int]`
    """
    print("\n[*] Evaluating Preparation of Session Rule in Subsequent Sessions...")
    
    # Set up the baseline session (done once with mentioned rule count).
    setup_state, rg_keys, mb_keys, k_s1, k_s2, s_salt, _, mb = setup_test_environment(RULES_3000)

    # Preprocess Endpoint.
    ep_prep = PreprocessingEndpoint(k_s1, k_s2, rg_keys.public, mb_keys.public)
    tilde_k_list = ep_prep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

    # Preprocess MB.
    mb_prep = PreprocessingMB(mb.y, mb.y_tilde)
    k_list = mb_prep.finalize_K(ep_prep.K_s1, tilde_k_list, [rt.R_i for rt in setup_state.rule_tuples])

    # CSV.
    csv_path_time = RESULTS_DIR / FIGURE_10A
    csv_path_bandwidth = RESULTS_DIR / FIGURE_10B
    with open(csv_path_time, "w", newline="") as ft, open(csv_path_bandwidth, "w", newline="") as fb:
        writer_time = csv.writer(ft)
        writer_bandwidth = csv.writer(fb)
        writer_time.writerow(["Number of Sessions", "Time Cost (ms)"])
        writer_bandwidth.writerow(["Number of Sessions", "Bandwidth (KB)"])

        for session_count in session_counts:
            # Set total time and bandwidth.
            total_time = 0.0
            total_bytes = 0

            for _ in range(session_count):
                # Endpoint generates new session key (K_s).
                new_k_s = group.random(ZR)
                k_s = G_BASE ** new_k_s

                # Bandwidth → Endpoint sends k_s to MB.
                total_bytes += 4 + len(serialize_element(k_s))

                # Time → MB calculates new session rules.
                start_time = time.perf_counter()
                _ = session_rules_subsequent_session(k_list, k_s)
                total_time += (time.perf_counter() - start_time) * (10 ** 3)
            
            total_bandwidth = total_bytes / 1024.0

            writer_time.writerow([session_count, round(total_time, 4)])
            writer_bandwidth.writerow([session_count, round(total_bandwidth, 4)])
    print(f"[+] Saved time to `{csv_path_time}`!")
    print(f"[+] Saved bandwidth to `{csv_path_bandwidth}`!")


if __name__ == "__main__":
    print("[*] Starting PrivBox Performance Evaluation (Part B)...")
    eval_b1a_performance_preprocessing_phase_time(RULE_COUNTS)
    eval_b1b_performance_preprocessing_phase_bandwidth(RULE_COUNTS)
    eval_b2_performance_traffic_inspection_phase(RULE_COUNTS)
    eval_b3_performance_preparation_of_session_rule(SESSION_COUNTS)
    print("\n[+] PrivBox Performance Evaluation (Part B) Completed!")
