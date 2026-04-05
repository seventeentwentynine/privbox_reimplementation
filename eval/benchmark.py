"""
Performance/Big-O Evaluation

benchmark.py
"""
import requests
import time
import csv
import os

# Container endpoints (from `docker-compose.yml`)
RG_URL = "http://localhost:8001"
MB_URL = "http://localhost:8002"
SENDER_URL = "http://localhost:8003"


def test_rule_scaling(n_values: list) -> list:
    """
    Tests O(n) complexity by varying a number of rules.
    Measures the times of:
    - Setup
    - Preprocessing
    - Traffic Inspection
    """
    print(f"--- Starting Rule Scaling Test (Varying 'n') ---")
    results = []

    # Fixed 'm' (tokens) to a constant so we are only measuring the impact of 'n' (rules).
    CONSTANT_M = 100
    dummy_tokens = [{
        "salt": "dummy_salt=",
        "ciphertext": f"dummy_cipher_{i}=",
        "offset": i
    } for i in range(CONSTANT_M)]

    for n in n_values:
        print(f"Testing with n={n} rules...")

        # Generate 'n' dummy rules.
        rules_payload = {
            f"rule_{i}": {
                "rule_id": f"rule_{i}",
                "keyword": f"threat_{i}"
            } for i in range(n)
        }

        # Setup Phase: Update Middlebox Rules
        setup_start_time = time.perf_counter()
        requests.post(f"{MB_URL}/rules/update", json=rules_payload)
        setup_time = time.perf_counter() - setup_start_time

        # Preprocessing Phase: Middlebox Prepares Rule Tuples
        session_response = requests.post(f"{MB_URL}/session/init").json()
        session_id = session_response["session_id"]
        preprocessing_start_time = time.perf_counter()
        requests.post(f"{MB_URL}/session/preprocess", json={
            "session_id": session_id,
            "K_s1": "dummy_base64_key="
        })
        preprocessing_time = time.perf_counter() - preprocessing_start_time

        # Traffic Inspection Phase: Middlebox Compares Tokens Against Rule Tuples
        traffic_inspection_start_time = time.perf_counter()
        requests.post(f"{MB_URL}/traffic/inspect", json={
            "session_id": session_id,
            "tokens": dummy_tokens
        })
        traffic_inspection_time = time.perf_counter() - traffic_inspection_start_time

        results.append({
            "n_rules": n,
            "setup_time_sec": setup_time,
            "preprocessing_time_sec": preprocessing_time,
            "traffic_inspection_time_sec": traffic_inspection_time
        })
    
    return results


def test_token_scaling(m_values: list) -> list:
    """
    Tests O(m) complexity by varying the number of tokens.
    Measures the times of:
    - Token Encryption (Sender)
    - Traffic Inspection (Middlebox)
    """
    print(f"--- Starting Token Scaling Test (Varying 'm') ---")
    results = []

    # Fixed 'n' (rules) to a constant so we are only measuring the impact of 'm' (tokens).
    CONSTANT_N = 100
    rules_payload = {
        f"rule{i}": {
            "rule_id": f"rule_{i}",
            "keyword": f"threat_{i}"
        } for i in range(CONSTANT_N)
    }
    requests.post(f"{MB_URL}/rules/update", json=rules_payload)
    
    # Set up Middlebox rule tuples.
    mb_session_response = requests.post(f"{MB_URL}/session/init").json()
    mb_session_id = mb_session_response["session_id"]
    requests.post(f"{MB_URL}/session/preprocess", json={
        "session_id": mb_session_id,
        "K_s1": "dummy_base64_key="
    })

    # Initialize Sender session.
    sender_session_response = requests.post(f"{SENDER_URL}/connect").json()
    sender_session_id = sender_session_response["session_id"]

    for m in m_values:
        print(f"Testing with m={m} tokens...")

        # Generate a payload string with 'm' tokens.
        payload = " ".join([f"random_privbox_log{i}" for i in range(m)])

        # Token Encryption Phase: Sender Tokenizes and Encrypts
        token_encryption_start_time = time.perf_counter()
        sender_send_response = requests.post(f"{SENDER_URL}/send", json={
            "session_id": sender_session_id,
            "payload": payload
        }).json()
        token_encryption_time = time.perf_counter() - token_encryption_start_time
        encrypted_tokens = sender_send_response.get("encrypted_tokens", [])  # Avoid using direct key access (i.e. `sender_send_response["encrypted_tokens"]`), which might crash the script.

        # Traffic Inspection Phase: Middlebox Compares Tokens Against Rule Tuples
        traffic_inspection_start_time = time.perf_counter()
        requests.post(f"{MB_URL}/traffic/inspect", json={
            "session_id": mb_session_id,
            "tokens": encrypted_tokens
        })
        traffic_inspection_time = time.perf_counter() - traffic_inspection_start_time
        
        results.append({
            "m_tokens": m,
            "token_encryption_time_sec": token_encryption_time,
            "traffic_inspection_time_sec": traffic_inspection_time
        })
    
    return results
