"""
Section VII-C: Performance of Endpoint Benchmark

Measures:
  - Table IV:  Endpoint preprocessing time vs number of rules
  - Table V:   Endpoint token encryption time vs number of tokens
  - Figure 11: Token encryption with repeated tokens

Uses the actual PrivBox cryptographic primitives from protocols.py.
Outputs JSON results to stdout.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List, Tuple

from crypto import G_BASE, H2, ZR, group
from protocols import (
    PreprocessingEndpoint,
    PreprocessingMB,
    RulePreparationMB,
    RulePreparationRG,
    TokenEncryptor,
    session_rules_first_session,
    session_rules_subsequent_session,
)
from signatures import generate_ed25519_keypair
from storage import SetupState


def generate_rules(n: int) -> List[bytes]:
    """Generate n unique 8-byte rule tokens."""
    return [f"rule{i:04d}".encode("utf-8")[:8].ljust(8, b"\x00") for i in range(n)]


def generate_tokens(m: int, prefix: str = "tok") -> List[bytes]:
    """Generate m unique 8-byte payload tokens."""
    return [f"{prefix}{i:04d}".encode("utf-8")[:8].ljust(8, b"\x00") for i in range(m)]


def full_setup(rules: List[bytes]) -> Tuple[SetupState, Any, Any, Any, Any]:
    """
    Run the full rule preparation protocol (Fig. 2) and return
    (setup_state, pk_sig_rg, pk_sig_mb, kp_rg, kp_mb).
    """
    kp_rg = generate_ed25519_keypair()
    kp_mb = generate_ed25519_keypair()

    rg = RulePreparationRG(rules, kp_rg.private)
    S_A, L = rg.step1_commitments()

    mb_rp = RulePreparationMB(rules, kp_mb.private, kp_rg.public)
    S_B, S = mb_rp.step2_commitments(S_A, L)

    V_list = rg.step3_compute_V(S_B, S)
    Y, R_tilde, S_i_list = mb_rp.step4_verify_and_mask(V_list)
    rg_out = rg.step5_compute_and_sign(Y, R_tilde, S_i_list)
    setup_state = mb_rp.step6_verify_and_store(rg_out)

    return setup_state, kp_rg.public, kp_mb.public, kp_rg, kp_mb


# ═══════════════════════════════════════════════════════════════
# TABLE IV: Endpoint Preprocessing Time
# ═══════════════════════════════════════════════════════════════

def bench_preprocessing(rule_counts: List[int], n_repeats: int = 3) -> List[Dict]:
    """Measure endpoint preprocessing time for varying rule counts."""
    results = []

    for n_rules in rule_counts:
        sys.stderr.write(f"\n[Table IV] n_rules={n_rules} ...\n")
        sys.stderr.flush()

        rules = generate_rules(n_rules)

        # Setup once (not timed — this is RG+MB setup, not endpoint)
        setup_state, pk_rg, pk_mb, _, _ = full_setup(rules)

        times_ep = []
        times_mb = []

        for trial in range(n_repeats):
            k_s1 = group.random(ZR)
            k_s2 = group.random(ZR)

            # ── Endpoint side (the measurement target) ──
            t0 = time.perf_counter()
            ep = PreprocessingEndpoint(k_s1, k_s2, pk_rg, pk_mb)
            tildeK_list = ep.verify_and_compute_tildeK(
                setup_state.R, setup_state.rule_tuples
            )
            t1 = time.perf_counter()

            # ── MB side (for completeness) ──
            t2 = time.perf_counter()
            mb_pp = PreprocessingMB(setup_state.y, setup_state.y_tilde)
            R_i_list = [rt.R_i for rt in setup_state.rule_tuples]
            K_list = mb_pp.finalize_K(ep.K_s1, tildeK_list, R_i_list)
            t3 = time.perf_counter()

            times_ep.append((t1 - t0) * 1000)
            times_mb.append((t3 - t2) * 1000)

            sys.stderr.write(f"  trial {trial+1}/{n_repeats}: endpoint={times_ep[-1]:.3f}ms\n")
            sys.stderr.flush()

        results.append({
            "n_rules": n_rules,
            "endpoint_avg_ms": sum(times_ep) / len(times_ep),
            "mb_avg_ms": sum(times_mb) / len(times_mb),
            "endpoint_all_ms": times_ep,
            "mb_all_ms": times_mb,
        })

    return results


# ═══════════════════════════════════════════════════════════════
# TABLE V: Endpoint Token Encryption Time
# ═══════════════════════════════════════════════════════════════

def bench_token_encryption(token_counts: List[int], n_rules: int = 10,
                           n_repeats: int = 3) -> List[Dict]:
    """Measure endpoint token encryption time for varying token counts."""
    results = []
    rules = generate_rules(n_rules)

    # Full setup + preprocessing (not timed)
    setup_state, pk_rg, pk_mb, _, _ = full_setup(rules)
    k_s1 = group.random(ZR)
    k_s2 = group.random(ZR)
    ep = PreprocessingEndpoint(k_s1, k_s2, pk_rg, pk_mb)
    tildeK_list = ep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
    mb_pp = PreprocessingMB(setup_state.y, setup_state.y_tilde)
    R_i_list = [rt.R_i for rt in setup_state.rule_tuples]
    K_list = mb_pp.finalize_K(ep.K_s1, tildeK_list, R_i_list)

    for n_tokens in token_counts:
        sys.stderr.write(f"\n[Table V] n_tokens={n_tokens} ...\n")
        sys.stderr.flush()

        tokens = generate_tokens(n_tokens)
        times = []

        for trial in range(n_repeats):
            S_salt = int.from_bytes(os.urandom(8), "big")

            t0 = time.perf_counter()
            te = TokenEncryptor(
                R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt
            )
            encrypted = [te.encrypt_token(t) for t in tokens]
            t1 = time.perf_counter()

            times.append((t1 - t0) * 1000)
            sys.stderr.write(f"  trial {trial+1}/{n_repeats}: {times[-1]:.3f}ms\n")
            sys.stderr.flush()

        results.append({
            "n_tokens": n_tokens,
            "avg_ms": sum(times) / len(times),
            "all_ms": times,
            "tokens_per_sec": n_tokens / (sum(times) / len(times) / 1000) if sum(times) > 0 else 0,
        })

    return results


# ═══════════════════════════════════════════════════════════════
# FIGURE 11: Token Encryption with Repeated Tokens
# ═══════════════════════════════════════════════════════════════

def bench_repeated_tokens_fig11a(total_tokens: int = 800, n_rules: int = 10,
                                  n_repeats: int = 3) -> List[Dict]:
    """
    Fig 11(a): Vary the number of repeated tokens (each repeating 4 times).
    Total token set = total_tokens. Some tokens appear 4 times.
    """
    results = []
    rules = generate_rules(n_rules)
    setup_state, pk_rg, pk_mb, _, _ = full_setup(rules)
    k_s1 = group.random(ZR)
    k_s2 = group.random(ZR)
    ep = PreprocessingEndpoint(k_s1, k_s2, pk_rg, pk_mb)
    tildeK_list = ep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

    # percentages of tokens that repeat 4x
    repeat_pcts = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    for pct in repeat_pcts:
        sys.stderr.write(f"\n[Fig11a] {pct}% repeated tokens (4x) ...\n")
        sys.stderr.flush()

        # Build token list: some unique, some repeated 4 times
        n_repeated = int(total_tokens * pct / 100)
        n_unique = total_tokens - n_repeated

        # The repeated tokens: each appears 4 times
        n_repeated_distinct = max(1, n_repeated // 4) if n_repeated > 0 else 0
        repeated_part = generate_tokens(n_repeated_distinct, prefix="rpt")
        repeated_expanded = repeated_part * 4
        repeated_expanded = repeated_expanded[:n_repeated]

        unique_part = generate_tokens(n_unique, prefix="unq")
        all_tokens = unique_part + repeated_expanded

        times = []
        for trial in range(n_repeats):
            S_salt = int.from_bytes(os.urandom(8), "big")
            t0 = time.perf_counter()
            te = TokenEncryptor(R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)
            for tok in all_tokens:
                te.encrypt_token(tok)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)

        results.append({
            "repeat_pct": pct,
            "n_repeated": n_repeated,
            "n_unique": n_unique,
            "avg_ms": sum(times) / len(times),
            "all_ms": times,
        })

    return results


def bench_repeated_tokens_fig11b(total_tokens: int = 800, n_rules: int = 10,
                                  n_repeats: int = 3) -> List[Dict]:
    """
    Fig 11(b): One specific token repeating N% of the time.
    Remaining tokens are unique.
    """
    results = []
    rules = generate_rules(n_rules)
    setup_state, pk_rg, pk_mb, _, _ = full_setup(rules)
    k_s1 = group.random(ZR)
    k_s2 = group.random(ZR)
    ep = PreprocessingEndpoint(k_s1, k_s2, pk_rg, pk_mb)
    tildeK_list = ep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

    repeat_pcts = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100]

    for pct in repeat_pcts:
        sys.stderr.write(f"\n[Fig11b] one token repeating {pct}% ...\n")
        sys.stderr.flush()

        n_repeated = int(total_tokens * pct / 100)
        n_unique = total_tokens - n_repeated

        repeated_token = b"RPTTOKEN"  # the one token that repeats
        unique_part = generate_tokens(n_unique, prefix="unq")
        all_tokens = unique_part + [repeated_token] * n_repeated

        times = []
        for trial in range(n_repeats):
            S_salt = int.from_bytes(os.urandom(8), "big")
            t0 = time.perf_counter()
            te = TokenEncryptor(R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)
            for tok in all_tokens:
                te.encrypt_token(tok)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)

        results.append({
            "repeat_pct": pct,
            "avg_ms": sum(times) / len(times),
            "all_ms": times,
        })

    return results


def bench_repeated_tokens_fig11c(total_tokens: int = 800, n_rules: int = 10,
                                  n_repeats: int = 3) -> List[Dict]:
    """
    Fig 11(c): Tokens repeated from a previous session.
    Simulate by running token encryption twice: session 1 (baseline),
    then session 2 where X% of tokens appeared in session 1.
    """
    results = []
    rules = generate_rules(n_rules)
    setup_state, pk_rg, pk_mb, _, _ = full_setup(rules)
    k_s1 = group.random(ZR)
    k_s2 = group.random(ZR)
    ep = PreprocessingEndpoint(k_s1, k_s2, pk_rg, pk_mb)
    tildeK_list = ep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)

    # Pre-generate "previous session" tokens
    prev_session_tokens = generate_tokens(total_tokens, prefix="prv")

    repeat_pcts = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100]

    for pct in repeat_pcts:
        sys.stderr.write(f"\n[Fig11c] {pct}% from previous session ...\n")
        sys.stderr.flush()

        n_from_prev = int(total_tokens * pct / 100)
        n_new = total_tokens - n_from_prev

        new_tokens = generate_tokens(n_new, prefix="new")
        reused_tokens = prev_session_tokens[:n_from_prev]
        all_tokens = new_tokens + reused_tokens

        times = []
        for trial in range(n_repeats):
            S_salt = int.from_bytes(os.urandom(8), "big")

            # Session 1: warm up with previous tokens (simulate prior session)
            te1 = TokenEncryptor(R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)
            for tok in prev_session_tokens:
                te1.encrypt_token(tok)

            # Session 2: encrypt current tokens, reusing cache from session 1
            # In PrivBox, cross-session reuse means the CT cache persists
            t0 = time.perf_counter()
            te2 = TokenEncryptor(R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)
            # Simulate reuse: pre-populate cache with previous session's entries
            te2.CT = dict(te1.CT)
            for tok in all_tokens:
                te2.encrypt_token(tok)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)

        results.append({
            "repeat_pct": pct,
            "avg_ms": sum(times) / len(times),
            "all_ms": times,
        })

    return results


def main():
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.write("PrivBox Endpoint Performance Benchmark\n")
    sys.stderr.write("Section VII-C of the paper\n")
    sys.stderr.write("=" * 60 + "\n")

    n_repeats = 3

    # ── Table IV: Preprocessing ──
    sys.stderr.write("\n\n>>> TABLE IV: Endpoint Preprocessing <<<\n")
    rule_counts = [1, 10, 50, 100, 200]
    table_iv = bench_preprocessing(rule_counts, n_repeats=n_repeats)

    # ── Table V: Token Encryption ──
    sys.stderr.write("\n\n>>> TABLE V: Endpoint Token Encryption <<<\n")
    token_counts = [1, 10, 50, 100, 200, 500]
    table_v = bench_token_encryption(token_counts, n_rules=10, n_repeats=n_repeats)

    # ── Figure 11 ──
    total_tokens = 200  # scaled down from 800 for reasonable runtime
    sys.stderr.write(f"\n\n>>> FIGURE 11: Repeated Tokens (total={total_tokens}) <<<\n")

    sys.stderr.write("\n--- Fig 11(a): Repeated tokens (4x each) ---\n")
    fig11a = bench_repeated_tokens_fig11a(total_tokens, n_rules=10, n_repeats=n_repeats)

    sys.stderr.write("\n--- Fig 11(b): One token repeating ---\n")
    fig11b = bench_repeated_tokens_fig11b(total_tokens, n_rules=10, n_repeats=n_repeats)

    sys.stderr.write("\n--- Fig 11(c): Tokens from previous session ---\n")
    fig11c = bench_repeated_tokens_fig11c(total_tokens, n_rules=10, n_repeats=n_repeats)

    output = {
        "benchmark": "endpoint_performance",
        "description": "Section VII-C: Endpoint preprocessing and token encryption",
        "table_iv_preprocessing": table_iv,
        "table_v_token_encryption": table_v,
        "fig11a_repeated_4x": fig11a,
        "fig11b_one_token_repeating": fig11b,
        "fig11c_from_previous_session": fig11c,
    }

    print(json.dumps(output, indent=2))
    sys.stderr.write("\n\nBenchmark complete!\n")


if __name__ == "__main__":
    main()
