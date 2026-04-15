"""
Section VII-A: Complexity Analysis Benchmark

Measures wall-clock time for each PrivBox phase across varying rule counts,
using the actual cryptographic primitives from protocols.py.

Outputs JSON results to stdout for downstream plotting.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List

# ── PrivBox imports ──
from crypto import G_BASE, H2, H3, H4, ZR, group
from protocols import (
    PreprocessingEndpoint,
    PreprocessingMB,
    RulePreparationMB,
    RulePreparationRG,
    TokenEncryptor,
    session_rules_first_session,
    session_rules_subsequent_session,
)
from inspection import TrafficInspector
from signatures import generate_ed25519_keypair
from storage import RuleTuple, SetupState


def generate_rules(n: int) -> List[bytes]:
    """Generate n unique 8-byte rule tokens (like Snort tokenized to 8 bytes)."""
    return [f"rule{i:04d}".encode("utf-8")[:8].ljust(8, b"\x00") for i in range(n)]


def generate_tokens(m: int) -> List[bytes]:
    """Generate m unique 8-byte payload tokens."""
    return [f"tok{i:05d}".encode("utf-8")[:8].ljust(8, b"\x00") for i in range(m)]


def run_benchmark(n_rules: int, n_tokens: int, n_repeats: int = 3) -> Dict[str, Any]:
    """
    Run the full PrivBox pipeline and time each phase.
    Returns a dict of phase -> time_ms.
    """
    rules = generate_rules(n_rules)
    tokens = generate_tokens(n_tokens)

    results: Dict[str, List[float]] = {
        "setup_rg": [],
        "setup_mb": [],
        "setup_total": [],
        "preproc_endpoint": [],
        "preproc_mb": [],
        "preproc_total": [],
        "session_rule_prep": [],
        "token_encryption": [],
        "traffic_inspection": [],
    }

    for trial in range(n_repeats):
        # ── Key generation (one-time, not timed) ──
        kp_rg = generate_ed25519_keypair()
        kp_mb = generate_ed25519_keypair()

        # ════════════════════════════════════════════
        # SETUP: Rule Preparation Protocol (Fig. 2)
        # ════════════════════════════════════════════

        # -- RG side --
        t0 = time.perf_counter()
        rg = RulePreparationRG(rules, kp_rg.private)
        S_A, L = rg.step1_commitments()
        t_rg_step1 = time.perf_counter()

        # -- MB side --
        t_mb_start = time.perf_counter()
        mb_rp = RulePreparationMB(rules, kp_mb.private, kp_rg.public)
        S_B, S = mb_rp.step2_commitments(S_A, L)
        t_mb_step2 = time.perf_counter()

        # -- RG step 3 --
        V_list = rg.step3_compute_V(S_B, S)
        t_rg_step3 = time.perf_counter()

        # -- MB step 4 --
        Y, R_tilde, S_i_list = mb_rp.step4_verify_and_mask(V_list)
        t_mb_step4 = time.perf_counter()

        # -- RG step 5 --
        rg_out = rg.step5_compute_and_sign(Y, R_tilde, S_i_list)
        t_rg_step5 = time.perf_counter()

        # -- MB step 6 --
        setup_state = mb_rp.step6_verify_and_store(rg_out)
        t_mb_step6 = time.perf_counter()

        setup_rg_ms = ((t_rg_step1 - t0) + (t_rg_step3 - t_mb_step2) + (t_rg_step5 - t_mb_step4)) * 1000
        setup_mb_ms = ((t_mb_step2 - t_rg_step1) + (t_mb_step4 - t_rg_step3) + (t_mb_step6 - t_rg_step5)) * 1000
        setup_total_ms = (t_mb_step6 - t0) * 1000

        results["setup_rg"].append(setup_rg_ms)
        results["setup_mb"].append(setup_mb_ms)
        results["setup_total"].append(setup_total_ms)

        # ════════════════════════════════════════════
        # PREPROCESSING: Endpoint <-> MB (Fig. 3)
        # ════════════════════════════════════════════
        k_s1 = group.random(ZR)
        k_s2 = group.random(ZR)

        # Endpoint side
        t_ep_start = time.perf_counter()
        ep = PreprocessingEndpoint(k_s1, k_s2, kp_rg.public, kp_mb.public)
        tildeK_list = ep.verify_and_compute_tildeK(setup_state.R, setup_state.rule_tuples)
        t_ep_done = time.perf_counter()

        # MB side
        t_mb_pp_start = time.perf_counter()
        mb_pp = PreprocessingMB(setup_state.y, setup_state.y_tilde)
        R_i_list = [rt.R_i for rt in setup_state.rule_tuples]
        K_list = mb_pp.finalize_K(ep.K_s1, tildeK_list, R_i_list)
        t_mb_pp_done = time.perf_counter()

        preproc_ep_ms = (t_ep_done - t_ep_start) * 1000
        preproc_mb_ms = (t_mb_pp_done - t_mb_pp_start) * 1000
        preproc_total_ms = (t_mb_pp_done - t_ep_start) * 1000

        results["preproc_endpoint"].append(preproc_ep_ms)
        results["preproc_mb"].append(preproc_mb_ms)
        results["preproc_total"].append(preproc_total_ms)

        # ════════════════════════════════════════════
        # SESSION RULE PREPARATION (Fig. 5)
        # ════════════════════════════════════════════
        t_sr_start = time.perf_counter()
        session_rules = session_rules_first_session(K_list)
        t_sr_done = time.perf_counter()

        results["session_rule_prep"].append((t_sr_done - t_sr_start) * 1000)

        # ════════════════════════════════════════════
        # TOKEN ENCRYPTION (Fig. 6)
        # ════════════════════════════════════════════
        S_salt = int.from_bytes(os.urandom(8), "big")

        t_te_start = time.perf_counter()
        te = TokenEncryptor(R=setup_state.R.value, k_s1=k_s1, k_s2=k_s2, S_salt=S_salt)
        encrypted_tokens = [te.encrypt_token(t) for t in tokens]
        t_te_done = time.perf_counter()

        results["token_encryption"].append((t_te_done - t_te_start) * 1000)

        # ════════════════════════════════════════════
        # TRAFFIC INSPECTION (Fig. 7)
        # ════════════════════════════════════════════
        t_ti_start = time.perf_counter()
        inspector = TrafficInspector(session_rules, S_salt)
        for pos, ct in enumerate(encrypted_tokens):
            inspector.inspect(ct, pos)
        t_ti_done = time.perf_counter()

        results["traffic_inspection"].append((t_ti_done - t_ti_start) * 1000)

        sys.stderr.write(f"  trial {trial+1}/{n_repeats} done\n")
        sys.stderr.flush()

    # Average over trials
    avg = {k: sum(v) / len(v) for k, v in results.items()}
    return {
        "n_rules": n_rules,
        "n_tokens": n_tokens,
        "n_repeats": n_repeats,
        "avg_ms": avg,
        "all_trials": results,
    }


def main():
    # Rule counts matching the paper's Table IV
    rule_counts = [1, 10, 50, 100]
    token_count = 100  # fixed token count for complexity analysis
    n_repeats = 3

    all_results = []

    for n_rules in rule_counts:
        sys.stderr.write(f"\n=== Benchmarking n_rules={n_rules}, n_tokens={token_count} ===\n")
        sys.stderr.flush()
        result = run_benchmark(n_rules, token_count, n_repeats=n_repeats)
        all_results.append(result)

    # Also vary tokens with fixed rules
    token_counts = [1, 10, 50, 100]
    fixed_rules = 10

    for n_tokens in token_counts:
        sys.stderr.write(f"\n=== Benchmarking n_rules={fixed_rules}, n_tokens={n_tokens} ===\n")
        sys.stderr.flush()
        result = run_benchmark(fixed_rules, n_tokens, n_repeats=n_repeats)
        all_results.append(result)

    output = {
        "benchmark": "complexity_analysis",
        "description": "Section VII-A: Time per phase for varying rules and tokens",
        "results": all_results,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
