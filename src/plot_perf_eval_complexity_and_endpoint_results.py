"""
Plot benchmark results from perf_eval_complexity.py and perf_eval_endpoint.py.

Usage:
    python plot_perf_eval_complexity_and_endpoint_results.py complexity_results.json endpoint_results.json

Generates PNG figures in the current directory.
"""

from __future__ import annotations

import json
import sys

import matplotlib.pyplot as plt
import numpy as np


PRIVBOX_COLOR = '#d62728'


def plot_complexity(data: dict, out_dir: str = "."):
    """Plot complexity analysis results."""
    results = data["results"]

    # Separate: varying rules (fixed tokens) vs varying tokens (fixed rules)
    # First batch: varying rules
    rule_vary = [r for r in results if r["n_tokens"] == 100]
    token_vary = [r for r in results if r["n_rules"] == 10 and r not in rule_vary]

    # ── Phase times vs number of rules ──
    phases = ["setup_total", "preproc_total", "session_rule_prep",
              "token_encryption", "traffic_inspection"]
    phase_labels = ["Setup\n(RG+MB)", "Preprocessing\n(EP+MB)",
                    "Session Rule\nPreparation", "Token\nEncryption",
                    "Traffic\nInspection"]

    if rule_vary:
        fig, ax = plt.subplots(figsize=(12, 6))
        x_rules = [r["n_rules"] for r in rule_vary]
        for phase, label in zip(phases, phase_labels):
            times = [r["avg_ms"][phase] for r in rule_vary]
            ax.plot(x_rules, times, marker='o', linewidth=2, markersize=7, label=label)

        ax.set_xlabel("Number of Rules", fontsize=12)
        ax.set_ylabel("Time (ms)", fontsize=12)
        ax.set_title("PrivBox Phase Times vs Number of Rules\n"
                      "(measured with actual Charm-Crypto primitives)", fontsize=13, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_complexity_by_rules.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_complexity_by_rules.png")

    # ── Phase times vs number of tokens ──
    if token_vary:
        fig, ax = plt.subplots(figsize=(12, 6))
        x_tokens = [r["n_tokens"] for r in token_vary]
        for phase, label in zip(phases, phase_labels):
            times = [r["avg_ms"][phase] for r in token_vary]
            ax.plot(x_tokens, times, marker='s', linewidth=2, markersize=7, label=label)

        ax.set_xlabel("Number of Tokens", fontsize=12)
        ax.set_ylabel("Time (ms)", fontsize=12)
        ax.set_title("PrivBox Phase Times vs Number of Tokens\n"
                      "(measured with actual Charm-Crypto primitives)", fontsize=13, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_complexity_by_tokens.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_complexity_by_tokens.png")

    # ── Stacked bar: RG vs MB vs Endpoint breakdown ──
    if rule_vary:
        fig, ax = plt.subplots(figsize=(10, 6))
        x = np.arange(len(rule_vary))
        width = 0.5
        x_labels = [str(r["n_rules"]) for r in rule_vary]

        setup_rg = [r["avg_ms"]["setup_rg"] for r in rule_vary]
        setup_mb = [r["avg_ms"]["setup_mb"] for r in rule_vary]
        preproc_ep = [r["avg_ms"]["preproc_endpoint"] for r in rule_vary]
        preproc_mb = [r["avg_ms"]["preproc_mb"] for r in rule_vary]

        ax.bar(x, setup_rg, width, label='Setup (RG)', color='#1f77b4')
        ax.bar(x, setup_mb, width, bottom=setup_rg, label='Setup (MB)', color='#ff7f0e')
        bottom2 = [a + b for a, b in zip(setup_rg, setup_mb)]
        ax.bar(x, preproc_ep, width, bottom=bottom2, label='Preproc (Endpoint)', color='#d62728')
        bottom3 = [a + b for a, b in zip(bottom2, preproc_ep)]
        ax.bar(x, preproc_mb, width, bottom=bottom3, label='Preproc (MB)', color='#2ca02c')

        ax.set_xlabel("Number of Rules", fontsize=12)
        ax.set_ylabel("Time (ms)", fontsize=12)
        ax.set_title("Time Breakdown: Setup + Preprocessing by Party", fontsize=13, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(x_labels)
        ax.legend(fontsize=10)
        ax.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_complexity_breakdown.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_complexity_breakdown.png")


def plot_endpoint(data: dict, out_dir: str = "."):
    """Plot endpoint performance results."""

    # ── Table IV: Preprocessing ──
    table_iv = data["table_iv_preprocessing"]
    if table_iv:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

        x_rules = [r["n_rules"] for r in table_iv]
        ep_times = [r["endpoint_avg_ms"] for r in table_iv]
        mb_times = [r["mb_avg_ms"] for r in table_iv]

        # Bar chart
        x = np.arange(len(x_rules))
        width = 0.35
        ax1.bar(x - width/2, ep_times, width, label='Endpoint', color=PRIVBOX_COLOR)
        ax1.bar(x + width/2, mb_times, width, label='Middlebox', color='#1f77b4')
        for i, (ev, mv) in enumerate(zip(ep_times, mb_times)):
            ax1.text(i - width/2, ev + 0.5, f'{ev:.1f}', ha='center', va='bottom', fontsize=7)
            ax1.text(i + width/2, mv + 0.5, f'{mv:.1f}', ha='center', va='bottom', fontsize=7)
        ax1.set_xticks(x)
        ax1.set_xticklabels([str(r) for r in x_rules])
        ax1.set_xlabel("Number of Rules", fontsize=11)
        ax1.set_ylabel("Time (ms)", fontsize=11)
        ax1.set_title("Table IV: Preprocessing Time (First Session)", fontsize=12, fontweight='bold')
        ax1.legend(fontsize=10)
        ax1.grid(axis='y', alpha=0.3)

        # Line chart
        ax2.plot(x_rules, ep_times, 'D-', color=PRIVBOX_COLOR, linewidth=2,
                 markersize=7, label='Endpoint')
        ax2.plot(x_rules, mb_times, 'o-', color='#1f77b4', linewidth=2,
                 markersize=7, label='Middlebox')
        ax2.set_xlabel("Number of Rules", fontsize=11)
        ax2.set_ylabel("Time (ms)", fontsize=11)
        ax2.set_title("Preprocessing Time Scaling", fontsize=12, fontweight='bold')
        ax2.legend(fontsize=10)
        ax2.grid(True, alpha=0.3)

        plt.suptitle("Endpoint Preprocessing Performance\n"
                      "(measured with PrivBox Charm-Crypto implementation)",
                      fontsize=13, fontweight='bold', y=1.04)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_table_iv_preprocessing.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_table_iv_preprocessing.png")

    # ── Table V: Token Encryption ──
    table_v = data["table_v_token_encryption"]
    if table_v:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

        x_tokens = [r["n_tokens"] for r in table_v]
        times = [r["avg_ms"] for r in table_v]
        tps = [r["tokens_per_sec"] for r in table_v]

        # Time vs tokens
        ax1.plot(x_tokens, times, 'D-', color=PRIVBOX_COLOR, linewidth=2, markersize=7)
        for xt, t in zip(x_tokens, times):
            ax1.annotate(f'{t:.2f}ms', (xt, t), textcoords="offset points",
                         xytext=(0, 10), ha='center', fontsize=8)
        ax1.set_xlabel("Number of Tokens", fontsize=11)
        ax1.set_ylabel("Time (ms)", fontsize=11)
        ax1.set_title("Table V: Token Encryption Time", fontsize=12, fontweight='bold')
        ax1.grid(True, alpha=0.3)

        # Throughput
        ax2.plot(x_tokens, tps, 's-', color='#2ca02c', linewidth=2, markersize=7)
        ax2.set_xlabel("Number of Tokens", fontsize=11)
        ax2.set_ylabel("Tokens / Second", fontsize=11)
        ax2.set_title("Token Encryption Throughput", fontsize=12, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        # Paper claims ~4672 tokens/sec
        if tps:
            ax2.axhline(y=4672, color='gray', linestyle='--', alpha=0.5)
            ax2.text(x_tokens[-1], 4672, '  Paper: 4,672 tok/s', va='bottom',
                     fontsize=9, color='gray')

        plt.suptitle("Endpoint Token Encryption\n"
                      "(measured with PrivBox Charm-Crypto implementation)",
                      fontsize=13, fontweight='bold', y=1.04)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_table_v_token_enc.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_table_v_token_enc.png")

    # ── Figure 11: Repeated Tokens ──
    fig11a = data.get("fig11a_repeated_4x", [])
    fig11b = data.get("fig11b_one_token_repeating", [])
    fig11c = data.get("fig11c_from_previous_session", [])

    if fig11a or fig11b or fig11c:
        n_plots = sum(1 for d in [fig11a, fig11b, fig11c] if d)
        fig, axes = plt.subplots(1, n_plots, figsize=(6 * n_plots, 5.5))
        if n_plots == 1:
            axes = [axes]

        plot_idx = 0

        if fig11a:
            ax = axes[plot_idx]
            x = [r["repeat_pct"] for r in fig11a]
            y = [r["avg_ms"] for r in fig11a]
            ax.plot(x, y, 'D-', color=PRIVBOX_COLOR, linewidth=2, markersize=6, label='PrivBox')
            ax.set_xlabel("% of Tokens Repeated (4x each)", fontsize=10)
            ax.set_ylabel("Token Encryption Time (ms)", fontsize=10)
            ax.set_title("(a) Repeated Tokens (4x)", fontsize=11, fontweight='bold')
            ax.legend(fontsize=9)
            ax.grid(True, alpha=0.3)
            plot_idx += 1

        if fig11b:
            ax = axes[plot_idx]
            x = [r["repeat_pct"] for r in fig11b]
            y = [r["avg_ms"] for r in fig11b]
            ax.plot(x, y, 'D-', color=PRIVBOX_COLOR, linewidth=2, markersize=6, label='PrivBox')
            ax.set_xlabel("% of One Token Repeating", fontsize=10)
            ax.set_ylabel("Token Encryption Time (ms)", fontsize=10)
            ax.set_title("(b) One Token Repeating", fontsize=11, fontweight='bold')
            ax.legend(fontsize=9)
            ax.grid(True, alpha=0.3)
            plot_idx += 1

        if fig11c:
            ax = axes[plot_idx]
            x = [r["repeat_pct"] for r in fig11c]
            y = [r["avg_ms"] for r in fig11c]
            ax.plot(x, y, 'D-', color=PRIVBOX_COLOR, linewidth=2, markersize=6, label='PrivBox')
            ax.set_xlabel("% Repeated from Previous Session", fontsize=10)
            ax.set_ylabel("Token Encryption Time (ms)", fontsize=10)
            ax.set_title("(c) Cross-Session Reuse", fontsize=11, fontweight='bold')
            ax.legend(fontsize=9)
            ax.grid(True, alpha=0.3)

        plt.suptitle("Figure 11: Token Encryption for Repeated Tokens\n"
                      "(measured with PrivBox Charm-Crypto implementation)",
                      fontsize=13, fontweight='bold', y=1.04)
        plt.tight_layout()
        plt.savefig(f"{out_dir}/fig_11_repeated_tokens.png", dpi=200, bbox_inches='tight')
        plt.close()
        print(f"Saved: {out_dir}/fig_11_repeated_tokens.png")


def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_perf_eval_complexity_and_endpoint_results.py <complexity.json> [endpoint.json]")
        print("  At least one JSON results file required.")
        sys.exit(1)

    out_dir = "."

    for fpath in sys.argv[1:]:
        with open(fpath, "r") as f:
            data = json.load(f)

        btype = data.get("benchmark", "")
        if btype == "complexity_analysis":
            print(f"\nPlotting complexity analysis from {fpath}...")
            plot_complexity(data, out_dir)
        elif btype == "endpoint_performance":
            print(f"\nPlotting endpoint performance from {fpath}...")
            plot_endpoint(data, out_dir)
        else:
            print(f"Unknown benchmark type in {fpath}: {btype}")

    print("\nAll plots generated!")


if __name__ == "__main__":
    main()
