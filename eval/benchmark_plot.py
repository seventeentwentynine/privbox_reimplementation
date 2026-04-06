"""
Performance/Big-O Evaluation Plot

benchmark_plot.py
"""
import pandas as pd
import matplotlib.pyplot as plt
import os


def plot_rule_scaling():
    """
    Plot the O(n) of rule scaling.
    """
    csv_path = "eval/results/rule_scaling_metrics.csv"
    if not os.path.exists(csv_path):
        print(f"[-] Could not find {csv_path}.")
        return
    