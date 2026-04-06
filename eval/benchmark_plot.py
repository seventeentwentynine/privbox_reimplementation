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
    
    # Create DataFrame from CSV data.
    df = pd.read_csv(csv_path)

    # Set up the plot.
    plt.figure(figsize=(8, 5))
    plt.plot(df['n_rules'], df['preprocessing_time_sec'], marker='o', color='firebrick', label='Preprocessing Time')
    plt.plot(df['n_rules'], df['traffic_inspection_time_sec'], marker='s', color='goldenrod', label='Traffic Inspection Time')

    # Set up the grid.
    plt.title('Middlebox Performance VS Number of Rules (O(n))')
    plt.xlabel('Number of Rules (n)')
    plt.ylabel('Time (seconds)')
    plt.grid(True)
    plt.legend()
    plt.savefig("eval/results/rule_scaling_graph.png")
    print("[*] Saved Rule Scaling Graph!")


