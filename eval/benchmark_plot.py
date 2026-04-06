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


def plot_token_scaling():
    """
    Plot the O(m) of token scaling.
    """
    csv_path = "eval/results/token_scaling_metrics.csv"
    if not os.path.exists(csv_path):
        print(f"[-] Could not find {csv_path}.")
        return
    
    # Create DataFrame from CSV data.
    df = pd.read_csv(csv_path)

    # Set up the plot.
    plt.figure(figsize=(8, 5))
    plt.plot(df['m_tokens'], df['token_encryption_time_sec'], marker='^', color='mediumturquoise', label='Token Encryption Time (Sender)')
    plt.plot(df['m_tokens'], df['traffic_inspection_time_sec'], marker='d', color='limegreen', label='Traffic Inspection Time (Middlebox)')

    # Set up the grid.
    plt.title('System Performance VS Number of Tokens (O(m))')
    plt.xlabel('Number of Tokens (m)')
    plt.ylabel('Time (seconds)')
    plt.grid(True)
    plt.legend()
    plt.savefig("eval/results/token_scaling_graph.png")
    print("[*] Saved Token Scaling Graph!")


if __name__ == "__main__":
    print("--- Generating Performance Graphs ---")
    plot_rule_scaling()
    plot_token_scaling()
    print("[+] Performance Graphs Generated!")
