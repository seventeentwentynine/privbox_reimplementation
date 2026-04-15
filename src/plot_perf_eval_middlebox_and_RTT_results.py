"""
Generate Graphs of performance results for Middlebox and Round Trip Time

plot_perf_eval_middlebox_and_RTT_results.py
"""
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


#####################
#                   #
# --- Constants --- #
#                   #
#####################


FIGURES_TO_PLOT = {
    "figure_09a.csv": "Fig 9(a): Time Cost of Preprocessing Phase",
    "figure_09b.csv": "Fig 9(b): Bandwidth Cost of Preprocessing Phase",
    "figure_10a.csv": "Fig 10(a): Time Cost of Session Rule Prep",
    "figure_10b.csv": "Fig 10(b): Bandwidth Cost of Session Rule Prep",
    "figure_12a.csv": "Fig 12(a): RTT vs Number of Rules (1st Session)",
    "figure_12b.csv": "Fig 12(b): RTT vs Number of Rules (Subsequent Sessions)",
    "figure_12c.csv": "Fig 12(c): RTT vs Number of Tokens (1st Session)",
    "figure_12d.csv": "Fig 12(d): RTT vs Number of Tokens (1st Session)",
}

def main():
    """
    Plot all graphs.
    """
    print("[*] Start plotting graphs...")

    # Establish project root.
    base_dir = Path(__file__).resolve().parent.parent

    # Create output folder in the root.
    output_dir = base_dir / "evaluation_plots"
    output_dir.mkdir(exist_ok=True)

    for filename, title in FIGURES_TO_PLOT.items():
        # Recursively search for filenames in the current directory and all subfolders.
        found_files = list(base_dir.rglob(filename))

        if not found_files:
            print(f"[!] WARNING! {filename} not found in any subfolders. Skipping...")
            continue

        # If file is found, use first match.
        csv_path = found_files[0]

        # Read CSV files into a pandas DataFrame.
        df = pd.read_csv(csv_path)

        # Extract header row.
        x_axis_label = df.columns[0]
        y_axis_label = df.columns[1]

        print(f"[*] Found {filename} inside `{csv_path.parent.name}/`")
        print(f"    -> Plotting: {y_axis_label} against {x_axis_label}")

        # Plot data rows.
        plt.figure(figsize=(7, 5))
        plt.plot(
            df[x_axis_label], df[y_axis_label],
            marker="o",
            linestyle="--",
            color="#552583",
            linewidth=2,
            markersize=8,
            label="PrivBox"
        )

        # Set dynamically extracted labels.
        plt.title(title, fontsize=14, fontweight="bold", pad=15)
        plt.xlabel(x_axis_label, fontsize=12)
        plt.ylabel(y_axis_label, fontsize=12)

        # Style grid and legend.
        plt.grid(True, linestyle=":", alpha=0.7)
        plt.legend(loc="best")
        plt.tight_layout()

        # Save figure.
        out_path = output_dir / f"{csv_path.stem}.png"
        plt.savefig(out_path, dpi=300)
        plt.close()

        print(f"[+] {out_path} generated!")
    print(f"\n[+] All figures successfully generated in: {output_dir.absolute()}")


if __name__ == "__main__":
    main()
