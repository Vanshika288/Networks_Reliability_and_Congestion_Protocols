import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys

def plot_with_confidence(datafile, exp_type):
    # Read CSV file
    df = pd.read_csv(datafile)
    
    # Choose which variable to plot
    if exp_type == "loss":
        group_var = "loss"
    elif exp_type == "jitter":
        group_var = "jitter"
    else:
        raise ValueError("Experiment type must be 'loss' or 'jitter'")
    
    # Compute mean and 90% confidence interval per group
    grouped = df.groupby(group_var)['ttc']
    mean_ttc = grouped.mean()
    std_ttc = grouped.std()
    n = grouped.count()
    
    # 90% confidence interval (z = 1.645)
    ci90 = 1.645 * std_ttc / np.sqrt(n)
    
    # Plot
    plt.figure(figsize=(7,5))
    plt.errorbar(mean_ttc.index, mean_ttc, yerr=ci90, fmt='-o', capsize=5, lw=2)
    plt.title(f"Download Time vs. {group_var.capitalize()} (with 90% CI)")
    plt.xlabel(f"{group_var.capitalize()} (%)" if group_var == "loss" else f"{group_var.capitalize()} (ms)")
    plt.ylabel("Download Time (seconds)")
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    
    # Save and show
    plt.savefig(f"plot_{exp_type}_90CI.png")
    plt.show()
    
    print(f"\n✅ Plot saved as plot_{exp_type}_90CI.png")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python plot_results.py <datafile.csv> <exp_type: loss|jitter>")
        sys.exit(1)
    
    datafile = sys.argv[1]
    exp_type = sys.argv[2].lower()
    plot_with_confidence(datafile, exp_type)
