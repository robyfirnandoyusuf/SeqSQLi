"""
Figure: Top Cross-Algorithm Consensus Ordering Pairs
Output: figures/fig_ordering_pairs.png
Run   : python3 -m tools.fig_ordering_pairs

Shows forward vs reversed SR for top consensus pairs (appearing in ≥2 algos).
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALGO_FILES = {
    "TRPO": os.path.join(ROOT, "ordering_trpo.json"),
    "PPO":  os.path.join(ROOT, "ordering_ppo.json"),
    "A2C":  os.path.join(ROOT, "ordering_a2c.json"),
}

def load_reversed_pairs(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    rp = data.get("reversed_pairs", {})
    result = {}
    for pair_key, val in rp.items():
        if val.get("ordering_matters"):
            result[pair_key] = {
                "fwd_sr": val["forward"]["success_rate"],
                "rev_sr": val["reversed"]["success_rate"],
                "gap":    val["sr_difference"],
            }
    return result

def format_pair(pair_key):
    parts = pair_key.split(" -> ")
    if len(parts) == 2:
        a, b = parts
        a = a.replace("_", "\\_") if False else a.replace("_", " ")
        b = b.replace("_", " ")
        return f"{a}  →  {b}"
    return pair_key

def main():
    os.makedirs(os.path.join(ROOT, "figures"), exist_ok=True)

    all_pairs = {}
    for algo, path in ALGO_FILES.items():
        if not os.path.exists(path):
            print(f"Missing: {path}")
            continue
        for pair, info in load_reversed_pairs(path).items():
            if pair not in all_pairs:
                all_pairs[pair] = {"algos": [], "gaps": [], "fwd": [], "rev": []}
            all_pairs[pair]["algos"].append(algo)
            all_pairs[pair]["gaps"].append(info["gap"])
            all_pairs[pair]["fwd"].append(info["fwd_sr"])
            all_pairs[pair]["rev"].append(info["rev_sr"])

    # Keep consensus pairs (≥2 algos)
    consensus = {k: v for k, v in all_pairs.items() if len(v["algos"]) >= 2}
    # Sort by mean gap desc, take top 12
    top = sorted(consensus.items(), key=lambda x: np.mean(x[1]["gaps"]), reverse=True)[:12]

    labels     = [format_pair(k)           for k, _ in top]
    fwd_means  = [np.mean(v["fwd"])        for _, v in top]
    rev_means  = [np.mean(v["rev"])        for _, v in top]
    gap_means  = [np.mean(v["gaps"])       for _, v in top]
    n_algos    = [len(v["algos"])          for _, v in top]

    y = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(8, 5.5))

    bar_fwd = ax.barh(y + 0.18, fwd_means, 0.34, color="#2166ac",
                      label="Forward SR (%)", zorder=3)
    bar_rev = ax.barh(y - 0.18, rev_means, 0.34, color="#d6604d",
                      label="Reversed SR (%)", zorder=3)

    # Gap annotation
    for i, (g, n) in enumerate(zip(gap_means, n_algos)):
        star = "★" if n == 3 else "◆"
        ax.text(max(fwd_means[i], 2) + 1.5, y[i],
                f"Δ{g:.0f}%  {star}", va="center", fontsize=8,
                color="#555555")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Success Rate (%)", fontsize=10)
    ax.set_xlim(0, 120)
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v)}%"))
    ax.set_title("Top Consensus Ordering-Dependent Pairs\n"
                 "(★ = all 3 algos, ◆ = 2 algos; Δ = mean forward–reversed gap)",
                 fontsize=11, pad=10)
    ax.grid(axis="x", linestyle=":", linewidth=0.6, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(fontsize=9, loc="lower right", framealpha=0.9)
    ax.invert_yaxis()

    fig.tight_layout()
    out = os.path.join(ROOT, "figures", "fig_ordering_pairs.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
