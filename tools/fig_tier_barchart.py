"""
Figure: Per-Tier Success Rate — PPO vs TRPO vs A2C
Output: figures/fig_tier_barchart.png
Run   : python3 -m tools.fig_tier_barchart
"""
import json, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_tier_map(csv_path):
    tier_map = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tier_map[row["payload_id"]] = row["tier"]
    return tier_map

def compute_tier_sr(eval_json_path, tier_map):
    with open(eval_json_path, encoding="utf-8") as f:
        data = json.load(f)
    counts = {"trivial": [0, 0], "medium": [0, 0], "complex": [0, 0]}
    for p in data["per_payload"]:
        tier = tier_map.get(p["payload_id"])
        if tier in counts:
            counts[tier][1] += 1
            if p["success"]:
                counts[tier][0] += 1
    return {t: (v[0] / v[1] * 100 if v[1] > 0 else 0) for t, v in counts.items()}

def main():
    os.makedirs(os.path.join(ROOT, "figures"), exist_ok=True)
    tier_map = load_tier_map(os.path.join(ROOT, "payloads_union_less1.csv"))

    algos = [
        ("TRPO", os.path.join(ROOT, "eval_trpo_union.json"),     "#2166ac"),
        ("PPO",  os.path.join(ROOT, "eval_ppo_union_agg.json"),  "#f4a582"),
        ("A2C",  os.path.join(ROOT, "eval_a2c_union.json"),      "#d6604d"),
    ]
    tiers = ["trivial", "medium", "complex"]
    tier_labels = ["Trivial", "Medium", "Complex"]

    results = {}
    for name, path, _ in algos:
        results[name] = compute_tier_sr(path, tier_map)

    x = np.arange(len(tiers))
    width = 0.22
    offsets = [-width, 0, width]

    fig, ax = plt.subplots(figsize=(7, 4.2))

    # Pre-collect all values per tier to detect duplicates
    all_sr = {t: [results[name][t] for name, _, _ in algos] for t in tiers}

    for i, (name, _, color) in enumerate(algos):
        sr_vals = [results[name][t] for t in tiers]
        bars = ax.bar(x + offsets[i], sr_vals, width, label=name,
                      color=color, edgecolor="white", linewidth=0.6, zorder=3)
        for j, (bar, val) in enumerate(zip(bars, sr_vals)):
            tier = tiers[j]
            tier_vals = all_sr[tier]
            # Stagger labels vertically when values are equal to avoid overlap
            same_count = sum(1 for v in tier_vals[:i] if abs(v - val) < 0.1)
            y_extra = same_count * 5.5
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 1.2 + y_extra,
                    f"{val:.1f}%", ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(tier_labels, fontsize=11)
    ax.set_ylabel("Success Rate (%)", fontsize=11)
    ax.set_ylim(0, 125)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v)}%"))
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.axhline(100, color="gray", linestyle="--", linewidth=0.8, alpha=0.5, zorder=2)
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(fontsize=10, framealpha=0.9, loc="lower left")
    ax.set_title("Bypass Success Rate by Payload Complexity Tier", fontsize=12, pad=10)

    fig.tight_layout()
    out = os.path.join(ROOT, "figures", "fig_tier_barchart.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    print(f"Saved: {out}")

if __name__ == "__main__":
    main()
