"""
Figure: Per-tier success rate (mean +/- std over 3 seeds) - PPO vs TRPO vs A2C
Output: figures/fig_tier_barchart.png
Run   : python3 -m tools.fig_tier_barchart_multiseed
"""
import json, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_tier_map(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        return {r["payload_id"]: r["tier"] for r in csv.DictReader(f)}

def tier_sr(eval_json, tier_map):
    data = json.load(open(eval_json, encoding="utf-8"))
    counts = {"trivial": [0, 0], "medium": [0, 0], "complex": [0, 0]}
    for p in data["per_payload"]:
        t = tier_map.get(p["payload_id"])
        if t in counts:
            counts[t][1] += 1
            counts[t][0] += 1 if p["success"] else 0
    return {t: (v[0] / v[1] * 100 if v[1] else 0) for t, v in counts.items()}

def main():
    tier_map = load_tier_map(os.path.join(ROOT, "payloads_union_less1.csv"))
    tiers = ["trivial", "medium", "complex"]
    labels = ["Trivial", "Medium", "Complex"]
    algos = [("TRPO", "#2166ac"), ("PPO", "#f4a582"), ("A2C", "#d6604d")]

    mean, std = {}, {}
    for name, _ in algos:
        per_seed = [tier_sr(os.path.join(ROOT, f"eval_{name.lower()}_union_seed{s}.json"), tier_map)
                    for s in (1, 2, 3)]
        mean[name] = {t: float(np.mean([ps[t] for ps in per_seed])) for t in tiers}
        std[name]  = {t: float(np.std ([ps[t] for ps in per_seed])) for t in tiers}

    x = np.arange(len(tiers)); width = 0.24; offs = [-width, 0, width]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for i, (name, color) in enumerate(algos):
        m = [mean[name][t] for t in tiers]
        e = [std[name][t] for t in tiers]
        bars = ax.bar(x + offs[i], m, width, yerr=e, capsize=3, label=name,
                      color=color, edgecolor="white", linewidth=0.6, zorder=3,
                      error_kw=dict(ecolor="#444444", lw=1.1, capthick=1.1))
        for j, (bar, mv, ev) in enumerate(zip(bars, m, e)):
            txt = f"{mv:.1f}%" if ev < 0.1 else f"{mv:.1f}±{ev:.1f}"
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + ev + 2.0,
                    txt, ha="center", va="bottom", fontsize=8, fontweight="bold")

    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("Success rate (%)", fontsize=11)
    ax.set_ylim(0, 125)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v)}%"))
    ax.axhline(100, color="gray", linestyle="--", linewidth=0.8, alpha=0.5, zorder=2)
    ax.legend(loc="lower left", frameon=True, fontsize=10)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.set_title("Per-tier success rate on the union corpus (mean ± SD over 3 seeds)",
                 fontsize=10.5)
    fig.tight_layout()
    out = os.path.join(ROOT, "figures", "fig_tier_barchart.png")
    fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
    print("Saved:", out)

if __name__ == "__main__":
    main()
