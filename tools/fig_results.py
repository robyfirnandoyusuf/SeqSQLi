"""
tools/fig_results.py
====================
Results figures (grayscale, consistent with Figs 1-2):
  Figure 3: per-tier success rate on the union corpus (RQ1).
  Figure 4: error-corpus IFNR across three seeds, showing A2C instability (RQ1).
No network. Output: figures/fig_tier_sr.png, figures/fig_seed_variance.png
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 11, "axes.edgecolor": "#333333"})
os.makedirs("figures", exist_ok=True)

# ---------- Figure 3: per-tier SR (union) ----------
tiers = ["Trivial", "Medium", "Complex"]
data = {"TRPO": [100,100,97.2], "PPO": [100,100,66.7], "A2C": [100,97.2,33.3]}
shades = {"TRPO": "#444444", "PPO": "#999999", "A2C": "#dddddd"}
hatch  = {"TRPO": "",        "PPO": "//",      "A2C": "xx"}

fig, ax = plt.subplots(figsize=(7.2, 4.4), dpi=200)
x = np.arange(len(tiers)); w = 0.26
for i,(algo,vals) in enumerate(data.items()):
    ax.bar(x+(i-1)*w, vals, w, label=algo, facecolor=shades[algo],
           edgecolor="black", linewidth=1.0, hatch=hatch[algo])
    for j,v in enumerate(vals):
        ax.text(x[j]+(i-1)*w, v+1.5, f"{v:.0f}", ha="center", va="bottom", fontsize=8.5)
ax.set_xticks(x); ax.set_xticklabels(tiers)
ax.set_ylabel("Success rate (%)"); ax.set_ylim(0,112)
ax.set_xlabel("Payload complexity tier")
ax.legend(frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5,-0.28))
for s in ["top","right"]: ax.spines[s].set_visible(False)
plt.tight_layout()
plt.savefig("figures/fig_tier_sr.png", bbox_inches="tight", facecolor="white")
print("[*] saved figures/fig_tier_sr.png")

# ---------- Figure 4: seed variance (error corpus) ----------
seeds = {"TRPO": [30.6,32.4,27.8], "PPO": [26.9,27.8,24.1], "A2C": [5.6,30.6,30.6]}
order = ["TRPO","PPO","A2C"]
fig, ax = plt.subplots(figsize=(7.0, 4.4), dpi=200)
for i,algo in enumerate(order):
    pts = seeds[algo]; m = np.mean(pts); sd = np.std(pts, ddof=1)
    ax.errorbar(i, m, yerr=sd, fmt="_", color="black", capsize=8,
                elinewidth=1.4, markersize=22, zorder=2)
    ax.scatter([i]*len(pts), pts, facecolor="white", edgecolor="black",
               s=55, zorder=3)
    ax.text(i+0.13, m, f"  {m:.1f}±{sd:.1f}%", va="center", fontsize=9.5)
ax.set_xticks(range(len(order))); ax.set_xticklabels(order)
ax.set_ylabel("IFNR on error corpus (%)"); ax.set_ylim(0,40)
ax.set_xlim(-0.5, 2.6)
ax.annotate("≈7× variance", xy=(2,18), xytext=(1.3,8),
            fontsize=9.5, ha="center",
            arrowprops=dict(arrowstyle="->", color="#333333"))
for s in ["top","right"]: ax.spines[s].set_visible(False)
plt.tight_layout()
plt.savefig("figures/fig_seed_variance.png", bbox_inches="tight", facecolor="white")
print("[*] saved figures/fig_seed_variance.png")
