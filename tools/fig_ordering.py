"""
tools/fig_ordering.py
=====================
Figure 5 (Results): forward vs reversed success rate for the top
ordering-dependent mutation pairs (TRPO, large-sample pairs). Grayscale.
Numbers from tools.rq3_synthesis on ordering_trpo.json.
Output: figures/fig_ordering.png
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

os.makedirs("figures", exist_ok=True)
plt.rcParams.update({"font.size": 10.5, "axes.edgecolor": "#333333"})

pairs = [
    ("ident_backtick → hex_to_char", 98.0, 0.0),
    ("agg_swap → hex_to_char",       93.8, 31.0),
    ("hex_to_char → case",           93.2, 27.4),
    ("case → newline",               97.6, 43.9),
    ("null_byte → agg_swap",         91.4, 40.1),
    ("func_sp_nbsp → null_byte",     97.4, 53.3),
]
labels = [p[0] for p in pairs][::-1]
fwd = [p[1] for p in pairs][::-1]
rev = [p[2] for p in pairs][::-1]

y = np.arange(len(labels)); h = 0.38
fig, ax = plt.subplots(figsize=(8.2, 4.6), dpi=200)
ax.barh(y+h/2, fwd, h, label="Forward order", facecolor="#444444", edgecolor="black", linewidth=1.0)
ax.barh(y-h/2, rev, h, label="Reversed order", facecolor="#dddddd", edgecolor="black", linewidth=1.0)
for yi,v in zip(y+h/2,fwd): ax.text(v+1, yi, f"{v:.0f}", va="center", fontsize=8.5)
for yi,v in zip(y-h/2,rev): ax.text(v+1, yi, f"{v:.0f}", va="center", fontsize=8.5)
ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=9.5)
ax.set_xlabel("Success rate (%)"); ax.set_xlim(0,108)
ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, fontsize=9.5)
for s in ["top","right"]: ax.spines[s].set_visible(False)
plt.tight_layout()
plt.savefig("figures/fig_ordering.png", bbox_inches="tight", facecolor="white")
print("[*] saved figures/fig_ordering.png")
