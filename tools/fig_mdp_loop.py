"""
tools/fig_mdp_loop.py
=====================
Figure 3 (Materials and Methods): the SeqSQLi agent-environment loop.
Grayscale, consistent with Figures 1-2. No network.
Output: figures/fig_mdp_loop.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

INK="#000000"; MUT="#444444"; LINE="#333333"; CARD="#FFFFFF"; HI="#E6E6E6"

fig, ax = plt.subplots(figsize=(11, 5.4), dpi=200)
ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")


def box(x, y, w, h, lines, fill=CARD):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=2",
                       linewidth=1.2, edgecolor=LINE, facecolor=fill, zorder=2)
    ax.add_patch(p)
    n=len(lines)
    for i,(t,fs,c,b) in enumerate(lines):
        ax.text(x+w/2, y+h-(h/(n+1))*(i+1), t, ha="center", va="center",
                fontsize=fs, color=c, fontweight=("bold" if b else "normal"), zorder=3)


def arrow(x1,y1,x2,y2,label=None,lx=0,ly=0):
    a=FancyArrowPatch((x1,y1),(x2,y2),arrowstyle="-|>",mutation_scale=13,lw=1.4,color=LINE,zorder=1)
    ax.add_patch(a)
    if label:
        ax.text((x1+x2)/2+lx,(y1+y2)/2+ly,label,ha="center",va="center",fontsize=9.5,
                color=MUT,style="italic",zorder=4,
                bbox=dict(boxstyle="round,pad=0.2",fc="white",ec="none"))

# Agent
box(4, 60, 24, 16, [("Agent",12,INK,True),
                    ("policy  πθ : sₜ → aₜ",10.5,INK,False),
                    ("MLP 2×64, tanh",9.5,MUT,False)], fill=HI)
# Environment pipeline
box(38, 60, 26, 16, [("Apply mutation  aₜ",11,INK,True),
                     ("pₜ₊₁ = g_{aₜ}(pₜ)",10.5,INK,False),
                     ("semantics preserved",9.5,MUT,False)])
box(72, 60, 24, 16, [("WAF + application",11,INK,True),
                     ("ModSecurity / Safeline",10,MUT,False),
                     ("+ sqli-labs",10,MUT,False)])
box(72, 30, 24, 14, [("Response",11,INK,True),
                     ("status, body",10,MUT,False)])
box(38, 30, 26, 14, [("Reward  rₜ",11,INK,True),
                     ("strict success + PBRS shaping",9.3,MUT,False)])

arrow(28, 68, 38, 68, "action aₜ", ly=4)
arrow(64, 68, 72, 68)
arrow(84, 60, 84, 44)
arrow(72, 37, 64, 37)
arrow(38, 37, 16, 37); arrow(16, 37, 16, 60, "sₜ₊₁ , rₜ", lx=-7, ly=0)

os.makedirs("figures", exist_ok=True)
out="figures/fig_mdp_loop.png"
plt.savefig(out, bbox_inches="tight", facecolor="white")
print("[*] saved", out)
