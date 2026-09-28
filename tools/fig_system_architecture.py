"""
Figure: SeqSQLi System Architecture (deployment topology)
Shows the end-to-end path: attacker/RL agent -> WAF layer -> backend app -> database.
Output: figures/fig_system_architecture.png
Run   : python3 -m tools.fig_system_architecture
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

C_AGENT = "#2166ac"
C_RULE  = "#4dac26"
C_ML    = "#8856a7"
C_NONE  = "#999999"
C_APP   = "#e08d00"
C_DB    = "#d6604d"

def box(ax, cx, cy, w, h, title, sub=None, fc="#ffffff", ec="#333333", tc="#111111"):
    ax.add_patch(FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                 boxstyle="round,pad=0,rounding_size=0.06",
                 facecolor=fc, edgecolor=ec, linewidth=1.8, zorder=3))
    if sub:
        ax.text(cx, cy+h*0.20, title, ha="center", va="center",
                fontsize=10.5, fontweight="bold", color=tc, zorder=4)
        ax.text(cx, cy-h*0.22, sub, ha="center", va="center",
                fontsize=7.8, color="#444444", zorder=4)
    else:
        ax.text(cx, cy, title, ha="center", va="center",
                fontsize=10.5, fontweight="bold", color=tc, zorder=4)

def arrow(ax, x1, y1, x2, y2, color="#333333", style="-|>", lw=1.8, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                 mutation_scale=14, color=color, lw=lw, linestyle=ls,
                 shrinkA=2, shrinkB=2, zorder=2))

def main():
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    ax.set_xlim(0, 100); ax.set_ylim(0, 62); ax.axis("off")

    ax.text(50, 59.5, "SeqSQLi System Architecture", ha="center",
            fontsize=15, fontweight="bold", color="#111111")

    # --- Attacker / RL agent ---
    box(ax, 12, 34, 20, 14, "Attacker / RL Agent",
        "SeqSQLi policy (PPO / TRPO / A2C)\nmutated SQLi payloads",
        fc="#e8eff6", ec=C_AGENT, tc=C_AGENT)

    # --- WAF layer (three parallel deployments) ---
    ax.text(45, 52, "Web Application Firewall layer", ha="center",
            fontsize=9.5, style="italic", color="#555555")
    box(ax, 45, 45, 26, 8.5, "Rule-based WAF",
        "ModSecurity WAF  (nginx, :8080)",
        fc="#e9f5e2", ec=C_RULE, tc=C_RULE)
    box(ax, 45, 34, 26, 8.5, "Learning-based WAF",
        "Chaitin SafeLine CE  (:8888)",
        fc="#efe7f4", ec=C_ML, tc=C_ML)
    box(ax, 45, 23, 26, 8.5, "No-WAF baseline",
        "plain nginx  (:8081)",
        fc="#f0f0f0", ec=C_NONE, tc="#555555")

    # --- Backend application ---
    box(ax, 75, 34, 18, 13, "Backend App",
        "sqli-labs Less-1\n(PHP)", fc="#fdf0da", ec=C_APP, tc=C_APP)

    # --- Database ---
    box(ax, 93, 34, 11, 13, "Database",
        "MySQL 5.7", fc="#f9e4e0", ec=C_DB, tc=C_DB)

    # --- request arrows: agent -> each WAF ---
    for wy in (45, 34, 23):
        arrow(ax, 22, 34, 32, wy, color=C_AGENT)
    # WAF -> backend app
    for wy in (45, 34, 23):
        arrow(ax, 58, wy, 66, 34, color="#666666")
    # app -> db (SQL query) and back
    arrow(ax, 84, 35, 87.5, 35, color=C_APP)
    arrow(ax, 87.5, 33, 84, 33, color=C_DB, ls=(0, (4, 2)))
    ax.text(85.7, 38.4, "SQL", ha="center", fontsize=7.4, color=C_APP, style="italic")

    # --- single clean response path along the bottom, back to the agent ---
    arrow(ax, 66, 30.5, 12, 8, color="#8a8a8a", ls=(0, (5, 3)), style="-|>")
    arrow(ax, 12, 8, 12, 27, color="#8a8a8a", ls=(0, (5, 3)))
    ax.text(40, 6.2, "HTTP response  (200 / 403 + response body)", ha="center",
            fontsize=8, color="#777777", style="italic")

    # --- request label (kept clear of the boxes) ---
    ax.text(23, 46, "HTTP request\n(mutated payload)", ha="center",
            fontsize=7.6, color=C_AGENT, style="italic")

    out = os.path.join(ROOT, "figures", "fig_system_architecture.png")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
    print("Saved:", out)

if __name__ == "__main__":
    main()
