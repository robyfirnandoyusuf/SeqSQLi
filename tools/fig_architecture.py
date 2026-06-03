"""
Figure: SeqSQLi System Architecture (MDP Loop)
Output: figures/fig_architecture.png
Run   : python3 -m tools.fig_architecture
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

C_AGENT  = "#2166ac"
C_ENV    = "#4dac26"
C_ACTION = "#e08d00"
C_REWARD = "#d6604d"
C_BG     = "#f8f9fa"

def rbox(ax, cx, cy, w, h, title, subtitle=None,
         fc="#ffffff", ec="#333333", title_color="#111111", r=0.35):
    rect = FancyBboxPatch((cx - w/2, cy - h/2), w, h,
                          boxstyle=f"round,pad=0,rounding_size={r}",
                          facecolor=fc, edgecolor=ec, linewidth=1.8, zorder=3)
    ax.add_patch(rect)
    if subtitle:
        ax.text(cx, cy + h * 0.16, title,
                ha="center", va="center", fontsize=10.5,
                fontweight="bold", color=title_color, zorder=4)
        ax.text(cx, cy - h * 0.22, subtitle,
                ha="center", va="center", fontsize=8.5,
                color="#555555", style="italic", zorder=4)
    else:
        ax.text(cx, cy, title,
                ha="center", va="center", fontsize=10.5,
                fontweight="bold", color=title_color, zorder=4)

def varrow(ax, x, y_start, y_end, color="#333333", lw=1.8):
    ax.annotate("", xy=(x, y_end), xytext=(x, y_start),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=lw, mutation_scale=16), zorder=2)

def harrow(ax, x_start, x_end, y, color="#333333", lw=1.8):
    ax.annotate("", xy=(x_end, y), xytext=(x_start, y),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=lw, mutation_scale=16), zorder=2)

def line(ax, xs, ys, color="#333333", lw=1.8):
    ax.plot(xs, ys, color=color, lw=lw, zorder=2, solid_capstyle="round")

def main():
    os.makedirs(os.path.join(ROOT, "figures"), exist_ok=True)

    # Canvas in "inches" — we use data coords 0..10 x 0..14
    fig, ax = plt.subplots(figsize=(7, 9.5))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 14)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    # ── dimensions ──────────────────────────────────────────────────────────
    CX   = 5.0          # centre x of main column
    BW   = 5.6          # box width
    BH   = 1.1          # box height
    GAP  = 1.85         # vertical gap between box centres (top→bottom)

    # y positions (top of canvas = 14, boxes go downward)
    Y = [13.0, 11.15, 9.30, 7.45, 5.60, 3.75, 1.90]
    # labels: pool, state, agent, action, waf, classifier, reward

    # ── 1. Payload Pool ─────────────────────────────────────────────────────
    rbox(ax, CX, Y[0], BW, BH,
         "SQL Payload Pool",
         "108 validated union-based payloads  ·  3 complexity tiers",
         fc="#edf7ed", ec=C_ENV, title_color=C_ENV)

    # ── 2. State ────────────────────────────────────────────────────────────
    rbox(ax, CX, Y[1], BW, BH,
         "State  sₜ  —  67-dim Observation Vector",
         "payload features (14)  ·  inj. bit (1)  ·  last-action one-hot (51)  ·  step norm (1)",
         fc="#dceeff", ec=C_AGENT, title_color=C_AGENT)

    # ── 3. RL Agent ─────────────────────────────────────────────────────────
    rbox(ax, CX, Y[2], BW, BH,
         "RL Agent  —  Policy  π(aₜ | sₜ)",
         "PPO  ·  TRPO  ·  A2C        two-layer MLP  (64 units, ReLU)",
         fc="#cce0f5", ec=C_AGENT, title_color=C_AGENT)

    # ── 4. Mutation Engine ───────────────────────────────────────────────────
    rbox(ax, CX, Y[3], BW, BH,
         "Mutation Engine  —  Action  aₜ",
         "51 grammar-aware operators across 9 families  ·  applied to payload string",
         fc="#fff3d6", ec=C_ACTION, title_color=C_ACTION)

    # ── 5. Live WAF ──────────────────────────────────────────────────────────
    rbox(ax, CX, Y[4], BW, BH,
         "Live WAF  —  ModSecurity CRS v3.3.2",
         "nginx 1.18  ·  sqli-labs Less-1  ·  HTTP request → 200 / 403 / error",
         fc="#edf7ed", ec=C_ENV, title_color=C_ENV)

    # ── 6. Response Classifier ───────────────────────────────────────────────
    rbox(ax, CX, Y[5], BW, BH,
         "Response Classifier",
         "SUCCESS  ·  WAF_BLOCKED  ·  SQL_ERROR  ·  FILTERED  ·  STAGNANT  …",
         fc="#fdecea", ec=C_REWARD, title_color=C_REWARD)

    # ── 7. Reward Function ───────────────────────────────────────────────────
    rbox(ax, CX, Y[6], BW, BH,
         "Reward Function  rₜ",
         "rₜ = base outcome  +  Φ(sₜ₊₁) − Φ(sₜ)  −  0.08·t        (PBRS shaping)",
         fc="#fde0dc", ec=C_REWARD, title_color=C_REWARD)

    # ── downward arrows with labels ──────────────────────────────────────────
    arrow_spec = [
        (Y[0], Y[1], "sample payload",         C_ENV),
        (Y[1], Y[2], "observe  sₜ",            C_AGENT),
        (Y[2], Y[3], "select  aₜ",             C_AGENT),
        (Y[3], Y[4], "HTTP request  (mutated payload)", C_ACTION),
        (Y[4], Y[5], "HTTP response",           C_ENV),
        (Y[5], Y[6], "outcome signal",          C_REWARD),
    ]
    for ya, yb, lbl, col in arrow_spec:
        y_start = ya - BH / 2
        y_end   = yb + BH / 2
        varrow(ax, CX, y_start, y_end, color=col)
        ax.text(CX + 0.22, (y_start + y_end) / 2, lbl,
                ha="left", va="center", fontsize=8.5,
                color=col, style="italic", zorder=5)

    # ── feedback loop (left rail): reward + next state → state box ──────────
    rail_x   = CX - BW / 2 - 0.45   # x of the vertical rail
    fb_bot   = Y[6] - BH / 2        # bottom of reward box
    fb_top   = Y[1] + BH / 2        # top of state box
    bx_left  = CX - BW / 2

    # horizontal: left edge of reward box → rail
    line(ax, [bx_left, rail_x], [fb_bot, fb_bot], color=C_REWARD)
    # vertical: up the rail
    line(ax, [rail_x, rail_x], [fb_bot, fb_top], color=C_REWARD)
    # horizontal arrow: rail → left edge of state box
    harrow(ax, rail_x, bx_left, fb_top, color=C_REWARD)

    # label on the rail
    ax.text(rail_x - 0.12, (fb_bot + fb_top) / 2,
            "rₜ ,  sₜ₊₁",
            ha="right", va="center", fontsize=9.5, color=C_REWARD,
            fontweight="bold", rotation=90)

    # ── episode termination note ─────────────────────────────────────────────
    ax.text(CX, Y[6] - BH / 2 - 0.30,
            "Episode terminates: SUCCESS (bypass + canary verified)  or  t = Tₘₐₓ = 15",
            ha="center", va="top", fontsize=8.2, color="#666666", style="italic")

    # ── title ────────────────────────────────────────────────────────────────
    ax.text(CX, 13.82,
            "SeqSQLi: Markov Decision Process for SQL Injection WAF Evasion",
            ha="center", va="center", fontsize=11.5, fontweight="bold",
            color="#1a1a1a")

    # ── legend ───────────────────────────────────────────────────────────────
    legend_items = [
        mpatches.Patch(fc="#cce0f5", ec=C_AGENT,  label="RL Agent / State"),
        mpatches.Patch(fc="#fff3d6", ec=C_ACTION, label="Action / Mutation"),
        mpatches.Patch(fc="#edf7ed", ec=C_ENV,    label="Environment (WAF)"),
        mpatches.Patch(fc="#fde0dc", ec=C_REWARD, label="Reward / Classifier"),
    ]
    ax.legend(handles=legend_items, loc="lower right",
              fontsize=8.5, framealpha=0.95, edgecolor="#cccccc",
              ncol=2, handlelength=1.3)

    out = os.path.join(ROOT, "figures", "fig_architecture.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    print(f"Saved: {out}")

if __name__ == "__main__":
    main()
