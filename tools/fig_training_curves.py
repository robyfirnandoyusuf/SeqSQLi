"""
Figure: Training Reward Curves — PPO, TRPO, A2C
Output: figures/fig_training_curves.png
Run   : python3 -m tools.fig_training_curves

Reads tensorboard event files (latest run per algo).
Requires: tensorboard  (pip install tensorboard)
"""
import os, glob
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_tb_scalars(event_dir, tag="rollout/ep_rew_mean"):
    """Return (steps, values) from the event file in event_dir."""
    try:
        from tensorboard.backend.event_processing.event_accumulator import EventAccumulator
    except ImportError:
        raise SystemExit("Install tensorboard: pip install tensorboard")

    ea = EventAccumulator(event_dir, size_guidance={"scalars": 0})
    ea.Reload()
    if tag not in ea.Tags()["scalars"]:
        available = ea.Tags()["scalars"]
        raise ValueError(f"Tag '{tag}' not found. Available: {available}")
    events = ea.Scalars(tag)
    steps  = [e.step  for e in events]
    values = [e.value for e in events]
    return np.array(steps), np.array(values)


def latest_run(base_dir):
    """Return the path of the most recently modified subdirectory."""
    subdirs = [d for d in glob.glob(os.path.join(base_dir, "*/"))
               if os.path.isdir(d)]
    if not subdirs:
        return base_dir
    return max(subdirs, key=os.path.getmtime)


def smooth(values, w=8):
    """Exponential moving average."""
    out = np.zeros_like(values, dtype=float)
    s = values[0]
    alpha = 2.0 / (w + 1)
    for i, v in enumerate(values):
        s = alpha * v + (1 - alpha) * s
        out[i] = s
    return out


def main():
    os.makedirs(os.path.join(ROOT, "figures"), exist_ok=True)

    algos = [
        ("TRPO", os.path.join(ROOT, "trpo_tensorboard"), "#2166ac", "-"),
        ("PPO",  os.path.join(ROOT, "ppo_tensorboard"),  "#e08d00", "--"),
        ("A2C",  os.path.join(ROOT, "a2c_tensorboard"),  "#d6604d", ":"),
    ]

    fig, ax = plt.subplots(figsize=(7, 4.2))

    all_series = []
    for name, tb_base, color, ls in algos:
        run_dir = latest_run(tb_base)
        print(f"{name}: reading from {run_dir}")
        steps, values = load_tb_scalars(run_dir, tag="rollout/ep_rew_mean")
        smoothed = smooth(values)
        all_series.append((name, steps, smoothed, color, ls))
        ax.plot(steps, smoothed, color=color, linewidth=2.0,
                linestyle=ls, label=name, zorder=3)

    # Shade only above y=0 for each curve to avoid clutter
    for name, steps, smoothed, color, _ in all_series:
        ax.fill_between(steps, smoothed,
                        where=(smoothed >= 0),
                        alpha=0.10, color=color, zorder=2)

    # Annotate A2C instability dip
    a2c_steps, a2c_vals = all_series[2][1], all_series[2][2]
    dip_idx = int(np.argmin(a2c_vals[len(a2c_vals)//2:]))  + len(a2c_vals)//2
    if dip_idx < len(a2c_steps):
        ax.annotate("A2C instability",
                    xy=(a2c_steps[dip_idx], a2c_vals[dip_idx]),
                    xytext=(a2c_steps[dip_idx] - 25000, a2c_vals[dip_idx] - 6),
                    fontsize=8, color="#d6604d",
                    arrowprops=dict(arrowstyle="->", color="#d6604d", lw=1.0))

    ax.axhline(0, color="gray", linestyle="-", linewidth=0.7, alpha=0.4, zorder=1)
    ax.set_xlabel("Training Timesteps", fontsize=11)
    ax.set_ylabel("Mean Episode Reward", fontsize=11)
    ax.set_title("Training Convergence: Mean Episode Reward", fontsize=12, pad=10)
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v/1000)}k"))
    ax.grid(linestyle=":", linewidth=0.6, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(fontsize=10, framealpha=0.9)

    fig.tight_layout()
    out = os.path.join(ROOT, "figures", "fig_training_curves.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
