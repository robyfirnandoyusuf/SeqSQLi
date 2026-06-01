"""
tools/rq3_synthesis.py
======================
Synthesize RQ3 (does mutation ORDER matter?) across the 3 deep-RL runs.
NO network — reads the ordering_*.json files produced by each training run.

For each algorithm it reports:
  - ordering_matters_count (pairs with forward-vs-reversed SR gap >= 10%)
  - the strongest ordering-dependent pairs (largest sr_difference)
Then it finds pairs where ordering matters in MULTIPLE algorithms
(cross-algorithm consensus = strongest causal evidence for the paper).

USAGE:
    python3 -m tools.rq3_synthesis
    python3 -m tools.rq3_synthesis --runs TRPO:ordering_trpo.json PPO:ordering_ppo.json A2C:ordering_a2c.json
"""
import argparse
import json
from collections import defaultdict

DEFAULT_RUNS = [
    "TRPO:ordering_trpo.json",
    "PPO:ordering_ppo.json",
    "A2C:ordering_a2c.json",
]
MIN_COUNT = 5   # ignore pairs observed too few times (noise)


def load(path):
    return json.load(open(path))


def strong_pairs(d, min_count=MIN_COUNT):
    """Return list of (pair, fwd_sr, rev_sr, diff, fwd_count) where ordering
    matters and the forward pair was observed >= min_count times."""
    out = []
    for pair, info in d.get("reversed_pairs", {}).items():
        if not info.get("ordering_matters"):
            continue
        fwd = info.get("forward", {})
        rev = info.get("reversed", {})
        if fwd.get("count", 0) < min_count:
            continue
        out.append((pair, fwd.get("success_rate", 0.0),
                    rev.get("success_rate", 0.0),
                    info.get("sr_difference", 0.0),
                    fwd.get("count", 0)))
    out.sort(key=lambda x: x[3], reverse=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="*", default=DEFAULT_RUNS)
    args = ap.parse_args()

    runs = {}
    for entry in args.runs:
        label, path = entry.split(":", 1)
        try:
            runs[label] = load(path)
        except FileNotFoundError:
            print(f"[!] missing: {path}")

    # --- Per-algorithm summary ---
    print("=" * 72)
    print(" RQ3 — Does mutation ORDER matter?  (per algorithm)")
    print("=" * 72)
    for label, d in runs.items():
        total = len(d.get("reversed_pairs", {}))
        matters = d.get("ordering_matters_count", "?")
        print(f"\n## {label}: {matters} ordering-dependent pairs "
              f"(of {total} compared)")
        print(f"  {'forward pair':<34} {'fwd':>6} {'rev':>6} {'Δ':>6} {'n':>6}")
        print("  " + "-" * 60)
        for pair, fwd, rev, diff, cnt in strong_pairs(d)[:8]:
            print(f"  {pair:<34} {fwd:>5.1f}% {rev:>5.1f}% {diff:>+5.1f} {cnt:>6}")

    # --- Cross-algorithm consensus ---
    pair_hits = defaultdict(list)   # forward-pair -> [(algo, diff), ...]
    for label, d in runs.items():
        for pair, fwd, rev, diff, cnt in strong_pairs(d):
            pair_hits[pair].append((label, diff))

    consensus = {p: hits for p, hits in pair_hits.items() if len(hits) >= 2}
    print("\n" + "=" * 72)
    print(" CROSS-ALGORITHM CONSENSUS  (ordering matters in >= 2 algorithms)")
    print(" -> strongest causal evidence that order is a learnable signal")
    print("=" * 72)
    if not consensus:
        print("  (none — ordering-dependent pairs are algorithm-specific)")
    else:
        for pair, hits in sorted(consensus.items(),
                                 key=lambda kv: len(kv[1]), reverse=True):
            tag = ", ".join(f"{a}(+{d:.0f})" for a, d in hits)
            print(f"  {pair:<34} in {len(hits)} algos: {tag}")


if __name__ == "__main__":
    main()
