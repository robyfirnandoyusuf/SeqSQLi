"""
tools/rq1_table.py
==================
Generate the RQ1 comparison table from existing eval JSON reports.
NO network, NO training — pure file read. Reproducible paper artifact.

Reads each eval report (from evaluate_ifnr_spbarc) + the payload CSV for the
tier mapping, then prints one row per algorithm:
    algo | IFNR | SPBARC | trivial SR | medium SR | complex SR | overall SR | via_agg

USAGE:
    python3 -m tools.rq1_table
    python3 -m tools.rq1_table --csv payloads_union_less1.csv \
        --runs PPO:eval_ppo_union_agg.json TRPO:eval_trpo_union.json A2C:eval_a2c_union.json
"""
import argparse
import csv
import json
from collections import Counter

DEFAULT_RUNS = [
    "TRPO:eval_trpo_union.json",
    "PPO:eval_ppo_union_agg.json",
    "A2C:eval_a2c_union.json",
]


def load_tier_map(csv_path):
    return {r["payload_id"]: r["tier"]
            for r in csv.DictReader(open(csv_path))}


def get(d, *keys, default=None):
    """Fetch the first present key (case-insensitive) from dict d."""
    low = {k.lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in low:
            return low[k.lower()]
    return default


def summarize(report_path, tier):
    d = json.load(open(report_path))
    ifnr   = get(d, "ifnr", "IFNR")
    spbarc = get(d, "spbarc", "SPBARC")
    per = d.get("per_payload") or d.get("results") or []

    tot, suc, agg = Counter(), Counter(), 0
    for r in per:
        t = tier.get(r.get("payload_id"), "?")
        tot[t] += 1
        if r.get("success"):
            suc[t] += 1
            if "json_arrayagg" in (r.get("final_payload") or "").lower():
                agg += 1

    def sr(t):
        return (100.0 * suc[t] / tot[t]) if tot[t] else float("nan")

    N, S = sum(tot.values()), sum(suc.values())
    return {
        "ifnr": ifnr, "spbarc": spbarc,
        "trivial": sr("trivial"), "medium": sr("medium"), "complex": sr("complex"),
        "overall": (100.0 * S / N) if N else 0.0,
        "agg": agg, "n": N,
    }


def fmt_ifnr(x):
    if x is None:
        return "  ?  "
    # stored as fraction (0.99) or percent? assume fraction if <=1.5
    pct = x * 100 if abs(x) <= 1.5 else x
    return f"+{pct:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="payloads_union_less1.csv")
    ap.add_argument("--runs", nargs="*", default=DEFAULT_RUNS,
                    help="LABEL:path.json entries")
    args = ap.parse_args()

    tier = load_tier_map(args.csv)

    hdr = (f"{'Algo':<6} | {'IFNR':>7} | {'SPBARC':>7} | "
           f"{'trivial':>7} | {'medium':>7} | {'complex':>7} | "
           f"{'overall':>7} | {'via_agg':>7}")
    print("=" * len(hdr))
    print(f" RQ1 — Deep-RL comparison  (corpus: {args.csv})")
    print("=" * len(hdr))
    print(hdr)
    print("-" * len(hdr))
    for entry in args.runs:
        label, path = entry.split(":", 1)
        try:
            s = summarize(path, tier)
        except FileNotFoundError:
            print(f"{label:<6} | (missing: {path})")
            continue
        print(f"{label:<6} | {fmt_ifnr(s['ifnr']):>7} | "
              f"{(s['spbarc'] if s['spbarc'] is not None else float('nan')):>7.2f} | "
              f"{s['trivial']:>6.1f}% | {s['medium']:>6.1f}% | {s['complex']:>6.1f}% | "
              f"{s['overall']:>6.1f}% | {s['agg']:>7}")
    print("-" * len(hdr))
    print("Note: tier label = SQL syntactic complexity, not bypass difficulty.")
    print("      via_agg = #successes whose final payload used JSON_ARRAYAGG (agg_swap).")


if __name__ == "__main__":
    main()
