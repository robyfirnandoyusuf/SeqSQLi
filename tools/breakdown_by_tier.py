"""
tools/breakdown_by_tier.py
==========================
Read an evaluate_ifnr_spbarc JSON report and break success down by TIER
(trivial / medium / complex), using payloads_union_less1.csv for the
payload_id -> tier mapping. NO network — pure file read.

This is the metric that tells us whether agg_swap unlocked the complex tier.

USAGE:
    python3 -m tools.breakdown_by_tier eval_ppo_union_agg.json
    python3 -m tools.breakdown_by_tier eval_ppo_union_agg.json --csv payloads_union_less1.csv
"""
import argparse
import csv
import json
from collections import Counter


def load_tier_map(csv_path):
    return {r["payload_id"]: r["tier"]
            for r in csv.DictReader(open(csv_path))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="eval JSON from evaluate_ifnr_spbarc")
    ap.add_argument("--csv", default="payloads_union_less1.csv")
    args = ap.parse_args()

    tier = load_tier_map(args.csv)
    data = json.load(open(args.report))
    per = data.get("per_payload") or data.get("results") or []

    tot = Counter()
    suc = Counter()
    agg_used = Counter()      # how many successes used JSON_ARRAYAGG
    for r in per:
        pid = r.get("payload_id")
        t = tier.get(pid, "?")
        tot[t] += 1
        if r.get("success"):
            suc[t] += 1
            fp = (r.get("final_payload") or "")
            if "json_arrayagg" in fp.lower():
                agg_used[t] += 1

    print(f"== Per-tier breakdown: {args.report} ==")
    print(f"  {'tier':<8} | {'succ':>5} / {'tot':>4} | {'SR':>6} | {'via agg_swap':>12}")
    print("  " + "-" * 48)
    order = ["trivial", "medium", "complex"]
    seen = [t for t in order if t in tot] + [t for t in tot if t not in order]
    for t in seen:
        n, s = tot[t], suc[t]
        sr = (100.0 * s / n) if n else 0.0
        print(f"  {t:<8} | {s:>5} / {n:>4} | {sr:>5.1f}% | {agg_used[t]:>12}")
    N = sum(tot.values())
    S = sum(suc.values())
    print("  " + "-" * 48)
    print(f"  {'ALL':<8} | {S:>5} / {N:>4} | {100.0*S/N if N else 0:>5.1f}% | "
          f"{sum(agg_used.values()):>12}")


if __name__ == "__main__":
    main()
