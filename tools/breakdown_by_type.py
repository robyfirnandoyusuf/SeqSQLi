"""
tools/breakdown_by_type.py
==========================
Split an evaluate_ifnr_spbarc.py report into union vs error metrics.

The main evaluator reports aggregate FNR0/MFNR/IFNR/SPBARC. For RQ1 we
also need the per-injection-type breakdown (e.g. to show union SR
recovered after the task-aware state fix). This reads one or more eval
JSON reports and prints, per payload type, the success rate, initial
(no-mutation) bypass rate, and a type-local SPBARC.

Type is inferred from payload_id prefix:
    'u...' -> union     'e...' -> error     anything else -> other

USAGE
-----
    python -m tools.breakdown_by_type results/random_less1.json
    python -m tools.breakdown_by_type results/ppo_less1.json results/trpo_less1.json
"""

from __future__ import annotations

import argparse
import json
from typing import Dict, List


def _type_of(payload_id: str) -> str:
    pid = (payload_id or "").strip().lower()
    if pid.startswith("u"):
        return "union"
    if pid.startswith("e"):
        return "error"
    return "other"


def summarize(report: dict) -> Dict[str, dict]:
    """Return {type: {n, success, initial, mutated, requests}} for a report."""
    buckets: Dict[str, dict] = {}
    for r in report.get("per_payload", []):
        t = _type_of(r.get("payload_id", ""))
        b = buckets.setdefault(
            t, {"n": 0, "success": 0, "initial": 0, "mutated": 0, "requests": 0}
        )
        b["n"] += 1
        b["requests"] += int(r.get("requests_used", 0))
        if r.get("success"):
            b["success"] += 1
            if r.get("initial_bypass"):
                b["initial"] += 1
            else:
                b["mutated"] += 1
    return buckets


def print_report(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)

    method = report.get("method", "?")
    buckets = summarize(report)

    print("=" * 72)
    print(f" {path}   (method={method})")
    print("=" * 72)
    header = (f"  {'Type':<8} | {'N':>4} | {'Success':>9} | {'SR':>7} | "
              f"{'Initial':>8} | {'Mutated':>8} | {'SPBARC':>8}")
    print(header)
    print("  " + "-" * (len(header) - 2))

    # Stable order: union, error, other — only those present.
    for t in ("union", "error", "other"):
        if t not in buckets:
            continue
        b = buckets[t]
        sr = b["success"] / b["n"] * 100 if b["n"] else 0.0
        spbarc = b["requests"] / b["mutated"] if b["mutated"] else float("inf")
        spbarc_s = f"{spbarc:>8.2f}" if spbarc != float("inf") else f"{'N/A':>8}"
        print(f"  {t:<8} | {b['n']:>4} | {b['success']:>9} | {sr:>6.1f}% | "
              f"{b['initial']:>8} | {b['mutated']:>8} | {spbarc_s}")

    # Overall line for cross-check against the evaluator's own numbers.
    n_all = sum(b["n"] for b in buckets.values())
    s_all = sum(b["success"] for b in buckets.values())
    sr_all = s_all / n_all * 100 if n_all else 0.0
    print("  " + "-" * (len(header) - 2))
    print(f"  {'ALL':<8} | {n_all:>4} | {s_all:>9} | {sr_all:>6.1f}% | "
          f"(report MFNR={report.get('mfnr')}, IFNR={report.get('ifnr')}, "
          f"SPBARC={report.get('spbarc')})")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Union/error breakdown of evaluate_ifnr_spbarc reports.")
    ap.add_argument("reports", nargs="+", help="One or more eval JSON paths")
    args = ap.parse_args()
    for path in args.reports:
        print_report(path)


if __name__ == "__main__":
    main()
