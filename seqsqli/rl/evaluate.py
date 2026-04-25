"""
seqsqli/rl/evaluate.py
=======================
Post-training analysis:
  - evaluate()         : print training summary (top mutations, shortest bypass)
  - greedy_eval()      : run one episode with greedy policy
  - analyze_q_table()  : print top Q-values
  - analyze_ordering() : RQ3 — does mutation ordering affect WAF bypass? (4 analyses)
"""

import json
import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

from seqsqli.config import MAX_STEPS, REQUEST_DELAY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.mutations import MUTATIONS, ACTION_LIST
from seqsqli.core.response import classify_response
from seqsqli.rl.state import encode_state
from seqsqli.rl.qlearning import Q

def evaluate(episode_logs: List[dict]) -> None:
    """Print training summary and statistics."""
    total = len(episode_logs)
    successes = [e for e in episode_logs if e["success"]]

    print(f"\n{'='*60}")
    print(f" TRAINING RESULTS")
    print(f"{'='*60}")
    print(f"  Total episodes     : {total}")
    print(f"  Successful bypass  : {len(successes)} ({len(successes)/total*100:.1f}%)")

    if successes:
        avg_steps = sum(e["steps"] for e in successes) / len(successes)
        print(f"  Avg steps (success): {avg_steps:.2f}")

        all_actions = []
        for e in successes:
            all_actions.extend(e["sequence"])
        top = Counter(all_actions).most_common(5)
        print(f"\n  Top mutations:")
        for action, count in top:
            print(f"    {action:<22} : {count}")

        shortest = min(successes, key=lambda e: e["steps"])
        print(f"\n  Shortest bypass:")
        print(f"    Steps    : {shortest['steps']}")
        print(f"    Sequence : {' -> '.join(shortest['sequence'])}")
        print(f"    Payload  : {shortest['final_payload']}")


def greedy_eval(target: TargetProfile) -> None:
    """Run a single greedy evaluation episode."""
    payload = target.base_payload
    state = encode_state("INIT", "none", 0, payload)

    print(f"\n[*] Greedy evaluation:")
    for step in range(MAX_STEPS):
        action = max(ACTION_LIST, key=lambda a: Q[(state, a)])
        mutated = MUTATIONS[action](payload)
        resp, status = send_request(target, mutated)
        result = classify_response(resp, status)
        next_state = encode_state(result, action, step + 1, mutated)

        print(f"  Step {step+1}: {action:<22} -> {result}")
        print(f"         {mutated[:100]}")

        if result == "SUCCESS":
            print("  *** BYPASS SUCCESSFUL ***")
            break
        payload = mutated
        state = next_state
        time.sleep(REQUEST_DELAY)


def analyze_q_table(top_n: int = 15) -> None:
    """Print top Q-values."""
    if not Q:
        print("[!] Q-table is empty.")
        return
    print(f"\n  Top {top_n} Q-values:")
    sorted_q = sorted(Q.items(), key=lambda x: x[1], reverse=True)[:top_n]
    for (state, action), value in sorted_q:
        print(f"    {action:<22} | Q={value:>7.3f} | state={state}")


# =============================================================================
# RQ3 ORDERING ANALYSIS
# =============================================================================

def analyze_ordering(episode_logs: List[dict], save_path: str = None) -> dict:
    """
    RQ3: Analyze how the ORDERING of mutation actions affects WAF bypass success.

    Four analyses are produced:

    1. First-step analysis
       Which mutation, when applied FIRST, leads to the highest success rate?
       Directly answers: "Does the starting mutation matter?"

    2. Bigram success rate  (A -> B)
       For every consecutive pair seen across all episodes, what % of episodes
       containing that transition were successful?

    3. Reversed-pair comparison  (A -> B  vs  B -> A)
       For pairs where both orders were observed, compare their success rates.
       This is the core RQ3 evidence — if SR(A->B) >> SR(B->A), ordering matters.

    4. Position sensitivity
       For each action, compare SR when it is used at position 1, 2, or 3+.
       Shows whether the same mutation is more effective earlier or later.

    Args:
        episode_logs : list of episode dicts produced by train()
        save_path    : optional JSON path to save the full report

    Returns:
        dict with keys: first_step, bigrams, reversed_pairs, position_sensitivity
    """

    successes  = [e for e in episode_logs if e["success"]]
    failures   = [e for e in episode_logs if not e["success"]]
    total_eps  = len(episode_logs)

    # ------------------------------------------------------------------
    # 1. FIRST-STEP ANALYSIS
    # ------------------------------------------------------------------
    first_step_success: Dict[str, int] = Counter()
    first_step_total:   Dict[str, int] = Counter()

    for ep in episode_logs:
        seq = ep["sequence"]
        if not seq:
            continue
        first = seq[0]
        first_step_total[first] += 1
        if ep["success"]:
            first_step_success[first] += 1

    first_step_sr = {}
    for action, total in first_step_total.items():
        sr = first_step_success[action] / total * 100
        first_step_sr[action] = {
            "success_rate": round(sr, 1),
            "success_count": first_step_success[action],
            "total_count":   total,
        }
    # Sort by success rate descending
    first_step_sr = dict(
        sorted(first_step_sr.items(), key=lambda x: x[1]["success_rate"], reverse=True)
    )

    # ------------------------------------------------------------------
    # 2. BIGRAM SUCCESS RATE  (A -> B)
    # ------------------------------------------------------------------
    bigram_success: Dict[str, int] = Counter()
    bigram_total:   Dict[str, int] = Counter()

    for ep in episode_logs:
        seq = ep["sequence"]
        for i in range(len(seq) - 1):
            pair = f"{seq[i]} -> {seq[i+1]}"
            bigram_total[pair] += 1
            if ep["success"]:
                bigram_success[pair] += 1

    bigram_sr = {}
    for pair, total in bigram_total.items():
        if total < 2:          # skip pairs seen only once — not reliable
            continue
        sr = bigram_success[pair] / total * 100
        bigram_sr[pair] = {
            "success_rate":  round(sr, 1),
            "success_count": bigram_success[pair],
            "total_count":   total,
        }
    bigram_sr = dict(
        sorted(bigram_sr.items(), key=lambda x: x[1]["success_rate"], reverse=True)
    )

    # ------------------------------------------------------------------
    # 3. REVERSED-PAIR COMPARISON  (A->B  vs  B->A)
    # ------------------------------------------------------------------
    reversed_pairs = {}
    seen = set()

    for pair in bigram_sr:
        if pair in seen:
            continue
        a, b = pair.split(" -> ")
        rev_pair = f"{b} -> {a}"
        if rev_pair in bigram_sr and rev_pair not in seen:
            sr_fwd = bigram_sr[pair]["success_rate"]
            sr_rev = bigram_sr[rev_pair]["success_rate"]
            diff   = round(sr_fwd - sr_rev, 1)
            reversed_pairs[pair] = {
                "forward":          {"pair": pair,     "success_rate": sr_fwd,
                                     "count": bigram_sr[pair]["total_count"]},
                "reversed":         {"pair": rev_pair, "success_rate": sr_rev,
                                     "count": bigram_sr[rev_pair]["total_count"]},
                "sr_difference":    diff,
                "ordering_matters": abs(diff) >= 10.0,   # ≥10% gap = meaningful
            }
            seen.add(pair)
            seen.add(rev_pair)

    # Sort by absolute difference (most impactful ordering first)
    reversed_pairs = dict(
        sorted(reversed_pairs.items(),
               key=lambda x: abs(x[1]["sr_difference"]), reverse=True)
    )

    # ------------------------------------------------------------------
    # 4. POSITION SENSITIVITY
    # ------------------------------------------------------------------
    # For each action: track (success_count, total_count) per position bucket
    # Positions: 1, 2, 3+ (bucketed to keep the table readable)
    pos_success: Dict[str, Dict[str, int]] = {}
    pos_total:   Dict[str, Dict[str, int]] = {}

    for ep in episode_logs:
        seq = ep["sequence"]
        for i, action in enumerate(seq):
            pos = str(i + 1) if i < 2 else "3+"
            if action not in pos_success:
                pos_success[action] = Counter()
                pos_total[action]   = Counter()
            pos_total[action][pos]   += 1
            if ep["success"]:
                pos_success[action][pos] += 1

    position_sensitivity = {}
    for action in pos_total:
        entry = {}
        for pos in ["1", "2", "3+"]:
            if pos in pos_total[action] and pos_total[action][pos] >= 2:
                sr = pos_success[action][pos] / pos_total[action][pos] * 100
                entry[f"pos_{pos}"] = {
                    "success_rate": round(sr, 1),
                    "count":        pos_total[action][pos],
                }
        if entry:
            # Only keep actions that appear in ≥2 different positions
            if len(entry) >= 2:
                position_sensitivity[action] = entry

    # ------------------------------------------------------------------
    # PRINT REPORT
    # ------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f" RQ3 — MUTATION ORDERING ANALYSIS")
    print(f"{'='*60}")

    # --- First step ---
    print(f"\n  [1] First-Step Success Rate (which mutation to apply FIRST?)")
    print(f"  {'Action':<22} | {'SR':>6} | {'Succ':>5} / {'Total':>5}")
    print(f"  {'-'*50}")
    for action, d in list(first_step_sr.items())[:10]:
        bar = "█" * int(d["success_rate"] / 10)
        print(f"  {action:<22} | {d['success_rate']:>5.1f}% | "
              f"{d['success_count']:>5} / {d['total_count']:>5}  {bar}")

    # --- Bigrams ---
    print(f"\n  [2] Top Bigram Sequences (A -> B success rate)")
    print(f"  {'Sequence':<35} | {'SR':>6} | {'Count':>5}")
    print(f"  {'-'*55}")
    for pair, d in list(bigram_sr.items())[:10]:
        bar = "█" * int(d["success_rate"] / 10)
        print(f"  {pair:<35} | {d['success_rate']:>5.1f}% | "
              f"{d['total_count']:>5}  {bar}")

    # --- Reversed pairs ---
    print(f"\n  [3] Ordering Effect: A->B  vs  B->A")
    print(f"  {'Forward':<25} {'SR':>6}  |  {'Reversed':<25} {'SR':>6}  | {'Diff':>6} | {'Matters?':>8}")
    print(f"  {'-'*80}")
    shown = 0
    for pair, d in reversed_pairs.items():
        fwd = d["forward"]
        rev = d["reversed"]
        flag = "✓ YES" if d["ordering_matters"] else "  no"
        print(f"  {fwd['pair']:<25} {fwd['success_rate']:>5.1f}%  |  "
              f"  {rev['pair']:<25} {rev['success_rate']:>5.1f}%  | "
              f"{d['sr_difference']:>+6.1f}% | {flag}")
        shown += 1
        if shown >= 10:
            break

    if not reversed_pairs:
        print(f"  (not enough data — run more episodes for reversed-pair comparison)")

    # --- Position sensitivity ---
    print(f"\n  [4] Position Sensitivity (does position in sequence matter?)")
    print(f"  {'Action':<22} | {'pos_1':>8} | {'pos_2':>8} | {'pos_3+':>8} | {'Δ(1 vs 2)':>10}")
    print(f"  {'-'*70}")
    for action, d in list(position_sensitivity.items())[:12]:
        p1  = d.get("pos_1",  {}).get("success_rate", "  N/A")
        p2  = d.get("pos_2",  {}).get("success_rate", "  N/A")
        p3p = d.get("pos_3+", {}).get("success_rate", "  N/A")
        if isinstance(p1, float) and isinstance(p2, float):
            delta = f"{p1 - p2:>+.1f}%"
        else:
            delta = "   N/A"
        p1_s  = f"{p1:>6.1f}%" if isinstance(p1, float) else f"{p1:>8}"
        p2_s  = f"{p2:>6.1f}%" if isinstance(p2, float) else f"{p2:>8}"
        p3p_s = f"{p3p:>6.1f}%" if isinstance(p3p, float) else f"{p3p:>8}"
        print(f"  {action:<22} | {p1_s:>8} | {p2_s:>8} | {p3p_s:>8} | {delta:>10}")

    # ------------------------------------------------------------------
    # Summary verdict
    # ------------------------------------------------------------------
    ordering_evidence = [p for p, d in reversed_pairs.items() if d["ordering_matters"]]
    print(f"\n  VERDICT:")
    if ordering_evidence:
        print(f"  Ordering matters (≥10% SR gap) in {len(ordering_evidence)} out of "
              f"{len(reversed_pairs)} observed pairs.")
        print(f"  Key pairs where order is critical:")
        for p in ordering_evidence[:5]:
            d  = reversed_pairs[p]
            print(f"    {d['forward']['pair']:<30} SR={d['forward']['success_rate']}%  vs  "
                  f"{d['reversed']['pair']:<30} SR={d['reversed']['success_rate']}%")
    else:
        print(f"  No reversed pairs with ≥10% gap found yet.")
        print(f"  Try running with more episodes (e.g. --episodes 500) for stronger evidence.")

    # ------------------------------------------------------------------
    # SAVE TO JSON
    # ------------------------------------------------------------------
    report = {
        "total_episodes":      total_eps,
        "successful_episodes": len(successes),
        "first_step":          first_step_sr,
        "bigrams":             bigram_sr,
        "reversed_pairs":      reversed_pairs,
        "position_sensitivity": position_sensitivity,
        "ordering_matters_count": len(ordering_evidence),
    }

    if save_path:
        with open(save_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Ordering analysis saved to: {save_path}")

    return report


