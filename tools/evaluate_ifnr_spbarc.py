"""
tools/evaluate_ifnr_spbarc.py
=============================
BWAFSQLi-aligned evaluation harness for SQLi WAF bypass methods.

Reads a validated payload CSV (produced by tools/payload_builder.py),
runs each payload through a mutation METHOD against a WAF-protected
endpoint, and reports the four headline metrics:

    FNR0   = Initial False Negative Rate
             = (# unmutated payloads that bypass the WAF) / |test_set|
             Measures the WAF's NATURAL miss rate on this payload set.

    MFNR   = Mutation False Negative Rate
             = (# payloads that succeed after mutation method is applied) / |test_set|
             Includes both naturally-passing payloads and bypasses earned
             by mutation.

    IFNR   = MFNR - FNR0
             Incremental bypass attributable to the mutation method itself,
             NOT to natural WAF misses. This is the metric reviewers will
             scrutinize.

    SPBARC = Successful Payload Bypass Average Request Count
             = total_inference_requests / # successful mutated bypasses
             Lower is better. Counts ONLY inference-time requests.
             Training-phase requests (for qlearning / ppo) are reported
             SEPARATELY as `training_requests` so the cost of learning
             is not hidden.

USAGE
-----
    # FNR0 baseline (method=none, payload sent as-is):
    python -m tools.evaluate_ifnr_spbarc \
        --payloads payloads_valid.csv \
        --url "http://localhost:8080/Less-1/" \
        --param id \
        --method none \
        --output fnr0_modsec_less1.json

    # Random baseline:
    python -m tools.evaluate_ifnr_spbarc \
        --payloads payloads_valid.csv \
        --url "http://localhost:8080/Less-1/" \
        --method random --max-steps 15 \
        --fnr0-file fnr0_modsec_less1.json \
        --output random_modsec_less1.json

    # Q-learning method (loads q_table.json):
    python -m tools.evaluate_ifnr_spbarc \
        --payloads payloads_valid.csv \
        --url "http://localhost:8080/Less-1/" \
        --method qlearning --qtable q_table.json \
        --fnr0-file fnr0_modsec_less1.json \
        --output qlearning_modsec_less1.json

    # PPO method (loads stable-baselines3 model):
    python -m tools.evaluate_ifnr_spbarc \
        --payloads payloads_valid.csv \
        --url "http://localhost:8080/Less-1/" \
        --method ppo --ppo-model seqsqli_ppo.zip \
        --fnr0-file fnr0_modsec_less1.json \
        --training-requests 6864 \
        --output ppo_modsec_less1.json

Tip: pass --fnr0-file once you've measured FNR0; the script will
re-use that number when reporting IFNR. Otherwise FNR0 is treated as 0.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from seqsqli.core.http import send_request, get_request_count
from seqsqli.core.mutations import (
    MUTATIONS, ACTION_LIST, FILTER_MUTATION_HINTS,
)
from seqsqli.core.profile import TargetProfile
from seqsqli.core.response import (
    classify_response, has_strict_markers,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PayloadResult:
    payload_id:           str
    original_payload:     str
    success:              bool
    final_payload:        str
    steps:                int          # mutations applied before success/timeout
    requests_used:        int          # HTTP requests during this episode
    final_status:         int
    final_result:         str          # SUCCESS / WAF_BLOCKED / ...
    initial_bypass:       bool         # True if payload bypassed BEFORE any mutation
    sequence:             List[str] = field(default_factory=list)


@dataclass
class EvalReport:
    method:               str
    target_url:           str
    payload_set:          str
    n_payloads:           int
    max_steps:            int
    seed:                 int
    fnr0:                 float        # initial bypass rate (no mutation)
    mfnr:                 float        # final bypass rate with method
    ifnr:                 float        # mfnr - fnr0 (or fnr0_override)
    fnr0_source:          str          # "measured" or "from_file:<path>"
    spbarc:               float        # avg requests per successful mutated bypass
    total_inference_requests: int
    successful_mutated_bypasses: int
    training_requests:    int          # report-only; user-supplied
    wall_clock_seconds:   float
    per_payload:          List[Dict]


# ---------------------------------------------------------------------------
# Method implementations
# ---------------------------------------------------------------------------

def _action_none(payload: str, _state: dict) -> Tuple[str, str]:
    """Identity method — used to measure FNR0."""
    return payload, "noop"


def _action_random(payload: str, state: dict) -> Tuple[str, str]:
    rng: random.Random = state["rng"]
    action = rng.choice(ACTION_LIST)
    return MUTATIONS[action](payload), action


def _action_static(payload: str, state: dict) -> Tuple[str, str]:
    """Round-robin through ACTION_LIST."""
    idx = state.get("rr_idx", 0)
    action = ACTION_LIST[idx % len(ACTION_LIST)]
    state["rr_idx"] = idx + 1
    return MUTATIONS[action](payload), action


def _action_filter_aware(payload: str, state: dict) -> Tuple[str, str]:
    """Pick from FILTER_MUTATION_HINTS bucket for current filter_type."""
    rng: random.Random = state["rng"]
    filter_type = state.get("filter_type", "unknown")
    pool = FILTER_MUTATION_HINTS.get(filter_type)
    if not pool:
        pool = ACTION_LIST
    action = rng.choice(pool)
    return MUTATIONS[action](payload), action


def _make_qlearning_picker(qtable_path: str):
    """Returns an action picker using a saved Q-table (greedy policy)."""
    from seqsqli.rl.qlearning import Q, load_q_table
    from seqsqli.rl.state import encode_state

    load_q_table(qtable_path)
    state_holder = {"last_result": "INIT", "last_action": "none", "step": 0}

    def picker(payload: str, state: dict) -> Tuple[str, str]:
        st = encode_state(
            state_holder["last_result"],
            state_holder["last_action"],
            state_holder["step"],
            payload,
        )
        # Greedy: pick action with highest Q-value at this state.
        best_action = max(ACTION_LIST, key=lambda a: Q[(st, a)])
        mutated = MUTATIONS[best_action](payload)
        state_holder["last_action"] = best_action
        state_holder["step"] += 1
        return mutated, best_action

    def reset():
        state_holder["last_result"] = "INIT"
        state_holder["last_action"] = "none"
        state_holder["step"] = 0

    picker.reset = reset  # type: ignore[attr-defined]
    return picker


def _make_ppo_picker(model_path: str, target: TargetProfile):
    """Returns an action picker using a saved PPO model (deterministic)."""
    import numpy as np
    from stable_baselines3 import PPO
    from seqsqli.rl.env import SeqSQLiEnv

    model = PPO.load(model_path)
    env = SeqSQLiEnv(target)  # used only for _obs() construction
    obs, _ = env.reset()

    def picker(payload: str, state: dict) -> Tuple[str, str]:
        # Sync env's internal payload + step to what we're tracking.
        env._payload = payload
        env._step_count = state.get("step", 0)
        # last_action_idx left unchanged; not critical for greedy eval.
        obs = env._obs()
        action_arr, _ = model.predict(obs, deterministic=True)
        action_idx = int(action_arr)
        action = ACTION_LIST[action_idx]
        mutated = MUTATIONS[action](payload)
        env._payload = mutated
        env._last_action_idx = action_idx
        return mutated, action

    def reset():
        env._payload = ""
        env._step_count = 0
        env._last_action_idx = -1

    picker.reset = reset  # type: ignore[attr-defined]
    return picker


# ---------------------------------------------------------------------------
# Core eval loop
# ---------------------------------------------------------------------------

def evaluate_one_payload(target: TargetProfile,
                          spec: dict,
                          picker,
                          max_steps: int,
                          delay: float,
                          state: dict) -> PayloadResult:
    """Run one payload through the method until SUCCESS or step budget."""
    original = spec["payload"]
    sequence: List[str] = []
    payload = original
    initial_bypass = False
    final_result = "UNKNOWN"
    final_status = 0
    pre_count = get_request_count()

    # Step 0 — probe original payload (no mutation yet). This measures
    # whether the WAF naturally misses this payload (contributes to FNR0).
    resp_text, status = send_request(target, payload)
    final_status = status
    result = classify_response(resp_text, status, strict_markers=True)
    final_result = result
    if result == "SUCCESS":
        initial_bypass = True
        post_count = get_request_count()
        return PayloadResult(
            payload_id=spec["payload_id"],
            original_payload=original,
            success=True,
            final_payload=payload,
            steps=0,
            requests_used=post_count - pre_count,
            final_status=final_status,
            final_result=final_result,
            initial_bypass=True,
            sequence=[],
        )

    # Step 1..max_steps — apply mutations.
    if hasattr(picker, "reset"):
        picker.reset()
    state["step"] = 0
    state.setdefault("filter_type", target.filter_type)

    success = False
    for step in range(1, max_steps + 1):
        mutated, action = picker(payload, state)
        sequence.append(action)
        state["step"] = step

        # Stagnation skip: don't waste an HTTP request if mutation is no-op.
        if mutated == payload:
            continue

        resp_text, status = send_request(target, mutated)
        final_status = status
        result = classify_response(resp_text, status, strict_markers=True)
        final_result = result
        payload = mutated

        if result == "SUCCESS":
            success = True
            break
        time.sleep(delay)

    post_count = get_request_count()
    return PayloadResult(
        payload_id=spec["payload_id"],
        original_payload=original,
        success=success,
        final_payload=payload,
        steps=len(sequence),
        requests_used=post_count - pre_count,
        final_status=final_status,
        final_result=final_result,
        initial_bypass=initial_bypass,
        sequence=sequence,
    )


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def load_payloads(path: str) -> List[dict]:
    out: List[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Only keep validated rows (column missing or "yes").
            v = row.get("valid_without_waf", "").strip().lower()
            if v in ("", "yes"):
                out.append(row)
    return out


def load_fnr0(path: Optional[str]) -> Optional[float]:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Accept either {"fnr0": x} or full EvalReport dict (use mfnr if method=none).
        if "fnr0" in data:
            return float(data["fnr0"])
        if data.get("method") == "none":
            return float(data["mfnr"])
    except Exception as e:
        print(f"[!] Failed to load fnr0 from {path}: {e}")
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BWAFSQLi-aligned evaluator for FNR0 / MFNR / IFNR / SPBARC.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--payloads", required=True,
                        help="Path to validated payloads CSV "
                             "(from tools/payload_builder.py)")
    parser.add_argument("--url", required=True,
                        help="WAF-protected target URL")
    parser.add_argument("--param", default="id")
    parser.add_argument("--method", required=True,
                        choices=["none", "random", "static",
                                 "filter_aware", "qlearning", "ppo"])
    parser.add_argument("--filter-type", default="unknown",
                        help="Filter class hint for filter_aware method")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--qtable", default="q_table.json",
                        help="Q-table path for method=qlearning")
    parser.add_argument("--ppo-model", default="seqsqli_ppo.zip",
                        help="PPO model path for method=ppo")
    parser.add_argument("--training-requests", type=int, default=0,
                        help="Training-phase HTTP request count for the "
                             "method (qlearning/ppo). Reported separately "
                             "from inference SPBARC.")
    parser.add_argument("--fnr0-file", default=None,
                        help="JSON file with measured FNR0 (from a prior "
                             "method=none run). When provided, IFNR is "
                             "computed against it instead of the within-run "
                             "initial-bypass rate.")
    parser.add_argument("--output", required=True,
                        help="Output JSON report path")
    args = parser.parse_args()

    # ----- Load payloads ----- #
    payloads = load_payloads(args.payloads)
    if not payloads:
        print(f"[!] No validated payloads in {args.payloads}")
        sys.exit(1)
    print(f"[*] Loaded {len(payloads)} validated payloads")

    # ----- Target ----- #
    target = TargetProfile(
        url=args.url, param=args.param, method="GET",
        filter_type=args.filter_type,
    )

    # ----- Build picker for the method ----- #
    state: dict = {"rng": random.Random(args.seed)}
    if args.method == "none":
        picker = _action_none
    elif args.method == "random":
        picker = _action_random
    elif args.method == "static":
        picker = _action_static
    elif args.method == "filter_aware":
        picker = _action_filter_aware
        state["filter_type"] = args.filter_type
    elif args.method == "qlearning":
        picker = _make_qlearning_picker(args.qtable)
    elif args.method == "ppo":
        picker = _make_ppo_picker(args.ppo_model, target)
    else:
        raise ValueError(args.method)

    # method=none: cap max_steps to 0 — we only probe original.
    if args.method == "none":
        args.max_steps = 0

    # ----- Run ----- #
    print(f"[*] Method={args.method} | max_steps={args.max_steps} | "
          f"target={args.url}")
    t0 = time.time()
    pre_total = get_request_count()
    results: List[PayloadResult] = []
    for i, spec in enumerate(payloads, 1):
        r = evaluate_one_payload(
            target, spec, picker, args.max_steps, args.delay, state,
        )
        results.append(r)
        if i % 10 == 0 or i == len(payloads):
            ok = sum(1 for x in results if x.success)
            init = sum(1 for x in results if x.initial_bypass)
            print(f"  [{i:>4}/{len(payloads)}] success={ok} (initial={init})")
    wall = time.time() - t0
    total_inference_requests = get_request_count() - pre_total

    # ----- Aggregate ----- #
    n = len(results)
    n_initial = sum(1 for r in results if r.initial_bypass)
    n_success = sum(1 for r in results if r.success)
    n_mutated_success = n_success - n_initial  # bypasses NOT from initial probe

    fnr0_in_run = n_initial / n if n else 0.0
    fnr0_override = load_fnr0(args.fnr0_file)
    if fnr0_override is not None:
        fnr0 = fnr0_override
        fnr0_source = f"from_file:{args.fnr0_file}"
    else:
        fnr0 = fnr0_in_run
        fnr0_source = "measured"

    mfnr = n_success / n if n else 0.0
    ifnr = mfnr - fnr0
    spbarc = (total_inference_requests / n_mutated_success
              if n_mutated_success > 0 else float("inf"))

    report = EvalReport(
        method=args.method,
        target_url=args.url,
        payload_set=args.payloads,
        n_payloads=n,
        max_steps=args.max_steps,
        seed=args.seed,
        fnr0=round(fnr0, 4),
        mfnr=round(mfnr, 4),
        ifnr=round(ifnr, 4),
        fnr0_source=fnr0_source,
        spbarc=round(spbarc, 2) if spbarc != float("inf") else -1,
        total_inference_requests=total_inference_requests,
        successful_mutated_bypasses=n_mutated_success,
        training_requests=args.training_requests,
        wall_clock_seconds=round(wall, 2),
        per_payload=[asdict(r) for r in results],
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)

    # ----- Summary ----- #
    print()
    print("=" * 60)
    print(f" RESULTS: method={args.method}")
    print("=" * 60)
    print(f"  Payloads             : {n}")
    print(f"  Initial bypasses     : {n_initial}  (within-run FNR0={fnr0_in_run:.4f})")
    print(f"  Total successes      : {n_success}")
    print(f"  Mutated bypasses     : {n_mutated_success}")
    print(f"  FNR0 (used)          : {fnr0:.4f}  ({fnr0_source})")
    print(f"  MFNR                 : {mfnr:.4f}")
    print(f"  IFNR                 : {ifnr:+.4f}")
    if spbarc == float("inf"):
        print(f"  SPBARC               : N/A (no mutated bypasses)")
    else:
        print(f"  SPBARC               : {spbarc:.2f}")
    print(f"  Inference requests   : {total_inference_requests}")
    print(f"  Training requests    : {args.training_requests} (reported-only)")
    print(f"  Wall clock           : {wall:.1f}s")
    print(f"  Report saved to      : {args.output}")


if __name__ == "__main__":
    main()
