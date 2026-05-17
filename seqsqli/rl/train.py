"""
seqsqli/rl/train.py
====================
Training loop: runs episodes, updates Q-table, returns episode logs.
"""

import random
import time
from typing import List, Optional

from seqsqli.config import EPSILON, EPSILON_DECAY, EPSILON_MIN, MAX_STEPS
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.mutations import MUTATIONS
from seqsqli.core.response import classify_response
from seqsqli.rl.state import encode_state
from seqsqli.rl.qlearning import choose_action, update_Q, get_reward
from seqsqli.rl.train_ppo import load_payloads_csv
from seqsqli.config import REQUEST_DELAY


def train(target: TargetProfile,
          episodes: int,
          payloads_csv: Optional[str] = None) -> List[dict]:
    """Train the RL agent against a target for N episodes.

    Args:
        payloads_csv: Optional path to a payload_builder.py CSV.
                      When provided, each episode samples a random
                      validated payload as starting point and strict
                      marker SUCCESS criterion is auto-enabled
                      (mirrors train_ppo for fair RQ1 comparison).

    Returns a list of episode dicts, each containing:
        episode, steps, total_reward, success, sequence, final_payload
    """
    filter_type  = target.filter_type
    base_payload = target.base_payload
    epsilon      = EPSILON
    episode_logs: List[dict] = []

    base_payloads: Optional[List[str]] = None
    if payloads_csv:
        base_payloads = load_payloads_csv(payloads_csv)
        if not base_payloads:
            raise ValueError(f"No payloads loaded from {payloads_csv}")
    strict_markers = bool(base_payloads)

    print("=" * 60)
    print(f" SeqSQLi v2 — Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {filter_type}")
    print(f" Columns     : {target.columns}")
    if base_payloads:
        print(f" Mode        : online-WAF (strict markers)")
        print(f" Payload pool: {len(base_payloads)} validated from {payloads_csv}")
    else:
        print(f" Base payload: {base_payload}")
    print(f" Episodes    : {episodes}")
    print("=" * 60)

    for ep in range(episodes):
        payload      = random.choice(base_payloads) if base_payloads else base_payload
        state        = encode_state("INIT", "none", 0, payload)
        total_reward = 0.0
        step_log     = []
        success      = False

        for step in range(MAX_STEPS):
            action  = choose_action(state, epsilon, filter_type)
            mutated = MUTATIONS[action](payload)

            resp_text, status = send_request(target, mutated)
            result            = classify_response(resp_text, status,
                                                  strict_markers=strict_markers)
            reward            = get_reward(result, step + 1)

            next_state = encode_state(result, action, step + 1, mutated)
            update_Q(state, action, reward, next_state)

            step_log.append({
                "step":    step + 1,
                "action":  action,
                "payload": mutated[:150],
                "result":  result,
                "reward":  round(reward, 2),
            })

            total_reward += reward
            payload = mutated
            state   = next_state

            if result == "SUCCESS":
                success = True
                break

            time.sleep(REQUEST_DELAY)

        epsilon = max(epsilon * EPSILON_DECAY, EPSILON_MIN)

        episode_logs.append({
            "episode":       ep + 1,
            "steps":         len(step_log),
            "total_reward":  round(total_reward, 2),
            "success":       success,
            "final_result":  step_log[-1]["result"] if step_log else "N/A",
            "sequence":      [s["action"] for s in step_log],
            "final_payload": step_log[-1]["payload"] if step_log else "",
        })

        if (ep + 1) % 10 == 0:
            recent    = episode_logs[-10:]
            sr        = sum(1 for e in recent if e["success"]) / 10 * 100
            avg_steps = sum(e["steps"] for e in recent) / 10
            avg_rew   = sum(e["total_reward"] for e in recent) / 10
            print(
                f"  Ep {ep+1:>4} | eps={epsilon:.3f} | "
                f"SR={sr:.0f}% | Steps={avg_steps:.1f} | R={avg_rew:.2f}"
            )

    return episode_logs
