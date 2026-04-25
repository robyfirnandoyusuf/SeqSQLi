"""
seqsqli/rl/train.py
====================
Training loop: runs episodes, updates Q-table, returns episode logs.
"""

import time
from typing import List

from seqsqli.config import EPSILON, EPSILON_DECAY, EPSILON_MIN, MAX_STEPS
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.mutations import MUTATIONS
from seqsqli.core.response import classify_response
from seqsqli.rl.state import encode_state
from seqsqli.rl.qlearning import choose_action, update_Q, get_reward
from seqsqli.config import REQUEST_DELAY


def train(target: TargetProfile,
          episodes: int) -> List[dict]:
    """Train the RL agent against a target for N episodes.

    Returns a list of episode dicts, each containing:
        episode, steps, total_reward, success, sequence, final_payload
    """
    filter_type  = target.filter_type
    base_payload = target.base_payload
    epsilon      = EPSILON
    episode_logs: List[dict] = []

    print("=" * 60)
    print(f" SeqSQLi v2 — Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {filter_type}")
    print(f" Columns     : {target.columns}")
    print(f" Base payload: {base_payload}")
    print(f" Episodes    : {episodes}")
    print("=" * 60)

    for ep in range(episodes):
        payload      = base_payload
        state        = encode_state("INIT", "none", 0, payload)
        total_reward = 0.0
        step_log     = []
        success      = False

        for step in range(MAX_STEPS):
            action  = choose_action(state, epsilon, filter_type)
            mutated = MUTATIONS[action](payload)

            resp_text, status = send_request(target, mutated)
            result            = classify_response(resp_text, status)
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
