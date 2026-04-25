"""
seqsqli/rl/qlearning.py
========================
Q-table, action selection, Q-update rule, reward function,
and Q-table persistence (save / load).
"""

import json
import random
from collections import defaultdict
from typing import Dict, Tuple

from seqsqli.config import (
    ALPHA, GAMMA, STEP_PENALTY, QTABLE_PATH,
)
from seqsqli.core.mutations import ACTION_LIST, FILTER_MUTATION_HINTS

# ---------------------------------------------------------------------------
# Q-table (global, shared across training and evaluation)
# ---------------------------------------------------------------------------
Q: Dict[Tuple, float] = defaultdict(float)


# ---------------------------------------------------------------------------
# Reward table
# ---------------------------------------------------------------------------
REWARD_TABLE = {
    "SUCCESS":      10.0,
    "SQL_ERROR":     0.5,   # query reached the DB engine
    "FILTERED":     -1.0,
    "UNKNOWN":      -0.5,
    "WAF_BLOCKED":  -2.0,
    "SERVER_ERROR": -1.5,
}


# ---------------------------------------------------------------------------
# Core RL functions
# ---------------------------------------------------------------------------

def choose_action(state: Tuple, epsilon: float,
                  filter_type: str = "none") -> str:
    """Epsilon-greedy action selection with filter-aware exploration bias.

    During exploration (random < epsilon), mutations relevant to the
    detected filter type appear 2× more often in the candidate pool.
    This is documented as 'filter-aware exploration bias' in the paper.
    """
    if random.random() < epsilon:
        hints = FILTER_MUTATION_HINTS.get(filter_type, ACTION_LIST[:10])
        pool = hints * 2 + ACTION_LIST   # hints appear 2x more often
        return random.choice(pool)
    return max(ACTION_LIST, key=lambda a: Q[(state, a)])


def update_Q(state: Tuple, action: str,
             reward: float, next_state: Tuple) -> None:
    """Standard Q-learning (off-policy) update rule:
        Q(s,a) += α * (r + γ * max_a' Q(s',a') - Q(s,a))
    """
    best_next = max(Q[(next_state, a)] for a in ACTION_LIST)
    Q[(state, action)] += ALPHA * (reward + GAMMA * best_next - Q[(state, action)])


def get_reward(result: str, step: int) -> float:
    """Reward = base value - step penalty (encourages shorter sequences)."""
    return REWARD_TABLE.get(result, -1.0) - (STEP_PENALTY * step)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_q_table(path: str = QTABLE_PATH) -> None:
    """Serialise Q-table to JSON."""
    data = [{"state": list(s), "action": a, "value": v}
            for (s, a), v in Q.items()]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Q-table saved: {path} ({len(data)} entries)")


def load_q_table(path: str = QTABLE_PATH) -> None:
    """Load Q-table from JSON; silently starts fresh if file not found."""
    global Q
    try:
        with open(path) as f:
            data = json.load(f)
        Q.clear()
        for item in data:
            Q[(tuple(item["state"]), item["action"])] = float(item["value"])
        print(f"[*] Q-table loaded: {path} ({len(Q)} entries)")
    except FileNotFoundError:
        print(f"[!] No Q-table at {path}, starting fresh.")
