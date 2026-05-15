"""
seqsqli/rl/env.py
=================
Gymnasium-compatible environment wrapper for SeqSQLi.
Used by PPO and other deep RL algorithms.
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces

from seqsqli.config import MAX_STEPS, STEP_PENALTY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.mutations import MUTATIONS, ACTION_LIST
from seqsqli.core.response import classify_response
from seqsqli.rl.state import extract_features


REWARD_TABLE = {
    "SUCCESS":      10.0,
    "SQL_ERROR":     0.5,
    "FILTERED":     -1.0,
    "UNKNOWN":      -0.5,
    "WAF_BLOCKED":  -2.0,
    "SERVER_ERROR": -1.5,
    "STAGNANT":     -1.5,
}

# State dim: 14 binary payload features + 41 last-action one-hot + 1 step_norm
_N_ACTIONS  = len(ACTION_LIST)
_N_FEATURES = 14
OBS_DIM     = _N_FEATURES + _N_ACTIONS + 1


class SeqSQLiEnv(gym.Env):
    """Gymnasium environment for SQL injection WAF bypass via mutation sequences."""

    metadata = {"render_modes": []}

    def __init__(self, target: TargetProfile):
        super().__init__()
        self.target = target

        self.action_space = spaces.Discrete(_N_ACTIONS)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(OBS_DIM,),
            dtype=np.float32,
        )

        self._payload    = ""
        self._step_count = 0
        self._last_action_idx = -1

    # ------------------------------------------------------------------
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._payload         = self.target.base_payload
        self._step_count      = 0
        self._last_action_idx = -1
        return self._obs(), {}

    # ------------------------------------------------------------------
    def step(self, action_idx: int):
        action  = ACTION_LIST[action_idx]
        mutated = MUTATIONS[action](self._payload)

        # Stagnation: mutation produced no change
        if mutated == self._payload:
            reward = REWARD_TABLE["STAGNANT"] - STEP_PENALTY * self._step_count
            self._step_count += 1
            self._last_action_idx = action_idx
            truncated = self._step_count >= MAX_STEPS
            return self._obs(), reward, False, truncated, {"result": "STAGNANT", "payload": self._payload}

        resp_text, status = send_request(self.target, mutated)
        result = classify_response(resp_text, status)
        reward = REWARD_TABLE.get(result, -1.0) - STEP_PENALTY * self._step_count

        self._payload         = mutated
        self._step_count     += 1
        self._last_action_idx = action_idx

        terminated = result == "SUCCESS"
        truncated  = self._step_count >= MAX_STEPS

        return self._obs(), reward, terminated, truncated, {"result": result, "payload": mutated}

    # ------------------------------------------------------------------
    def _obs(self) -> np.ndarray:
        features = np.array(extract_features(self._payload), dtype=np.float32)

        action_onehot = np.zeros(_N_ACTIONS, dtype=np.float32)
        if self._last_action_idx >= 0:
            action_onehot[self._last_action_idx] = 1.0

        step_norm = np.array([self._step_count / MAX_STEPS], dtype=np.float32)

        return np.concatenate([features, action_onehot, step_norm])

    # ------------------------------------------------------------------
    def get_payload(self) -> str:
        return self._payload
