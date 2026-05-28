"""
seqsqli/rl/env.py
=================
Gymnasium-compatible environment wrapper for SeqSQLi.
Used by PPO and other deep RL algorithms.

Each episode samples one base payload from a corpus and the agent
mutates it for up to MAX_STEPS steps. The success criterion is
delegated to classify_response() and routed via per-payload
signal_type (union | error) + error_function (for error-based
signature lookup).
"""

import random
from typing import Dict, List, Optional

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


def _coerce_specs(base_payloads: Optional[List[str]],
                  base_payload_specs: Optional[List[Dict]]) -> List[Dict]:
    """Normalize either input form into a list of spec dicts.

    Backward compat: if `base_payloads` (list of strings) is given,
    each entry is wrapped into a dict with sensible defaults
    (injection_type='union', error_function='').
    """
    if base_payload_specs:
        out: List[Dict] = []
        for s in base_payload_specs:
            out.append({
                "payload":        s.get("payload", ""),
                "injection_type": s.get("injection_type", "union") or "union",
                "error_function": s.get("error_function", "") or "",
            })
        return [s for s in out if s["payload"]]
    if base_payloads:
        return [
            {"payload": p, "injection_type": "union", "error_function": ""}
            for p in base_payloads if p
        ]
    return []


class SeqSQLiEnv(gym.Env):
    """Gymnasium environment for SQL injection WAF bypass via mutation sequences."""

    metadata = {"render_modes": []}

    def __init__(self, target: TargetProfile,
                 base_payloads: Optional[List[str]] = None,
                 base_payload_specs: Optional[List[Dict]] = None,
                 strict_markers: Optional[bool] = None):
        """
        Args:
            target:             TargetProfile (URL, param, method, ...).
            base_payloads:      DEPRECATED — list of payload strings, all
                                treated as injection_type='union'. Kept
                                for backward compatibility with older
                                trainers.
            base_payload_specs: Preferred. List of dicts, each with at
                                least the keys 'payload', 'injection_type'
                                (union|error), and 'error_function'
                                (extractvalue|updatexml|floor|exp|
                                gtid_subset, '' for union). Typically
                                produced by csv.DictReader over the output
                                of tools/payload_builder.py.
                                When provided, reset() samples uniformly
                                from this list each episode.
                                When None and base_payloads is also None,
                                falls back to target.base_payload (union).
            strict_markers:     Force strict marker success criterion.
                                Only meaningful for union episodes.
                                When None, auto-enabled iff any specs
                                are provided (those payloads embed
                                SEQSQLI_*).
        """
        super().__init__()
        self.target = target
        self.base_payload_specs: List[Dict] = _coerce_specs(
            base_payloads, base_payload_specs,
        )
        if strict_markers is None:
            self.strict_markers = bool(self.base_payload_specs)
        else:
            self.strict_markers = bool(strict_markers)

        self.action_space = spaces.Discrete(_N_ACTIONS)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(OBS_DIM,),
            dtype=np.float32,
        )

        self._payload          = ""
        self._signal_type      = "union"
        self._error_function   = ""
        self._step_count       = 0
        self._last_action_idx  = -1

    # ------------------------------------------------------------------
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        if self.base_payload_specs:
            spec = random.choice(self.base_payload_specs)
            self._payload        = spec["payload"]
            self._signal_type    = spec.get("injection_type", "union") or "union"
            self._error_function = spec.get("error_function", "") or ""
        else:
            self._payload        = self.target.base_payload
            self._signal_type    = "union"
            self._error_function = ""
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
        result = classify_response(
            resp_text, status,
            signal_type=self._signal_type,
            error_function=self._error_function,
            strict_markers=self.strict_markers,
        )
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
