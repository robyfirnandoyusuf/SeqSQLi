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
import re
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
    # STAGNANT must be the WORST outcome. If a no-op mutation (-1.5) is
    # cheaper than getting WAF-blocked (-2.0), the policy learns to stop
    # changing the payload and collapses — observed as ~2.9 HTTP req/episode
    # over 15 allowed steps. Making no-ops strictly worse than any real
    # attempt forces the agent to keep mutating.
    "STAGNANT":     -3.0,
}

# ---------------------------------------------------------------------------
# Potential-based reward shaping (Ng et al., 1999)
# ---------------------------------------------------------------------------
# The bypass is reachable but needs a SPECIFIC mutation order (e.g. null_byte
# must precede any space-replacement, else '-- -' becomes '--%0a-' and can no
# longer be stripped — confirmed via tools/probe_bypass.py). Sparse SUCCESS=10
# gives no gradient toward that order. We add F = gamma*phi(s') - phi(s), where
# phi counts how many known ModSec-100010/100023 triggers the payload has shed.
# This is policy-INVARIANT (cannot create reward-hacking): the only terminal
# reward is still strict-marker SUCCESS; phi merely guides exploration and is
# computed from the payload STRING, never from the server response.
PBRS_GAMMA  = 0.99
SHAPE_COEF  = 1.0

# Each pattern, when ABSENT, means one WAF trigger has been removed.
_TRIGGER_COMMENT = re.compile(r'(--|#|/\*)')
_TRIGGER_EXACT_KW = re.compile(r'(union|UNION|Union|select|SELECT|Select)')
_TRIGGER_FUNC_ADJ = re.compile(
    r'(?i)(database|user|version|current_user|session_user|schema)\s*\('
)
# --- Complex/medium-tier triggers (rules 100021 / 100031 / 100030 / 100020) ---
_TRIGGER_GROUP_CONCAT = re.compile(r'(?i)group_concat\s*\(')   # rule 100021
_TRIGGER_HEX          = re.compile(r'0x[0-9a-fA-F]{2,}')        # rule 100031
_TRIGGER_FROM_TABLE   = re.compile(                              # rule 100030
    r'(?i)from\s+(users|accounts|admin|members|password)\b'
)
_TRIGGER_INFO_SCHEMA  = re.compile(r'(?i)information_schema')    # rule 100020


def _waf_readiness(payload: str) -> int:
    """Structural progress score 0-8 (higher = closer to bypass).

    Mirrors the live ModSec rules so each correct mutation raises the score.
    Trivial/T2b triggers (1-4) plus medium/complex triggers (5-8); without the
    latter, the agent gets NO gradient for the extra mutations that complex
    payloads require (agg_swap/hex_to_char/ident_backtick), so it could only
    ever learn the trivial tier. Each trigger maps to a live rule:
      1. no comment/terminator token  (--, #, /*)         -> rule 100010
      2. no literal space or '+'                           -> rule 100010
      3. no exact-case UNION/SELECT token                  -> rule 100010
      4. info-leak func not adjacent to '(' via \\s        -> rule 100023
         (%a0/NBSP is literal text here, not \\s, so database%a0() scores +1)
      5. no group_concat( adjacency                        -> rule 100021
         (cleared by agg_swap -> json_arrayagg)
      6. no 0x.. hex literal                               -> rule 100031
         (cleared by hex_to_char -> CHAR(..))
      7. no bare FROM <known table>                        -> rule 100030
         (cleared by ident_backtick -> FROM `users`)
      8. no exact 'information_schema' literal             -> rule 100020
         (cleared by case/random_case; rule has no lowercase transform)
    """
    score = 0
    if not _TRIGGER_COMMENT.search(payload):
        score += 1
    if ' ' not in payload and '+' not in payload:
        score += 1
    if not _TRIGGER_EXACT_KW.search(payload):
        score += 1
    if not _TRIGGER_FUNC_ADJ.search(payload):
        score += 1
    if not _TRIGGER_GROUP_CONCAT.search(payload):
        score += 1
    if not _TRIGGER_HEX.search(payload):
        score += 1
    if not _TRIGGER_FROM_TABLE.search(payload):
        score += 1
    if not _TRIGGER_INFO_SCHEMA.search(payload):
        score += 1
    return score

# State dim: 14 binary payload features + 1 injection-type bit
#            + 41 last-action one-hot + 1 step_norm
# The injection-type bit makes the task identity (union vs error) observable.
# Without it, a union and an error payload that have had the same mutations
# applied produce identical observations, yet require different optimal
# actions and have different SUCCESS criteria — the policy cannot separate
# them and collapses onto the easier (error) task.
_N_ACTIONS    = len(ACTION_LIST)
_N_FEATURES   = 14
_N_INJECTION  = 1
OBS_DIM       = _N_FEATURES + _N_INJECTION + _N_ACTIONS + 1


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

        # Potential-based shaping: reward shedding WAF triggers (policy-invariant)
        shaping = SHAPE_COEF * (
            PBRS_GAMMA * _waf_readiness(mutated) - _waf_readiness(self._payload)
        )
        reward += shaping

        self._payload         = mutated
        self._step_count     += 1
        self._last_action_idx = action_idx

        terminated = result == "SUCCESS"
        truncated  = self._step_count >= MAX_STEPS

        return self._obs(), reward, terminated, truncated, {"result": result, "payload": mutated}

    # ------------------------------------------------------------------
    def _obs(self) -> np.ndarray:
        features = np.array(extract_features(self._payload), dtype=np.float32)

        injection_bit = np.array(
            [1.0 if self._signal_type == "error" else 0.0], dtype=np.float32
        )

        action_onehot = np.zeros(_N_ACTIONS, dtype=np.float32)
        if self._last_action_idx >= 0:
            action_onehot[self._last_action_idx] = 1.0

        step_norm = np.array([self._step_count / MAX_STEPS], dtype=np.float32)

        return np.concatenate([features, injection_bit, action_onehot, step_norm])

    # ------------------------------------------------------------------
    def get_payload(self) -> str:
        return self._payload
