"""
seqsqli/rl/train_a2c.py
========================
A2C training loop using stable-baselines3.
Produces episode logs in the same format as train.py (Q-learning),
train_ppo.py, and train_trpo.py so evaluate() and analyze_ordering()
can be reused unchanged.

A2C is the synchronous variant of A3C (Mnih et al., 2016). We use A2C
instead of A3C because asynchronous parallel workers would issue concurrent
HTTP requests to the target WAF, introducing rate-limiting and stateful
WAF artifacts that confound the reward signal.
"""

import csv
import time
from typing import Dict, List, Optional

import numpy as np
from stable_baselines3 import A2C
from stable_baselines3.common.callbacks import BaseCallback

from seqsqli.config import MAX_STEPS, REQUEST_DELAY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.mutations import ACTION_LIST, MUTATIONS
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.rl.env import SeqSQLiEnv
# Single source of truth for the CSV loader — reuses train_ppo's
# dict-returning load_payloads_csv so all trainers share the same schema.
from seqsqli.rl.train_ppo import load_payloads_csv


# ---------------------------------------------------------------------------
# A2C hyperparameters
# ---------------------------------------------------------------------------
# Chosen to mirror PPO/TRPO setup where possible for apples-to-apples RQ1.
# A2C's defining feature is short rollout (n_steps=5) + per-rollout update
# without epoching (vs PPO which does multiple epochs per rollout).
A2C_TIMESTEPS   = 50_000
A2C_LR          = 7e-4       # default A2C LR (higher than PPO's 3e-4)
A2C_N_STEPS     = 5          # short rollout — defining feature of A2C
A2C_GAMMA       = 0.99
A2C_GAE_LAMBDA  = 1.0        # A2C default: no GAE smoothing
A2C_ENT_COEF    = 0.0        # entropy bonus coefficient
A2C_VF_COEF     = 0.5        # value-function loss coefficient
A2C_MAX_GRAD_NORM = 0.5
A2C_MODEL_PATH  = "seqsqli_a2c"


# ---------------------------------------------------------------------------
# Logging callback (identical schema to PPO/TRPO)
# ---------------------------------------------------------------------------

class EpisodeLogCallback(BaseCallback):
    """Collects per-episode stats during A2C training for paper metrics."""

    def __init__(self, verbose=0):
        super().__init__(verbose)
        self.episode_logs: List[dict] = []
        self._ep_steps    = 0
        self._ep_reward   = 0.0
        self._ep_actions: List[str] = []
        self._ep_payload  = ""
        self._ep_num      = 0
        self._best_steps  = None

    def _on_step(self) -> bool:
        info      = self.locals["infos"][0]
        reward    = float(self.locals["rewards"][0])
        done      = bool(self.locals["dones"][0])
        action    = ACTION_LIST[int(self.locals["actions"][0])]
        result    = info.get("result", "UNKNOWN")
        payload   = info.get("payload", "")

        self._ep_steps  += 1
        self._ep_reward += reward
        self._ep_actions.append(action)
        if payload:
            self._ep_payload = payload

        if done:
            success = result == "SUCCESS"
            self._ep_num += 1
            self.episode_logs.append({
                "episode":      int(self._ep_num),
                "steps":        int(self._ep_steps),
                "total_reward": round(float(self._ep_reward), 2),
                "success":      bool(success),
                "final_result": str(result),
                "sequence":     list(self._ep_actions),
                "final_payload": self._ep_payload[:150],
            })

            if success:
                is_new_best = self._best_steps is None or self._ep_steps < self._best_steps
                marker = "  *** NEW SHORTEST ***" if is_new_best else ""
                if is_new_best:
                    self._best_steps = self._ep_steps
                print(f"  [BYPASS] Ep {self._ep_num:>4} | steps={self._ep_steps} | "
                      f"seq={' -> '.join(self._ep_actions)}")
                print(f"           payload: {self._ep_payload[:150]}{marker}")

            if self._ep_num % 10 == 0:
                recent = self.episode_logs[-10:]
                sr     = sum(1 for e in recent if e["success"]) / 10 * 100
                avg_s  = sum(e["steps"] for e in recent) / 10
                avg_r  = sum(e["total_reward"] for e in recent) / 10
                print(f"  Ep {self._ep_num:>4} | "
                      f"SR={sr:.0f}% | Steps={avg_s:.1f} | R={avg_r:.2f}")

            self._ep_steps   = 0
            self._ep_reward  = 0.0
            self._ep_actions = []
            self._ep_payload = ""

        return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def train_a2c(target: TargetProfile,
              timesteps: int = A2C_TIMESTEPS,
              save_path: str = A2C_MODEL_PATH,
              payloads_csv: Optional[str] = None) -> List[dict]:
    """Train an A2C agent against target and return episode logs.

    Same calling convention as train_ppo()/train_trpo() so agent.py can swap freely.
    """

    base_payload_specs: Optional[List[Dict]] = None
    if payloads_csv:
        base_payload_specs = load_payloads_csv(payloads_csv)
        if not base_payload_specs:
            raise ValueError(f"No payloads loaded from {payloads_csv}")

    env = SeqSQLiEnv(target, base_payload_specs=base_payload_specs)

    print("=" * 60)
    print(f" SeqSQLi v2 — A2C Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {target.filter_type}")
    if base_payload_specs:
        n_union = sum(1 for s in base_payload_specs if s["injection_type"] == "union")
        n_error = sum(1 for s in base_payload_specs if s["injection_type"] == "error")
        print(f" Mode        : online-WAF (dual-signal: union+error)")
        print(f" Payload pool: {len(base_payload_specs)} validated from {payloads_csv}")
        print(f"               (union={n_union}, error={n_error})")
    else:
        print(f" Base payload: {target.base_payload}")
    print(f" Timesteps   : {timesteps}")
    print(f" Rollout     : n_steps={A2C_N_STEPS} (synchronous A3C variant)")
    print("=" * 60)

    callback = EpisodeLogCallback(verbose=0)

    model = A2C(
        "MlpPolicy",
        env,
        learning_rate = A2C_LR,
        n_steps       = A2C_N_STEPS,
        gamma         = A2C_GAMMA,
        gae_lambda    = A2C_GAE_LAMBDA,
        ent_coef      = A2C_ENT_COEF,
        vf_coef       = A2C_VF_COEF,
        max_grad_norm = A2C_MAX_GRAD_NORM,
        verbose       = 0,
        tensorboard_log = "./a2c_tensorboard/",
    )

    model.learn(total_timesteps=timesteps, callback=callback)
    model.save(save_path)
    print(f"[*] A2C model saved: {save_path}.zip")

    return callback.episode_logs


def greedy_eval_a2c(target: TargetProfile,
                    model_path: str = A2C_MODEL_PATH,
                    n_episodes: int = 50) -> List[dict]:
    """Run greedy evaluation using a saved A2C model.

    Returns episode logs compatible with evaluate() and analyze_ordering().
    """
    model = A2C.load(model_path)
    env   = SeqSQLiEnv(target)
    logs: List[dict] = []

    for ep in range(n_episodes):
        obs, _ = env.reset()
        done      = False
        truncated = False
        steps     = 0
        total_r   = 0.0
        sequence: List[str] = []
        final_result = "UNKNOWN"

        while not done and not truncated:
            action_arr, _ = model.predict(obs, deterministic=True)
            action_idx    = int(action_arr)
            obs, reward, done, truncated, info = env.step(action_idx)

            steps        += 1
            total_r      += reward
            sequence.append(ACTION_LIST[action_idx])
            final_result  = info.get("result", "UNKNOWN")
            time.sleep(REQUEST_DELAY)

        logs.append({
            "episode":       ep + 1,
            "steps":         steps,
            "total_reward":  round(float(total_r), 2),
            "success":       final_result == "SUCCESS",
            "final_result":  final_result,
            "sequence":      sequence,
            "final_payload": env.get_payload(),
        })

    return logs
