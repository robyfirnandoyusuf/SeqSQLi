"""
seqsqli/rl/train_ppo.py
========================
PPO training loop using stable-baselines3.
Produces episode logs in the same format as train.py (Q-learning)
so evaluate() and analyze_ordering() can be reused unchanged.
"""

import time
from typing import List

import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

from seqsqli.config import MAX_STEPS, REQUEST_DELAY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.mutations import ACTION_LIST, MUTATIONS
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.rl.env import SeqSQLiEnv


# ---------------------------------------------------------------------------
# PPO hyperparameters
# ---------------------------------------------------------------------------
PPO_TIMESTEPS  = 50_000   # total env steps for training
PPO_LR         = 3e-4
PPO_N_STEPS    = 128      # steps collected per update
PPO_BATCH_SIZE = 64
PPO_N_EPOCHS   = 10
PPO_GAMMA      = 0.99
PPO_CLIP_RANGE = 0.2
PPO_MODEL_PATH = "seqsqli_ppo"


# ---------------------------------------------------------------------------
# Logging callback
# ---------------------------------------------------------------------------

class EpisodeLogCallback(BaseCallback):
    """Collects per-episode stats during PPO training for paper metrics."""

    def __init__(self, verbose=0):
        super().__init__(verbose)
        self.episode_logs: List[dict] = []
        self._ep_steps    = 0
        self._ep_reward   = 0.0
        self._ep_actions: List[str] = []
        self._ep_num      = 0

    def _on_step(self) -> bool:
        info      = self.locals["infos"][0]
        reward    = float(self.locals["rewards"][0])
        done      = bool(self.locals["dones"][0])
        action    = ACTION_LIST[int(self.locals["actions"][0])]
        result    = info.get("result", "UNKNOWN")

        self._ep_steps  += 1
        self._ep_reward += reward
        self._ep_actions.append(action)

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
                "final_payload": "",
            })

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

        return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def train_ppo(target: TargetProfile,
              timesteps: int = PPO_TIMESTEPS,
              save_path: str = PPO_MODEL_PATH) -> List[dict]:
    """Train a PPO agent against target and return episode logs."""

    env = SeqSQLiEnv(target)

    print("=" * 60)
    print(f" SeqSQLi v2 — PPO Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {target.filter_type}")
    print(f" Base payload: {target.base_payload}")
    print(f" Timesteps   : {timesteps}")
    print("=" * 60)

    callback = EpisodeLogCallback(verbose=0)

    model = PPO(
        "MlpPolicy",
        env,
        learning_rate  = PPO_LR,
        n_steps        = PPO_N_STEPS,
        batch_size     = PPO_BATCH_SIZE,
        n_epochs       = PPO_N_EPOCHS,
        gamma          = PPO_GAMMA,
        clip_range     = PPO_CLIP_RANGE,
        verbose        = 0,
        tensorboard_log= "./ppo_tensorboard/",
    )

    model.learn(total_timesteps=timesteps, callback=callback)
    model.save(save_path)
    print(f"[*] PPO model saved: {save_path}.zip")

    return callback.episode_logs


def greedy_eval_ppo(target: TargetProfile,
                    model_path: str = PPO_MODEL_PATH,
                    n_episodes: int = 50) -> List[dict]:
    """Run greedy evaluation using a saved PPO model.

    Returns episode logs compatible with evaluate() and analyze_ordering().
    """
    model = PPO.load(model_path)
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
            "total_reward":  round(total_r, 2),
            "success":       final_result == "SUCCESS",
            "final_result":  final_result,
            "sequence":      sequence,
            "final_payload": env.get_payload(),
        })

    return logs
