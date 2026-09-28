#!/usr/bin/env bash
# =============================================================================
# E1 — Multi-seed UNION corpus vs ModSecurity (reviewer R1-1)
# =============================================================================
# Trains TRPO/PPO/A2C fresh with 3 explicit seeds each (9 runs, 150k timesteps),
# then evaluates each model -> eval_{algo}_union_seed{1,2,3}.json.
# Aggregate afterwards with tools/rq1_table.py for mean +/- std + per-tier.
#
# Prereq: ModSecurity lab up on :8080  (docker compose -f docker-sqlilab up -d)
# Interpreter: python3.13 (the one with stable_baselines3 + sb3_contrib)
# Usage: bash tools/run_e1_union_multiseed.sh 2>&1 | tee results/run_e1.log
# =============================================================================
set -uo pipefail

PY=python3.13
URL_BASE="http://localhost:8080"
EVAL_URL="http://localhost:8080/Less-1/"
CORPUS="payloads_union_less1.csv"
TIMESTEPS=150000
FNR0="results/fnr0_union_modsec.json"
ALGOS=(trpo ppo a2c)
SEEDS=(1 2 3)

mkdir -p models results

# --- preflight: lab reachable? -------------------------------------------------
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${URL_BASE}/Less-1/?id=1" || echo 000)
if [ "$code" = "000" ]; then
  echo "[FATAL] ModSec lab not reachable at ${URL_BASE} (curl=$code)."
  echo "        Start it first:  docker compose -f docker-sqlilab/docker-compose.yml up -d"
  exit 1
fi
echo "[OK] ModSec reachable (HTTP $code)"

# --- make env 51-action (paper) by disabling the Safeline-only div_break op ---
# The paper documents 51 operators; div_break (action #52) was added later as a
# Safeline PoC and inflates the union/ModSec action space. Patch it out for the
# duration of E1 and restore mutations.py on ANY exit (trap), so HEAD is never
# left modified. This does NOT touch git.
MUT="seqsqli/core/mutations.py"
cp "$MUT" "${MUT}.e1bak"
restore_mut() { [ -f "${MUT}.e1bak" ] && mv -f "${MUT}.e1bak" "$MUT" && echo "[cleanup] mutations.py restored to 52-action HEAD"; }
trap restore_mut EXIT INT TERM
$PY - <<'PY'
import re
p="seqsqli/core/mutations.py"; s=open(p).read()
s=re.sub(r'\n\s*"div_break":\s*MutationEngine\.div_break,.*', '', s, count=1)
open(p,"w").write(s)
PY
n=$($PY -c "from seqsqli.core.mutations import ACTION_LIST; print(len(ACTION_LIST))")
if [ "$n" != "51" ]; then echo "[FATAL] expected 51 actions after patch, got $n"; exit 1; fi
echo "[OK] env is 51-action (paper-consistent); div_break disabled for E1"

# --- Step 0: baseline FNR0 for the union corpus on this lab -------------------
if [ ! -f "$FNR0" ]; then
  echo "=== Step 0: measuring union FNR0 (method=none) -> $FNR0 ==="
  $PY -m tools.evaluate_ifnr_spbarc --payloads "$CORPUS" \
    --url "$EVAL_URL" --method none \
    --output "$FNR0"
else
  echo "[skip] $FNR0 already exists"
fi

# --- Step 1: train + eval, 3 algos x 3 seeds ---------------------------------
for ALGO in "${ALGOS[@]}"; do
  for S in "${SEEDS[@]}"; do
    MODEL="models/${ALGO}_union_seed${S}"
    EVAL="eval_${ALGO}_union_seed${S}.json"
    TRAINLOG="results/train_${ALGO}_union_seed${S}.txt"

    echo ""
    echo "############################################################"
    echo "# TRAIN  ${ALGO}  seed=${S}  (${TIMESTEPS} steps)"
    echo "############################################################"
    if [ -f "${MODEL}.zip" ]; then
      echo "[skip] ${MODEL}.zip exists — not retraining"
    else
      $PY agent.py --less 1 --base-url "$URL_BASE" --no-fingerprint \
        --algo "$ALGO" --timesteps "$TIMESTEPS" --seed "$S" \
        --payloads-csv "$CORPUS" \
        --save-model "$MODEL" 2>&1 | tee "$TRAINLOG"

      # Preserve per-seed training logs + ordering (agent.py writes the
      # tracked single-seed originals results_/ordering_{algo}_less1.0.json;
      # rename them so seeds don't clobber each other, restore originals at end).
      [ -f "results_${ALGO}_less1.0.json" ]  && mv -f "results_${ALGO}_less1.0.json"  "results_${ALGO}_union_seed${S}.json"
      [ -f "ordering_${ALGO}_less1.0.json" ] && mv -f "ordering_${ALGO}_less1.0.json" "ordering_${ALGO}_union_seed${S}.json"
    fi

    echo ""
    echo "=== EVAL  ${ALGO}  seed=${S}  -> ${EVAL} ==="
    # Deterministic (greedy) eval to match the original Table 2 protocol
    # (eval_{algo}_union.json were deterministic; that is what reproduces 99.1%).
    $PY -m tools.evaluate_ifnr_spbarc --payloads "$CORPUS" \
      --url "$EVAL_URL" --method "$ALGO" \
      --${ALGO}-model "${MODEL}.zip" \
      --fnr0-file "$FNR0" --max-steps 15 \
      --output "$EVAL"
  done
done

# --- restore the committed single-seed originals clobbered during training ---
echo ""
echo "=== restoring committed single-seed originals from git ==="
git checkout -- \
  results_trpo_less1.0.json results_ppo_less1.0.json results_a2c_less1.0.json \
  ordering_trpo_less1.0.json ordering_ppo_less1.0.json ordering_a2c_less1.0.json \
  2>/dev/null && echo "[ok] originals restored" || echo "[warn] git restore skipped (check manually)"

echo ""
echo "############################################################"
echo "# E1 DONE. Aggregate with:"
echo "#   $PY -m tools.rq1_table --csv $CORPUS \\"
echo "#     --runs TRPO:eval_trpo_union_seed1.json TRPO:eval_trpo_union_seed2.json ..."
echo "############################################################"
