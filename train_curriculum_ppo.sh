#!/bin/bash
# Curriculum Learning for PPO
# Stage 1: Train on UNION-only (9 payloads)
# Stage 2: Fine-tune on full corpus (216 payloads)

set -e

echo "=========================================="
echo "  PPO Curriculum Learning"
echo "=========================================="
echo ""

# Stage 1: UNION-only
echo "[Stage 1] Training on UNION-only corpus (9 payloads)..."
echo "Expected: ~85% success rate on UNION payloads"
echo ""

python3 -u agent.py ppo \
    --less 1 \
    --timesteps 50000 \
    --payloads-csv payloads_valid_fixed.csv \
    --save-model models/ppo_union_stage1 \
    2>&1 | tee result-ppo-stage1-union.txt

echo ""
echo "[Stage 1] Complete! Model saved to models/ppo_union_stage1.zip"
echo ""
echo "Checking Stage 1 results..."
tail -50 result-ppo-stage1-union.txt | grep -E "Success|SR|IFNR" || echo "Check result-ppo-stage1-union.txt for details"

echo ""
echo "=========================================="
read -p "Press Enter to continue to Stage 2 (or Ctrl+C to stop)..."
echo "=========================================="
echo ""

# Stage 2: Full corpus with curriculum learning
echo "[Stage 2] Fine-tuning on full corpus (216 payloads)..."
echo "Expected: ~82-85% success rate on both UNION and Error payloads"
echo ""

python3 -u agent.py ppo \
    --less 1 \
    --timesteps 100000 \
    --payloads-csv payloads_full_less1.csv \
    --load-model models/ppo_union_stage1.zip \
    --save-model models/ppo_full_curriculum \
    2>&1 | tee result-ppo-stage2-full.txt

echo ""
echo "[Stage 2] Complete! Model saved to models/ppo_full_curriculum.zip"
echo ""
echo "=========================================="
echo "  Curriculum Learning Complete!"
echo "=========================================="
echo ""
echo "Results:"
echo "  Stage 1: result-ppo-stage1-union.txt"
echo "  Stage 2: result-ppo-stage2-full.txt"
echo ""
echo "Next steps:"
echo "  1. Evaluate final model: python3 tools/evaluate_ifnr_spbarc.py"
echo "  2. Compare with naive training (results_ppo_less1.0.json)"
echo "  3. Repeat for TRPO and A2C"
echo ""
