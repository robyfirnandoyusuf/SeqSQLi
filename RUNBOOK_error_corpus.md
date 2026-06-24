# RUNBOOK — RQ1 Error Corpus (publication)

> Mirror persis pipeline union kemarin, tapi corpus = `payloads_error_less1.csv`
> (108 payload, tier 36 trivial / 36 medium / 36 complex, semua injection_type=error).
> **Semua command di bawah dijalankan USER di WSL** (Claude tak bisa command HTTP-SQLi).
> Setelah tiap fase, paste output / bilang "selesai" → Claude baca file & analisis.

Naming dibuat sejajar union:
| | union (sudah ada) | error (target) |
|---|---|---|
| model | `models/{algo}_union_stage1.zip` | `models/{algo}_error_stage1.zip` |
| FNR₀ | `results/fnr0_less1.json` | `results/fnr0_error_modsec.json` |
| eval | `eval_{algo}_union.json` | `eval_{algo}_error.json` |

---

## Phase 0 — Pastikan lab ModSec hidup
```bash
cd /mnt/d/Kuliah/RL/SeqSQLi
# normal harus 200
curl -s -o /dev/null -w "normal=%{http_code}\n" "http://localhost:8080/Less-1/?id=1"
```
Kalau bukan 200 → nyalakan dulu container sqli-labs (`docker compose up -d` di folder docker-sqlilab).

---

## Phase 1 — Training 3 model di error corpus (150k timesteps, dari scratch)
> Ini fase paling lama (ribuan request HTTP per model, seperti union dulu).
> Jalankan satu-satu; tiap log disimpan ke `results/`.
>
> PENTING: WAJIB `--base-url http://localhost:8080`. Tanpa ini, `--less 1` nembak ke
> remote default `https://lab.0xffsec.co` (DEFAULT_BASE_URL), bukan lab lokal.
> URL final = `{base_url}/Less-1/` → `http://localhost:8080/Less-1/`.
> `--no-fingerprint` aman karena mode `--payloads-csv` ambil payload awal dari CSV.
> `filter_type` preset (none) TIDAK dipakai PPO/TRPO/A2C — env.py tak baca filter_type.

```bash
# TRPO
python3 agent.py --less 1 --base-url http://localhost:8080 --no-fingerprint \
  --algo trpo --timesteps 150000 \
  --payloads-csv payloads_error_less1.csv \
  --save-model models/trpo_error_stage1 2>&1 | tee results/train_trpo_error.txt

# PPO
python3 agent.py --less 1 --base-url http://localhost:8080 --no-fingerprint \
  --algo ppo --timesteps 150000 \
  --payloads-csv payloads_error_less1.csv \
  --save-model models/ppo_error_stage1 2>&1 | tee results/train_ppo_error.txt

# A2C
python3 agent.py --less 1 --base-url http://localhost:8080 --no-fingerprint \
  --algo a2c --timesteps 150000 \
  --payloads-csv payloads_error_less1.csv \
  --save-model models/a2c_error_stage1 2>&1 | tee results/train_a2c_error.txt
```
Output: `models/{trpo,ppo,a2c}_error_stage1.zip` + log di `results/train_*_error.txt`.

---

## Phase 2 — FNR₀ baseline (error corpus tanpa agent)
```bash
python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
  --url "http://localhost:8080/Less-1/" --method none \
  --output results/fnr0_error_modsec.json
```

---

## Phase 3 — Eval tiap model (error, ModSec)
```bash
# TRPO
python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
  --url "http://localhost:8080/Less-1/" --method trpo \
  --trpo-model models/trpo_error_stage1.zip \
  --fnr0-file results/fnr0_error_modsec.json --stochastic --max-steps 15 \
  --output eval_trpo_error.json

# PPO
python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
  --url "http://localhost:8080/Less-1/" --method ppo \
  --ppo-model models/ppo_error_stage1.zip \
  --fnr0-file results/fnr0_error_modsec.json --stochastic --max-steps 15 \
  --output eval_ppo_error.json

# A2C
python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
  --url "http://localhost:8080/Less-1/" --method a2c \
  --a2c-model models/a2c_error_stage1.zip \
  --fnr0-file results/fnr0_error_modsec.json --stochastic --max-steps 15 \
  --output eval_a2c_error.json
```
Output: `eval_{trpo,ppo,a2c}_error.json`.

---

## Phase 4 — (CLAUDE, no-HTTP) breakdown per tier + tabel
Setelah Phase 3 selesai, Claude jalankan:
```bash
python3 -m tools.breakdown_by_tier eval_trpo_error.json --csv payloads_error_less1.csv
python3 -m tools.rq1_table --csv payloads_error_less1.csv \
  --runs PPO:eval_ppo_error.json TRPO:eval_trpo_error.json A2C:eval_a2c_error.json
```
→ menghasilkan tabel IFNR/SPBARC + SR per tier (trivial/medium/complex), sama format RQ1 union.

---

## Phase 5 — RQ2 Safeline transfer (ZERO-SHOT, ModSec→Safeline)
> Ambil model yang DILATIH di ModSec, eval langsung ke Safeline (port 8888) TANPA retrain.
> Transferability gap = IFNR(ModSec) − IFNR(Safeline).
> Sejajar pelaporan RQ1: union = single-run, error = multi-seed (3 seed).

### Phase 5.0 — Pastikan Safeline + upstream hidup
```bash
# Safeline serve di 8888; upstream sqli-labs harus hidup juga (Safeline proxy ke 8081)
curl -s -o /dev/null -w "normal=%{http_code}\n" "http://localhost:8888/Less-1/?id=1"   # harus 200
```
Kalau bukan 200 → nyalakan stack Safeline (`docker-safeline/`) + sqli-labs upstream dulu.

### Phase 5.1 — FNR₀ Safeline (2 baseline: union + error)
```bash
python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_union_less1.csv \
  --url "http://localhost:8888/Less-1/" --method none \
  --output results/fnr0_union_safeline.json

python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
  --url "http://localhost:8888/Less-1/" --method none \
  --output results/fnr0_error_safeline.json
```

### Phase 5.2 — Transfer UNION (model union_stage1 → Safeline, 3 eval)
```bash
for ALGO in trpo ppo a2c; do
  python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_union_less1.csv \
    --url "http://localhost:8888/Less-1/" --method $ALGO \
    --${ALGO}-model models/${ALGO}_union_stage1.zip \
    --fnr0-file results/fnr0_union_safeline.json --stochastic --max-steps 15 \
    --output eval_${ALGO}_union_safeline.json
done
```

### Phase 5.3 — Transfer ERROR (model error multi-seed → Safeline, 9 eval)
```bash
for ALGO in trpo ppo a2c; do
  for S in 1 2 3; do
    python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
      --url "http://localhost:8888/Less-1/" --method $ALGO \
      --${ALGO}-model models/${ALGO}_error_seed$S.zip \
      --fnr0-file results/fnr0_error_safeline.json --stochastic --max-steps 15 \
      --output eval_${ALGO}_error_seed${S}_safeline.json
  done
done
```
Lalu CLAUDE agregasi → tabel transferability gap (ModSec vs Safeline) untuk union & error.

---

## Phase 6 — Multi-seed A2C (buktikan collapse konsisten, bukan sial seed)
> A2C high-variance → 1 seed 0% rawan digugat reviewer. Latih 3 seed eksplisit + eval.
> `--seed` sudah didukung agent.py (diteruskan ke konstruktor A2C: semai python/numpy/torch+env).
> eval pakai FNR₀ yang sama (`results/fnr0_error_modsec.json`), eval seed dibiarkan default
> agar yang divariasikan murni seed TRAINING.

```bash
for S in 1 2 3; do
  python3 agent.py --less 1 --base-url http://localhost:8080 --no-fingerprint \
    --algo a2c --timesteps 150000 --seed $S \
    --payloads-csv payloads_error_less1.csv \
    --save-model models/a2c_error_seed$S 2>&1 | tee results/train_a2c_error_seed$S.txt

  python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
    --url "http://localhost:8080/Less-1/" --method a2c \
    --a2c-model models/a2c_error_seed$S.zip \
    --fnr0-file results/fnr0_error_modsec.json --stochastic --max-steps 15 \
    --output eval_a2c_error_seed$S.json
done
```
Output: `models/a2c_error_seed{1,2,3}.zip`, `eval_a2c_error_seed{1,2,3}.json`.
Lalu CLAUDE agregasi: IFNR per seed + mean±std + per-tier → buktikan collapse konsisten.

## Phase 7 — Multi-seed TRPO + PPO (buktikan MEREKA low-variance)
> A2C terbukti high-variance (0–30.6% antar seed). Untuk kontras kuat "TRPO/PPO stabil",
> jalankan keduanya 3 seed juga → tabel mean±std lengkap 3 algo.
> `--seed` kini didukung train_trpo & train_ppo (diteruskan ke konstruktor SB3).

```bash
for ALGO in trpo ppo; do
  for S in 1 2 3; do
    python3 agent.py --less 1 --base-url http://localhost:8080 --no-fingerprint \
      --algo $ALGO --timesteps 150000 --seed $S \
      --payloads-csv payloads_error_less1.csv \
      --save-model models/${ALGO}_error_seed$S 2>&1 | tee results/train_${ALGO}_error_seed$S.txt

    python3 -m tools.evaluate_ifnr_spbarc --payloads payloads_error_less1.csv \
      --url "http://localhost:8080/Less-1/" --method $ALGO \
      --${ALGO}-model models/${ALGO}_error_seed$S.zip \
      --fnr0-file results/fnr0_error_modsec.json --stochastic --max-steps 15 \
      --output eval_${ALGO}_error_seed$S.json
  done
done
```
Output: `models/{trpo,ppo}_error_seed{1,2,3}.zip`, `eval_{trpo,ppo}_error_seed{1,2,3}.json`.
Lalu CLAUDE agregasi mean±std untuk 3 algo → tabel RQ1-error final reviewer-proof.

**Hasil A2C multi-seed (sudah ada):** IFNR per seed 5.6 / 30.6 / 30.6% → 22.3% ± 14.4%.

---

### Checklist progress
- [ ] Phase 0 lab up
- [ ] Phase 1 train trpo / ppo / a2c
- [ ] Phase 2 FNR₀ error
- [ ] Phase 3 eval trpo / ppo / a2c
- [ ] Phase 4 tabel (Claude)
- [ ] Phase 5 Safeline error (opsional)
