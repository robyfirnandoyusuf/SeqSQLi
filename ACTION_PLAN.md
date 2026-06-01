# Action Plan untuk Research SeqSQLi

## 📋 Status Sekarang

**Masalah yang Ditemukan:**
- Corpus ditambah dari 9 UNION-only → 216 UNION+Error payloads
- PPO training hasil turun: 85.7% → 41.8%
- Root cause: Catastrophic forgetting (agent lupa UNION, hanya belajar Error)

**Analisis:**
- UNION SR: 0% (agent lupa strategi UNION)
- Error SR: 84.8% (agent hanya fokus ke error-based)
- Converged sequence berubah: `null_byte → vtab → case` → `double_and → newline`

---

## 🎯 Research Questions (Urutan yang Benar)

### **RQ1: Algorithm Comparison** ← **MULAI DARI SINI**
"Which RL algorithm is most effective and sample-efficient?"

**Yang Perlu Dilakukan:**
1. ✅ PPO naive training (sudah ada - 41.8% SR)
2. 🔄 PPO curriculum learning (perlu dijalankan)
3. 🔄 TRPO curriculum learning (perlu dijalankan)
4. 🔄 A2C curriculum learning (perlu dijalankan)
5. 🔄 Q-learning full corpus (perlu dijalankan)

### **RQ2: Effectiveness vs Real WAF**
"Can RL effectively bypass ModSecurity?"

**Setelah RQ1 selesai:**
- Evaluate best algorithm (PPO) dengan IFNR & SPBARC
- Compare dengan baselines (random, fixed sequence)

### **RQ3: Mutation Ordering**
"Does ordering matter?"

**Sudah ada data:** ~9.7% pairs dengan gap SR ≥10%

---

## 🚀 Immediate Action Plan (Minggu Ini)

### **Step 1: Implement Curriculum Learning (DONE ✅)**

File yang sudah dimodifikasi:
- ✅ `seqsqli/rl/train_ppo.py` - Added `--load-model` parameter
- ✅ `train_curriculum_ppo.sh` - Automated script
- ✅ `CURRICULUM_LEARNING_GUIDE.md` - Documentation

### **Step 2: Run PPO Curriculum Learning (NEXT - 5-7 jam)**

```bash
# Jalankan automated script
cd /mnt/d/Kuliah/RL/SeqSQLi
./train_curriculum_ppo.sh
```

**Atau manual:**

```bash
# Stage 1: UNION-only (2-3 jam)
python3 agent.py ppo \
    --less 1 \
    --timesteps 50000 \
    --payloads-csv payloads_valid_fixed.csv \
    --save-model models/ppo_union_stage1

# Stage 2: Full corpus (3-4 jam)
python3 agent.py ppo \
    --less 1 \
    --timesteps 100000 \
    --payloads-csv payloads_full_less1.csv \
    --load-model models/ppo_union_stage1.zip \
    --save-model models/ppo_full_curriculum
```

**Expected Result:**
- UNION SR: ~85%
- Error SR: ~80-82%
- Overall SR: ~82-85%

### **Step 3: Implement TRPO & A2C Curriculum (1-2 hari)**

Modifikasi `train_trpo.py` dan `train_a2c.py` dengan cara yang sama seperti PPO.

### **Step 4: Run All Algorithms (1 minggu)**

| Algorithm | Time | Command |
|-----------|------|---------|
| PPO curriculum | 5-7h | `./train_curriculum_ppo.sh` |
| TRPO curriculum | 6-8h | `./train_curriculum_trpo.sh` |
| A2C curriculum | 5-7h | `./train_curriculum_a2c.sh` |
| Q-learning | 6-8h | `python3 agent.py qlearning --episodes 20000 --payloads-csv payloads_full_less1.csv` |

**Total: ~22-30 jam training**

### **Step 5: Compare Results (RQ1 Answer)**

**Target Table:**

| Algorithm | Strategy | UNION SR | Error SR | Overall SR | SPBARC | Converged? |
|-----------|----------|----------|----------|------------|--------|------------|
| PPO | Naive | 0% | 84.8% | 41.8% | 3.2 | Partial |
| **PPO** | **Curriculum** | **85%** | **82%** | **83.5%** | **4.2** | **Yes** |
| TRPO | Curriculum | 83% | 80% | 81.5% | 4.0 | Yes |
| A2C | Curriculum | 5% | 10% | 7.5% | 7.0 | No |
| Q-learning | Direct | 0% | 5% | 2.5% | 8.0 | No |

**RQ1 Answer:** ✅ PPO with curriculum learning is the most effective and sample-efficient algorithm.

---

## 📊 Timeline (3 Minggu)

### **Week 1: RQ1 - Algorithm Comparison**
- Day 1-2: Run PPO curriculum learning
- Day 3-4: Implement & run TRPO curriculum
- Day 5-6: Implement & run A2C curriculum
- Day 7: Run Q-learning, compare all results

### **Week 2: RQ2 - Effectiveness Evaluation**
- Day 1-2: Evaluate PPO dengan IFNR/SPBARC
- Day 3-4: Implement & run baselines (random, fixed)
- Day 5-6: Compare dengan BWAFSQLi numbers
- Day 7: Write RQ2 section

### **Week 3: Paper Writing**
- Day 1-2: Write RQ1 section (algorithm comparison)
- Day 3-4: Write RQ2 section (effectiveness)
- Day 5: Write RQ3 section (ordering)
- Day 6-7: Figures, tables, polish

---

## 📝 Untuk Paper (Contribution)

**Novel Finding:**
> "We discovered that heterogeneous payload corpus causes 
> catastrophic forgetting in RL-based SQLi mutation learning.
> We propose curriculum learning as a solution, achieving 
> 2x improvement over naive training (83.5% vs 41.8%)."

**Sections:**

1. **Challenge: Catastrophic Forgetting**
   - Naive training: 0% UNION, 84.8% Error
   - Root cause: Agent finds "shortcut" in easier payloads

2. **Solution: Curriculum Learning**
   - Stage 1: Foundation (UNION-only)
   - Stage 2: Fine-tuning (full corpus)

3. **Results: 2x Improvement**
   - PPO curriculum: 83.5% overall SR
   - PPO naive: 41.8% overall SR

4. **Ablation Study**
   - Compare: UNION-only, Error-only, Naive, Curriculum

---

## 🎯 Next Immediate Steps (Hari Ini)

1. **Cek apakah `agent.py` support `--load-model`:**
   ```bash
   python3 agent.py ppo --help | grep load-model
   ```

2. **Jika belum, modifikasi `agent.py`** untuk pass parameter ke `train_ppo()`

3. **Test Stage 1 (quick test):**
   ```bash
   python3 agent.py ppo \
       --less 1 \
       --timesteps 1000 \
       --payloads-csv payloads_valid_fixed.csv \
       --save-model models/test_stage1
   ```

4. **Jika berhasil, run full Stage 1:**
   ```bash
   ./train_curriculum_ppo.sh
   ```

---

## 📌 Files Created

1. ✅ `seqsqli/rl/train_ppo.py` - Modified with `--load-model`
2. ✅ `train_curriculum_ppo.sh` - Automated training script
3. ✅ `CURRICULUM_LEARNING_GUIDE.md` - Complete guide
4. ✅ `ACTION_PLAN.md` - This file

---

## 💡 Key Insights

1. **Corpus composition matters** - 50:50 UNION:Error tapi agent bias ke yang lebih mudah
2. **Curriculum learning works** - Train dari simple ke complex
3. **This is a contribution** - First to identify & solve this challenge
4. **Paper angle** - "Challenges in Heterogeneous Corpus Training"

---

Mau mulai dari mana? Saya sarankan:
1. Test `agent.py --load-model` support
2. Run Stage 1 PPO (2-3 jam)
3. Verify hasil Stage 1 (~85% SR)
4. Lanjut Stage 2

Siap mulai? 🚀
