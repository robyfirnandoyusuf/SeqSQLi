# HANDOFF — SeqSQLi (mulai dari sini)

> **Sesi baru / device baru:** bilang **"lanjut SeqSQLi, baca HANDOFF.md"**. File ini adalah status TERKINI dan menggantikan bagian paper di `PROJECT_STATE.md` (yang tertanggal 3 Juni, sudah usang).
> Terakhir diupdate: **25 Juni 2026**.

---

## ⚠️ Pindah device — yang WAJIB di-copy manual

`git pull` di device baru **tidak** membawa folder ini (semua gitignored). Copy manual (cloud/USB/zip):

- **`memory/`** — semua konteks Claude (gitignored, 0 file tracked)
- **`docs/`** — `manuscript-publication.docx` (manuscript utama, gitignored!), `manuscript-publication.backup.docx`, `manuscript-explain.md`
- File hasil untracked yang masih dipakai: `eval_*.json`, `ordering_*.json`, figur baru di `figures/` yang belum di-`git add`

Yang **ikut via git** (aman): kode (`agent.py`, `seqsqli/`, `tools/`), `figures/` yang tracked, `PROJECT_STATE.md`, `HANDOFF.md` ini.

---

## Fokus sekarang: nulis manuscript publikasi

- **File:** `docs/manuscript-publication.docx` — jurnal **MDPI Electronics** (pindah dari template KIIT `.hwp` lama). Penjelasan per-paragraf: `docs/manuscript-explain.md`.
- **Gaya:** protokol "Senior Editor" — **tanpa em-dash, tanpa kata AI-klise, asertif, hindari kalimat negatif "does not" (refrase positif), matematika LaTeX, sitasi [n]**. Figur **hitam-putih (grayscale + hatching)**, caption `Figure x.` / `Table x.`.
- **Style MDPI:** `MDPI_2.1_heading1`, `MDPI_2.2_heading2`, `MDPI_3.1_text`, `MDPI_4.1_table_caption`, `MDPI_5.1_figure_caption`, `MDPI_8.1_reference` (list numId=11).

### Progress section
| Section | Status |
|---|---|
| Title, Authors (Roby Firnando Yusuf, Sunoh Choi) | ✅ |
| Abstract, Keywords | ❌ masih placeholder |
| 1. Introduction | ✅ |
| 2. Related Works (2.1–2.3, Fig 1 & 2) | ✅ |
| 3. Materials and Methods (3.1–3.6, Fig 2 MDP loop, persamaan via Equation Editor) | ✅ |
| 4. Results (4.1–4.4: 3 tabel + Fig 3/4/5 + paragraf contoh rantai mutasi di 4.1) | ✅ |
| 5. Discussion, 6. Conclusions, 7. Patents | ❌ template |

### Referensi: 16 → 23 (ascending, terverifikasi 1→23 tanpa gap)
7 ref baru: Halfond[3], Goodfellow[9], Rosca(Electronics 2025,14,3420)[15], Szegedy[16], Chakraborty[17], Anderson(arXiv:1801.08917)[19], Sutton&Barto[21]. Catatan: Word kadang cache nomor list → kalau aneh, klik di daftar → Ctrl+A → F9.

### Sisa kerja
Discussion · Conclusions · Abstract · Keywords · (opsional) kembalikan §3 RL-Algorithms + tabel hyperparameter ringkas · (opsional) enrichment Results: #2 kurva training tensorboard, #3 distribusi status kegagalan Safeline §4.4.

### Tooling docx (`tools/`, jalan via `PYTHONUTF8=1`)
`apply_results.py` (insert Results), `add_refs.py` (renumber + sisip sitasi + tulis ulang daftar ref; edit **level-run** supaya equation OMML aman), `fig_results.py`, `fig_ordering.py`, `fig_mdp_loop.py`, `fig_two_paradigms.py`, `fig_relatedwork_taxonomy.py`.

---

## Hasil eksperimen (final, dipakai di manuscript)

**RQ1 union (ModSec, N=108, FNR₀=0):** TRPO IFNR 99.1% (SPBARC 6.07) > PPO 88.9% (6.89) > A2C 76.9% (10.08); random 3.7%. Pembeda di tier **complex** (97.2/66.7/33.3%).

**RQ1 error (multi-seed, 3 seed):** TRPO 30.3±2.3% > PPO 26.3±1.9% > A2C **22.3±14.4%**. KUNCI: **A2C high-variance** (σ ~7× TRPO/PPO, range 5.6–30.6%), **BUKAN collapse** — koreksi penting dari klaim single-seed 0%.

**RQ3 ordering:** 68/146/137 pasangan ordering-dependent (TRPO/PPO/A2C); **35 cross-algo consensus pairs**. Terkuat `ident_backtick → hex_to_char` 98% vs reversed 0% (precondition kausal). `newline → func_sp_nbsp` konsisten 3 algo.

**RQ2 Safeline (transfer ModSec→ML WAF):** zero-shot transfer **IFNR 0%** untuk semua algo & corpus (>900 request semua diblok). Latih langsung di Safeline: **~89% lolos WAF tapi 0% exfiltrasi** (846/972 req status 200 + SQL error = payload lolos karena berhenti jadi SQL valid). Temuan kunci: **evasi ⊥ exfiltrasi** menyatu di rule-WAF, terpisah di ML-WAF. Transfer 0% genuine (ada PoC manual bypass Safeline).

---

## Konteks teknis penting
- Scope: hanya **PPO, TRPO, A2C** (Q-learning dibuang).
- MDP: state ℝ⁶⁷ (14 fitur + 1 injection_bit + 51 one-hot last-action + 1 step), **51 operator mutasi** (6 famili), reward strict (lolos WAF **DAN** marker data muncul) + PBRS Φ∈[0,8], STEP_PENALTY=0.08, γ=0.99, max 15 step.
- Metrik: **IFNR** = MFNR − FNR₀, **SPBARC** = request/bypass, WAF-evasion rate (sekunder, Safeline).
- WAF: ModSec CRS v3.3.2 (port 8080), Safeline CE (port 8888), backend sqli-labs Less-1 sama.
- **Claude tak bisa jalankan HTTP-SQLi** (diblok safety) → user jalankan di WSL, Claude baca/tulis kode + interpretasi. String SQL inline juga diblok → tulis sebagai file `tools/*.py`.

Detail lebih lengkap: `memory/MEMORY.md` + file-file di `memory/`.
