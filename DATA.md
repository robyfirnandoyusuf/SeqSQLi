# SeqSQLi — Data and Reproducibility Map

This repository contains the source code, mutation operators, payload corpora, and
raw per-payload evaluation logs behind the paper *SeqSQLi: Sequential SQL Injection
WAF Bypass via Deep Reinforcement Learning*. This file maps each data artifact to the
result it supports.

## Payload corpora (Section 3.4)
| File | Description |
|---|---|
| `payloads_union_less1.csv` | 108 validated union-based payloads (36 trivial / 36 medium / 36 complex) with tier, column count and marker metadata. |
| `payloads_error_less1.csv` | 108 validated error-based payloads. |
| `payloads_full_less1.csv`  | Combined corpus. |

Every payload is verified to execute on the unprotected application before any firewall
is introduced (`valid_without_waf` column).

## Multi-seed algorithm comparison — union corpus (Table 2, Figure 4; R1-1)
`eval_{trpo,ppo,a2c}_union_seed{1,2,3}.json` — nine runs (three algorithms × three seeds).
Baseline: `results/fnr0_union_modsec.json`.

## Error corpus, three seeds (Table 4)
`eval_{trpo,ppo,a2c}_error_seed{1,2,3}.json`.

## Cross-paradigm transfer to SafeLine (Table 5, Section 4.4)
`eval_*_union_safeline.json`, `eval_*_error_seed{1,2,3}_safeline.json` (zero-shot transfer)
and `eval_*_safeline_direct_seed{1,2,3}.json` (trained directly against SafeLine).

## Mutation-ordering analysis (Section 4.3, Figure 6)
- Trajectory-level ordering statistics: `ordering_{trpo,ppo,a2c}_less1.0.json`.
- Controlled intervention (R1-5): `results/r1_5_ordering_intervention.json`,
  `results/r1_5_ordering_allswaps.json` — forward vs reversed and all adjacent swaps.

## WAF-rule latency overhead (Section 5, Table B3; R2-11)
`results/r2_11_timing_with_rules.json`, `results/r2_11_timing_without_rules.json`.

## Firewall configuration (Table B2)
`docker-sqlilab/modsecurity/custom-sqli.conf` — the tiered SQL-injection ruleset.
`docker-sqlilab/docker-compose.yml`, `docker-safeline/` — the lab deployment.

## Eval-log schema
Each `eval_*.json` has top-level metrics (`ifnr`, `spbarc`, `waf_evasion_rate`, ...) and a
`per_payload` list; each entry records `payload_id`, `original_payload`, `final_payload`,
`success`, `final_status`, `requests_used`, and the `sequence` of mutation operators applied.

## Training and evaluation
Hyperparameters: `seqsqli/rl/train_{ppo,trpo,a2c}.py`, `seqsqli/config.py` (see Table B1).
Runner used for the multi-seed union experiment: `tools/run_e1_union_multiseed.sh`.
Metrics tool: `tools/evaluate_ifnr_spbarc.py`.
