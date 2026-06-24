"""
tools/tier_count.py
===================
Pure-file (no network) tier distribution counter for a payload corpus CSV.
Uses csv.DictReader so quoted payloads containing commas parse correctly.

USAGE:
    python3 -m tools.tier_count payloads_error_less1.csv
"""
import csv
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "payloads_error_less1.csv"
rows = list(csv.DictReader(open(path, newline="")))
tiers = Counter(r["tier"] for r in rows)
itypes = Counter(r["injection_type"] for r in rows)
print(f"file: {path}")
print(f"total rows: {len(rows)}")
print("tier:", dict(tiers))
print("injection_type:", dict(itypes))
