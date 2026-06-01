"""
tools/analyze_complex_blockers.py
=================================
Petakan trigger WAF apa saja yang dikandung payload medium+complex di
payloads_union_less1.csv. Tujuannya: sebelum nulis mutasi substitusi fungsi,
tahu dulu APAKAH group_concat satu-satunya blocker, atau ada CONCAT/hex/dll.

USAGE:
    python3 -m tools.analyze_complex_blockers
"""
import csv
import re
from collections import Counter


def main():
    rows = list(csv.DictReader(open("payloads_union_less1.csv")))
    cat = Counter()
    examples = {}
    by_tier = Counter()

    for r in rows:
        tier = r["tier"]
        by_tier[tier] += 1
        if tier == "trivial":
            continue
        p = r["payload"]
        pl = p.lower()
        tags = []
        if "group_concat" in pl:
            tags.append("group_concat")
        if "concat(" in pl and "group_concat" not in pl:
            tags.append("concat")
        if re.search(r"0x[0-9a-f]{2,}", pl):
            tags.append("hex0x")
        if "information_schema" in pl:
            tags.append("info_schema")
        key = tuple(tags) if tags else ("(none)",)
        cat[key] += 1
        examples.setdefault(key, p)

    print("=== Jumlah per tier ===")
    for t, n in by_tier.items():
        print(f"  {t:<8}: {n}")

    print("\n=== Distribusi trigger di payload medium+complex ===")
    for k, v in cat.most_common():
        print(f"  {v:>3}x  triggers = {'+'.join(k)}")
        print(f"         ex: {examples[k][:120]}")


if __name__ == "__main__":
    main()
