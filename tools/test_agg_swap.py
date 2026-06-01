"""
tools/test_agg_swap.py
======================
Pure unit test (NO network) for the agg_swap mutation. Verifies the
GROUP_CONCAT -> JSON_ARRAYAGG(CONCAT(...)) rewrite across all corpus shapes.

USAGE:
    python3 -m tools.test_agg_swap
"""
from seqsqli.core.mutations import MUTATIONS

f = MUTATIONS["agg_swap"]

TESTS = [
    ("A single-arg",  "GROUP_CONCAT(table_name)"),
    ("B multi-arg",   "GROUP_CONCAT(table_schema,0x2e,table_name)"),
    ("C from-users",  "GROUP_CONCAT(username,0x3a,password)"),
    ("D DISTINCT",    "GROUP_CONCAT(DISTINCT table_name)"),
    ("E nested CHAR", "GROUP_CONCAT(a,CHAR(46),b)"),
    ("F no-op",       "database()"),
    ("G case-applied","grOuP_cOnCaT(taBLe_name)"),
    ("H outer concat","CONCAT(0x7c,GROUP_CONCAT(DISTINCT table_name),0x7c)"),
]


def main():
    print("action count:", len(MUTATIONS))
    print("agg_swap registered:", "agg_swap" in MUTATIONS)
    print()
    for label, inp in TESTS:
        out = f(inp)
        print(f"{label:16} {inp}")
        print(f"{'':16} -> {out}")
        print()


if __name__ == "__main__":
    main()
