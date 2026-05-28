"""
tools/sqlmap_to_csv.py
======================
Parse sqlmap verbose output into a SeqSQLi-compatible payload CSV.

Scope: extract UNION-based and error-based payloads only. Time-based and
boolean-blind are intentionally skipped (out of current research scope).

UNION payloads are REWRITTEN to embed SeqSQLi markers
(SEQSQLI_START / SEQSQLI_END) so the existing marker-based success
criterion in seqsqli/core/response.py continues to work unchanged.

Error-based payloads are kept verbatim — success will be detected via
SQL error indicators in the response (handled in a later refactor of
classify_response).

WORKFLOW
--------
Phase 1: run sqlmap against the WAF-disabled lab and save its output.

    sqlmap -u "http://lab.0xffsec.co/Less-1/?id=1" \
           --level=5 --risk=3 -v 3 --batch \
           > sqlmap_less1.log

Phase 2: feed the log into this adapter.

    python -m tools.sqlmap_to_csv \
        --sqlmap-log sqlmap_less1.log \
        --param id \
        --output payloads_sqlmap_less1.csv

The output CSV uses the same schema as tools/payload_builder.py so it
plugs straight into the existing trainers and evaluator.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from typing import List, Optional


# Same fieldnames as tools/payload_builder.py — one schema across the project.
FIELDNAMES = [
    "payload_id", "payload", "injection_type", "tier",
    "context", "columns", "comment_style",
    "marker_column_left", "marker_column_right",
    "extraction_expr", "union_keyword", "error_function",
    "valid_without_waf", "status_code", "response_len", "notes",
]


# Map sqlmap "Type:" strings to our injection_type taxonomy.
# Anything not listed is skipped.
def _classify_type(type_line: str) -> str:
    t = type_line.lower()
    if "union query" in t:
        return "union"
    if "error-based" in t:
        return "error"
    return ""  # skip boolean-blind, time-based, stacked queries, etc.


# Map sqlmap comment suffix to our comment_style taxonomy.
def _detect_comment_style(payload: str) -> str:
    if payload.rstrip().endswith("--+"):
        return "dashplus"
    if payload.rstrip().endswith("#"):
        return "hash"
    if re.search(r"--\s*-?\s*$", payload):
        return "dash"
    return ""


# Detect injection context from the payload prefix.
def _detect_context(payload: str) -> str:
    # sqlmap prefix typically: "<num>" or "<num>'" or "<num>\""
    if re.match(r"^-?\d+'\)\)", payload):
        return "paren2_single"
    if re.match(r"^-?\d+'\)", payload):
        return "paren_single"
    if re.match(r"^-?\d+\"\)", payload):
        return "paren_double"
    if re.match(r"^-?\d+'", payload):
        return "single_quote"
    if re.match(r"^-?\d+\"", payload):
        return "double_quote"
    if re.match(r"^-?\d+\s", payload):
        return "numeric"
    return ""


@dataclass
class Injection:
    inj_type: str   # "union" | "error"
    title:    str
    payload:  str   # full payload value (already stripped of "param=")


# ---------------------------------------------------------------------------
# Sqlmap log parsing
# ---------------------------------------------------------------------------

_BLOCK_RE = re.compile(
    r"Type:\s*([^\n\r]+)\s*\n"
    r"\s*Title:\s*([^\n\r]+)\s*\n"
    r"\s*Payload:\s*([^\n\r]+)",
)


def parse_sqlmap_log(text: str, param: str) -> List[Injection]:
    """Walk every 'Type/Title/Payload' triplet, keep union & error only."""
    out: List[Injection] = []
    prefix = f"{param}="
    for m in _BLOCK_RE.finditer(text):
        inj_type = _classify_type(m.group(1))
        if not inj_type:
            continue
        title   = m.group(2).strip()
        payload = m.group(3).strip()
        if payload.startswith(prefix):
            payload = payload[len(prefix):]
        out.append(Injection(inj_type=inj_type, title=title, payload=payload))
    return out


# ---------------------------------------------------------------------------
# UNION payload rewriting (Strategy A — embed SEQSQLi markers)
# ---------------------------------------------------------------------------

def _build_marker_col_list(n_cols: int, extraction: str = "database()") -> str:
    """Layout: col1=extraction, col2='SEQSQLI_START', colN='SEQSQLI_END', rest=NULL.
    Matches the convention used by payload_builder.py / payloads_valid_fixed.csv."""
    if n_cols < 2:
        raise ValueError("UNION marker rewrite needs >= 2 columns")
    if n_cols == 2:
        return "'SEQSQLI_START','SEQSQLI_END'"
    parts: List[str] = []
    for c in range(1, n_cols + 1):
        if c == 1:
            parts.append(extraction)
        elif c == 2:
            parts.append("'SEQSQLI_START'")
        elif c == n_cols:
            parts.append("'SEQSQLI_END'")
        else:
            parts.append("NULL")
    return ",".join(parts)


def _extract_column_count(title: str) -> Optional[int]:
    m = re.search(r"(\d+)\s+columns?", title, re.IGNORECASE)
    return int(m.group(1)) if m else None


_UNION_SPLIT_RE = re.compile(
    r"\bUNION\s+(?:ALL\s+)?SELECT\s+",
    re.IGNORECASE,
)
_COMMENT_TAIL_RE = re.compile(
    r"(\s*(?:--\s*-?|--\+|#)\s*)$",
)


def rewrite_union_payload(payload: str, n_cols: int,
                          extraction: str = "database()") -> Optional[str]:
    """Replace sqlmap's NULL/CONCAT column list with our marker layout.

    Returns the rewritten payload, or None if the structure can't be parsed
    (caller should fall back to keeping the raw payload + a warning).
    """
    m = _UNION_SPLIT_RE.search(payload)
    if not m:
        return None
    prefix    = payload[:m.end()]    # "...UNION SELECT " inclusive
    remainder = payload[m.end():]

    tail = _COMMENT_TAIL_RE.search(remainder)
    if tail:
        # Drop sqlmap's column list, keep its comment suffix.
        suffix = tail.group(1)
    else:
        suffix = " -- -"             # fallback: ensure trailing comment

    new_cols = _build_marker_col_list(n_cols, extraction)
    return f"{prefix}{new_cols}{suffix}"


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------

def injection_to_row(inj: Injection, idx: int,
                     extraction: str = "database()") -> dict:
    """Convert one Injection into a CSV row dict."""
    row = {k: "" for k in FIELDNAMES}
    row["payload_id"]        = f"sqlmap_{idx:04d}"
    row["injection_type"]    = inj.inj_type
    row["tier"]              = "trivial"  # sqlmap default = single built-in
    row["valid_without_waf"] = "yes"  # sqlmap already confirmed this works
    row["notes"]             = f"sqlmap:{inj.title}"

    if inj.inj_type == "union":
        n_cols = _extract_column_count(inj.title)
        if n_cols is None:
            # Can't rewrite without column count — skip rewrite, flag in notes.
            row["payload"] = inj.payload
            row["notes"]  += " | WARN:no_column_count_in_title"
        else:
            rewritten = rewrite_union_payload(inj.payload, n_cols, extraction)
            if rewritten is None:
                row["payload"] = inj.payload
                row["notes"]  += " | WARN:union_rewrite_failed"
            else:
                row["payload"]             = rewritten
                row["columns"]             = str(n_cols)
                row["marker_column_left"]  = "1" if n_cols == 2 else "2"
                row["marker_column_right"] = str(n_cols)
                row["extraction_expr"]     = "" if n_cols == 2 else extraction
        row["context"]       = _detect_context(inj.payload)
        row["comment_style"] = _detect_comment_style(row["payload"] or inj.payload)
    else:
        # error-based — keep payload verbatim, no marker rewrite.
        row["payload"]       = inj.payload
        row["context"]       = _detect_context(inj.payload)
        row["comment_style"] = _detect_comment_style(inj.payload)

    return row


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

def write_csv(path: str, rows: List[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Parse sqlmap -v 3 output into a SeqSQLi payload CSV "
                    "(union + error only). UNION payloads are rewritten to "
                    "embed SEQSQLI_START / SEQSQLI_END markers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--sqlmap-log", required=True,
                   help="Path to a file containing sqlmap's verbose stdout output.")
    p.add_argument("--param", default="id",
                   help="Parameter name sqlmap targeted (default: id). "
                        "Used to strip 'param=' prefix from sqlmap's payload lines.")
    p.add_argument("--extraction", default="database()",
                   help="Extraction expression to inject in UNION column 1 "
                        "(default: database()). Use e.g. user() or version().")
    p.add_argument("--output", default="payloads_sqlmap.csv",
                   help="Output CSV path.")
    args = p.parse_args()

    try:
        with open(args.sqlmap_log, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.sqlmap_log}", file=sys.stderr)
        sys.exit(2)

    injections = parse_sqlmap_log(text, args.param)
    if not injections:
        print(f"[!] No union or error-based payloads found in "
              f"{args.sqlmap_log}.\n"
              f"    Check that sqlmap ran with -v 3 (or higher) and that the "
              f"log captured the 'Parameter: ...' summary block.",
              file=sys.stderr)
        sys.exit(1)

    rows = [injection_to_row(inj, i, args.extraction)
            for i, inj in enumerate(injections, 1)]
    write_csv(args.output, rows)

    by_type: dict = {}
    warnings = 0
    for r in rows:
        by_type[r["injection_type"]] = by_type.get(r["injection_type"], 0) + 1
        if "WARN:" in r["notes"]:
            warnings += 1

    print("=" * 60)
    print(f" sqlmap → CSV adapter")
    print("=" * 60)
    print(f"  Input log    : {args.sqlmap_log}")
    print(f"  Param        : {args.param}")
    print(f"  Extraction   : {args.extraction}")
    print(f"  Payloads     : {len(rows)}")
    for t, c in sorted(by_type.items()):
        print(f"     {t:<8} : {c}")
    if warnings:
        print(f"  Warnings     : {warnings} (check 'notes' column)")
    print(f"  Output CSV   : {args.output}")


if __name__ == "__main__":
    main()
