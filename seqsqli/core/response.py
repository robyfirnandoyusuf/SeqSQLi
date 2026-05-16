"""
seqsqli/core/response.py
========================
Response classification and data extraction from server replies.

Strict success criterion (BWAFSQLi-style):
    A payload counts as SUCCESS only when WAF allows the request AND the
    backend response reflects both SEQSQLI_START and SEQSQLI_END markers.
    HTTP 200 alone is NOT sufficient — a payload can pass the WAF while
    losing its SQLi semantics (broken syntax echoed as plain text).
"""

from typing import Optional

# ---------------------------------------------------------------------------
# Strict markers (paper-grade success criterion)
# ---------------------------------------------------------------------------
# These are the canonical markers for IFNR/SPBARC measurement.
# Payloads built by tools/payload_builder.py embed this pair via a UNION
# SELECT column, and SUCCESS is asserted iff both markers reflect.
STRICT_MARKERS = ("SEQSQLI_START", "SEQSQLI_END")

# Legacy markers used by DataExtractor (kept for backward compatibility).
DATA_MARKERS = ("~~START~~", "~~END~~")


# ---------------------------------------------------------------------------
# Indicator lists (fallback when no markers are embedded)
# ---------------------------------------------------------------------------
SUCCESS_INDICATORS = [
    "your login name", "you are in",
    "your username", "your password", "flag",
]
WAF_INDICATORS = [
    "blocked", "forbidden", "not acceptable",
    "attack detected", "firewall", "waf",
]
SQL_ERROR_INDICATORS = [
    "sql syntax", "warning: mysqli", "unclosed quotation",
    "you have an error in your sql", "supplied argument is not",
    "warning: mysql", "error in your sql syntax",
]
FILTERED_INDICATORS = [
    "your input has been filtered",
    "input was stripped",
    "query stripped",
]
# SQL_ERROR_PHRASES = [
#     "you have an error in your sql syntax",
#     "error in your sql",
#     "mysql server version",
#     "near '",
#     "syntax error",
# ]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def has_strict_markers(body: str) -> bool:
    if not body:
        return False

    body_lower = body.lower()
    start_idx = body.find("SEQSQLI_START")
    end_idx   = body.find("SEQSQLI_END")

    if start_idx == -1 or end_idx == -1 or start_idx >= end_idx:
        return False

    # Cek apakah marker ada di dalam SQL error message
    context = body_lower[max(0, start_idx-200) : end_idx+50]
    for phrase in SQL_ERROR_INDICATORS:
        if phrase in context:
            return False  # False positive — marker di error, bukan di data

    return True


def classify_response(resp_text: str, status_code: int,
                      strict_markers: bool = False) -> str:
    """Classify WAF/success/error from HTTP response.

    Returns one of:
        'SUCCESS', 'WAF_BLOCKED', 'SQL_ERROR',
        'FILTERED', 'SERVER_ERROR', 'UNKNOWN'

    Args:
        resp_text   : Response body text.
        status_code : HTTP status code.
        strict_markers : When True, SUCCESS requires both SEQSQLI_START
                         and SEQSQLI_END markers to be reflected in the
                         response (paper-grade IFNR/SPBARC criterion).
                         Default False uses legacy SUCCESS_INDICATORS so
                         that existing training loops with non-marker base
                         payloads keep working.
                         Marker check is ALWAYS attempted first regardless
                         of this flag — if both markers are present, SUCCESS
                         is returned. The flag only controls the FALLBACK
                         path (legacy indicators or not).
    """
    text = resp_text.lower()

    # WAF block always wins — short-circuit.
    if status_code in (403, 406, 429, 501):
        return "WAF_BLOCKED"
    for ind in WAF_INDICATORS:
        if ind in text:
            return "WAF_BLOCKED"

    # Strict success criterion (paper-grade): both markers must be reflected.
    # Always check this first; it's the strongest signal we have.
    if has_strict_markers(resp_text):
        return "SUCCESS"

    # Legacy fallback — only when strict mode is disabled.
    if not strict_markers:
        for ind in SUCCESS_INDICATORS:
            if ind in text:
                return "SUCCESS"

    for ind in SQL_ERROR_INDICATORS:
        if ind in text:
            return "SQL_ERROR"
    for ind in FILTERED_INDICATORS:
        if ind in text:
            return "FILTERED"
    if status_code >= 500:
        return "SERVER_ERROR"
    return "UNKNOWN"


def extract_between_markers(resp_text: str) -> Optional[str]:
    """Extract data between ~~START~~ and ~~END~~ markers (legacy)."""
    start, end = DATA_MARKERS
    idx_s = resp_text.find(start)
    idx_e = resp_text.find(end)
    if idx_s != -1 and idx_e != -1 and idx_e > idx_s:
        return resp_text[idx_s + len(start):idx_e].strip()
    return None


def has_valid_output(resp_text: str, baseline_text: str) -> bool:
    """True if response differs meaningfully from baseline."""
    if not baseline_text:
        return False
    return (
        abs(len(resp_text) - len(baseline_text)) > 50
        or resp_text.lower().count("your") > baseline_text.lower().count("your")
    )
