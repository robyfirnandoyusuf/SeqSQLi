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

# ---------------------------------------------------------------------------
# Error-based success signatures
# ---------------------------------------------------------------------------
# Keys match the error_function names used by tools/payload_builder.py
# (ERROR_FUNCTIONS dict). When signal_type='error', the function-specific
# signature is checked first for tight detection.
ERROR_SUCCESS_SIGNATURES = {
    "extractvalue": "xpath syntax error",
    "updatexml":    "xpath syntax error",
    "floor":        "duplicate entry",
    "exp":          "double value is out of range",
    "gtid_subset":  "malformed gtid",
}

# Generic SQL error markers — sufficient evidence that the injected
# payload reached the SQL parser and produced a server-visible error.
# Used as fallback when the function-specific signature isn't found
# (e.g., MySQL version mismatch returning a generic error message).
ERROR_SUCCESS_FALLBACK = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
    "supplied argument is not",
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
                      signal_type: str = "union",
                      error_function: str = "",
                      strict_markers: bool = False) -> str:
    """Classify WAF / success / error from HTTP response.

    Returns one of:
        'SUCCESS', 'WAF_BLOCKED', 'SQL_ERROR',
        'FILTERED', 'SERVER_ERROR', 'UNKNOWN'

    Args:
        resp_text       : Response body text.
        status_code     : HTTP status code.
        signal_type     : Selects success criterion.
                          "union" (default) — both SEQSQLI_START and
                                  SEQSQLI_END must reflect.
                          "error" — function-specific SQL error signature
                                  (or generic SQL error fallback) must
                                  appear in the response.
        error_function  : Only meaningful when signal_type='error'.
                          Names the error-triggering function in use
                          (extractvalue / updatexml / floor / exp /
                          gtid_subset) so the tight signature can be
                          looked up. When empty, only the generic
                          fallback list is checked.
        strict_markers  : Only meaningful when signal_type='union'.
                          False (default) — legacy SUCCESS_INDICATORS
                                  (login/password text) also counts as
                                  SUCCESS when markers don't reflect.
                                  Kept for backward compatibility with
                                  pre-marker training loops.
                          True — strict marker-only mode (paper-grade
                                  IFNR/SPBARC criterion).
    """
    text = resp_text.lower()

    # ---- WAF block always wins ---------------------------------------
    if status_code in (403, 406, 429, 501):
        return "WAF_BLOCKED"
    for ind in WAF_INDICATORS:
        if ind in text:
            return "WAF_BLOCKED"

    # ---- Success criterion (per signal_type) -------------------------
    if signal_type == "error":
        # Function-specific signature first — tightest detection.
        sig = ERROR_SUCCESS_SIGNATURES.get(error_function, "")
        if sig and sig in text:
            return "SUCCESS"
        # Generic SQL error fallback — payload reached parser & errored.
        for fb in ERROR_SUCCESS_FALLBACK:
            if fb in text:
                return "SUCCESS"
    else:
        # signal_type == "union" (or anything unknown — default to union).
        # Strict marker check — always the strongest signal we have.
        if has_strict_markers(resp_text):
            return "SUCCESS"
        # Legacy fallback (loose mode) — only when strict_markers=False.
        if not strict_markers:
            for ind in SUCCESS_INDICATORS:
                if ind in text:
                    return "SUCCESS"

    # ---- Non-success classifications ---------------------------------
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