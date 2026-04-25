"""
seqsqli/core/response.py
========================
Response classification and data extraction from server replies.
"""

from typing import Optional

# ---------------------------------------------------------------------------
# Indicator lists
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

# Markers injected into payloads for data extraction
DATA_MARKERS = ("~~START~~", "~~END~~")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_response(resp_text: str, status_code: int) -> str:
    """Classify WAF/success/error from HTTP response.

    Returns one of:
        'SUCCESS', 'WAF_BLOCKED', 'SQL_ERROR',
        'FILTERED', 'SERVER_ERROR', 'UNKNOWN'
    """
    text = resp_text.lower()

    if status_code in (403, 406, 429, 501):
        return "WAF_BLOCKED"
    for ind in SUCCESS_INDICATORS:
        if ind in text:
            return "SUCCESS"
    for ind in WAF_INDICATORS:
        if ind in text:
            return "WAF_BLOCKED"
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
    """Extract data between ~~START~~ and ~~END~~ markers."""
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
