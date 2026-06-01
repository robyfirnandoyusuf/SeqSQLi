"""
seqsqli/core/http.py
====================
HTTP engine: session management, smart URL encoding, request dispatch.
"""

import re
import time
import urllib.parse

import requests

from seqsqli.config import TIMEOUT, REQUEST_DELAY, MAX_RETRIES
from seqsqli.core.profile import TargetProfile

# ---------------------------------------------------------------------------
# Session (shared across all requests)
# ---------------------------------------------------------------------------
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (SeqSQLi/2.0)"})

# Global counter — checked/printed in main
_request_count: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _smart_url_encode(payload: str) -> str:
    """URL-encode a payload while preserving existing %XX sequences.

    Mutations embed things like %0a, %09, %bf%27 as literal text.
    We must keep those intact and only encode the *rest* of the string
    so that the web server decodes them to the intended bytes.
    """
    parts = re.split(r'(%[0-9a-fA-F]{2})', payload)
    result = []
    for part in parts:
        if re.match(r'^%[0-9a-fA-F]{2}$', part):
            result.append(part)
        else:
            # NOTE: '&' and ';' are query-string parameter separators. If left
            # unencoded, mutations like double_and ('AND'->'&&') split ARGS:id
            # and truncate the payload, producing a fake WAF-bypass + trivial
            # syntax error that the error-based SUCCESS check misreads as a win.
            result.append(urllib.parse.quote(part, safe="-_.~!*()+,:@/="))
    return ''.join(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_request(target: TargetProfile, payload: str):
    """Send payload to target, return (response_text, status_code).

    For GET requests the URL is built manually so that %-encoded
    sequences already present in the payload (e.g. %0a for newline)
    are sent verbatim instead of being double-encoded by ``requests``.
    """
    global _request_count
    _request_count += 1

    for attempt in range(MAX_RETRIES + 1):
        try:
            if target.method == "GET":
                encoded = _smart_url_encode(payload)
                sep = "&" if "?" in target.url else "?"
                full_url = f"{target.url}{sep}{target.param}={encoded}"
                resp = session.get(full_url, timeout=TIMEOUT, allow_redirects=True)
            else:
                data = {target.param: payload}
                data.update(target.extra_params)
                resp = session.post(target.url, data=data,
                                    timeout=TIMEOUT, allow_redirects=True)
            return resp.text, resp.status_code

        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES:
                time.sleep(1)
                continue
            return "TIMEOUT", 408
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES:
                time.sleep(2)
                continue
            return "CONNECTION_ERROR", 503
        except Exception as e:
            return str(e), 500

    return "MAX_RETRIES_EXCEEDED", 503


def get_request_count() -> int:
    """Return total HTTP requests made this session."""
    return _request_count
