"""
bypass_lab/verify.py
====================
Shared verification utilities. Strict bypass = WAF pass + genuine data leak.
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import has_strict_markers, classify_response
import requests

PLAIN   = "http://localhost:8081/Less-1/"
WAF     = "http://localhost:8888/Less-1/"
DELAY   = 0.3

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})


def check(url, payload=None, params=None, method="GET",
          headers=None, data=None, label=""):
    """Send request and return (http_status, is_bypass, result_str)."""
    try:
        kw = dict(timeout=10, allow_redirects=True)
        if headers:
            kw["headers"] = headers
        if method == "GET":
            if params:
                kw["params"] = params
            elif payload:
                kw["params"] = {"id": payload}
            r = session.get(url, **kw)
        else:
            if data:
                kw["data"] = data
            r = session.post(url, **kw)
        time.sleep(DELAY)
    except Exception as e:
        return 0, False, f"ERR:{e}"

    result  = classify_response(r.text, r.status_code,
                                signal_type="union", strict_markers=True)
    bypass  = result == "SUCCESS"
    status  = r.status_code
    tag     = "✓ BYPASS" if bypass else ("BLOCK" if status == 403 else result)
    return status, bypass, tag


def run_suite(name, cases, url=WAF, verify_plain=True):
    """Run a list of (label, payload_or_kwargs) against WAF (and optionally plain)."""
    print(f"\n{'='*60}")
    print(f" {name}")
    print(f"{'='*60}")
    bypasses = []
    for label, kwargs in cases:
        if isinstance(kwargs, str):
            kwargs = {"payload": kwargs}

        if verify_plain:
            ps, pb, pt = check(PLAIN, label=label, **kwargs)
            plain_ok = pb or ps == 200
        else:
            plain_ok = True

        ws, wb, wt = check(url, label=label, **kwargs)
        marker = " ← !!!" if wb else ""
        plain_tag = f"plain={'ok' if plain_ok else 'fail'}" if verify_plain else ""
        print(f"  {label:<45} {plain_tag:12} WAF={wt}{marker}")
        if wb:
            bypasses.append(label)

    print(f"\n  Bypasses found: {len(bypasses)}")
    for b in bypasses:
        print(f"    → {b}")
    return bypasses
