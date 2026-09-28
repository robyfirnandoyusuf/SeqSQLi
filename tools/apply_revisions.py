# -*- coding: utf-8 -*-
"""Apply reviewer quick-fixes + Conclusion contradiction fix to the manuscript.
Run-level edits (preserve equations). Backup first. Run: python3 -m tools.apply_revisions"""
import docx, shutil, sys
from docx.oxml.ns import qn

SRC = "docs/manuscript-publication.docx"
shutil.copy(SRC, "docs/manuscript-publication.backup.docx")
d = docx.Document(SRC)
ps = d.paragraphs

def has_math(p):
    return p._p.find(qn('.//m:oMath')) is not None or len(p._p.findall(qn('m:oMath'))) > 0 \
        or p._p.find('.//' + qn('m:oMath')) is not None

def repl(idx, old, new):
    p = ps[idx]
    # try single-run first
    for r in p.runs:
        if old in r.text:
            r.text = r.text.replace(old, new, 1)
            return True
    # fallback: join runs (only if no equation object present)
    joined = "".join(r.text for r in p.runs)
    if old in joined and p._p.find('.//' + qn('m:oMath')) is None:
        joined = joined.replace(old, new, 1)
        for i, r in enumerate(p.runs):
            r.text = joined if i == 0 else ""
        return True
    return False

EDITS = [
    (100, "PPO performed best under the rule-based WAF",
          "TRPO performed best under the rule-based WAF"),                      # #23/#34
    (21,  "We estabilished", "We established"),                                 # #7
    (65,  "at most $15$ mutations", "at most 15 mutations"),                    # #22
    (14,  "This corpus has three deficits", "This body of work has three deficits"),  # #5
    (11,  "just a string of code.", "just a string of code [3]."),              # #36 Halfond
    (36,  "Prior RL-based WAF evasion systems each fixed a single algorithm",
          "Reinforcement learning has also been applied to evade learned security "
          "classifiers in adjacent domains, including static PE malware detectors [19]. "
          "Prior RL-based WAF evasion systems each fixed a single algorithm"),  # #37 Anderson
]

for idx, old, new in EDITS:
    ok = repl(idx, old, new)
    print(f"[{'OK ' if ok else 'MISS'}] para {idx}: {old[:45]!r}")

out = SRC
try:
    d.save(out)
except PermissionError:
    out = "docs/manuscript-publication_fixed.docx"
    print("[!] locked -> " + out, file=sys.stderr); d.save(out)
print("saved:", out)
