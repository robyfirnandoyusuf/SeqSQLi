# -*- coding: utf-8 -*-
"""Red-highlight the spans changed during the reviewer revision, so the edits
are easy to spot in Word. Run-level split (equations preserved). Backup first.
Run: python3 -m tools.highlight_revisions"""
import docx, shutil, copy, sys
from docx.enum.text import WD_COLOR_INDEX
from docx.text.run import Run

SRC = "docs/manuscript-publication.docx"
shutil.copy(SRC, "docs/manuscript-publication.backup.docx")
d = docx.Document(SRC)
ps = d.paragraphs

def hl(idx, target):
    p = ps[idx]
    for r in list(p.runs):
        i = r.text.find(target)
        if i < 0:
            continue
        before, after = r.text[:i], r.text[i + len(target):]
        rEl = r._r
        midEl = copy.deepcopy(rEl)
        aftEl = copy.deepcopy(rEl)
        rEl.addnext(aftEl)
        rEl.addnext(midEl)
        r.text = before
        mid = Run(midEl, p._parent); mid.text = target
        mid.font.highlight_color = WD_COLOR_INDEX.RED
        Run(aftEl, p._parent).text = after
        return True
    return False

TARGETS = [
    (100, "TRPO performed best"),                                   # #23/#34
    (21,  "established"),                                           # #7
    (65,  "at most 15 mutations"),                                  # #22
    (14,  "This body of work has three deficits"),                 # #5
    (11,  "[3]"),                                                   # #36 Halfond cite
    (36,  "Reinforcement learning has also been applied to evade learned security "
          "classifiers in adjacent domains, including static PE malware detectors [20]."),  # #37 Anderson
    (36,  "[19]"),                                                  # ordering swap (Hemmati)
    (33,  "[19]"),                                                  # ordering swap (Hemmati)
]
for idx, t in TARGETS:
    print(f"[{'OK ' if hl(idx, t) else 'MISS'}] para {idx}: {t[:50]!r}")

out = SRC
try:
    d.save(out)
except PermissionError:
    out = "docs/manuscript-publication_fixed.docx"
    print("[!] locked -> " + out, file=sys.stderr); d.save(out)
print("saved:", out)
