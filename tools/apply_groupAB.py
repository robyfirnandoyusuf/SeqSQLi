# -*- coding: utf-8 -*-
"""Group A/B reviewer edits (text) + red highlight. Run-level, equation-safe.
Backup first. Run: python3 -m tools.apply_groupAB"""
import docx, shutil, copy, sys
from docx.enum.text import WD_COLOR_INDEX
from docx.text.run import Run
from docx.oxml.ns import qn

SRC = "docs/manuscript-publication.docx"
shutil.copy(SRC, "docs/manuscript-publication.backup.docx")
d = docx.Document(SRC)
ps = d.paragraphs

def has_math(p):
    return p._p.find('.//' + qn('m:oMath')) is not None

def replace(idx, old, new):
    p = ps[idx]
    for r in p.runs:
        if old in r.text:
            r.text = r.text.replace(old, new, 1)
            return True
    # fallback: join runs only when the paragraph has NO equation object
    if not has_math(p):
        joined = "".join(r.text for r in p.runs)
        if old in joined:
            joined = joined.replace(old, new, 1)
            for i, r in enumerate(p.runs):
                r.text = joined if i == 0 else ""
            return True
    return False

def highlight(idx, target):
    p = ps[idx]
    for r in list(p.runs):
        i = r.text.find(target)
        if i < 0:
            continue
        before, after = r.text[:i], r.text[i + len(target):]
        rEl = r._r
        midEl = copy.deepcopy(rEl); aftEl = copy.deepcopy(rEl)
        rEl.addnext(aftEl); rEl.addnext(midEl)
        r.text = before
        mid = Run(midEl, p._parent); mid.text = target
        mid.font.highlight_color = WD_COLOR_INDEX.RED
        Run(aftEl, p._parent).text = after
        return True
    return False

A15 = (" Across the 541 successful bypasses recorded in this study, the chain length has a "
       "median of 5 steps and a 90th percentile of 8, and only a single trajectory reached the "
       "15-step cap, so the horizon adds roughly twice the typical headroom while truncating "
       "none of the solutions the agents discovered.")
A25_new = ("So, within the 1.5 × 10⁵-step training budget used here, the factor that appears "
           "to drive the performance difference is the length of the search horizon rather than the "
           "syntax of SQL, and a larger budget could shift which factor dominates.")
A27 = (" The union corpus is reported from a single seed per algorithm rather than the three-seed "
       "protocol applied to the harder corpus, because the trivial and medium tiers saturate at or "
       "near 100% and leave no room for seed-to-seed variation. The complex tier is the exception: "
       "since it does not saturate, its single-seed rates, in particular for PPO and A2C, should be "
       "read as indicative of the ranking rather than as precise point estimates, and confirming the "
       "complex-tier gap under multiple seeds remains future work.")
A29 = (" The two-of-three majority is a deliberate midpoint: requiring unanimous agreement across all "
       "three algorithms collapses the set to a single pair, newline → func_sp_nbsp, which is too "
       "restrictive to characterize the structure, whereas the majority criterion retains the 35 pairs "
       "analyzed here while still excluding any single-optimizer artifact.")
A31_clause = ("the cross-paradigm transfer result rests on a single rule-based product, ModSecurity with "
              "the OWASP Core Rule Set, and a single machine-learning product, Safeline Community Edition, "
              "so the 0% and 89% pattern may be specific to this pair")
A16 = "Appendix A enumerates the complete set of 51 operators."

EDITS = [
    # (idx, old_anchor, new_text, highlight_substring)
    (46, "admitting the longest chains observed during validation.",
         "admitting the longest chains observed during validation." + A15, A15.strip()),
    (71, "So, the main factor that makes a difference in performance is the length of the search horizon, not the syntax of SQL.",
         A25_new, A25_new),
    (71, "This finding at first appears to suggest that our comparison only looks at the performance stability of the optimization.",
         "This finding at first appears to suggest that our comparison only looks at the performance stability of the optimization." + A27, A27.strip()),
    (83, "not of one search procedure.",
         "not of one search procedure." + A29, A29.strip()),
    (98, "Second, the Safeline classifier is specific to a particular version.",
         "Second, " + A31_clause + ", and the Safeline classifier is furthermore specific to a particular version.", A31_clause),
    (48, "the transformation classes a human tester applies by hand.",
         "the transformation classes a human tester applies by hand. " + A16, A16),
]

for idx, old, new, hlsub in EDITS:
    ok = replace(idx, old, new)
    hok = highlight(idx, hlsub) if ok else False
    print(f"[{'OK ' if ok else 'MISS'}|hl {'ok' if hok else 'NO'}] para {idx}: {old[:40]!r}")

out = SRC
try:
    d.save(out)
except PermissionError:
    out = "docs/manuscript-publication_fixed.docx"
    print("[!] locked -> " + out, file=sys.stderr); d.save(out)
print("saved:", out)
