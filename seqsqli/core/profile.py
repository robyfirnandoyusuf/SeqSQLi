"""
seqsqli/core/profile.py
=======================
TargetProfile dataclass and sqli-labs preset definitions.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class TargetProfile:
    """Holds everything we know about the injection point."""
    url:             str        = ""
    param:           str        = "id"
    method:          str        = "GET"
    quote:           str        = ""       # ' or " or empty
    closure:         str        = ""       # ) or )) etc.
    suffix:          str        = "--+"    # comment suffix
    columns:         int        = 0
    injectable_cols: List[int]  = field(default_factory=list)
    filter_type:     str        = "unknown"
    extra_params:    Dict       = field(default_factory=dict)
    base_payload:    str        = ""
    dbms:            str        = "mysql"


# ---------------------------------------------------------------------------
# sqli-labs preset definitions
# Each key is the Less-N number (float allows 25.1, 26a, etc.)
# ---------------------------------------------------------------------------
LESS_PRESETS: Dict = {
    1:    {"path": "Less-1/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "none"},
    2:    {"path": "Less-2/",   "param": "id",    "method": "GET",  "quote": "",    "closure": "",   "filter": "none"},
    3:    {"path": "Less-3/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": ")",  "filter": "none"},
    4:    {"path": "Less-4/",   "param": "id",    "method": "GET",  "quote": '"',   "closure": ")",  "filter": "none"},
    5:    {"path": "Less-5/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "none"},
    6:    {"path": "Less-6/",   "param": "id",    "method": "GET",  "quote": '"',   "closure": "",   "filter": "none"},
    7:    {"path": "Less-7/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": "))", "filter": "none"},
    8:    {"path": "Less-8/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "none"},
    9:    {"path": "Less-9/",   "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "none"},
    10:   {"path": "Less-10/",  "param": "id",    "method": "GET",  "quote": '"',   "closure": "",   "filter": "none"},
    11:   {"path": "Less-11/",  "param": "uname", "method": "POST", "quote": "'",   "closure": "",   "filter": "none",
           "extra_params": {"passwd": "x", "submit": "Submit"}},
    12:   {"path": "Less-12/",  "param": "uname", "method": "POST", "quote": '"',   "closure": ")",  "filter": "none",
           "extra_params": {"passwd": "x", "submit": "Submit"}},
    25:   {"path": "Less-25/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "or_and"},
    25.1: {"path": "Less-25a/", "param": "id",    "method": "GET",  "quote": "",    "closure": "",   "filter": "or_and"},
    26:   {"path": "Less-26/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "comments_spaces_or_and"},
    26.1: {"path": "Less-26a/", "param": "id",    "method": "GET",  "quote": "'",   "closure": ")",  "filter": "comments_spaces_or_and"},
    27:   {"path": "Less-27/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "union_select_comments_spaces"},
    27.1: {"path": "Less-27a/", "param": "id",    "method": "GET",  "quote": '"',   "closure": "",   "filter": "union_select_comments_spaces"},
    28:   {"path": "Less-28/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": ")",  "filter": "union_select_combined"},
    28.1: {"path": "Less-28a/", "param": "id",    "method": "GET",  "quote": "'",   "closure": ")",  "filter": "union_select_combined"},
    32:   {"path": "Less-32/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "addslashes_gbk"},
    33:   {"path": "Less-33/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "addslashes_gbk"},
    36:   {"path": "Less-36/",  "param": "id",    "method": "GET",  "quote": "'",   "closure": "",   "filter": "addslashes_gbk"},
}
