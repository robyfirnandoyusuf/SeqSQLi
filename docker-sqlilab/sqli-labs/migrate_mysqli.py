#!/usr/bin/env python3
"""
Batch migrate mysql_* to mysqli_* for PHP 7 compatibility.
Run from the sqli-labs root directory:
    python3 migrate_mysqli.py
"""

import os
import re

# Replacements: order matters - more specific first
REPLACEMENTS = [
    # Connection
    (r'mysql_connect\(([^)]+)\)',          r'mysqli_connect(\1)'),
    (r'mysql_select_db\(([^,]+),\s*(\$\w+)\)', r'mysqli_select_db(\2, \1)'),
    (r'mysql_select_db\(([^)]+)\)',        r'mysqli_select_db($con, \1)'),

    # Queries
    (r'mysql_query\(([^,)]+),\s*(\$\w+)\)', r'mysqli_query(\2, \1)'),
    (r'mysql_query\(([^)]+)\)',            r'mysqli_query($con, \1)'),

    # Fetch
    (r'mysql_fetch_array\(([^)]+)\)',      r'mysqli_fetch_array(\1)'),
    (r'mysql_fetch_row\(([^)]+)\)',        r'mysqli_fetch_row(\1)'),
    (r'mysql_fetch_assoc\(([^)]+)\)',      r'mysqli_fetch_assoc(\1)'),
    (r'mysql_fetch_object\(([^)]+)\)',     r'mysqli_fetch_object(\1)'),

    # Result info
    (r'mysql_num_rows\(([^)]+)\)',         r'mysqli_num_rows(\1)'),
    (r'mysql_affected_rows\(([^)]+)\)',    r'mysqli_affected_rows(\1)'),
    (r'mysql_insert_id\(([^)]+)\)',        r'mysqli_insert_id(\1)'),
    (r'mysql_insert_id\(\)',               r'mysqli_insert_id($con)'),
    (r'mysql_num_fields\(([^)]+)\)',       r'mysqli_num_fields(\1)'),

    # Error handling
    (r'mysql_error\(\)',                   r'mysqli_error($con)'),
    (r'mysql_error\(([^)]+)\)',            r'mysqli_error(\1)'),
    (r'mysql_errno\(\)',                   r'mysqli_errno($con)'),

    # Escaping
    (r'mysql_real_escape_string\(([^,)]+),\s*(\$\w+)\)', r'mysqli_real_escape_string(\2, \1)'),
    (r'mysql_real_escape_string\(([^)]+)\)', r'mysqli_real_escape_string($con, \1)'),

    # Close
    (r'mysql_close\(([^)]+)\)',            r'mysqli_close(\1)'),
    (r'mysql_close\(\)',                   r'mysqli_close($con)'),

    # Free result
    (r'mysql_free_result\(([^)]+)\)',      r'mysqli_free_result(\1)'),

    # Data seek
    (r'mysql_data_seek\(([^)]+)\)',        r'mysqli_data_seek(\1)'),
]

def migrate_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    original = content

    for pattern, replacement in REPLACEMENTS:
        content = re.sub(pattern, replacement, content)

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    root = os.path.dirname(os.path.abspath(__file__))
    changed = []
    skipped = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip .git
        dirnames[:] = [d for d in dirnames if d != '.git']

        for filename in filenames:
            if not filename.endswith('.php'):
                continue
            filepath = os.path.join(dirpath, filename)
            rel = os.path.relpath(filepath, root)

            # Skip already-migrated connection files
            if rel in ['sql-connections/sql-connect.php',
                       'sql-connections/sql-connect-1.php',
                       'sql-connections/sqli-connect.php',
                       'sql-connections/functions.php']:
                skipped.append(rel)
                continue

            if migrate_file(filepath):
                changed.append(rel)
                print(f"  [UPDATED] {rel}")
            else:
                print(f"  [OK]      {rel}")

    print(f"\nDone. {len(changed)} file(s) updated, {len(skipped)} skipped.")

if __name__ == '__main__':
    main()
