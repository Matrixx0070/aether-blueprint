#!/usr/bin/env bash
# Verifies SQL injection was fixed via parameterized query.
# Pass conditions:
#   - Happy path: find_user("alice") returns alice's row.
#   - Injection probe: find_user("anything' OR '1'='1") returns None
#     (the vulnerable version returns alice's row because the OR matches).
#   - Source no longer uses string concatenation: cur.execute must use
#     a parameter placeholder ("?", "%s", or "(:name)").
#   - Happy path for username with a literal apostrophe (e.g., "o'brien")
#     stored via a SECOND seeded row — verifies escaping works.

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import sqlite3
import sys
import re

# Behavior checks first.
import importlib.util
spec = importlib.util.spec_from_file_location("db", "./db.py")
db = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db)

conn = sqlite3.connect(":memory:")
db.init_db(conn)
# Seed a user whose name has an apostrophe to test escaping.
conn.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (3, \"o'brien\", \"ob@example.com\")")
conn.commit()

failures = []

# Happy path.
r = db.find_user(conn, "alice")
if not (r and r["username"] == "alice"):
    failures.append(f"happy-path: got {r!r}")

# Injection probe.
r = db.find_user(conn, "anything' OR '1'='1")
if r is not None:
    failures.append(f"sql-injection allowed: got {r!r}")

# Apostrophe in legitimate username.
r = db.find_user(conn, "o'brien")
if not (r and r["username"] == "o'brien"):
    failures.append(f"apostrophe-escaping: got {r!r}")

# Source check.
src = open("db.py").read()
if "username + '" in src or "+ username" in src or "\" + username" in src:
    failures.append("source still concatenates username into the query")
if not re.search(r'execute\([^)]*[?%]|execute\([^)]*:[a-zA-Z]', src):
    failures.append("source has no parameter placeholder (?/%s/:name)")

if failures:
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print("OK: SQL injection patched, escaping works")
PY
