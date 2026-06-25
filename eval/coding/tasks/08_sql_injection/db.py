"""User-lookup helper backed by sqlite3.

Current implementation is SQL-injection-vulnerable: it concatenates the
username into the query string.
"""
import sqlite3


def find_user(conn: sqlite3.Connection, username: str) -> dict | None:
    """Look up a user by username; return their row as a dict, or None."""
    cur = conn.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE username = '" + username + "'")
    row = cur.fetchone()
    if row is None:
        return None
    return {"id": row[0], "username": row[1], "email": row[2]}


def init_db(conn: sqlite3.Connection) -> None:
    """Create the schema + seed two users."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (1, 'alice', 'alice@example.com')")
    conn.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (2, 'bob', 'bob@example.com')")
    conn.commit()
