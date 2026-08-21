"""SQLite access layer. Every statement here is parameterised.

House rule for this file: no f-string, no `%`, no `+` and no `.format()` ever
touches a SQL string with user data in it. Values go in as `?` parameters and
sqlite3 binds them, so the driver never parses them as SQL. The one place that
rule is broken is src/vulnerable_demo.py, which exists to show what happens when
you break it, and which is only importable behind an explicit flag.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    NOT NULL UNIQUE,
    password_hash     TEXT    NOT NULL,
    created_at        REAL    NOT NULL,
    totp_secret_b32   TEXT,
    totp_enabled      INTEGER NOT NULL DEFAULT 0,
    totp_last_counter INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    sid_hash     TEXT    PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    auth_level   TEXT    NOT NULL,
    csrf_token   TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_seen_at REAL    NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    flash        TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    username TEXT,
    ip       TEXT,
    outcome  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_username_ts ON login_attempts(username, ts);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts ON login_attempts(ip, ts);
"""


def connect(path: str) -> sqlite3.Connection:
    # check_same_thread=False because the dev server is threaded and we hand
    # out one connection per request from the app factory; each request keeps
    # its connection to itself, so there is no cross-thread sharing of a cursor.
    conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL so a read during a write does not block; the lockout counters get
    # written on every failed attempt and readers should not stall behind them.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    # executescript is safe here: SCHEMA is a literal constant with no
    # interpolation. It is the only executescript call in the project.
    conn.executescript(SCHEMA)
    conn.commit()


# --- users -------------------------------------------------------------------

def create_user(conn: sqlite3.Connection, username: str, password_hash: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, time.time()))
    conn.commit()
    return int(cur.lastrowid)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_password_hash(conn: sqlite3.Connection, user_id: int, new_hash: str) -> None:
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
    conn.commit()


def set_totp_secret(conn: sqlite3.Connection, user_id: int, secret_b32: str) -> None:
    # Enrolment is two-phase: the secret is stored but totp_enabled stays 0
    # until the user proves they can generate a code from it. Otherwise a
    # mistyped QR scan locks the account owner out of their own account.
    conn.execute(
        "UPDATE users SET totp_secret_b32 = ?, totp_enabled = 0, "
        "totp_last_counter = NULL WHERE id = ?", (secret_b32, user_id))
    conn.commit()


def enable_totp(conn: sqlite3.Connection, user_id: int, used_counter: int) -> None:
    conn.execute(
        "UPDATE users SET totp_enabled = 1, totp_last_counter = ? WHERE id = ?",
        (used_counter, user_id))
    conn.commit()


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret_b32 = NULL, "
        "totp_last_counter = NULL WHERE id = ?", (user_id,))
    conn.commit()


def record_totp_counter(conn: sqlite3.Connection, user_id: int, counter: int) -> bool:
    """Burn a TOTP counter. Returns False if it was already spent.

    The WHERE clause carries the replay check, so the read and the write are one
    atomic statement. Doing it as SELECT-then-UPDATE would let two concurrent
    requests with the same code both pass the check before either wrote.
    """
    cur = conn.execute(
        "UPDATE users SET totp_last_counter = ? "
        "WHERE id = ? AND (totp_last_counter IS NULL OR totp_last_counter < ?)",
        (counter, user_id, counter))
    conn.commit()
    return cur.rowcount == 1


# --- sessions ----------------------------------------------------------------

def insert_session(conn: sqlite3.Connection, sid_hash: str, user_id: int | None,
                   auth_level: str, csrf_token: str, ip: str | None,
                   user_agent: str | None) -> None:
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (sid_hash, user_id, auth_level, csrf_token, "
        "created_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sid_hash, user_id, auth_level, csrf_token, now, now, ip, user_agent))
    conn.commit()


def get_session(conn: sqlite3.Connection, sid_hash: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM sessions WHERE sid_hash = ?", (sid_hash,)).fetchone()


def touch_session(conn: sqlite3.Connection, sid_hash: str) -> None:
    conn.execute("UPDATE sessions SET last_seen_at = ? WHERE sid_hash = ?",
                 (time.time(), sid_hash))
    conn.commit()


def set_session_flash(conn: sqlite3.Connection, sid_hash: str,
                      message: str | None) -> None:
    conn.execute("UPDATE sessions SET flash = ? WHERE sid_hash = ?",
                 (message, sid_hash))
    conn.commit()


def delete_session(conn: sqlite3.Connection, sid_hash: str) -> None:
    conn.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))
    conn.commit()


def delete_sessions_for_user(conn: sqlite3.Connection, user_id: int) -> int:
    """Kill every session a user holds. Used on password change and 2FA change:
    if a credential changed, anything issued under the old one is suspect."""
    cur = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    return cur.rowcount


def purge_expired_sessions(conn: sqlite3.Connection, idle_timeout_s: int,
                           absolute_timeout_s: int) -> int:
    now = time.time()
    cur = conn.execute(
        "DELETE FROM sessions WHERE last_seen_at < ? OR created_at < ?",
        (now - idle_timeout_s, now - absolute_timeout_s))
    conn.commit()
    return cur.rowcount


def count_sessions(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"])


# --- login attempts ----------------------------------------------------------

def record_attempt(conn: sqlite3.Connection, username: str | None, ip: str | None,
                   outcome: str) -> None:
    conn.execute(
        "INSERT INTO login_attempts (ts, username, ip, outcome) VALUES (?, ?, ?, ?)",
        (time.time(), username, ip, outcome))
    conn.commit()


def count_recent_failures(conn: sqlite3.Connection, column: str, value: str,
                          since: float) -> int:
    """Count recent failures for a username or an IP.

    `column` is chosen from a hard-coded allow-list below, so the only string
    ever concatenated into this SQL is one of two literals this module owns.
    User data still goes in as a parameter.
    """
    if column not in {"username", "ip"}:
        raise ValueError("column must be 'username' or 'ip'")
    sql = (f"SELECT COUNT(*) AS n FROM login_attempts "
           f"WHERE {column} = ? AND ts >= ? AND outcome = 'failure'")
    return int(conn.execute(sql, (value, since)).fetchone()["n"])


def clear_failures_for_username(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("DELETE FROM login_attempts WHERE username = ? AND "
                 "outcome = 'failure'", (username,))
    conn.commit()


def all_usernames(conn: sqlite3.Connection) -> Iterable[str]:
    return [r["username"] for r in conn.execute("SELECT username FROM users")]


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    return {
        "users": int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]),
        "sessions": count_sessions(conn),
        "attempts": int(conn.execute(
            "SELECT COUNT(*) AS n FROM login_attempts").fetchone()["n"]),
    }
