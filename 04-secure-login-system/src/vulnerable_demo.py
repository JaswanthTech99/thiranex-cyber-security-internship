"""!!! DELIBERATELY VULNERABLE CODE -- DO NOT COPY, DO NOT DEPLOY !!!

                        ############################
                        #   THIS FILE IS THE BUG   #
                        ############################

This module exists for one reason: to be the control group in the SQL-injection
experiment. tests/test_sqli.py fires the same public payload corpus at the real
login endpoint and at this one, and reports that the real one rejects all of
them while this one is bypassed. Without a vulnerable target, "no payload got
in" only proves the payloads were fired at something; it does not prove the
parameterised query is what stopped them.

What is wrong with it, on purpose:
  - The SQL is built by string concatenation from request data, so the driver
    parses attacker input as SQL.
  - It stores and compares PLAINTEXT passwords, so the query can be a single
    string comparison the injection can short-circuit.
  - No rate limiting, no lockout, no CSRF token, no session rotation.

It is mounted ONLY when run.py is given --demo-vulnerable, it lives in its own
table (demo_vulnerable_users) that no other code path reads, it refuses to load
unless the config flag is set, and the app prints a red-handed warning banner at
startup and returns a warning header on every response from it.

One honest limitation to note in the writeup: Python's sqlite3
`Cursor.execute()` refuses to run more than one statement, so stacked payloads
like `'; DROP TABLE users; --` cannot destroy anything here even though the
injection itself succeeds. That is a property of the driver, not of the code
being safe. The authentication bypass -- which is the thing that matters for a
login form -- works exactly as it does anywhere else.
"""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, jsonify, request

VULNERABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_vulnerable_users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL        -- PLAINTEXT. On purpose. This is the bad table.
);
"""

# Seeded so the bypass has something to find. These credentials are fake and
# only ever exist inside the demo table.
DEMO_USERS = [("demo_victim", "correct horse battery staple"),
              ("demo_admin", "Tr0ub4dor&3-not-real")]


def init_vulnerable_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(VULNERABLE_SCHEMA)
    for username, password in DEMO_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO demo_vulnerable_users (username, password) "
            "VALUES (?, ?)", (username, password))
    conn.commit()


def build_blueprint() -> Blueprint:
    bp = Blueprint("vulnerable_demo", __name__)

    @bp.after_request
    def _mark(response):
        response.headers["X-Danger"] = "deliberately-vulnerable-demo-endpoint"
        return response

    @bp.route("/demo/vulnerable/login", methods=["POST"])
    def vulnerable_login():
        if not current_app.config["SLS"].demo_vulnerable:
            # Defence in depth: even if the blueprint got registered by mistake,
            # it does nothing without the flag.
            return jsonify({"error": "not enabled"}), 404

        username = request.form.get("username", request.args.get("username", ""))
        password = request.form.get("password", request.args.get("password", ""))

        # ------------------------------------------------------------------
        # THE VULNERABILITY. Request data concatenated straight into SQL.
        # A username of  ' OR '1'='1  turns the WHERE clause into a tautology
        # and the query returns a row without any password ever matching.
        # The correct version of this line is in src/db.py: pass values as
        # ? parameters and let the driver bind them.
        # ------------------------------------------------------------------
        sql = ("SELECT id, username FROM demo_vulnerable_users "
               f"WHERE username = '{username}' AND password = '{password}'")

        conn = current_app.config["SLS_CONNECT"]()
        try:
            row = conn.execute(sql).fetchone()
        except sqlite3.Error as exc:
            # A raw driver error leaking to the client is itself a finding: it
            # tells an attacker their payload reached the parser and how it
            # broke. Kept verbose here because the whole point is to show it.
            return jsonify({"authenticated": False, "sql": sql,
                            "db_error": f"{type(exc).__name__}: {exc}"}), 500
        finally:
            conn.close()

        if row is not None:
            return jsonify({"authenticated": True, "sql": sql,
                            "user": row["username"]}), 200
        return jsonify({"authenticated": False, "sql": sql}), 401

    return bp
