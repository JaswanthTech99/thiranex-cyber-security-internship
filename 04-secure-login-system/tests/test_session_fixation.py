"""Session fixation, session rotation, and server-side invalidation.

The attack being tested: the attacker arranges for the victim's browser to carry
a session identifier the attacker already knows -- a link carrying a session
parameter, a cookie written from a sibling subdomain, an XSS write -- and then
waits for the victim to authenticate. If login keeps the same identifier and
merely flips it to "logged in", the attacker's known identifier is now an
authenticated session and no credential was ever stolen.

The defence is to issue a brand-new identifier on every privilege change and
delete the old row. Asserting "the new id differs from the old one" is not
enough on its own, because a server could hand out a new id and still honour the
old one; so this file also presents the old identifier afterwards and reads the
sessions table directly to confirm the row is gone.
"""

from __future__ import annotations

import os
import sqlite3
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import sessions as S  # noqa: E402
from src import totp  # noqa: E402
from tests.harness import Suite  # noqa: E402
from tests.server import AppServer, Client, TEST_PASSWORD  # noqa: E402

USER = "fixation.target"
COOKIE = "sls_sid"


def session_row(db_path: str, sid: str) -> sqlite3.Row | None:
    """Read the sessions table directly, to check what the server really kept.

    Opened read-only (mode=ro) so the test cannot perturb the thing it measures.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM sessions WHERE sid_hash = ?",
                            (S.hash_sid(sid),)).fetchone()
    finally:
        conn.close()


def probe_with_cookie(server: AppServer, sid: str) -> requests.Response:
    """Hit the protected page carrying exactly one cookie, by hand."""
    return requests.get(server.base + "/dashboard",
                        headers={"Accept": "application/json"},
                        cookies={COOKIE: sid}, allow_redirects=False, timeout=30)


def run(suite: Suite) -> dict[str, object]:
    results: dict[str, object] = {}

    suite.section("Password-only login rotates the session id")
    with AppServer(extra_args=["--no-breach-check"], label="fixation") as server:
        client = Client(server)
        suite.check("account created",
                    client.register(USER, TEST_PASSWORD).status_code, 201)

        # The attacker's foothold: a pre-login session id that they know.
        client.prime_csrf("/login")
        attacker_known_sid = client.sid
        suite.check_true("a pre-login session exists to fixate on",
                         bool(attacker_known_sid))
        pre_row = session_row(server.db_path, attacker_known_sid)
        suite.check("pre-login session is anonymous",
                    pre_row["auth_level"], S.ANONYMOUS)
        suite.check("pre-login session has no user attached",
                    pre_row["user_id"], None)

        response = client.login(USER, TEST_PASSWORD)
        suite.check("login succeeded", response.json().get("authenticated"), True)
        post_login_sid = client.sid

        suite.check_true("the session id changed on login",
                         attacker_known_sid != post_login_sid)
        suite.check("the pre-login row was DELETED, not upgraded",
                    session_row(server.db_path, attacker_known_sid), None)
        suite.check("the new row is authenticated",
                    session_row(server.db_path, post_login_sid)["auth_level"],
                    S.AUTHENTICATED)

        # The assertion that actually matters: the attacker's known id must not
        # work, even though the victim has now logged in.
        replayed = probe_with_cookie(server, attacker_known_sid)
        suite.check("the fixated pre-login id is not honoured after login",
                    replayed.status_code, 401)
        # And the victim's real session still works, so the fix did not simply
        # break login.
        suite.check("the victim's own session works",
                    client.dashboard().status_code, 200)

        results["password_only"] = {
            "pre_login_sid_changed": attacker_known_sid != post_login_sid,
            "pre_login_row_deleted": True,
            "fixated_id_status": replayed.status_code,
        }

    suite.section("Every privilege change rotates: anonymous -> pending_2fa "
                 "-> authenticated")
    with AppServer(extra_args=["--no-breach-check"], label="fixation-2fa") as server:
        client = Client(server)
        client.register(USER, TEST_PASSWORD)
        client.login(USER, TEST_PASSWORD)

        enrol = client.start_enrolment()
        secret = totp.b32decode(enrol["secret_b32"])
        client.confirm_enrolment(totp.totp(secret))

        # Fresh client, so the three stages are cleanly observable.
        victim = Client(server)
        victim.prime_csrf("/login")
        sid_anonymous = victim.sid
        suite.check("stage 1 is anonymous",
                    session_row(server.db_path, sid_anonymous)["auth_level"],
                    S.ANONYMOUS)

        victim.login(USER, TEST_PASSWORD)
        sid_pending = victim.sid
        suite.check_true("id rotated after the password step",
                         sid_pending != sid_anonymous)
        suite.check("stage 2 is pending_2fa",
                    session_row(server.db_path, sid_pending)["auth_level"],
                    S.PENDING_2FA)
        suite.check("the anonymous row is gone",
                    session_row(server.db_path, sid_anonymous), None)
        suite.check("a pending_2fa session cannot read the protected page",
                    probe_with_cookie(server, sid_pending).status_code, 401)

        # A code from a step already burned during enrolment would be refused,
        # so wait for the counter to advance. Same reason as tests/test_e2e.py.
        from tests.test_e2e import code_in_next_step
        code, _ = code_in_next_step(secret)
        response = victim.submit_totp(code)
        suite.check("second factor accepted", response.json().get("authenticated"),
                    True)
        sid_authenticated = victim.sid
        suite.check_true("id rotated again after the second factor",
                         sid_authenticated not in (sid_anonymous, sid_pending))
        suite.check("stage 3 is authenticated",
                    session_row(server.db_path, sid_authenticated)["auth_level"],
                    S.AUTHENTICATED)
        suite.check("the pending_2fa row is gone",
                    session_row(server.db_path, sid_pending), None)
        suite.check("the pending_2fa id is not honoured once it has been rotated",
                    probe_with_cookie(server, sid_pending).status_code, 401)

        suite.check_true("all three stage ids are distinct",
                         len({sid_anonymous, sid_pending, sid_authenticated}) == 3)
        results["three_stage_rotation"] = {
            "distinct_ids": len({sid_anonymous, sid_pending, sid_authenticated}),
            "levels": [S.ANONYMOUS, S.PENDING_2FA, S.AUTHENTICATED],
        }

        suite.section("Logout deletes the row server-side")
        live_sid = victim.sid
        suite.check_true("session row exists before logout",
                         session_row(server.db_path, live_sid) is not None)
        suite.check("logout returns 200", victim.logout().status_code, 200)
        suite.check("session row is gone after logout",
                    session_row(server.db_path, live_sid), None)
        suite.check("re-presenting the logged-out cookie is refused",
                    probe_with_cookie(server, live_sid).status_code, 401)
        results["logout_deletes_row"] = True

    suite.section("Enabling 2FA evicts every other session for that user")
    with AppServer(extra_args=["--no-breach-check"], label="fixation-evict") as server:
        owner = Client(server)
        owner.register(USER, TEST_PASSWORD)
        owner.login(USER, TEST_PASSWORD)

        # A second live session for the same account, standing in for an
        # attacker who already has one.
        intruder = Client(server)
        intruder.prime_csrf("/login")
        intruder.login(USER, TEST_PASSWORD)
        intruder_sid = intruder.sid
        suite.check("the second session is live before enrolment",
                    probe_with_cookie(server, intruder_sid).status_code, 200)

        enrol = owner.start_enrolment()
        owner.confirm_enrolment(totp.totp(totp.b32decode(enrol["secret_b32"])))

        suite.check("the second session is dead after 2FA is enabled",
                    probe_with_cookie(server, intruder_sid).status_code, 401)
        suite.check("its row was deleted",
                    session_row(server.db_path, intruder_sid), None)
        suite.check("the enrolling user is still logged in",
                    owner.dashboard().status_code, 200)
        results["enabling_2fa_evicts_other_sessions"] = True

    return results


if __name__ == "__main__":
    suite = Suite("Session fixation, rotation and server-side invalidation")
    run(suite)
    sys.exit(suite.finish())
