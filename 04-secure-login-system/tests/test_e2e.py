"""End-to-end drive of the live app, transcribed to outputs/reports/.

This is the "does it actually work" test: register, log in, enrol a second
factor, log in again through the 2FA step, read a protected page, log out, and
confirm the session is dead server-side. Every request and response line in the
transcript is captured from a real HTTP exchange against a real server process.
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import totp  # noqa: E402
from tests.harness import Suite  # noqa: E402
from tests.server import PROJECT_ROOT, AppServer, Client, TEST_PASSWORD  # noqa: E402

TRANSCRIPT_PATH = os.path.join(PROJECT_ROOT, "outputs", "reports",
                               "session_transcript.md")

# Fixed so the transcript is reproducible; the account is created fresh in a
# throwaway database each run, so a constant name is safe.
E2E_USER = "jaswanth.demo"

REDACT_KEYS = {"secret_b32", "otpauth_uri", "csrf_token"}


def code_in_next_step(secret: bytes) -> tuple[str, float]:
    """Block until the TOTP counter advances, then return a code from it.

    This exists because of a real interaction the first run of this test found.
    Confirming enrolment consumes a code, which burns that counter in
    totp_last_counter. The replay guard then correctly refuses the same counter
    at the next login, so a code generated within the same 30 second step as the
    enrolment code is rejected -- and the test failed, having asserted the login
    would succeed.

    The app is behaving correctly; the test was wrong. Keeping the wait here
    rather than loosening the replay guard is the whole point: a spent counter
    must stay spent. In the product this is invisible, because confirming
    enrolment already leaves the user authenticated, so nobody has to log in
    during those few seconds. It is recorded in findings.md because it is
    exactly the sort of thing that gets "fixed" by weakening the replay check.
    """
    start_counter = totp.counter_for_time()
    began = time.time()
    while totp.counter_for_time() == start_counter:
        time.sleep(0.2)
    return totp.totp(secret), time.time() - began


class Transcript:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.step = 0

    def heading(self, text: str) -> None:
        self.lines.append(f"\n## {text}\n")

    def note(self, text: str) -> None:
        self.lines.append(text + "\n")

    def exchange(self, method: str, path: str, response, *,
                 sent: dict | None = None, redact: bool = True) -> None:
        self.step += 1
        self.lines.append(f"\n### Step {self.step}: {method} {path}\n")
        self.lines.append("```http")
        self.lines.append(f"{method} {path}")
        if sent:
            shown = {k: ("<redacted>" if k in REDACT_KEYS or "password" in k else v)
                     for k, v in sent.items()}
            self.lines.append(f"form: {json.dumps(shown)}")
        self.lines.append("")
        self.lines.append(f"HTTP/1.1 {response.status_code} {response.reason}")
        for header in ("Location", "Set-Cookie", "Content-Security-Policy",
                       "Cache-Control", "X-Frame-Options",
                       "X-Content-Type-Options", "Referrer-Policy"):
            if header in response.headers:
                value = response.headers[header]
                if header == "Set-Cookie" and redact:
                    # Show the flags, not the session id: the transcript is a
                    # committed artefact and a live-looking session id in a
                    # committed file is a bad habit even when the database is
                    # thrown away at the end of the run.
                    parts = value.split(";")
                    parts[0] = parts[0].split("=")[0] + "=<redacted-256-bit-value>"
                    value = ";".join(parts)
                self.lines.append(f"{header}: {value}")
        body = response.text.strip()
        if body.startswith("{"):
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    parsed = {k: ("<redacted>" if k in REDACT_KEYS else v)
                              for k, v in parsed.items()}
                body = json.dumps(parsed, indent=2, sort_keys=True)
            except ValueError:
                pass
        if len(body) > 900:
            body = body[:900] + "\n...[truncated]"
        self.lines.append("")
        self.lines.append(body)
        self.lines.append("```")

    def write(self, path: str, header: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(header)
            fh.write("\n".join(self.lines))
            fh.write("\n")


def run(suite: Suite) -> dict[str, object]:
    t = Transcript()
    summary: dict[str, object] = {}

    # Breach check left ON here: this is the run that proves the real
    # registration path, including the HIBP call, works end to end.
    with AppServer(label="e2e") as server:
        config = server.config()
        t.note("Server started with default security settings, except the "
               "session cookie's Secure flag, which is cleared because this "
               "harness speaks plain HTTP over loopback and a Secure cookie is "
               "not sent to an http:// origin. Everything else is production "
               "default.")
        t.note("")
        t.note("Effective configuration:")
        t.note("```json")
        t.note(json.dumps(config, indent=2, sort_keys=True))
        t.note("```")

        client = Client(server)

        # --- 1. registration ------------------------------------------------
        t.heading("Registration")
        client.prime_csrf("/register")
        response = client.post_json("/register", {
            "username": E2E_USER, "password": TEST_PASSWORD,
            "confirm": TEST_PASSWORD, "csrf_token": client.csrf_token})
        t.exchange("POST", "/register", response,
                   sent={"username": E2E_USER, "password": "<redacted>",
                         "confirm": "<redacted>",
                         "csrf_token": "<redacted>"})
        suite.check("registration returns 201", response.status_code, 201)
        body = response.json()
        suite.check("registration reports created", body.get("created"), True)
        breach = body.get("breach") or {}
        suite.check("chosen password is not in the breach corpus",
                    breach.get("breached"), False)
        suite.note(f"HIBP: prefix {breach.get('prefix')}, "
                   f"{breach.get('candidates_returned')} candidate suffixes "
                   f"returned, available={breach.get('available')}")
        summary["hibp"] = breach

        # A breached password must be refused.
        rejected = Client(server)
        rejected.prime_csrf("/register")
        response = rejected.post_json("/register", {
            "username": "breach.probe", "password": "Password123!",
            "confirm": "Password123!", "csrf_token": rejected.csrf_token})
        t.exchange("POST", "/register", response,
                   sent={"username": "breach.probe",
                         "password": "<a known-breached password>",
                         "confirm": "<redacted>", "csrf_token": "<redacted>"})
        suite.check("a known-breached password is refused at registration",
                    response.status_code, 400)
        summary["breached_password_rejected"] = response.status_code == 400

        # --- 2. password-only login ------------------------------------------
        t.heading("Login, password only (no second factor yet)")
        pre_login_sid = client.sid
        client.prime_csrf("/login")
        response = client.login(E2E_USER, TEST_PASSWORD)
        t.exchange("POST", "/login", response,
                   sent={"username": E2E_USER, "password": "<redacted>",
                         "csrf_token": "<redacted>"})
        suite.check("login succeeds", response.json().get("authenticated"), True)
        post_login_sid = client.sid
        suite.check_true("session id changed on login", pre_login_sid != post_login_sid)
        t.note(f"\nSession id rotated on login: pre-login and post-login "
               f"identifiers differ ({'yes' if pre_login_sid != post_login_sid else 'no'}).")

        # --- 3. protected page ------------------------------------------------
        t.heading("Protected page")
        response = client.dashboard()
        t.exchange("GET", "/dashboard", response)
        suite.check("dashboard reachable when authenticated",
                    response.status_code, 200)
        suite.check("dashboard reports the right user",
                    response.json().get("username"), E2E_USER)

        # --- 4. TOTP enrolment ------------------------------------------------
        t.heading("TOTP enrolment")
        enrol = client.get_json("/2fa/enrol")
        t.exchange("GET", "/2fa/enrol", enrol)
        enrol_body = enrol.json()
        secret_b32 = enrol_body["secret_b32"]
        secret = totp.b32decode(secret_b32)
        suite.check("enrolment returns a 160-bit secret", len(secret) * 8, 160)
        suite.check_true("provisioning URI is an otpauth:// TOTP URI",
                         enrol_body["otpauth_uri"].startswith("otpauth://totp/"))
        t.note("\nThe base32 secret and otpauth:// URI are redacted above. The "
               "secret is 160 bits, the length RFC 4226 section 4 recommends.")

        # Enrolment is not complete until a code proves the secret round-trips.
        client.csrf_token = enrol_body["csrf_token"]
        code = totp.totp(secret)
        response = client.post_json("/2fa/enrol",
                                    {"code": code, "csrf_token": client.csrf_token})
        t.exchange("POST", "/2fa/enrol", response,
                   sent={"code": "<current 6-digit code>",
                         "csrf_token": "<redacted>"})
        suite.check("2FA enabled after a valid code", response.status_code, 200)
        suite.check("2FA enabled flag", response.json().get("enabled"), True)
        client.csrf_token = response.json()["csrf_token"]
        enrolled_sid = client.sid
        suite.check_true("session id rotated when 2FA was enabled",
                         enrolled_sid != post_login_sid)

        response = client.dashboard()
        suite.check("dashboard shows 2FA on",
                    response.json().get("totp_enabled"), True)

        # --- 5. log out, then log in again through the 2FA gate ---------------
        t.heading("Logout and a fresh login through the second factor")
        response = client.logout()
        t.exchange("POST", "/logout", response,
                   sent={"csrf_token": "<redacted>"})
        suite.check("logout returns 200", response.status_code, 200)

        second = Client(server)
        second.prime_csrf("/login")
        response = second.login(E2E_USER, TEST_PASSWORD)
        t.exchange("POST", "/login", response,
                   sent={"username": E2E_USER, "password": "<redacted>",
                         "csrf_token": "<redacted>"})
        first_step = response.json()
        suite.check("password step does not authenticate on its own",
                    first_step.get("authenticated"), False)
        suite.check("password step demands the second factor",
                    first_step.get("totp_required"), True)

        # A session stuck at the password step must reach nothing.
        blocked = second.dashboard()
        t.exchange("GET", "/dashboard", blocked)
        suite.check("pending-2FA session cannot read the protected page",
                    blocked.status_code, 401)

        # Wait out the step the enrolment code was spent in -- see
        # code_in_next_step() for why this is the app being right, not lenient.
        code, waited = code_in_next_step(totp.b32decode(secret_b32))
        t.note(f"\nWaited {waited:.1f}s for the TOTP counter to advance past the "
               "one consumed during enrolment. The replay guard refuses a spent "
               "counter, so a code from the enrolment step would be rejected "
               "here -- correctly.")
        summary["waited_for_step_boundary_s"] = round(waited, 2)
        response = second.submit_totp(code)
        t.exchange("POST", "/login/2fa", response,
                   sent={"code": "<current 6-digit code>",
                         "csrf_token": "<redacted>"})
        suite.check("valid TOTP code completes authentication",
                    response.json().get("authenticated"), True)

        # Replay the very same code: must fail even though it is still inside
        # its 30 second step.
        third = Client(server)
        third.prime_csrf("/login")
        third.login(E2E_USER, TEST_PASSWORD)
        replay = third.submit_totp(code)
        t.exchange("POST", "/login/2fa", replay,
                   sent={"code": "<the code just used>",
                         "csrf_token": "<redacted>"})
        suite.check("replaying an already-used code is refused",
                    replay.status_code, 401)
        summary["totp_replay_refused"] = replay.status_code == 401

        response = second.dashboard()
        t.exchange("GET", "/dashboard", response)
        suite.check("protected page reachable after 2FA", response.status_code, 200)

        # --- 6. logout kills the session server-side --------------------------
        t.heading("Logout invalidates the session server-side")
        dead_sid = second.sid
        response = second.logout()
        t.exchange("POST", "/logout", response, sent={"csrf_token": "<redacted>"})
        suite.check("logout returns 200", response.status_code, 200)

        # Present the old cookie by hand. A client that kept the cookie must
        # still be locked out, because the row is gone.
        import requests as _requests
        raw = _requests.get(server.base + "/dashboard",
                            headers={"Accept": "application/json"},
                            cookies={"sls_sid": dead_sid},
                            allow_redirects=False, timeout=30)
        t.exchange("GET", "/dashboard", raw)
        t.note("\nThe request above deliberately re-presents the pre-logout "
               "session cookie. It is refused because logout deleted the "
               "server-side row, not merely asked the browser to forget it.")
        suite.check("the pre-logout session id is no longer honoured",
                    raw.status_code, 401)
        summary["logout_invalidates_server_side"] = raw.status_code == 401

        # --- 7. session bookkeeping ------------------------------------------
        t.heading("Session table sweep")
        response = client.http.post(server.base + "/admin/maintenance",
                                    headers={"Accept": "application/json"},
                                    timeout=30)
        t.exchange("POST", "/admin/maintenance", response)
        suite.check("maintenance endpoint responds", response.status_code, 200)
        summary["db_stats_after_run"] = response.json().get("stats")

        t.note(f"\nCaptured {t.step} HTTP exchanges at "
               f"{time.strftime('%Y-%m-%d %H:%M:%S')} local time.")

    header = (
        "# Live session transcript\n\n"
        "Produced by `python tests/test_e2e.py`. Every exchange below is a real "
        "HTTP request against a freshly started instance of the app with a "
        "throwaway SQLite database. Session identifiers, CSRF tokens, TOTP "
        "secrets and passwords are redacted; status lines, headers and "
        "everything else are verbatim.\n\n"
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} local time.\n")
    t.write(TRANSCRIPT_PATH, header)
    suite.note(f"transcript written to {TRANSCRIPT_PATH}")
    return summary


if __name__ == "__main__":
    suite = Suite("End-to-end: register, login, 2FA, protected page, logout")
    run(suite)
    sys.exit(suite.finish())
