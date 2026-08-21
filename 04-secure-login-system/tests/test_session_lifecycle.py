"""Cookie flags, idle timeout, absolute timeout, CSRF, and response headers.

The two timeouts are tested separately because they stop different things and a
common bug is to implement one and believe you have both:

  idle     -- an unattended browser stops being a way in.
  absolute -- a stolen identifier expires even if the thief keeps it warm. A
              server with only an idle timeout gives an attacker who holds a
              cookie an indefinitely renewable session.

The timeout tests run servers with the timeouts set to a few seconds via
environment variables. Nothing about the mechanism changes; only the constants.
"""

from __future__ import annotations

import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.harness import Suite  # noqa: E402
from tests.server import AppServer, Client, TEST_PASSWORD  # noqa: E402

USER = "lifecycle.user"


def parse_set_cookie(raw: str) -> dict[str, str]:
    """Flags from a Set-Cookie header, lowercased keys, '' for valueless flags."""
    out: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        out[key.strip().lower()] = value.strip()
    return out


def run(suite: Suite) -> dict[str, object]:
    results: dict[str, object] = {}

    suite.section("Cookie flags at the production default")
    # No --insecure-cookies here, so this is exactly what a deployment emits.
    # The client cannot log in over plain HTTP with a Secure cookie, which is
    # the point: we only need the Set-Cookie header the server produces.
    with AppServer(extra_args=["--no-breach-check"], label="cookie-flags",
                   production_cookies=True) as server:
        response = requests.get(server.base + "/", timeout=30,
                                allow_redirects=False)
        raw = response.headers.get("Set-Cookie", "")
        suite.note(f"Set-Cookie: {raw}")
        flags = parse_set_cookie(raw)
        suite.check_true("HttpOnly is set (no JS access to the session id)",
                         "httponly" in flags)
        suite.check_true("Secure is set by default (cookie never sent over HTTP)",
                         "secure" in flags)
        suite.check("SameSite is Lax", flags.get("samesite"), "Lax")
        suite.check("Path is /", flags.get("path"), "/")
        suite.check_true("no Expires/Max-Age, so it dies with the browser",
                         "expires" not in flags and "max-age" not in flags)
        results["cookie_flags"] = {k: v for k, v in flags.items()
                                   if k != "sls_sid"}

        # Proof the flag has teeth rather than merely being present in a header.
        # A client stores a Secure cookie it was given but must not SEND it back
        # over plain HTTP, so the server never sees a session on the second
        # request and issues yet another new one. That is why every other test
        # here runs with --insecure-cookies: over loopback HTTP no session can
        # be carried at all.
        http = requests.Session()
        first = http.get(server.base + "/login", timeout=30)
        second = http.get(server.base + "/login", timeout=30)
        first_sid = parse_set_cookie(first.headers.get("Set-Cookie", "")).get("sls_sid")
        second_sid = parse_set_cookie(second.headers.get("Set-Cookie", "")).get("sls_sid")
        suite.note("the client stores the Secure cookie but withholds it on the "
                   "next plain-HTTP request, so the server issues a new one")
        suite.check_true("a Secure cookie is not returned over HTTP, so the "
                         "server issues a fresh session on the second request",
                         bool(second_sid) and second_sid != first_sid)

        suite.section("Security response headers")
        for header, expected in [
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer")]:
            suite.check(header, response.headers.get(header), expected)
        csp = response.headers.get("Content-Security-Policy", "")
        suite.check_true("CSP default-src 'none'", "default-src 'none'" in csp)
        suite.check_true("CSP frame-ancestors 'none'", "frame-ancestors 'none'" in csp)
        suite.check_true("CSP form-action 'self'", "form-action 'self'" in csp)
        cache = response.headers.get("Cache-Control", "")
        suite.check_true("Cache-Control no-store", "no-store" in cache)
        results["headers"] = {
            "csp": csp,
            "cache_control": cache,
            "x_frame_options": response.headers.get("X-Frame-Options"),
        }

    suite.section("Idle timeout")
    idle_s = 3
    with AppServer(extra_args=["--no-breach-check"],
                   env={"SLS_IDLE_TIMEOUT_S": str(idle_s)},
                   label="idle") as server:
        suite.check("configured idle timeout",
                    server.config()["session"]["idle_timeout_s"], idle_s)
        client = Client(server)
        client.register(USER, TEST_PASSWORD)
        client.login(USER, TEST_PASSWORD)
        suite.check("authenticated immediately after login",
                    client.dashboard().status_code, 200)

        # A request inside the window must keep it alive, or the "idle" timeout
        # is really an absolute one wearing the wrong name.
        time.sleep(idle_s * 0.5)
        suite.check("a request inside the idle window is served",
                    client.dashboard().status_code, 200)
        time.sleep(idle_s * 0.5)
        suite.check("and that request reset the idle clock",
                    client.dashboard().status_code, 200)

        time.sleep(idle_s + 1.0)
        suite.check("session is dead after sitting idle past the timeout",
                    client.dashboard().status_code, 401)
        results["idle_timeout"] = {"configured_s": idle_s, "expired": True,
                                  "refreshed_by_activity": True}

    suite.section("Absolute timeout")
    absolute_s = 6
    with AppServer(extra_args=["--no-breach-check"],
                   env={"SLS_ABSOLUTE_TIMEOUT_S": str(absolute_s),
                        "SLS_IDLE_TIMEOUT_S": "1800"},
                   label="absolute") as server:
        config = server.config()["session"]
        suite.check("configured absolute timeout",
                    config["absolute_timeout_s"], absolute_s)
        suite.check("idle timeout is much longer, so only the absolute one "
                    "can fire", config["idle_timeout_s"], 1800)

        client = Client(server)
        client.register(USER, TEST_PASSWORD)
        client.login(USER, TEST_PASSWORD)

        # Stay continuously active. With only an idle timeout this session would
        # live forever; the absolute timeout must kill it anyway.
        polls = 0
        deadline = time.time() + absolute_s + 2.0
        last_status = 200
        while time.time() < deadline:
            last_status = client.dashboard().status_code
            polls += 1
            if last_status != 200:
                break
            time.sleep(0.8)
        suite.note(f"polled the protected page {polls} times, staying active "
                   "throughout")
        suite.check("a continuously active session still expires at the "
                    "absolute limit", last_status, 401)
        results["absolute_timeout"] = {"configured_s": absolute_s,
                                      "polls_before_expiry": polls,
                                      "expired_while_active": last_status == 401}

    suite.section("CSRF")
    with AppServer(extra_args=["--no-breach-check"], label="csrf") as server:
        client = Client(server)
        client.register(USER, TEST_PASSWORD)

        client.prime_csrf("/login")
        good_token = client.csrf_token
        suite.check_true("a CSRF token is bound to the anonymous session",
                         bool(good_token))

        missing = client.post_json("/login", {"username": USER,
                                             "password": TEST_PASSWORD})
        suite.check("login without a CSRF token is refused",
                    missing.status_code, 403)
        wrong = client.post_json("/login", {"username": USER,
                                            "password": TEST_PASSWORD,
                                            "csrf_token": "not-the-token"})
        suite.check("login with a wrong CSRF token is refused",
                    wrong.status_code, 403)
        ok = client.login(USER, TEST_PASSWORD, csrf_token=good_token)
        suite.check("login with the right CSRF token succeeds",
                    ok.json().get("authenticated"), True)

        # The token rotates with the session, so the pre-login token must not
        # still work on a post-login action.
        stale = client.http.post(server.base + "/logout",
                                 headers={"Accept": "application/json"},
                                 data={"csrf_token": good_token}, timeout=30)
        suite.check("the pre-login CSRF token does not work after rotation",
                    stale.status_code, 403)
        suite.check("logout with the current token works",
                    client.logout().status_code, 200)

        suite.check("GET /logout is not routed (a GET logout would be CSRF-able)",
                    requests.get(server.base + "/logout",
                                 headers={"Accept": "application/json"},
                                 timeout=30).status_code, 405)
        results["csrf"] = {"missing_token": 403, "wrong_token": 403,
                          "stale_token_after_rotation": 403,
                          "get_logout_not_allowed": 405}

    return results


if __name__ == "__main__":
    suite = Suite("Session lifecycle: cookies, timeouts, CSRF, headers")
    run(suite)
    sys.exit(suite.finish())
