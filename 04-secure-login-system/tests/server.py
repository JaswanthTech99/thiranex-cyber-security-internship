"""Start the real app in a subprocess and talk to it over HTTP.

The tests could use Flask's test client, which would be faster and simpler. They
deliberately do not, for two reasons:

  - The enumeration measurement is about wall-clock latency as an attacker
    observes it. A test client short-circuits the socket, so it measures a
    different thing.
  - Firing SQL-injection payloads through a test client proves the payloads
    reach the view function. Firing them over HTTP also exercises the WSGI
    layer's parsing, which is where some payloads would otherwise be mangled.

Every helper here takes the app's own path through registration and login, so
the tests cannot accidentally pass by poking the database directly.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_HEADERS = {"Accept": "application/json"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class AppServer:
    """A running instance of the app, with its own throwaway database."""

    def __init__(self, *, extra_args: list[str] | None = None,
                 env: dict[str, str] | None = None, label: str = "app",
                 production_cookies: bool = False) -> None:
        self.label = label
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.tempdir = tempfile.mkdtemp(prefix="sls-test-")
        self.db_path = os.path.join(self.tempdir, "test.db")
        # By default the harness passes --insecure-cookies, because it speaks
        # plain HTTP over loopback and `requests` (like every browser) will not
        # send a Secure cookie to an http:// origin, so no test could ever log
        # in. Pass production_cookies=True to check the real default; such a
        # server can be inspected for its Set-Cookie header but cannot be
        # logged into over HTTP, which is the flag working as intended.
        self.args = [sys.executable, "run.py",
                     "--port", str(self.port),
                     "--db", self.db_path]
        if not production_cookies:
            self.args.append("--insecure-cookies")
        self.args += (extra_args or [])
        self.production_cookies = production_cookies
        self.env = {**os.environ, **(env or {})}
        self.proc: subprocess.Popen | None = None
        self.stderr_path = os.path.join(self.tempdir, "stderr.log")

    def __enter__(self) -> "AppServer":
        self._stderr = open(self.stderr_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            self.args, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL,
            stderr=self._stderr, env=self.env)
        self._wait_ready()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._stderr.close()
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def _wait_ready(self, timeout: float = 40.0) -> None:
        deadline = time.time() + timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError(
                    f"server '{self.label}' exited with code {self.proc.returncode}; "
                    f"stderr:\n{self.stderr_text()}")
            try:
                r = requests.get(self.base + "/healthz", timeout=3)
                if r.status_code == 200:
                    return
            except requests.RequestException as exc:
                last_error = exc
            time.sleep(0.15)
        raise RuntimeError(f"server '{self.label}' did not become ready: "
                           f"{last_error}\nstderr:\n{self.stderr_text()}")

    def stderr_text(self) -> str:
        try:
            with open(self.stderr_path, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return "<unavailable>"

    def config(self) -> dict[str, Any]:
        return requests.get(self.base + "/healthz", timeout=5).json()["config"]


class Client:
    """A browser-ish client: keeps cookies, tracks the CSRF token."""

    def __init__(self, server: AppServer) -> None:
        self.server = server
        self.http = requests.Session()
        self.csrf_token: str | None = None

    @property
    def sid(self) -> str | None:
        return self.http.cookies.get("sls_sid")

    def url(self, path: str) -> str:
        return self.server.base + path

    def get_json(self, path: str, **kwargs: Any) -> requests.Response:
        return self.http.get(self.url(path), headers=JSON_HEADERS,
                             timeout=30, **kwargs)

    def post_json(self, path: str, data: dict[str, Any],
                  **kwargs: Any) -> requests.Response:
        return self.http.post(self.url(path), data=data, headers=JSON_HEADERS,
                              timeout=60, allow_redirects=False, **kwargs)

    def prime_csrf(self, path: str = "/login") -> str:
        """Fetch a page to obtain an anonymous session and its CSRF token."""
        body = self.get_json(path).json()
        self.csrf_token = body.get("csrf_token")
        return self.csrf_token

    def register(self, username: str, password: str,
                 confirm: str | None = None) -> requests.Response:
        self.prime_csrf("/register")
        return self.post_json("/register", {
            "username": username, "password": password,
            "confirm": password if confirm is None else confirm,
            "csrf_token": self.csrf_token})

    def login(self, username: str, password: str,
              csrf_token: str | None = None) -> requests.Response:
        if csrf_token is None:
            if self.csrf_token is None:
                self.prime_csrf("/login")
            csrf_token = self.csrf_token
        response = self.post_json("/login", {
            "username": username, "password": password,
            "csrf_token": csrf_token})
        # Successful auth rotates the session and hands back a new CSRF token.
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if isinstance(payload, dict) and payload.get("csrf_token"):
            self.csrf_token = payload["csrf_token"]
        return response

    def submit_totp(self, code: str) -> requests.Response:
        response = self.post_json("/login/2fa",
                                  {"code": code, "csrf_token": self.csrf_token})
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if isinstance(payload, dict) and payload.get("csrf_token"):
            self.csrf_token = payload["csrf_token"]
        return response

    def start_enrolment(self) -> dict[str, Any]:
        body = self.get_json("/2fa/enrol").json()
        if body.get("csrf_token"):
            self.csrf_token = body["csrf_token"]
        return body

    def confirm_enrolment(self, code: str) -> requests.Response:
        response = self.post_json("/2fa/enrol",
                                  {"code": code, "csrf_token": self.csrf_token})
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if isinstance(payload, dict) and payload.get("csrf_token"):
            self.csrf_token = payload["csrf_token"]
        return response

    def dashboard(self) -> requests.Response:
        return self.get_json("/dashboard", allow_redirects=False)

    def logout(self) -> requests.Response:
        return self.post_json("/logout", {"csrf_token": self.csrf_token})


# A password that is long, unique to this project, and therefore absent from the
# breach corpus. Tests that need registration to succeed use it.
TEST_PASSWORD = "thiranex-sls-2026-correct-horse-42"
