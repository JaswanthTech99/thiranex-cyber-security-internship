"""Rate limiting and account lockout.

This is the mitigation for trap 3 as much as it is an anti-brute-force control.
Each login attempt costs an Argon2id verify: 64 MiB of RAM and tens of
milliseconds of four-way-parallel CPU. That is deliberate against an offline
cracker and it is a gift to anyone who wants to exhaust the server, because the
attacker pays nothing and the server pays 64 MiB per in-flight request. An
unauthenticated endpoint that allocates 64 MiB on demand is a DoS primitive.
Rate limiting is what puts a ceiling on it.

The important design decision: the counter is keyed on the SUBMITTED username
string, not on a resolved user id.

Keying on a resolved user is the obvious implementation and it is a user
enumeration oracle. Only a real account can be locked, so an attacker sends six
bad passwords for "alice" and six for "alicx": if "alice" starts answering "too
many attempts" and "alicx" keeps answering "invalid credentials", the attacker
has learned which one exists -- and this time timing had nothing to do with it,
so the dummy-hash fix from passwords.py does not help. Keying on the raw string
means every username the attacker tries locks out identically, real or not.

The cost of that choice, stated honestly: an attacker can lock out a known
username by spraying it. That is a real denial of service against one account
and it is the standard trade-off of any lockout scheme. The mitigations are the
finite lockout duration (15 minutes, not permanent) and the fact that a
legitimate user's successful login clears their failure count. For a system
where locking a user out is worse than the enumeration leak, the answer is a
proof-of-work or CAPTCHA step instead of a lockout, not a lockout keyed on
resolved users.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from . import db
from .config import Config


@dataclass
class LimitDecision:
    allowed: bool
    reason: str | None = None
    retry_after_s: int = 0
    username_failures: int = 0
    ip_failures: int = 0


class RateLimiter:
    def __init__(self, config: Config) -> None:
        self.config = config

    def check(self, conn: sqlite3.Connection, username: str,
              ip: str | None) -> LimitDecision:
        if not self.config.rate_limit_enabled:
            # Off only for the measurement harnesses, which need to fire
            # hundreds of requests to say anything statistically. Never off in
            # a normal run; the app warns on startup when it is.
            return LimitDecision(True, reason="rate limiting disabled")

        now = time.time()
        username_failures = db.count_recent_failures(
            conn, "username", username, now - self.config.lockout_window_s)
        ip_failures = 0
        if ip:
            ip_failures = db.count_recent_failures(
                conn, "ip", ip, now - self.config.ip_limit_window_s)

        if username_failures >= self.config.lockout_threshold:
            return LimitDecision(
                False, "account_locked", self.config.lockout_duration_s,
                username_failures, ip_failures)
        if ip and ip_failures >= self.config.ip_limit_threshold:
            return LimitDecision(
                False, "ip_throttled", self.config.ip_limit_window_s,
                username_failures, ip_failures)
        return LimitDecision(True, None, 0, username_failures, ip_failures)

    def record_failure(self, conn: sqlite3.Connection, username: str,
                       ip: str | None) -> None:
        db.record_attempt(conn, username, ip, "failure")

    def record_success(self, conn: sqlite3.Connection, username: str,
                       ip: str | None) -> None:
        db.record_attempt(conn, username, ip, "success")
        # Clearing on success is what keeps a real user from being permanently
        # locked out by a low-rate sprayer: one good login resets the window.
        db.clear_failures_for_username(conn, username)
