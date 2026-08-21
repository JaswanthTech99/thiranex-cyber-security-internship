"""Server-side session management.

Design, and why it is not Flask's default signed-cookie session:

  A signed cookie session cannot be revoked. Flask's default session puts the
  state in the cookie and signs it; the server keeps nothing, so "log out" can
  only mean "ask the browser nicely to drop the cookie". Anyone who copied the
  cookie beforehand still holds a valid session, and there is no server-side
  record to delete. The task asks for server-side invalidation on logout, and
  that requires the server to hold the authoritative record. So: an opaque
  random session id in the cookie, all state in the `sessions` table.

  The cookie holds a 256-bit `secrets.token_urlsafe` value. The table stores
  only SHA-256 of it. That way a leaked database (backup, SQL-injection read,
  log file) does not hand over live sessions -- the same reason password hashes
  exist. There is no work factor because a 256-bit random value has no
  dictionary to attack. It also means lookup is by primary key on the hash, so
  there is no string comparison whose timing could leak.

  auth_level makes the 2FA step real. A session is 'anonymous', then
  'pending_2fa' after the password checks out, then 'authenticated' after the
  TOTP code. Every protected page demands 'authenticated', so a client that
  stops after the password step holds a session that can reach nothing but the
  2FA form. Storing "password was OK" in a cookie the client controls is the
  classic way this gets broken.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass

from . import db
from .config import Config

ANONYMOUS = "anonymous"
PENDING_2FA = "pending_2fa"
AUTHENTICATED = "authenticated"


def hash_sid(sid: str) -> str:
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


@dataclass
class SessionRecord:
    sid_hash: str
    user_id: int | None
    auth_level: str
    csrf_token: str
    created_at: float
    last_seen_at: float
    flash: str | None

    @property
    def is_authenticated(self) -> bool:
        return self.auth_level == AUTHENTICATED

    def age_s(self, now: float | None = None) -> float:
        return (now or time.time()) - self.created_at

    def idle_s(self, now: float | None = None) -> float:
        return (now or time.time()) - self.last_seen_at


class SessionManager:
    def __init__(self, config: Config) -> None:
        self.config = config

    def new_sid(self) -> str:
        return secrets.token_urlsafe(self.config.session_id_bytes)

    def create(self, conn: sqlite3.Connection, *, user_id: int | None = None,
               auth_level: str = ANONYMOUS, ip: str | None = None,
               user_agent: str | None = None) -> tuple[str, str]:
        """Create a session. Returns (raw sid for the cookie, csrf token)."""
        sid = self.new_sid()
        csrf_token = secrets.token_urlsafe(32)
        db.insert_session(conn, hash_sid(sid), user_id, auth_level, csrf_token,
                          ip, user_agent)
        return sid, csrf_token

    def rotate(self, conn: sqlite3.Connection, old_sid: str | None, *,
               user_id: int | None, auth_level: str, ip: str | None = None,
               user_agent: str | None = None) -> tuple[str, str]:
        """Issue a new session id and destroy the old one.

        This is the fix for trap 2 (session fixation). The attack: get a victim's
        browser to carry a session id the attacker already knows (via a link
        with a session parameter, a subdomain cookie, an XSS write) and then wait
        for the victim to log in. If the server keeps the same id and merely
        flips it to "logged in", the attacker's known id is now an authenticated
        session.

        The fix is that authentication issues a brand-new id and the old row is
        deleted, so the pre-login id is not merely stale, it does not exist.
        Called on every privilege change, not just login: anonymous ->
        pending_2fa -> authenticated, and again on 2FA enable/disable, because
        each of those is a change in what the session can do.
        """
        new_sid, csrf_token = self.create(
            conn, user_id=user_id, auth_level=auth_level, ip=ip,
            user_agent=user_agent)
        if old_sid:
            db.delete_session(conn, hash_sid(old_sid))
        return new_sid, csrf_token

    def load(self, conn: sqlite3.Connection, sid: str | None) -> SessionRecord | None:
        """Fetch and validate a session, enforcing both timeouts.

        Two timeouts, because they stop different things:
          - idle (last_seen_at): an unattended browser stops being a way in.
          - absolute (created_at): a stolen session id has a hard expiry even if
            the thief keeps it active. Without this, "stay logged in forever" is
            exactly what a cookie thief gets.
        An expired session is deleted here rather than just refused, so the
        table does not accumulate dead rows waiting for a sweeper.
        """
        if not sid:
            return None
        sid_hash = hash_sid(sid)
        row = db.get_session(conn, sid_hash)
        if row is None:
            return None

        now = time.time()
        if (now - row["last_seen_at"] > self.config.session_idle_timeout_s
                or now - row["created_at"] > self.config.session_absolute_timeout_s):
            db.delete_session(conn, sid_hash)
            return None

        db.touch_session(conn, sid_hash)
        return SessionRecord(
            sid_hash=row["sid_hash"], user_id=row["user_id"],
            auth_level=row["auth_level"], csrf_token=row["csrf_token"],
            created_at=row["created_at"], last_seen_at=now, flash=row["flash"])

    def destroy(self, conn: sqlite3.Connection, sid: str | None) -> None:
        if sid:
            db.delete_session(conn, hash_sid(sid))

    def destroy_all_for_user(self, conn: sqlite3.Connection, user_id: int) -> int:
        return db.delete_sessions_for_user(conn, user_id)

    def cookie_kwargs(self) -> dict[str, object]:
        return {
            "httponly": self.config.cookie_httponly,
            "secure": self.config.cookie_secure,
            "samesite": self.config.cookie_samesite,
            "path": "/",
            # No max_age/expires: a session cookie that dies with the browser.
            # The server-side absolute timeout is the real bound; a persistent
            # cookie would only widen the window for a stolen one.
        }
