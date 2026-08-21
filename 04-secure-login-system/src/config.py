"""Configuration, with the security-relevant constants gathered in one place.

Every value here is a judgement call, so each one carries its reason. The
defaults are the safe ones; the knobs that weaken the app exist only so the
measurement harnesses can produce a before/after comparison, and each of those
is loud about what it does.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


@dataclass
class Config:
    # --- Argon2id, RFC 9106 section 4, SECOND RECOMMENDED option ---------------
    # "If much less memory is available, a uniformly safe option is Argon2id
    #  with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of RAM), 128-bit salt,
    #  and 256-bit tag size."
    # We take the second option and not the first (t=1, m=2 GiB) because the
    # first one cannot be run concurrently on a normal machine: 2 GiB per
    # in-flight login means four simultaneous attempts exhaust 8 GiB of RAM.
    # See outputs/reports/findings.md for the measured numbers behind that.
    argon2_time_cost: int = _env_int("SLS_ARGON2_TIME_COST", 3)
    argon2_memory_cost_kib: int = _env_int("SLS_ARGON2_MEMORY_KIB", 65536)  # 2^16 KiB
    argon2_parallelism: int = _env_int("SLS_ARGON2_PARALLELISM", 4)
    argon2_salt_bytes: int = 16   # 128-bit salt, per the same recommendation
    argon2_hash_bytes: int = 32   # 256-bit tag, per the same recommendation

    # Cap on Argon2 operations in flight at once, which is what actually bounds
    # peak memory: max_concurrent x 64 MiB. Default 4 because that is where
    # bench/bench_argon2.py measured throughput on this machine stopping to
    # improve; beyond it, concurrency bought latency and memory and nothing
    # else. Set to a large number to effectively disable, which the benchmark
    # does for its no-cap arm.
    argon2_max_concurrent: int = _env_int("SLS_ARGON2_MAX_CONCURRENT", 4)
    # How long a request will wait for a slot before being refused with 503.
    # Long enough to absorb a burst, short enough that a client is not left
    # hanging; a refusal with Retry-After is more useful than a timeout.
    argon2_queue_timeout_s: float = float(
        os.environ.get("SLS_ARGON2_QUEUE_TIMEOUT_S", "5.0"))

    # --- Password and username policy ----------------------------------------
    # NIST SP 800-63B rev 3 section 5.1.1.2: memorised secrets SHALL be at least
    # 8 characters and SHOULD permit at least 64. We set the floor at 12 because
    # 8 is a 2017-era floor and offline cracking has not got slower, and the
    # ceiling at 128 to bound the input we feed Argon2 (a 10 MB "password" is a
    # cheap way to make the server do work).
    password_min_length: int = 12
    password_max_length: int = 128
    username_min_length: int = 3
    username_max_length: int = 32

    # SP 800-63B section 5.1.1.2 says verifiers SHOULD NOT impose composition
    # rules (one upper, one digit, one symbol). We follow that: composition rules
    # push users to Password1! and buy nothing measurable. We check the password
    # against a breach corpus instead, which is what the same section recommends.
    require_breach_check: bool = _env_flag("SLS_BREACH_CHECK", True)
    hibp_timeout_s: float = 5.0

    # --- Session management ---------------------------------------------------
    session_id_bytes: int = 32          # 256 bits from secrets.token_urlsafe
    session_cookie_name: str = "sls_sid"
    # Idle timeout: a session unused for this long is dead. 30 minutes is the
    # usual figure for a low-value app; it is short enough that a walked-away
    # browser is not a standing invitation.
    session_idle_timeout_s: int = _env_int("SLS_IDLE_TIMEOUT_S", 1800)
    # Absolute timeout: even a continuously active session dies at 8 hours.
    # Without this, a stolen session id is valid forever as long as the thief
    # keeps it warm, which is exactly what an attacker with a stolen cookie does.
    session_absolute_timeout_s: int = _env_int("SLS_ABSOLUTE_TIMEOUT_S", 28800)
    # Cookie flags. Secure defaults ON. It has to be switchable because the
    # local dev server speaks plain HTTP and a Secure cookie is simply not sent
    # over HTTP, so the end-to-end harness could never log in. Turning it off is
    # a development-only action and the app logs a warning when it happens.
    cookie_secure: bool = _env_flag("SLS_COOKIE_SECURE", True)
    cookie_httponly: bool = True        # no reason for JS to read the session id
    # SameSite=Lax, not Strict: Strict breaks the "click a link in your email and
    # arrive logged in" flow, and Lax already stops the cross-site POST that CSRF
    # needs. We also carry a synchroniser token, so Lax is belt and braces.
    cookie_samesite: str = "Lax"

    # --- Rate limiting / lockout ---------------------------------------------
    rate_limit_enabled: bool = _env_flag("SLS_RATE_LIMIT", True)
    # Per submitted username. Keyed on the string the client sent, NOT on a
    # resolved user id -- see findings.md; keying on the resolved user turns the
    # lockout itself into a user-enumeration oracle, because only real accounts
    # could ever be locked.
    lockout_threshold: int = _env_int("SLS_LOCKOUT_THRESHOLD", 5)
    lockout_window_s: int = _env_int("SLS_LOCKOUT_WINDOW_S", 900)
    lockout_duration_s: int = _env_int("SLS_LOCKOUT_DURATION_S", 900)
    # Per source IP, a coarser net to catch spraying across many usernames.
    ip_limit_threshold: int = _env_int("SLS_IP_THRESHOLD", 30)
    ip_limit_window_s: int = _env_int("SLS_IP_WINDOW_S", 300)

    # --- TOTP ----------------------------------------------------------------
    totp_digits: int = 6
    totp_step_s: int = 30
    totp_skew_steps: int = 1             # +/- one step; justified in src/totp.py
    totp_algorithm: str = "sha1"         # what every authenticator app supports
    totp_issuer: str = "SecureLoginSystem"

    # --- User-enumeration mitigation -----------------------------------------
    # ON by default. The off switch exists solely so tests/test_enumeration.py
    # can measure the leak it prevents; there is no production reason to set it.
    enum_mitigation: bool = _env_flag("SLS_ENUM_MITIGATION", True)

    # --- The dangerous one ---------------------------------------------------
    # Mounts /demo/vulnerable/login, which builds SQL by string concatenation
    # against a table of PLAINTEXT passwords. It exists to demonstrate the
    # difference against the real endpoint and it must never be enabled anywhere
    # that is reachable from a network you do not own. Off unless explicitly
    # asked for on the command line.
    demo_vulnerable: bool = False

    database_path: str = os.environ.get("SLS_DB", "app.db")
    # Auth state lives in the server-side sessions table, not in a signed
    # cookie, so this key is not what protects a session. It is generated fresh
    # at each start unless SLS_SECRET_KEY is set, which means no secret is ever
    # written to disk or committed; the cost is that Flask-internal signed
    # values do not survive a restart, which nothing here depends on.
    secret_key: bytes = field(
        default_factory=lambda: (
            os.environ["SLS_SECRET_KEY"].encode("utf-8")
            if os.environ.get("SLS_SECRET_KEY") else secrets.token_bytes(32)))
    secret_key_from_env: bool = field(
        default_factory=lambda: bool(os.environ.get("SLS_SECRET_KEY")))

    def argon2_memory_mib(self) -> float:
        return self.argon2_memory_cost_kib / 1024

    def describe(self) -> dict[str, object]:
        """Everything worth putting in a report. Never includes the secret key."""
        return {
            "argon2": {
                "type": "Argon2id",
                "time_cost_t": self.argon2_time_cost,
                "memory_cost_kib": self.argon2_memory_cost_kib,
                "memory_cost_mib": self.argon2_memory_mib(),
                "parallelism_p": self.argon2_parallelism,
                "salt_bytes": self.argon2_salt_bytes,
                "hash_bytes": self.argon2_hash_bytes,
                "source": "RFC 9106 section 4, second recommended option",
                "max_concurrent": self.argon2_max_concurrent,
                "queue_timeout_s": self.argon2_queue_timeout_s,
                "bounded_peak_transient_mib": round(
                    self.argon2_max_concurrent * self.argon2_memory_mib(), 1),
            },
            "session": {
                "id_bits": self.session_id_bytes * 8,
                "idle_timeout_s": self.session_idle_timeout_s,
                "absolute_timeout_s": self.session_absolute_timeout_s,
                "cookie_secure": self.cookie_secure,
                "cookie_httponly": self.cookie_httponly,
                "cookie_samesite": self.cookie_samesite,
            },
            "rate_limit": {
                "enabled": self.rate_limit_enabled,
                "lockout_threshold": self.lockout_threshold,
                "lockout_window_s": self.lockout_window_s,
                "lockout_duration_s": self.lockout_duration_s,
                "ip_threshold": self.ip_limit_threshold,
                "ip_window_s": self.ip_limit_window_s,
            },
            "totp": {
                "digits": self.totp_digits,
                "step_s": self.totp_step_s,
                "skew_steps": self.totp_skew_steps,
                "acceptance_window_s": (2 * self.totp_skew_steps + 1) * self.totp_step_s,
                "algorithm": self.totp_algorithm,
            },
            "policy": {
                "password_min_length": self.password_min_length,
                "password_max_length": self.password_max_length,
                "breach_check": self.require_breach_check,
                "composition_rules": False,
            },
            "enum_mitigation": self.enum_mitigation,
            "demo_vulnerable_endpoint_mounted": self.demo_vulnerable,
            "secret_key_source": "SLS_SECRET_KEY env var" if self.secret_key_from_env
                                 else "generated at runtime (secrets.token_bytes)",
        }
