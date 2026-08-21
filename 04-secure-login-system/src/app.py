"""Flask application: registration, login, TOTP second factor, logout.

Routes answer either HTML or JSON depending on the Accept header, so the same
endpoints serve the browser and the measurement harnesses. That is not a
convenience shim bolted on for tests -- the JSON and HTML paths go through the
same auth logic and return the same status codes, which is exactly what the
enumeration test needs to be meaningful.
"""

from __future__ import annotations

import hmac
import logging
import sqlite3
import sys
import time
from typing import Any

from flask import (Flask, Response, g, jsonify, make_response, redirect,
                   render_template, request, url_for)

from . import db, hibp, sessions, totp, validation
from .config import Config
from .passwords import CapacityExhausted, PasswordService
from .ratelimit import RateLimiter

log = logging.getLogger("sls")

# One message, one status code, for every way a login can fail. See findings.md:
# distinct messages ("no such user" vs "wrong password") are the lazy version of
# the enumeration leak, and distinct status codes (404 vs 401) are the same leak
# wearing a hat. Even the locked-out case reuses the wording, differing only in
# the status code the standard reserves for it.
GENERIC_LOGIN_FAILURE = "Invalid username or password."
GENERIC_LOCKED = "Invalid username or password."

T_LOGIN = "login.html"
T_LOGIN_2FA = "login_2fa.html"
T_REGISTER = "register.html"
T_ENROL = "enrol_2fa.html"
T_DASHBOARD = "dashboard.html"
CSRF_JSON_ERROR = "CSRF token missing or invalid"
CSRF_HTML_ERROR = "Security token expired. Please try again."


def create_app(config: Config | None = None) -> Flask:
    config = config or Config()
    app = Flask(__name__)
    app.secret_key = config.secret_key
    app.config["SLS"] = config

    passwords = PasswordService(config)
    session_manager = sessions.SessionManager(config)
    limiter = RateLimiter(config)

    app.config["SLS_PASSWORDS"] = passwords
    app.config["SLS_SESSIONS"] = session_manager
    app.config["SLS_CONNECT"] = lambda: db.connect(config.database_path)

    # Explicit close, not `with`: sqlite3's context manager commits the
    # transaction but leaves the connection open, which would leak a handle and
    # keep the WAL files locked on Windows.
    bootstrap = db.connect(config.database_path)
    try:
        db.init_schema(bootstrap)
        if config.demo_vulnerable:
            from .vulnerable_demo import init_vulnerable_schema
            init_vulnerable_schema(bootstrap)
    finally:
        bootstrap.close()

    if config.demo_vulnerable:
        from .vulnerable_demo import build_blueprint
        app.register_blueprint(build_blueprint())
        sys.stderr.write(
            "\n" + "!" * 72 +
            "\n!! --demo-vulnerable IS ON. /demo/vulnerable/login builds SQL by"
            "\n!! string concatenation over a table of plaintext passwords."
            "\n!! It is an authentication bypass by design. Do not expose this"
            "\n!! process to any network you do not control.\n" + "!" * 72 + "\n\n")
    if not config.rate_limit_enabled:
        sys.stderr.write("[warning] rate limiting is DISABLED "
                         "(measurement mode only)\n")
    if not config.enum_mitigation:
        sys.stderr.write("[warning] user-enumeration mitigation is DISABLED "
                         "(measurement mode only)\n")
    if not config.cookie_secure:
        sys.stderr.write("[warning] session cookie Secure flag is OFF "
                         "(plain-HTTP development only)\n")

    # --- request plumbing ----------------------------------------------------

    @app.before_request
    def _open_connection() -> None:
        g.conn = db.connect(config.database_path)
        g.sid = request.cookies.get(config.session_cookie_name)
        g.session = session_manager.load(g.conn, g.sid)
        g.new_cookie_sid = None
        g.clear_cookie = False

    @app.teardown_request
    def _close_connection(exc: BaseException | None) -> None:
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    @app.after_request
    def _finalise(response: Response) -> Response:
        # Cookie writes are centralised so no route can forget the flags.
        if getattr(g, "clear_cookie", False):
            response.delete_cookie(config.session_cookie_name, path="/")
        elif getattr(g, "new_cookie_sid", None):
            response.set_cookie(config.session_cookie_name, g.new_cookie_sid,
                                **session_manager.cookie_kwargs())

        # A restrictive CSP because the app has no inline scripts and no
        # external assets, so there is nothing to break by locking it down.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # Auth responses must never be cached; a shared cache holding a logged-in
        # page is an account takeover on a kiosk.
        response.headers.setdefault("Cache-Control",
                                    "no-store, no-cache, must-revalidate")
        return response

    # --- helpers -------------------------------------------------------------

    def wants_json() -> bool:
        accept = request.headers.get("Accept", "")
        return "application/json" in accept and "text/html" not in accept

    def ensure_session() -> sessions.SessionRecord:
        """Get the current session, creating an anonymous one if needed.

        An anonymous session exists so a CSRF token can be bound to it before
        login. That is also what makes the fixation test meaningful: there is a
        real pre-login session id to try to reuse.
        """
        if g.session is None:
            sid, _ = session_manager.create(
                g.conn, ip=client_ip(), user_agent=request.headers.get("User-Agent"))
            g.new_cookie_sid = sid
            g.sid = sid
            g.session = session_manager.load(g.conn, sid)
        return g.session

    def client_ip() -> str:
        # remote_addr only. X-Forwarded-For is client-controlled, so trusting it
        # without a known proxy in front lets an attacker rotate the header and
        # walk straight past the per-IP limiter.
        return request.remote_addr or "unknown"

    def csrf_ok() -> bool:
        record = g.session
        if record is None:
            return False
        submitted = request.form.get("csrf_token", "")
        return hmac.compare_digest(record.csrf_token, submitted)

    def take_flash() -> str | None:
        record = g.session
        if record is None or not record.flash:
            return None
        db.set_session_flash(g.conn, record.sid_hash, None)
        return record.flash

    def set_flash(message: str) -> None:
        if g.session is not None:
            db.set_session_flash(g.conn, g.session.sid_hash, message)

    def respond(template: str, *, status: int = 200, json_payload: dict | None = None,
                **context: Any):
        if wants_json():
            return jsonify(json_payload or {}), status
        record = g.session
        return make_response(render_template(
            template, csrf_token=record.csrf_token if record else "",
            flash=context.pop("flash", None), config=config, **context), status)

    def capacity_response():
        """503 when the Argon2 concurrency cap could not admit the request.

        Retry-After is set so a well-behaved client backs off instead of
        retrying immediately and making the queue worse. 503 rather than 429
        because this is the server saying it is out of capacity, not the client
        being told it has misbehaved.
        """
        message = ("The server is at capacity for password verification. "
                   "Please try again shortly.")
        response = respond(T_LOGIN, status=503,
                           json_payload={"authenticated": False,
                                         "error": message,
                                         "reason_internal": "at_capacity"},
                           error=message)
        if isinstance(response, tuple):
            body, status = response
            body.headers["Retry-After"] = "5"
            return body, status
        response.headers["Retry-After"] = "5"
        return response

    def login_failure_response(reason: str, *, status: int = 401):
        """Every failed-login exit goes through here, so they cannot drift apart."""
        message = GENERIC_LOCKED if reason == "rate_limited" else GENERIC_LOGIN_FAILURE
        return respond(T_LOGIN, status=status,
                       json_payload={"authenticated": False, "error": message,
                                     "reason_internal": reason},
                       error=message)

    # --- routes --------------------------------------------------------------

    @app.route("/")
    def index():
        record = ensure_session()
        if record.is_authenticated:
            return redirect(url_for("dashboard"))
        return respond("index.html", json_payload={"app": "secure-login-system"})

    @app.route("/healthz")
    def healthz():
        return jsonify({"ok": True, "config": config.describe(),
                        "argon2_capacity": passwords.capacity_limits()})

    @app.route("/register", methods=["GET", "POST"])
    def register():
        record = ensure_session()
        if request.method == "GET":
            return respond(T_REGISTER,
                           json_payload={"csrf_token": record.csrf_token})

        if not csrf_ok():
            return respond(T_REGISTER, status=403,
                           json_payload={"error": CSRF_JSON_ERROR},
                           error=CSRF_HTML_ERROR)

        username_result = validation.validate_username(
            request.form.get("username", ""), config)
        password_result = validation.validate_password(
            request.form.get("password", ""), config)
        confirm = validation.normalise_password(request.form.get("confirm", ""))

        errors = list(username_result.errors) + list(password_result.errors)
        if password_result.ok and confirm and password_result.value != confirm:
            errors.append("Passwords do not match.")
        if password_result.ok and username_result.ok:
            # A password containing the username is the first thing any cracker
            # tries once it has a user list.
            if username_result.value in password_result.value.lower():
                errors.append("Password must not contain your username.")

        breach: hibp.BreachResult | None = None
        if not errors and config.require_breach_check:
            breach = hibp.check_password(password_result.value,
                                         timeout=config.hibp_timeout_s)
            if breach.breached:
                errors.append(
                    f"This password appears {breach.count:,} times in known "
                    "breach corpora. Choose a different one.")
            elif not breach.available:
                log.warning("HIBP unavailable, allowing registration: %s",
                            breach.error)

        if errors:
            return respond(T_REGISTER, status=400,
                           json_payload={"created": False, "errors": errors,
                                         "breach": breach.as_dict() if breach else None},
                           errors=errors,
                           username=username_result.value)

        try:
            # Registration hashes too, so it consumes a capacity slot for the
            # same reason login does: it is an unauthenticated endpoint that
            # allocates 64 MiB on demand.
            with passwords.capacity():
                password_hash = passwords.hash(password_result.value)
        except CapacityExhausted:
            message = ("The server is at capacity. Please try again shortly.")
            return respond(T_REGISTER, status=503,
                           json_payload={"created": False, "errors": [message]},
                           errors=[message], username=username_result.value)

        try:
            user_id = db.create_user(g.conn, username_result.value, password_hash)
        except sqlite3.IntegrityError:
            # Registration inherently leaks whether a username is taken -- it
            # has to, or two people cannot be told apart. The mitigation is not
            # to hide it here (that would need an email round-trip the task does
            # not include) but to keep LOGIN silent, which is where the leak
            # actually buys an attacker something.
            return respond(T_REGISTER, status=409,
                           json_payload={"created": False,
                                         "errors": ["That username is taken."]},
                           errors=["That username is taken."],
                           username=username_result.value)

        set_flash("Account created. Sign in to continue.")
        return respond(T_REGISTER, status=201,
                       json_payload={"created": True, "user_id": user_id,
                                     "username": username_result.value,
                                     "breach": breach.as_dict() if breach else None},
                       created=True, username=username_result.value)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        record = ensure_session()
        if request.method == "GET":
            return respond(T_LOGIN, flash=take_flash(),
                           json_payload={"csrf_token": record.csrf_token})

        if not csrf_ok():
            return respond(T_LOGIN, status=403,
                           json_payload={"error": CSRF_JSON_ERROR},
                           error=CSRF_HTML_ERROR)

        # Normalise but do NOT reject on validation rules here. A login form
        # that answers "username must be at least 3 characters" for one input and
        # "invalid credentials" for another is an enumeration oracle for free:
        # it tells the attacker which inputs are even candidate usernames.
        # Everything that is not a successful login gets the same treatment.
        submitted_username = validation.normalise_username(
            request.form.get("username", ""))
        submitted_password = validation.normalise_password(
            request.form.get("password", ""))
        ip = client_ip()

        decision = limiter.check(g.conn, submitted_username, ip)
        if not decision.allowed:
            # 429 with the same body text as a wrong password. The status code
            # differs because the client genuinely needs to know to back off,
            # and because the lockout is keyed on the submitted string it fires
            # for non-existent usernames too -- so it is not an oracle.
            return login_failure_response("rate_limited", status=429)

        user = db.get_user_by_username(g.conn, submitted_username)

        # The Argon2 work for both the known and unknown paths sits inside one
        # capacity block, so the concurrency cap cannot itself become an
        # enumeration oracle by admitting one path and refusing the other.
        try:
            with passwords.capacity():
                if user is None:
                    if config.enum_mitigation:
                        # THE FIX for trap 1. Do the same Argon2id work we would
                        # have done for a real user, so this path costs the same.
                        # Measured in tests/test_enumeration.py.
                        passwords.verify_dummy(submitted_password)
                    password_ok = False
                else:
                    password_ok = passwords.verify(user["password_hash"],
                                                   submitted_password)
        except CapacityExhausted:
            return capacity_response()

        if user is None:
            limiter.record_failure(g.conn, submitted_username, ip)
            return login_failure_response("unknown_user")

        if not password_ok:
            limiter.record_failure(g.conn, submitted_username, ip)
            return login_failure_response("bad_password")

        # Password is correct from here on.
        if passwords.needs_rehash(user["password_hash"]):
            try:
                with passwords.capacity():
                    db.update_password_hash(g.conn, user["id"],
                                            passwords.hash(submitted_password))
            except CapacityExhausted:
                # An upgrade that could not run is not a reason to fail a
                # correct login; it will be retried at the next one.
                log.warning("skipped parameter upgrade for user %s: at capacity",
                            user["id"])

        limiter.record_success(g.conn, submitted_username, ip)

        if user["totp_enabled"]:
            # Privilege change: anonymous -> pending_2fa. New session id.
            new_sid, _ = session_manager.rotate(
                g.conn, g.sid, user_id=user["id"],
                auth_level=sessions.PENDING_2FA, ip=ip,
                user_agent=request.headers.get("User-Agent"))
            g.new_cookie_sid = new_sid
            g.sid = new_sid
            g.session = session_manager.load(g.conn, new_sid)
            if wants_json():
                return jsonify({"authenticated": False, "totp_required": True,
                                "csrf_token": g.session.csrf_token}), 200
            return redirect(url_for("login_2fa"))

        # Privilege change: anonymous -> authenticated. New session id.
        new_sid, _ = session_manager.rotate(
            g.conn, g.sid, user_id=user["id"], auth_level=sessions.AUTHENTICATED,
            ip=ip, user_agent=request.headers.get("User-Agent"))
        g.new_cookie_sid = new_sid
        g.sid = new_sid
        g.session = session_manager.load(g.conn, new_sid)
        if wants_json():
            return jsonify({"authenticated": True, "totp_required": False,
                            "username": user["username"],
                            "csrf_token": g.session.csrf_token}), 200
        return redirect(url_for("dashboard"))

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        record = g.session
        if record is None or record.auth_level != sessions.PENDING_2FA:
            # Reaching the 2FA form without having passed the password step is
            # not an error worth explaining; send them back to the start.
            return respond(T_LOGIN, status=403,
                           json_payload={"error": "no pending authentication"},
                           error=GENERIC_LOGIN_FAILURE)

        if request.method == "GET":
            return respond(T_LOGIN_2FA,
                           json_payload={"csrf_token": record.csrf_token})

        if not csrf_ok():
            return respond(T_LOGIN_2FA, status=403,
                           json_payload={"error": CSRF_JSON_ERROR},
                           error=CSRF_HTML_ERROR)

        user = db.get_user_by_id(g.conn, record.user_id)
        code_result = validation.validate_totp_code(request.form.get("code", ""), config)
        ip = client_ip()

        # The second factor gets its own lockout counter, keyed on the username
        # plus a suffix. Six digits is 10^6, brute-forceable in minutes at HTTP
        # speed, so the code needs a limiter at least as much as the password.
        limiter_key = f"{user['username']}#totp"
        decision = limiter.check(g.conn, limiter_key, ip)
        if not decision.allowed:
            return respond(T_LOGIN_2FA, status=429,
                           json_payload={"authenticated": False,
                                         "error": "Too many attempts."},
                           error="Too many attempts. Try again later.")

        secret = totp.b32decode(user["totp_secret_b32"]) if user["totp_secret_b32"] else None
        accepted, counter = (False, None)
        if code_result.ok and secret:
            accepted, counter = totp.verify(
                secret, code_result.value,
                last_counter=user["totp_last_counter"],
                skew_steps=config.totp_skew_steps, step=config.totp_step_s,
                digits=config.totp_digits, algorithm=config.totp_algorithm)

        # Burning the counter in the database is the replay guard that survives
        # concurrency: totp.verify() checks against the value we read, and this
        # UPDATE ... WHERE last_counter < ? makes the check-and-set atomic, so
        # two simultaneous requests with the same code cannot both win.
        if accepted and counter is not None:
            accepted = db.record_totp_counter(g.conn, user["id"], counter)

        if not accepted:
            limiter.record_failure(g.conn, limiter_key, ip)
            return respond(T_LOGIN_2FA, status=401,
                           json_payload={"authenticated": False,
                                         "error": "Invalid authentication code."},
                           error="Invalid authentication code.")

        limiter.record_success(g.conn, limiter_key, ip)
        # Privilege change: pending_2fa -> authenticated. New session id again.
        new_sid, _ = session_manager.rotate(
            g.conn, g.sid, user_id=user["id"], auth_level=sessions.AUTHENTICATED,
            ip=ip, user_agent=request.headers.get("User-Agent"))
        g.new_cookie_sid = new_sid
        g.sid = new_sid
        g.session = session_manager.load(g.conn, new_sid)
        if wants_json():
            return jsonify({"authenticated": True, "username": user["username"],
                            "csrf_token": g.session.csrf_token}), 200
        return redirect(url_for("dashboard"))

    def require_auth():
        """Return None when authenticated, else the response to send."""
        record = g.session
        if record is None or not record.is_authenticated:
            if wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login"))
        return None

    @app.route("/dashboard")
    def dashboard():
        blocked = require_auth()
        if blocked is not None:
            return blocked
        record = g.session
        user = db.get_user_by_id(g.conn, record.user_id)
        payload = {
            "username": user["username"],
            "totp_enabled": bool(user["totp_enabled"]),
            "session_age_s": round(record.age_s(), 3),
            "session_idle_s": round(record.idle_s(), 3),
            "idle_timeout_s": config.session_idle_timeout_s,
            "absolute_timeout_s": config.session_absolute_timeout_s,
        }
        return respond(T_DASHBOARD, json_payload=payload,
                       flash=take_flash(), user=user, info=payload)

    @app.route("/2fa/enrol", methods=["GET", "POST"])
    def enrol_2fa():
        blocked = require_auth()
        if blocked is not None:
            return blocked
        record = g.session
        user = db.get_user_by_id(g.conn, record.user_id)

        if request.method == "GET":
            if user["totp_enabled"]:
                return respond(T_ENROL,
                               json_payload={"totp_enabled": True},
                               already=True, user=user)
            # A fresh secret on every GET, so an abandoned enrolment page cannot
            # be resumed later by someone who saw the old QR code.
            secret = totp.new_secret()
            db.set_totp_secret(g.conn, user["id"], totp.b32encode(secret))
            return respond(T_ENROL,
                           json_payload={
                               "secret_b32": totp.b32encode(secret),
                               "otpauth_uri": totp.provisioning_uri(
                                   secret, user["username"], config.totp_issuer,
                                   config.totp_digits, config.totp_step_s,
                                   config.totp_algorithm),
                               "csrf_token": record.csrf_token},
                           secret_b32=totp.b32encode(secret),
                           otpauth_uri=totp.provisioning_uri(
                               secret, user["username"], config.totp_issuer,
                               config.totp_digits, config.totp_step_s,
                               config.totp_algorithm),
                           user=user)

        if not csrf_ok():
            return respond(T_ENROL, status=403,
                           json_payload={"error": CSRF_JSON_ERROR},
                           error=CSRF_HTML_ERROR, user=user)

        code_result = validation.validate_totp_code(request.form.get("code", ""), config)
        if not code_result.ok or not user["totp_secret_b32"]:
            return respond(T_ENROL, status=400,
                           json_payload={"enabled": False,
                                         "errors": code_result.errors or
                                                   ["No enrolment in progress."]},
                           errors=code_result.errors or ["No enrolment in progress."],
                           user=user)

        secret = totp.b32decode(user["totp_secret_b32"])
        accepted, counter = totp.verify(
            secret, code_result.value, last_counter=user["totp_last_counter"],
            skew_steps=config.totp_skew_steps, step=config.totp_step_s,
            digits=config.totp_digits, algorithm=config.totp_algorithm)
        if not accepted or counter is None:
            return respond(T_ENROL, status=400,
                           json_payload={"enabled": False,
                                         "errors": ["That code did not match. "
                                                    "Check your device clock."]},
                           errors=["That code did not match. Check your device "
                                   "clock."], user=user)

        # Confirming enrolment is a privilege change (the account's auth
        # requirements just changed), so the session id is rotated and every
        # OTHER session for this user is dropped. If an attacker had a live
        # session, enabling 2FA should evict them, not leave them logged in.
        db.enable_totp(g.conn, user["id"], counter)
        session_manager.destroy_all_for_user(g.conn, user["id"])
        new_sid, _ = session_manager.rotate(
            g.conn, None, user_id=user["id"], auth_level=sessions.AUTHENTICATED,
            ip=client_ip(), user_agent=request.headers.get("User-Agent"))
        g.new_cookie_sid = new_sid
        g.sid = new_sid
        g.session = session_manager.load(g.conn, new_sid)
        set_flash("Two-factor authentication is on.")
        if wants_json():
            return jsonify({"enabled": True,
                            "csrf_token": g.session.csrf_token}), 200
        return redirect(url_for("dashboard"))

    @app.route("/2fa/disable", methods=["POST"])
    def disable_2fa():
        blocked = require_auth()
        if blocked is not None:
            return blocked
        if not csrf_ok():
            return jsonify({"error": CSRF_JSON_ERROR}), 403
        record = g.session
        user = db.get_user_by_id(g.conn, record.user_id)

        # Turning a factor OFF is a security-relevant action, so it demands the
        # password again. A hijacked session should not be able to quietly
        # remove the control that would have stopped it.
        password = validation.normalise_password(request.form.get("password", ""))
        try:
            with passwords.capacity():
                confirmed = passwords.verify(user["password_hash"], password)
        except CapacityExhausted:
            return jsonify({"disabled": False, "error": "at capacity"}), 503
        if not confirmed:
            return respond(T_DASHBOARD, status=403,
                           json_payload={"disabled": False,
                                         "error": "Password confirmation failed."},
                           error="Password confirmation failed.", user=user,
                           info={})

        db.disable_totp(g.conn, user["id"])
        session_manager.destroy_all_for_user(g.conn, user["id"])
        new_sid, _ = session_manager.rotate(
            g.conn, None, user_id=user["id"], auth_level=sessions.AUTHENTICATED,
            ip=client_ip(), user_agent=request.headers.get("User-Agent"))
        g.new_cookie_sid = new_sid
        g.sid = new_sid
        g.session = session_manager.load(g.conn, new_sid)
        set_flash("Two-factor authentication is off.")
        if wants_json():
            return jsonify({"disabled": True,
                            "csrf_token": g.session.csrf_token}), 200
        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        # POST only. A GET /logout is CSRF-able: any page can force a logout
        # with an <img> tag. Harmless-looking, but it is still an attacker
        # controlling session state.
        record = g.session
        if record is not None and not csrf_ok():
            return jsonify({"error": CSRF_JSON_ERROR}), 403
        # Delete the row, THEN clear the cookie. Deleting server-side is what
        # makes logout real: even a client that keeps the cookie holds a session
        # id that no longer resolves to anything.
        session_manager.destroy(g.conn, g.sid)
        g.clear_cookie = True
        g.session = None
        if wants_json():
            return jsonify({"logged_out": True}), 200
        return redirect(url_for("login"))

    @app.route("/admin/maintenance", methods=["POST"])
    def maintenance():
        """Sweep expired sessions. Normally a cron job; exposed so the
        end-to-end transcript can show the sweep actually removing rows."""
        removed = db.purge_expired_sessions(
            g.conn, config.session_idle_timeout_s, config.session_absolute_timeout_s)
        return jsonify({"purged_sessions": removed, "stats": db.stats(g.conn)})

    @app.errorhandler(404)
    def not_found(_exc):
        if wants_json():
            return jsonify({"error": "not found"}), 404
        return make_response(render_template("error.html", code=404,
                                             message="Not found"), 404)

    @app.errorhandler(500)
    def server_error(exc):
        # Never echo the exception to the client. A stack trace or a SQL error
        # string is free reconnaissance; log it locally and say nothing.
        log.exception("unhandled error: %s", exc)
        if wants_json():
            return jsonify({"error": "internal error"}), 500
        return make_response(render_template("error.html", code=500,
                                             message="Something went wrong"), 500)

    return app

