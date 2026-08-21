"""Rate limiting and lockout: that it works, and what it costs.

Three questions:

  1. Does the lockout fire? Measured against the configured threshold.
  2. Is the lockout itself a user-enumeration oracle? A lockout keyed on a
     resolved user id can only ever trigger for real accounts, so it answers
     "does this account exist" without any timing analysis at all. This asserts
     that a username which does not exist locks out identically.
  3. What does it buy against the Argon2 DoS problem? Every rejected attempt is
     an Argon2id verify the server did NOT perform. This measures how many
     expensive hashes a single attacker can force through one username before
     the limiter stops answering, which is the concrete availability number.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.harness import Suite  # noqa: E402
from tests.server import AppServer, Client, TEST_PASSWORD  # noqa: E402

REAL_USER = "lockout.real"
ABSENT_USER = "lockout.absent"
WRONG = "not-the-password-at-all-1234"


def attempts_until_429(client: Client, username: str,
                       limit: int = 25) -> tuple[int, list[int], list[float]]:
    """Hammer one username. Returns (attempts before the first 429, statuses,
    per-request latencies in ms)."""
    statuses: list[int] = []
    latencies: list[float] = []
    first_429: int | None = None
    for i in range(limit):
        start = time.perf_counter()
        response = client.post_json("/login", {"username": username,
                                              "password": WRONG,
                                              "csrf_token": client.csrf_token})
        latencies.append((time.perf_counter() - start) * 1000.0)
        statuses.append(response.status_code)
        if response.status_code == 429 and first_429 is None:
            first_429 = i
            # Two more past the first 429, to confirm it stays shut.
            if len(statuses) >= (first_429 + 3):
                break
    return (first_429 if first_429 is not None else -1), statuses, latencies


def run(suite: Suite) -> dict[str, object]:
    results: dict[str, object] = {}

    with AppServer(extra_args=["--no-breach-check"], label="lockout") as server:
        config = server.config()["rate_limit"]
        threshold = config["lockout_threshold"]
        suite.note(f"configured: {threshold} failures per "
                   f"{config['lockout_window_s']}s locks for "
                   f"{config['lockout_duration_s']}s; per-IP cap "
                   f"{config['ip_threshold']} per {config['ip_window_s']}s")

        setup = Client(server)
        suite.check("real account created",
                    setup.register(REAL_USER, TEST_PASSWORD).status_code, 201)

        suite.section("The lockout fires at the configured threshold")
        attacker = Client(server)
        attacker.prime_csrf("/login")
        first_429, statuses, latencies = attempts_until_429(attacker, REAL_USER)
        suite.note(f"statuses: {statuses}")
        suite.check("the first 429 arrives after exactly `threshold` failures",
                    first_429, threshold)
        suite.check_true("it stays locked on subsequent attempts",
                         all(s == 429 for s in statuses[first_429:]))

        expensive = latencies[:threshold]
        cheap = latencies[first_429:]
        mean_expensive = sum(expensive) / len(expensive)
        mean_cheap = sum(cheap) / len(cheap)

        # Baseline: what a request costs before any authentication work. This is
        # measured rather than assumed, because the first run of this test found
        # the rejected path was only ~2.8x cheaper than the hashed one, not the
        # orders of magnitude I had expected, and the baseline is the reason.
        # /healthz does no session work and no writes; GET /login loads the
        # session and commits a last_seen_at update, which is an fsync.
        floor_healthz = []
        floor_session = []
        for _ in range(15):
            start = time.perf_counter()
            attacker.get_json("/healthz")
            floor_healthz.append((time.perf_counter() - start) * 1000.0)
            start = time.perf_counter()
            attacker.get_json("/login")
            floor_session.append((time.perf_counter() - start) * 1000.0)
        mean_healthz = sum(floor_healthz) / len(floor_healthz)
        mean_session = sum(floor_session) / len(floor_session)

        suite.note(f"latency of the {len(expensive)} attempts that ran Argon2id: "
                   f"mean {mean_expensive:.1f} ms")
        suite.note(f"latency of the {len(cheap)} rejected-by-limiter attempts: "
                   f"mean {mean_cheap:.1f} ms")
        suite.note(f"baseline GET /healthz (no session, no write): "
                   f"mean {mean_healthz:.1f} ms")
        suite.note(f"baseline GET /login (session load + last_seen commit): "
                   f"mean {mean_session:.1f} ms")
        suite.note(f"ratio hashed/rejected = {mean_expensive / mean_cheap:.2f}x; "
                   "the rejected path is not near-zero because it still pays the "
                   "per-request SQLite commits, which is the app's latency floor")

        suite.check_true("a rejected attempt is cheaper than a hashed one",
                         mean_cheap < mean_expensive)
        # The claim worth asserting is about the Argon2 work specifically: the
        # rejected path must cost less than the baseline plus a hash.
        suite.check_true("the rejected path skips the Argon2id work entirely "
                         "(it costs no more than the session baseline plus "
                         "measurement noise)",
                         mean_cheap < mean_session * 2.0)
        results["lockout"] = {
            "threshold": threshold,
            "first_429_after": first_429,
            "statuses": statuses,
            "mean_hashed_attempt_ms": round(mean_expensive, 3),
            "mean_rejected_attempt_ms": round(mean_cheap, 3),
            "baseline_healthz_ms": round(mean_healthz, 3),
            "baseline_session_request_ms": round(mean_session, 3),
            "hashed_over_rejected_ratio": round(mean_expensive / mean_cheap, 3),
        }

        suite.section("The lockout is not a user-enumeration oracle")
        # Same treatment for a username that does not exist. If this stayed at
        # 401 forever while the real one went to 429, the limiter would be
        # telling the attacker which usernames are real.
        prober = Client(server)
        prober.prime_csrf("/login")
        absent_first_429, absent_statuses, _ = attempts_until_429(prober, ABSENT_USER)
        suite.note(f"statuses for a username that does not exist: {absent_statuses}")
        suite.check("a non-existent username locks out after the same count",
                    absent_first_429, first_429)
        suite.check("and the status sequence is identical",
                    absent_statuses[:first_429 + 1], statuses[:first_429 + 1])
        results["enumeration_safe"] = {
            "real_user_first_429_after": first_429,
            "absent_user_first_429_after": absent_first_429,
            "identical": absent_first_429 == first_429,
        }

        suite.section("A successful login clears the failure count")
        # A legitimate user who mistypes a few times and then gets it right must
        # not stay one attempt away from a lockout.
        user2 = "lockout.clears"
        good = Client(server)
        good.register(user2, TEST_PASSWORD)
        good.prime_csrf("/login")
        for _ in range(threshold - 1):
            good.post_json("/login", {"username": user2, "password": WRONG,
                                      "csrf_token": good.csrf_token})
        response = good.login(user2, TEST_PASSWORD)
        suite.check("login still works one attempt short of the threshold",
                    response.json().get("authenticated"), True)

        after = Client(server)
        after.prime_csrf("/login")
        cleared_first_429, cleared_statuses, _ = attempts_until_429(after, user2)
        suite.note(f"statuses after the successful login: {cleared_statuses}")
        suite.check("the counter was reset, so a full threshold is available "
                    "again", cleared_first_429, threshold)
        results["success_clears_counter"] = cleared_first_429 == threshold

    suite.section("What the limiter buys against the Argon2 DoS problem")
    # The comparison: with the limiter off, every attempt costs the server a
    # 64 MiB Argon2id verify. With it on, only `threshold` attempts per username
    # per window do.
    with AppServer(extra_args=["--no-breach-check", "--no-rate-limit"],
                   label="nolimit") as server:
        setup = Client(server)
        setup.register(REAL_USER, TEST_PASSWORD)
        attacker = Client(server)
        attacker.prime_csrf("/login")
        n = 20
        start = time.perf_counter()
        for _ in range(n):
            attacker.post_json("/login", {"username": REAL_USER,
                                         "password": WRONG,
                                         "csrf_token": attacker.csrf_token})
        elapsed = time.perf_counter() - start
        per_request = elapsed / n * 1000

        hashed_with_limit = results["lockout"]["threshold"]
        suite.note(f"limiter OFF: {n}/{n} attempts each cost a full Argon2id "
                   f"verify, {per_request:.1f} ms each, "
                   f"{n * 64} MiB of transient allocation in total")
        suite.note(f"limiter ON:  only {hashed_with_limit} of those attempts "
                   f"would have been hashed before the username was locked, "
                   f"so {hashed_with_limit * 64} MiB instead of {n * 64} MiB")
        suite.check_true("the limiter caps hashed attempts well below the "
                         "unlimited case", hashed_with_limit < n)
        results["dos_bound"] = {
            "unlimited_attempts_measured": n,
            "unlimited_mean_ms": round(per_request, 3),
            "unlimited_transient_mib": n * 64,
            "limited_hashed_attempts_per_username_per_window": hashed_with_limit,
            "limited_transient_mib": hashed_with_limit * 64,
        }

    return results


if __name__ == "__main__":
    suite = Suite("Rate limiting and lockout")
    run(suite)
    sys.exit(suite.finish())
