"""Run every suite, print the combined output, and write summary_stats.json.

Order matters: the cheap deterministic suites run first so a broken build fails
in seconds rather than after the timing measurements. The timing and SQLi suites
are last because they are the slow ones.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.harness import Suite, write_json  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY_PATH = os.path.join(PROJECT_ROOT, "outputs", "reports",
                            "summary_stats.json")

# (module, suite title). Each module exposes run(suite) and may return a dict of
# measurements, which is folded into summary_stats.json.
SUITES = [
    ("tests.test_rfc_vectors", "RFC 4226 / RFC 6238 test vectors"),
    ("tests.test_validation", "Validation, Argon2 parameters, HIBP breach check"),
    ("tests.test_session_lifecycle", "Session lifecycle: cookies, timeouts, CSRF"),
    ("tests.test_lockout", "Rate limiting and lockout"),
    ("tests.test_session_fixation", "Session fixation and rotation"),
    ("tests.test_e2e", "End-to-end: register, login, 2FA, protected page, logout"),
    ("tests.test_sqli", "SQL injection: SecLists corpus"),
    ("tests.test_enumeration", "User enumeration timing"),
]


def main() -> int:
    started = time.time()
    summaries = []
    measurements: dict[str, object] = {}
    failures = 0

    for module_name, title in SUITES:
        module = importlib.import_module(module_name)
        suite = Suite(title)
        try:
            result = module.run(suite)
        except Exception as exc:  # a crashed suite is a failed suite, not a stop
            suite.check(f"{module_name} raised {type(exc).__name__}", str(exc), None)
            result = None
        code = suite.finish()
        failures += suite.failed
        summaries.append(suite.summary())
        if isinstance(result, dict):
            measurements[module_name.rsplit(".", 1)[-1]] = result

    total_checks = sum(s["checks"] for s in summaries)
    total_passed = sum(s["passed"] for s in summaries)

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    for s in summaries:
        status = "OK  " if s["failed"] == 0 else "FAIL"
        print(f"  [{status}] {s['suite']}: {s['passed']}/{s['checks']} "
              f"({s['duration_s']}s)")
    print(f"\n  {total_passed}/{total_checks} checks passed, {failures} failed, "
          f"{round(time.time() - started, 1)}s total")

    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "totals": {"checks": total_checks, "passed": total_passed,
                   "failed": failures,
                   "duration_s": round(time.time() - started, 1)},
        "suites": summaries,
        "measurements": measurements,
    }
    write_json(SUMMARY_PATH, payload)
    print(f"\n  summary written to {SUMMARY_PATH}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
