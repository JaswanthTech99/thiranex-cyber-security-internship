"""Minimal test harness.

Deliberately not pytest: this project is judged on being runnable from a clean
Python 3.14 install with only the pinned requirements, and every test here also
has to emit a human-readable table that goes into outputs/reports/. A 90-line
harness that prints exactly that is less machinery than a pytest plugin doing
the same job.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from typing import Any, Callable

PASS = "PASS"
FAIL = "FAIL"


class Suite:
    def __init__(self, name: str, stream: io.TextIOBase | None = None) -> None:
        self.name = name
        self.results: list[dict[str, Any]] = []
        self.started = time.time()
        self._stream = stream or sys.stdout
        self._section = ""
        self._write(f"\n=== {name} ===\n")

    def _write(self, text: str) -> None:
        self._stream.write(text)
        self._stream.flush()

    def section(self, title: str) -> None:
        self._section = title
        self._write(f"\n-- {title}\n")

    def check(self, label: str, actual: Any, expected: Any) -> bool:
        ok = actual == expected
        self.results.append({
            "section": self._section,
            "label": label,
            "ok": ok,
            "actual": _short(actual),
            "expected": _short(expected),
        })
        status = PASS if ok else FAIL
        line = f"  [{status}] {label}"
        if not ok:
            line += f"\n         expected: {_short(expected)}\n         actual:   {_short(actual)}"
        self._write(line + "\n")
        return ok

    def check_true(self, label: str, actual: Any) -> bool:
        return self.check(label, bool(actual), True)

    def note(self, text: str) -> None:
        """Record an observation that is not a pass/fail assertion."""
        self._write(f"  ...  {text}\n")

    @staticmethod
    def raises(exc: type[BaseException], fn: Callable[..., Any], *args: Any,
               **kwargs: Any) -> bool:
        try:
            fn(*args, **kwargs)
        except exc:
            return True
        except BaseException:
            return False
        return False

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r["ok"])

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r["ok"])

    def summary(self) -> dict[str, Any]:
        return {
            "suite": self.name,
            "checks": len(self.results),
            "passed": self.passed,
            "failed": self.failed,
            "duration_s": round(time.time() - self.started, 3),
        }

    def finish(self) -> int:
        s = self.summary()
        self._write(
            f"\n{self.name}: {s['passed']}/{s['checks']} passed, "
            f"{s['failed']} failed, {s['duration_s']}s\n")
        return 1 if self.failed else 0


def _short(value: Any, limit: int = 220) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
