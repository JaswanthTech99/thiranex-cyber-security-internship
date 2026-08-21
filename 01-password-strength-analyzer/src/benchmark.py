"""Measures real hash throughput on this machine.

Crack-time figures are only as honest as the guess rate behind them, and most
password meters quote a rate from nowhere. Two of the four rates used by this
project - CPU SHA-1 and Argon2id - are measured here, on this CPU, and written to
outputs/reports/hash_rates.json. The other two, the single-GPU SHA-1 rate and the
throttled online rate, are explicitly-labelled assumptions, because a GPU cannot
be benchmarked from a laptop and a lockout policy is not a hardware fact.

Run: python -m src.benchmark
"""
from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "outputs" / "reports"

# A single high-end consumer GPU against unsalted SHA-1, taken from published
# hashcat benchmarks and deliberately rounded to one significant figure. This is
# an assumption, not a measurement, and it is labelled as such in every report.
ASSUMED_SHA1_GPU_HASHES_PER_SEC = 5.0e10

# Policy rate for an online attack against an endpoint that locks out or
# exponentially backs off. Also an assumption, and a generous one.
ASSUMED_ONLINE_HASHES_PER_SEC = 10.0


def bench_sha1(seconds: float = 2.0) -> float:
    """Single-thread SHA-1 throughput, measured over distinct inputs so the
    result is not a repeated-buffer cache artefact."""
    n = 0
    payloads = [f"candidate-{i}".encode() for i in range(4096)]
    start = time.perf_counter()
    while True:
        for p in payloads:
            hashlib.sha1(p).digest()
        n += len(payloads)
        if time.perf_counter() - start >= seconds:
            break
    return n / (time.perf_counter() - start)


def bench_argon2id(time_cost: int = 3, memory_kib: int = 65536, parallelism: int = 4,
                   rounds: int = 8) -> float:
    """Argon2id throughput at RFC 9106 section 4's second recommended option."""
    salt = b"0123456789abcdef"
    start = time.perf_counter()
    for i in range(rounds):
        hash_secret_raw(
            secret=f"candidate-{i}".encode(),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
    elapsed = time.perf_counter() - start
    return rounds / elapsed


def measure() -> dict:
    sha1 = bench_sha1()
    argon2 = bench_argon2id()
    return {
        "machine": {
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "python": platform.python_version(),
        },
        "measured": {
            "sha1_cpu_single_thread_hps": round(sha1, 1),
            "argon2id_t3_m64MiB_p4_hps": round(argon2, 3),
        },
        "assumed": {
            "sha1_single_gpu_hps": ASSUMED_SHA1_GPU_HASHES_PER_SEC,
            "sha1_single_gpu_source": (
                "published hashcat benchmark for one high-end consumer GPU, "
                "rounded to 1 significant figure - assumption, not measured here"
            ),
            "online_throttled_hps": ASSUMED_ONLINE_HASHES_PER_SEC,
            "online_throttled_source": "policy assumption for a rate-limited login endpoint",
        },
    }


def load_rates() -> dict:
    """Read cached rates, measuring them first if that has never been done."""
    path = REPORTS / "hash_rates.json"
    if not path.exists():
        rates = measure()
        REPORTS.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rates, indent=2), encoding="utf-8")
        return rates
    return json.loads(path.read_text(encoding="utf-8"))


def scenarios() -> list[tuple[str, float]]:
    """(label, guesses per second) for the three attack models reported."""
    r = load_rates()
    return [
        ("online, rate-limited endpoint (10/s, assumed)",
         r["assumed"]["online_throttled_hps"]),
        ("offline, unsalted SHA-1, 1 GPU (5e10/s, assumed)",
         r["assumed"]["sha1_single_gpu_hps"]),
        (f"offline, Argon2id RFC 9106 (t=3,64MiB,p=4) "
         f"({r['measured']['argon2id_t3_m64MiB_p4_hps']:.1f}/s, measured here)",
         r["measured"]["argon2id_t3_m64MiB_p4_hps"]),
    ]


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    for unit, size in (("second", 60), ("minute", 60), ("hour", 24), ("day", 365.25)):
        if seconds < size:
            return f"{seconds:.0f} {unit}{'s' if seconds >= 2 else ''}"
        seconds /= size
    if seconds < 1e3:
        return f"{seconds:.0f} years"
    if seconds < 1e6:
        return f"{seconds/1e3:.0f} thousand years"
    if seconds < 1e9:
        return f"{seconds/1e6:.0f} million years"
    if seconds < 1e15:
        return f"{seconds/1e9:.0f} billion years"
    return f"{seconds:.1e} years"


if __name__ == "__main__":
    REPORTS.mkdir(parents=True, exist_ok=True)
    rates = measure()
    (REPORTS / "hash_rates.json").write_text(json.dumps(rates, indent=2), encoding="utf-8")
    print(json.dumps(rates, indent=2))
