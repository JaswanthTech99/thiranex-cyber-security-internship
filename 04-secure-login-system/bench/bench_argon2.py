"""Argon2id cost measurement: the parameter choice as a real trade-off.

The premise worth stating plainly, because it is the thing people get wrong:
raising Argon2's memory cost is not free and it is not monotonically good. The
cost is paid by the defender, on every login, in RAM and latency, on the
unauthenticated path. 64 MiB per verify means N simultaneous login attempts hold
N x 64 MiB, and nothing about that requires the attacker to have any credentials
at all. So the question is not "how high can we set m" but "what is the highest m
whose worst case we can still serve".

This script measures, on this machine:
  1. Latency at the chosen parameters (RFC 9106 second recommended option).
  2. Latency across a memory sweep at fixed t and p, and across a time sweep at
     fixed m -- the two knobs, so the shape of each is visible.
  3. In-process throughput and latency as concurrency rises, with the transient
     memory that implies.
  4. What an attacker's load does to a legitimate user's login, over HTTP,
     across three protection arms: nothing, a concurrency cap on Argon2, and
     the cap plus rate limiting. Latency AND whether the user was actually
     served, because the first version of this benchmark measured only latency
     and drew the wrong conclusion from it -- see the comment in
     bench_http_under_load().

Everything printed here is measured, not modelled.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import json
import os
import platform
import random
import statistics
import sys
import time

import numpy as np
from argon2 import PasswordHasher, Type

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config  # noqa: E402
from tests.server import AppServer, Client, TEST_PASSWORD  # noqa: E402

SEED = 20260821
PASSWORD = "bench-password-not-a-real-credential-2026"
FIGURE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "outputs", "figures", "argon2_cost.png")

MEMORY_SWEEP_KIB = [8192, 16384, 32768, 65536, 131072, 262144]  # 8 MiB .. 256 MiB
TIME_SWEEP = [1, 2, 3, 4, 6]
CONCURRENCY_LEVELS = [1, 2, 4, 8, 16]
HASHES_PER_POINT = 8
SWEEP_ROUNDS = 8

# Why the sweeps are interleaved and randomised rather than run one parameter at
# a time, which is the obvious way to write this:
#
# The first version of this script measured each configuration to completion
# before moving to the next. It produced numbers that contradicted each other --
# t=1 at m=64 MiB came out at 56 ms while t=3 at the same memory cost came out at
# 54 ms in an earlier phase, which is impossible, since t=3 does three passes
# over the same memory. The cause was drift: this is a mobile CPU (Tiger Lake),
# a few minutes of sustained Argon2 load makes it throttle, and running the
# configurations in sequence meant later configurations were measured on a
# slower machine. The parameter axis and the time axis were confounded.
#
# The fix is to measure one hash per configuration per round, in a fresh random
# order each round, so any drift lands evenly across all configurations instead
# of masquerading as an effect of the parameter. The drift itself is then
# measured and reported rather than hidden.



def machine_info() -> dict[str, object]:
    total_mib = None
    if sys.platform == "win32":
        # GlobalMemoryStatusEx, so no third-party dependency just to read RAM.
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            total_mib = round(status.ullTotalPhys / (1024 ** 2))
            avail_mib = round(status.ullAvailPhys / (1024 ** 2))
        else:
            avail_mib = None
    else:
        avail_mib = None
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
        "total_ram_mib": total_mib,
        "available_ram_mib": avail_mib,
    }


def time_hashes(hasher: PasswordHasher, count: int) -> list[float]:
    """Sequential hash latencies in ms, after one untimed warm-up."""
    hasher.hash(PASSWORD)  # warm-up: first call pays for allocator behaviour
    out = []
    for _ in range(count):
        start = time.perf_counter()
        hasher.hash(PASSWORD)
        out.append((time.perf_counter() - start) * 1000.0)
    return out


def make_hasher(config: Config, *, memory_kib: int | None = None,
                time_cost: int | None = None) -> PasswordHasher:
    return PasswordHasher(
        time_cost=time_cost or config.argon2_time_cost,
        memory_cost=memory_kib or config.argon2_memory_cost_kib,
        parallelism=config.argon2_parallelism,
        hash_len=config.argon2_hash_bytes,
        salt_len=config.argon2_salt_bytes,
        type=Type.ID)


def summarise(values: list[float]) -> dict[str, float]:
    arr = np.array(values)
    return {"n": int(arr.size),
            "mean_ms": round(float(arr.mean()), 2),
            "median_ms": round(float(np.median(arr)), 2),
            "p95_ms": round(float(np.percentile(arr, 95)), 2),
            "min_ms": round(float(arr.min()), 2),
            "max_ms": round(float(arr.max()), 2)}


def bench_chosen(config: Config) -> dict[str, object]:
    hasher = make_hasher(config)
    latencies = time_hashes(hasher, 20)
    return {"parameters": {"t": config.argon2_time_cost,
                           "m_kib": config.argon2_memory_cost_kib,
                           "m_mib": config.argon2_memory_mib(),
                           "p": config.argon2_parallelism},
            "latency": summarise(latencies)}


def bench_parameter_sweeps(config: Config,
                           rng: "random.Random") -> dict[str, object]:
    """Interleaved memory and time sweeps. See the note at the top of the file.

    Every configuration gets one hash per round, in a random order per round, so
    thermal drift is spread across configurations instead of being attributed to
    whichever parameter happened to be measured last.
    """
    hashers: dict[str, PasswordHasher] = {}
    for memory_kib in MEMORY_SWEEP_KIB:
        hashers[f"m:{memory_kib}"] = make_hasher(config, memory_kib=memory_kib)
    for time_cost in TIME_SWEEP:
        hashers[f"t:{time_cost}"] = make_hasher(config, time_cost=time_cost)

    # One untimed hash per configuration, so no configuration is charged for
    # first-call allocator behaviour.
    for hasher in hashers.values():
        hasher.hash(PASSWORD)

    samples: dict[str, list[float]] = {key: [] for key in hashers}
    # A drift probe: the chosen configuration is re-measured once per round, and
    # the per-round values are kept so the drift can be quantified afterwards.
    drift_probe = make_hasher(config)
    drift_probe.hash(PASSWORD)
    drift_per_round: list[float] = []

    keys = list(hashers)
    for _ in range(SWEEP_ROUNDS):
        start = time.perf_counter()
        drift_probe.hash(PASSWORD)
        drift_per_round.append((time.perf_counter() - start) * 1000.0)

        rng.shuffle(keys)
        for key in keys:
            start = time.perf_counter()
            hashers[key].hash(PASSWORD)
            samples[key].append((time.perf_counter() - start) * 1000.0)

    memory_sweep = [
        {"m_kib": memory_kib, "m_mib": memory_kib / 1024,
         "t": config.argon2_time_cost, **summarise(samples[f"m:{memory_kib}"])}
        for memory_kib in MEMORY_SWEEP_KIB]
    time_sweep = [
        {"t": time_cost, "m_mib": config.argon2_memory_mib(),
         **summarise(samples[f"t:{time_cost}"])}
        for time_cost in TIME_SWEEP]

    first_half = drift_per_round[:len(drift_per_round) // 2]
    second_half = drift_per_round[len(drift_per_round) // 2:]
    drift = {
        "probe_per_round_ms": [round(v, 2) for v in drift_per_round],
        "first_half_mean_ms": round(statistics.fmean(first_half), 2),
        "second_half_mean_ms": round(statistics.fmean(second_half), 2),
        "drift_ratio": round(statistics.fmean(second_half) /
                             statistics.fmean(first_half), 3),
    }
    return {"memory_sweep": memory_sweep, "time_sweep": time_sweep,
            "drift": drift, "rounds": SWEEP_ROUNDS}


def bench_concurrency(config: Config, rng: "random.Random") -> list[dict[str, object]]:
    """Throughput and latency as concurrent hashes rise, in one process.

    Whether this scales at all depends on the binding releasing the GIL around
    the C call. Whatever it does, it gets reported: the point is the number on
    this machine, not the number I expected.

    Each level also carries its own serial reference, measured immediately
    before it, for the same drift reason as the parameter sweeps: a raw
    hashes-per-second figure measured ten minutes into the run is not comparable
    to one measured at the start, but the ratio to a same-moment serial baseline
    is.
    """
    hasher = make_hasher(config)
    hasher.hash(PASSWORD)  # warm-up outside every timed region

    def one_hash_ms() -> float:
        start = time.perf_counter()
        hasher.hash(PASSWORD)
        return (time.perf_counter() - start) * 1000.0

    levels = list(CONCURRENCY_LEVELS)
    rng.shuffle(levels)
    out = []
    for workers in levels:
        serial_reference = statistics.fmean(one_hash_ms() for _ in range(3))

        total = workers * HASHES_PER_POINT
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            latencies = list(pool.map(lambda _: one_hash_ms(), range(total)))
        wall = time.perf_counter() - start

        throughput = total / wall
        out.append({
            "concurrency": workers,
            "hashes": total,
            "wall_s": round(wall, 3),
            "throughput_hashes_per_s": round(throughput, 2),
            "serial_reference_ms": round(serial_reference, 2),
            # 1.0 means threads bought nothing; `workers` would be perfect
            # scaling. Reported as a ratio so it survives machine drift.
            "speedup_over_serial": round(throughput / (1000 / serial_reference), 2),
            "peak_transient_mib": workers * config.argon2_memory_mib(),
            **summarise(latencies),
        })
    return sorted(out, key=lambda row: row["concurrency"])


def bench_http_under_load() -> dict[str, object]:
    """A legitimate login's latency while N attackers hammer the endpoint.

    Run twice: rate limiting off (what the attacker gets if there is no limiter)
    and on (what the limiter reduces it to). The victim uses a different
    username from the attackers, so the per-username lockout does not shield the
    victim by accident -- only the per-IP limiter and the server's own capacity
    are in play.
    """
    victim_user = "bench.victim"
    attack_users = [f"bench.attacker{i}" for i in range(8)]
    wrong = "definitely-the-wrong-password-000"
    results: dict[str, object] = {}

    # Three arms, isolating the two controls:
    #   no_protection     -- no rate limiting, no concurrency cap. What the raw
    #                        Argon2 endpoint gives an attacker.
    #   concurrency_cap   -- cap on, rate limiting off. Bounds peak memory
    #                        without any per-username or per-IP counting.
    #   rate_limited      -- both on. The production default.
    for arm, extra in (("no_protection",
                        ["--no-rate-limit", "--argon2-max-concurrent", "1024"]),
                       ("concurrency_cap", ["--no-rate-limit"]),
                       ("rate_limited", [])):
        with AppServer(extra_args=["--no-breach-check"] + extra,
                       label=f"dos-{arm}") as server:
            setup = Client(server)
            setup.register(victim_user, TEST_PASSWORD)

            # Latency alone is not enough here, and the first run of this
            # benchmark proved it: with the limiter on and 16 attacker threads
            # the victim's p95 came out at 1.0x baseline, which looked like the
            # limiter perfectly protecting them. It was not. The victim was
            # being refused, and a refusal is fast. So record the status of
            # every victim request and count how many actually authenticated.
            def victim_login() -> tuple[float, int, bool]:
                client = Client(server)
                client.prime_csrf("/login")
                start = time.perf_counter()
                response = client.post_json("/login", {
                    "username": victim_user, "password": TEST_PASSWORD,
                    "csrf_token": client.csrf_token})
                elapsed = (time.perf_counter() - start) * 1000.0
                try:
                    ok = bool(response.json().get("authenticated"))
                except ValueError:
                    ok = False
                return elapsed, response.status_code, ok

            baseline_samples = [victim_login() for _ in range(8)]
            baseline = [s[0] for s in baseline_samples]

            per_arm: dict[str, object] = {
                "baseline_ms": summarise(baseline),
                "baseline_success_rate": round(
                    sum(1 for s in baseline_samples if s[2]) / len(baseline_samples), 3),
                "under_load": []}
            for attackers in [4, 16]:
                stop = time.time() + 6.0
                sent = {"n": 0}

                def flood(index: int) -> None:
                    client = Client(server)
                    client.prime_csrf("/login")
                    username = attack_users[index % len(attack_users)]
                    while time.time() < stop:
                        try:
                            client.post_json("/login", {
                                "username": username, "password": wrong,
                                "csrf_token": client.csrf_token})
                            sent["n"] += 1
                        except Exception:
                            break

                with concurrent.futures.ThreadPoolExecutor(
                        max_workers=attackers + 1) as pool:
                    futures = [pool.submit(flood, i) for i in range(attackers)]
                    time.sleep(1.0)  # let the flood reach steady state
                    samples = [victim_login() for _ in range(6)]
                    for f in futures:
                        f.result()

                under = [s[0] for s in samples]
                statuses = sorted({s[1] for s in samples})
                successes = sum(1 for s in samples if s[2])
                per_arm["under_load"].append({
                    "attacker_threads": attackers,
                    "attack_requests_sent": sent["n"],
                    "victim_latency": summarise(under),
                    "victim_p95_slowdown_x": round(
                        summarise(under)["p95_ms"] /
                        summarise(baseline)["p95_ms"], 2),
                    "victim_status_codes": statuses,
                    "victim_success_rate": round(successes / len(samples), 3),
                    # The honest headline: a fast response the victim was
                    # refused is worse than a slow one they were served.
                    "victim_served": successes == len(samples),
                })
            results[arm] = per_arm
    return results


def make_figure(data: dict[str, object], path: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(11.5, 8))
    chosen = data["chosen"]["parameters"]

    # Memory sweep.
    ax = axes[0][0]
    sweep = data["memory_sweep"]
    x = [p["m_mib"] for p in sweep]
    y = [p["mean_ms"] for p in sweep]
    ax.plot(x, y, "o-", color="#3f7fb5")
    for point in sweep:
        if point["m_kib"] == chosen["m_kib"]:
            ax.plot([point["m_mib"]], [point["mean_ms"]], "o", color="#c94f4f",
                    markersize=11, label="chosen: RFC 9106 option 2")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("memory cost m (MiB, log2)")
    ax.set_ylabel("mean latency per hash (ms)")
    ax.set_title(f"Latency vs memory cost (t={chosen['t']}, p={chosen['p']})",
                 fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.25)

    # Time sweep.
    ax = axes[0][1]
    sweep = data["time_sweep"]
    ax.plot([p["t"] for p in sweep], [p["mean_ms"] for p in sweep], "o-",
            color="#3f7fb5")
    for point in sweep:
        if point["t"] == chosen["t"]:
            ax.plot([point["t"]], [point["mean_ms"]], "o", color="#c94f4f",
                    markersize=11, label="chosen: RFC 9106 option 2")
    ax.set_xlabel("time cost t (iterations)")
    ax.set_ylabel("mean latency per hash (ms)")
    ax.set_title(f"Latency vs time cost (m={chosen['m_mib']:.0f} MiB, "
                 f"p={chosen['p']})", fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.25)

    # Concurrency: throughput and transient memory on twin axes.
    ax = axes[1][0]
    conc = data["concurrency"]
    levels = [p["concurrency"] for p in conc]
    ax.plot(levels, [p["throughput_hashes_per_s"] for p in conc], "o-",
            color="#3f7fb5", label="throughput")
    ax.set_xlabel("concurrent hashes in flight")
    ax.set_ylabel("hashes per second", color="#3f7fb5")
    ax.set_xscale("log", base=2)
    ax.grid(alpha=0.25)
    twin = ax.twinx()
    twin.plot(levels, [p["peak_transient_mib"] for p in conc], "s--",
              color="#c94f4f", label="transient memory")
    twin.set_ylabel("peak transient memory (MiB)", color="#c94f4f")
    ax.set_title("Throughput and memory footprint vs concurrency", fontsize=10)
    lines = ax.get_lines() + twin.get_lines()
    ax.legend(lines, [ln.get_label() for ln in lines], fontsize=8, loc="upper left")

    # HTTP: victim latency under attacker load, both arms.
    ax = axes[1][1]
    http = data["http_under_load"]
    arms = [("no_protection", "#c94f4f", "no protection"),
            ("concurrency_cap", "#d9a13b", "concurrency cap only"),
            ("rate_limited", "#4a9e6b", "cap + rate limiting")]
    width = 0.26
    labels = ["no load", "4 attackers", "16 attackers"]
    for offset, (arm, colour, name) in enumerate(arms):
        values = [http[arm]["baseline_ms"]["p95_ms"]] + [
            entry["victim_latency"]["p95_ms"]
            for entry in http[arm]["under_load"]]
        served = [True] + [entry["victim_served"]
                           for entry in http[arm]["under_load"]]
        positions = [i + offset * width for i in range(len(values))]
        ax.bar(positions, values, width, color=colour, label=name)
        # A bar is only good news if the user was actually let in. Mark the ones
        # where the low latency is a refusal, not a service.
        for pos, value, ok in zip(positions, values, served):
            if not ok:
                ax.text(pos, value, "refused", ha="center", va="bottom",
                        fontsize=7, rotation=90, color="#c94f4f")
    ax.set_xticks([i + width for i in range(len(labels))])
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("legitimate login p95 latency (ms)")
    ax.set_title("Availability: what the flood does to a real user\n"
                 "(a 'refused' bar is a denial, not a fast success)", fontsize=9)
    ax.legend(fontsize=7)
    ax.grid(alpha=0.25, axis="y")

    info = data["machine"]
    fig.suptitle(
        "Argon2id cost as a defender-side trade-off\n"
        f"{info['logical_cpus']} logical CPUs, {info['total_ram_mib']} MiB RAM, "
        f"Python {info['python']}", fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)


def main() -> dict[str, object]:
    config = Config()
    print("=== Argon2id cost measurement ===\n")

    info = machine_info()
    print("Machine:")
    for key, value in info.items():
        print(f"  {key}: {value}")

    chosen = bench_chosen(config)
    print(f"\nChosen parameters (RFC 9106 section 4, second recommended): "
          f"t={chosen['parameters']['t']}, "
          f"m={chosen['parameters']['m_mib']:.0f} MiB, "
          f"p={chosen['parameters']['p']}")
    lat = chosen["latency"]
    print(f"  single-hash latency: mean {lat['mean_ms']} ms, "
          f"median {lat['median_ms']} ms, p95 {lat['p95_ms']} ms, "
          f"min {lat['min_ms']} ms (n={lat['n']})")
    print("  The minimum is the least-interference estimate of the true cost: "
          "this is a shared laptop with other processes running, and every "
          "source of interference makes a sample slower, never faster.")

    rng = random.Random(SEED)
    sweeps = bench_parameter_sweeps(config, rng)
    memory_sweep = sweeps["memory_sweep"]
    time_sweep = sweeps["time_sweep"]

    print(f"\nParameter sweeps, {sweeps['rounds']} interleaved rounds in a "
          f"random order per round (seed {SEED}).")
    print("\nMemory sweep (t=3, p=4):")
    print(f"  {'m (MiB)':>9} {'mean ms':>9} {'p95 ms':>8} "
          f"{'hashes/s (serial)':>18}")
    for point in memory_sweep:
        print(f"  {point['m_mib']:>9.0f} {point['mean_ms']:>9.2f} "
              f"{point['p95_ms']:>8.2f} {1000 / point['mean_ms']:>18.1f}")

    print("\nTime-cost sweep (m=64 MiB, p=4):")
    print(f"  {'t':>3} {'mean ms':>9} {'p95 ms':>8}")
    for point in time_sweep:
        print(f"  {point['t']:>3} {point['mean_ms']:>9.2f} {point['p95_ms']:>8.2f}")

    drift = sweeps["drift"]
    print(f"\nDrift probe (chosen parameters, once per round): "
          f"first half mean {drift['first_half_mean_ms']} ms, "
          f"second half mean {drift['second_half_mean_ms']} ms, "
          f"ratio {drift['drift_ratio']}x")
    if drift["drift_ratio"] > 1.15:
        print("  The machine slowed measurably during the sweep. Interleaving is "
              "what keeps that out of the parameter curves; treat the absolute "
              "millisecond values as this-machine-under-load figures, and the "
              "relative shape of each curve as the reliable part.")

    print("\nConcurrency (chosen parameters, levels in random order):")
    concurrency = bench_concurrency(config, rng)
    print(f"  {'threads':>7} {'hashes/s':>10} {'speedup':>8} {'mean ms':>9} "
          f"{'p95 ms':>8} {'transient MiB':>14}")
    for point in concurrency:
        print(f"  {point['concurrency']:>7} "
              f"{point['throughput_hashes_per_s']:>10.2f} "
              f"{point['speedup_over_serial']:>8.2f} "
              f"{point['mean_ms']:>9.2f} {point['p95_ms']:>8.2f} "
              f"{point['peak_transient_mib']:>14.0f}")

    print("\nHTTP availability under attacker load:")
    http = bench_http_under_load()
    for arm in ("no_protection", "concurrency_cap", "rate_limited"):
        print(f"  {arm}:")
        base = http[arm]["baseline_ms"]
        print(f"    victim login, no load: mean {base['mean_ms']} ms, "
              f"p95 {base['p95_ms']} ms, "
              f"success rate {http[arm]['baseline_success_rate']:.0%}")
        for entry in http[arm]["under_load"]:
            v = entry["victim_latency"]
            print(f"    {entry['attacker_threads']:>2} attacker threads "
                  f"({entry['attack_requests_sent']} requests in 6 s): "
                  f"victim mean {v['mean_ms']} ms, p95 {v['p95_ms']} ms "
                  f"({entry['victim_p95_slowdown_x']}x baseline p95), "
                  f"statuses {entry['victim_status_codes']}, "
                  f"logged in {entry['victim_success_rate']:.0%} of the time")
            if not entry["victim_served"]:
                print("        ^ the victim was REFUSED, not served. The low "
                      "latency here is the sound of the door being shut in "
                      "their face, not of the limiter protecting them.")

    # Re-measure the chosen parameters after everything else has run, so the
    # difference between an idle machine and a loaded one is a reported number
    # rather than an excuse. This is directly relevant to the DoS discussion:
    # the cost of a login is not a constant, it is a function of what else the
    # box is doing, and an attacker's job is to make the box busy.
    chosen_after = bench_chosen(config)
    after = chosen_after["latency"]
    print(f"\nChosen parameters re-measured after the full benchmark load: "
          f"mean {after['mean_ms']} ms, median {after['median_ms']} ms, "
          f"min {after['min_ms']} ms")
    print(f"  vs at the start: mean {lat['mean_ms']} ms, "
          f"median {lat['median_ms']} ms, min {lat['min_ms']} ms")

    data = {
        "seed": SEED,
        "machine": info,
        "machine_note": ("shared Windows laptop with unrelated processes "
                         "running; absolute latencies are this-machine-under-"
                         "load figures, the curve shapes and ratios are the "
                         "portable findings"),
        "chosen": chosen,
        "chosen_after_load": chosen_after,
        "memory_sweep": memory_sweep,
        "time_sweep": time_sweep,
        "sweep_drift": drift,
        "sweep_rounds": sweeps["rounds"],
        "concurrency": concurrency,
        "http_under_load": http,
    }
    make_figure(data, FIGURE_PATH)
    print(f"\nFigure written to {FIGURE_PATH}")
    return data


if __name__ == "__main__":
    result = main()
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "outputs", "reports", "argon2_bench.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"Raw data written to {out}")

