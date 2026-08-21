"""User enumeration by response timing: measure the leak, then measure the fix.

The leak. POST /login with a username that does not exist can return as soon as
the SELECT misses. POST /login with a username that does exist has to run an
Argon2id verify first -- 64 MiB and tens of milliseconds. If the server takes
that shortcut, response time is an oracle for "does this account exist", and it
does not matter that the error message and the status code are identical.

The fix, in src/passwords.py: on the unknown-user path, verify the submitted
password against a throwaway hash built with the same parameters, and discard
the result. Same work, same latency.

This file measures both. It starts two servers that differ in exactly one
setting, fires interleaved known/unknown login attempts at each, and reports
distributions plus how well a single request classifies. Interleaving matters:
measuring all the known-user requests and then all the unknown-user ones would
attribute any drift in machine load to the thing being measured.

Rate limiting is off on both servers. It has to be -- 300 failed logins against
the same two usernames would otherwise be answered by the lockout after the
fifth -- and that is honest rather than convenient, because in production the
lockout is what bounds how many timing samples an attacker can take. That cost
is quantified separately in tests/test_lockout.py.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.harness import Suite  # noqa: E402
from tests.server import PROJECT_ROOT, AppServer, Client, TEST_PASSWORD  # noqa: E402

SEED = 20260821
SAMPLES_PER_CLASS = 150
KNOWN_USER = "enum.known"
UNKNOWN_USER = "enum.absent"
WRONG_PASSWORD = "definitely-not-the-right-password-0000"
FIGURE_PATH = os.path.join(PROJECT_ROOT, "outputs", "figures",
                           "enumeration_timing.png")


def measure(server: AppServer, samples: int,
            rng: random.Random) -> dict[str, object]:
    """Interleaved known/unknown login attempts. Returns latencies in ms."""
    client = Client(server)
    client.prime_csrf("/login")

    plan = [KNOWN_USER] * samples + [UNKNOWN_USER] * samples
    rng.shuffle(plan)

    timings: dict[str, list[float]] = {KNOWN_USER: [], UNKNOWN_USER: []}
    statuses: dict[str, set[int]] = {KNOWN_USER: set(), UNKNOWN_USER: set()}
    bodies: dict[str, set[str]] = {KNOWN_USER: set(), UNKNOWN_USER: set()}

    # Warm-up requests that are not recorded: the first request into a fresh
    # process pays for connection setup and lazy imports, and attributing that
    # to the mitigation would be wrong.
    for username in (KNOWN_USER, UNKNOWN_USER):
        client.post_json("/login", {"username": username,
                                    "password": WRONG_PASSWORD,
                                    "csrf_token": client.csrf_token})

    for username in plan:
        start = time.perf_counter()
        response = client.post_json("/login", {
            "username": username, "password": WRONG_PASSWORD,
            "csrf_token": client.csrf_token})
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        timings[username].append(elapsed_ms)
        statuses[username].add(response.status_code)
        payload = response.json()
        # Compare the client-visible message only. reason_internal is a debug
        # field the harness uses to confirm which branch ran; it is not part of
        # what a real client is told, and the test asserts that separately.
        bodies[username].add(payload.get("error", ""))

    return {"timings": timings, "statuses": statuses, "bodies": bodies}


def describe(values: list[float]) -> dict[str, float]:
    arr = np.array(values)
    return {
        "n": int(arr.size),
        "mean_ms": round(float(arr.mean()), 3),
        "median_ms": round(float(np.median(arr)), 3),
        "stdev_ms": round(float(arr.std(ddof=1)), 3),
        "p05_ms": round(float(np.percentile(arr, 5)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "min_ms": round(float(arr.min()), 3),
        "max_ms": round(float(arr.max()), 3),
    }


def best_threshold_accuracy(known: list[float],
                            unknown: list[float]) -> dict[str, float]:
    """How well can ONE request classify a username as existing or not?

    Sweeps every candidate threshold and reports the best accuracy achievable by
    "slower than t means the account exists". 0.5 is chance, i.e. no leak. This
    is the number that matters: an attacker does not need statistics if a single
    request answers the question.
    """
    known_arr = np.array(known)
    unknown_arr = np.array(unknown)
    candidates = np.unique(np.concatenate([known_arr, unknown_arr]))
    best_acc, best_t = 0.0, float("nan")
    total = known_arr.size + unknown_arr.size
    for t in candidates:
        correct = int((known_arr > t).sum() + (unknown_arr <= t).sum())
        acc = correct / total
        if acc > best_acc:
            best_acc, best_t = acc, float(t)

    # Cohen's d: the separation in units of pooled standard deviation. Useful
    # alongside accuracy because it says how far apart the distributions are,
    # not just whether a line can be drawn between them.
    pooled = np.sqrt(((known_arr.size - 1) * known_arr.var(ddof=1) +
                      (unknown_arr.size - 1) * unknown_arr.var(ddof=1)) /
                     (known_arr.size + unknown_arr.size - 2))
    cohens_d = float(abs(known_arr.mean() - unknown_arr.mean()) / pooled) if pooled else 0.0

    return {"best_single_request_accuracy": round(best_acc, 4),
            "best_threshold_ms": round(best_t, 3),
            "cohens_d": round(cohens_d, 3)}


def make_figure(arms: dict[str, dict], path: str) -> None:
    import matplotlib
    matplotlib.use("Agg")  # no display on this machine, and none needed
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(11, 7.5))
    order = ["mitigation_off", "mitigation_on"]
    titles = {"mitigation_off": "Mitigation OFF (no dummy verify)",
              "mitigation_on": "Mitigation ON (dummy Argon2id verify)"}
    colours = {"known": "#c94f4f", "unknown": "#3f7fb5"}

    for col, arm in enumerate(order):
        known = arms[arm]["known_ms"]
        unknown = arms[arm]["unknown_ms"]

        # Row 0: histogram, log-x. Log because the OFF arm spans two orders of
        # magnitude and a linear axis would collapse the fast class into a spike.
        ax = axes[0][col]
        lo = max(min(min(known), min(unknown)), 0.1)
        hi = max(max(known), max(unknown))
        bins = np.logspace(np.log10(lo * 0.8), np.log10(hi * 1.2), 45)
        ax.hist(unknown, bins=bins, color=colours["unknown"], alpha=0.75,
                label="username does not exist")
        ax.hist(known, bins=bins, color=colours["known"], alpha=0.75,
                label="username exists")
        ax.set_xscale("log")
        ax.set_title(titles[arm], fontsize=10)
        ax.set_xlabel("response time (ms, log scale)")
        ax.set_ylabel("requests")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.2)

        # Row 1: ECDF, shared linear axis, so the two arms are comparable.
        ax = axes[1][col]
        for label, values in (("username does not exist", unknown),
                              ("username exists", known)):
            arr = np.sort(np.array(values))
            ax.step(arr, np.arange(1, arr.size + 1) / arr.size, where="post",
                    label=label,
                    color=colours["unknown" if "not" in label else "known"])
        acc = arms[arm]["classifier"]["best_single_request_accuracy"]
        ax.set_title(f"ECDF -- single-request classifier accuracy {acc:.1%}",
                     fontsize=10)
        ax.set_xlabel("response time (ms)")
        ax.set_ylabel("fraction of requests")
        ax.set_xlim(0, max(max(arms[a]["known_ms"] + arms[a]["unknown_ms"])
                           for a in order) * 1.05)
        ax.legend(fontsize=8)
        ax.grid(alpha=0.2)

    fig.suptitle("User enumeration by login response time\n"
                 f"{SAMPLES_PER_CLASS} interleaved samples per class per arm, "
                 "Argon2id t=3 m=64MiB p=4", fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)


def run(suite: Suite) -> dict[str, object]:
    rng = random.Random(SEED)
    arms: dict[str, dict] = {}

    for arm, extra in (("mitigation_off", ["--no-enum-mitigation"]),
                       ("mitigation_on", [])):
        suite.section(f"Arm: {arm}")
        with AppServer(extra_args=["--no-rate-limit", "--no-breach-check"] + extra,
                       label=arm) as server:
            config = server.config()
            suite.check(f"{arm}: server reports the expected mitigation state",
                        config["enum_mitigation"], arm == "mitigation_on")

            setup = Client(server)
            created = setup.register(KNOWN_USER, TEST_PASSWORD)
            suite.check(f"{arm}: known user created", created.status_code, 201)

            # Same seed for both arms, so both arms see the same interleaving.
            measured = measure(server, SAMPLES_PER_CLASS, random.Random(SEED))

        known_ms = measured["timings"][KNOWN_USER]
        unknown_ms = measured["timings"][UNKNOWN_USER]
        classifier = best_threshold_accuracy(known_ms, unknown_ms)

        arms[arm] = {
            "known_ms": known_ms,
            "unknown_ms": unknown_ms,
            "known": describe(known_ms),
            "unknown": describe(unknown_ms),
            "classifier": classifier,
            "statuses": {k: sorted(v) for k, v in measured["statuses"].items()},
            "bodies": {k: sorted(v) for k, v in measured["bodies"].items()},
        }

        k, u = arms[arm]["known"], arms[arm]["unknown"]
        suite.note(f"{arm}: existing username   mean {k['mean_ms']:.1f} ms, "
                   f"median {k['median_ms']:.1f}, p95 {k['p95_ms']:.1f}, "
                   f"p99 {k['p99_ms']:.1f}")
        suite.note(f"{arm}: absent username     mean {u['mean_ms']:.1f} ms, "
                   f"median {u['median_ms']:.1f}, p95 {u['p95_ms']:.1f}, "
                   f"p99 {u['p99_ms']:.1f}")
        suite.note(f"{arm}: median difference {k['median_ms'] - u['median_ms']:+.1f} ms, "
                   f"Cohen's d {classifier['cohens_d']}, "
                   f"single-request classifier accuracy "
                   f"{classifier['best_single_request_accuracy']:.1%}")

        # These must hold in BOTH arms: the leak under test is timing, so the
        # message and status must already be identical or the experiment is
        # measuring two things at once.
        suite.check(f"{arm}: identical status code for both classes",
                    arms[arm]["statuses"][KNOWN_USER],
                    arms[arm]["statuses"][UNKNOWN_USER])
        suite.check(f"{arm}: identical error message for both classes",
                    arms[arm]["bodies"][KNOWN_USER],
                    arms[arm]["bodies"][UNKNOWN_USER])
        suite.check(f"{arm}: the error message is the single generic one",
                    arms[arm]["bodies"][KNOWN_USER],
                    ["Invalid username or password."])

    suite.section("Did the mitigation work?")
    off = arms["mitigation_off"]
    on = arms["mitigation_on"]

    off_acc = off["classifier"]["best_single_request_accuracy"]
    on_acc = on["classifier"]["best_single_request_accuracy"]
    off_gap = off["known"]["median_ms"] - off["unknown"]["median_ms"]
    on_gap = on["known"]["median_ms"] - on["unknown"]["median_ms"]

    suite.note(f"median gap: {off_gap:+.1f} ms without the fix, "
               f"{on_gap:+.1f} ms with it")
    suite.note(f"single-request classifier: {off_acc:.1%} without the fix, "
               f"{on_acc:.1%} with it (50% is chance)")
    suite.note(f"Cohen's d: {off['classifier']['cohens_d']} without the fix, "
               f"{on['classifier']['cohens_d']} with it")

    suite.check_true("without the fix, one request identifies an account "
                     "almost perfectly (accuracy >= 95%)", off_acc >= 0.95)
    suite.check_true("with the fix, the median gap shrinks by at least 20x",
                     abs(on_gap) * 20 <= abs(off_gap))
    suite.check_true("with the fix, single-request accuracy drops below 70%",
                     on_acc < 0.70)
    # Deliberately not asserting accuracy == 50%. A dummy verify equalises the
    # dominant cost, not every last instruction, and asserting perfection would
    # be a flaky test dressed up as a strong claim. The honest claim is that the
    # oracle stops being usable from a single request.

    make_figure(arms, FIGURE_PATH)
    suite.note(f"figure written to {FIGURE_PATH}")

    return {
        "samples_per_class": SAMPLES_PER_CLASS,
        "seed": SEED,
        "arms": {name: {"known": data["known"], "unknown": data["unknown"],
                        "classifier": data["classifier"],
                        "status_codes": data["statuses"],
                        "client_visible_messages": data["bodies"]}
                 for name, data in arms.items()},
        "median_gap_ms": {"mitigation_off": round(off_gap, 3),
                          "mitigation_on": round(on_gap, 3)},
        "figure": os.path.relpath(FIGURE_PATH, PROJECT_ROOT).replace("\\", "/"),
    }


if __name__ == "__main__":
    suite = Suite("User enumeration timing: leak and mitigation")
    result = run(suite)
    print(json.dumps(result["median_gap_ms"], indent=2))
    sys.exit(suite.finish())
