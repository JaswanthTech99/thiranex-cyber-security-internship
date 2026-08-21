"""SQL injection: fire a real public payload corpus at the live login endpoint.

Corpus (fetched at run time, cached under .cache/ so a re-run works offline):
  SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt
  SecLists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt
  SecLists/Fuzzing/Databases/SQLi/quick-SQLi.txt

Two targets, same payloads:

  A. POST /login  -- the real endpoint, parameterised queries.
     Assertions: no payload authenticates, and no payload produces a 5xx. The
     second assertion matters as much as the first. A 500 means the payload
     reached something that could not cope with it, which is both an information
     leak (error text) and a hint that the input is being parsed somewhere it
     should not be. "Rejected cleanly" is the bar, not "rejected".

  B. POST /demo/vulnerable/login -- the control group, string-concatenated SQL.
     Assertion: a non-zero number of the SAME payloads DO authenticate. Without
     this half, target A only proves the payloads were sent somewhere.

Rate limiting is disabled on both servers for this suite. With lockout on, the
tenth payload onwards would be answered 429 and the run would prove nothing
about the SQL layer -- every payload would be "rejected" by the limiter rather
than by parameterisation. The limiter is tested on its own in
tests/test_lockout.py.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
import urllib.parse

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.harness import Suite  # noqa: E402
from tests.server import PROJECT_ROOT, AppServer, Client, TEST_PASSWORD  # noqa: E402

SOURCES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Fuzzing/Databases/SQLi/quick-SQLi.txt",
]

CACHE_DIR = os.path.join(PROJECT_ROOT, ".cache")
EVIDENCE_PATH = os.path.join(PROJECT_ROOT, "outputs", "reports",
                             "sqli_payloads_fired.txt")
VICTIM_USER = "sqli_victim"
SHARDS = 4  # four in-flight Argon2 verifies is ~256 MiB, comfortable here


def fetch_payloads() -> tuple[list[str], dict[str, int], list[str]]:
    """Return (deduped payloads, per-source counts, notes)."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    per_source: dict[str, int] = {}
    notes: list[str] = []
    seen: dict[str, None] = {}

    for url in SOURCES:
        name = url.rsplit("/", 1)[-1]
        cache_path = os.path.join(CACHE_DIR, name)
        text: str | None = None
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            text = response.text
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            notes.append(f"{name}: fetched from SecLists ({len(text)} bytes)")
        except requests.RequestException as exc:
            if os.path.exists(cache_path):
                with open(cache_path, encoding="utf-8") as fh:
                    text = fh.read()
                notes.append(f"{name}: network failed ({exc}); used cache")
            else:
                notes.append(f"{name}: UNAVAILABLE ({exc})")
                per_source[name] = 0
                continue

        lines = [ln.rstrip("\r\n") for ln in text.splitlines()]
        # Keep blank-ish lines out but keep everything else verbatim, including
        # leading spaces -- some payloads depend on them.
        payloads = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
        per_source[name] = len(payloads)
        for payload in payloads:
            seen.setdefault(payload, None)

    return list(seen), per_source, notes


def _fire_at_real(server: AppServer, payloads: list[str],
                  field: str) -> dict[str, object]:
    """Send every payload into one field of POST /login. Returns a summary."""
    authenticated: list[str] = []
    server_errors: list[tuple[str, int, str]] = []
    status_counts: dict[int, int] = {}
    transport_errors: list[tuple[str, str]] = []

    def worker(shard: list[str]) -> None:
        client = Client(server)
        client.prime_csrf("/login")
        for payload in shard:
            if field == "username":
                username, password = payload, "irrelevant-not-the-password"
            else:
                username, password = VICTIM_USER, payload
            try:
                response = client.post_json("/login", {
                    "username": username, "password": password,
                    "csrf_token": client.csrf_token})
            except requests.RequestException as exc:
                transport_errors.append((payload, str(exc)))
                continue

            status_counts[response.status_code] = \
                status_counts.get(response.status_code, 0) + 1
            if response.status_code >= 500:
                server_errors.append((payload, response.status_code,
                                      response.text[:200]))
            body = {}
            try:
                body = response.json()
            except ValueError:
                pass
            if body.get("authenticated") or response.status_code in (302, 303):
                authenticated.append(payload)

    shards = [payloads[i::SHARDS] for i in range(SHARDS)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=SHARDS) as pool:
        list(pool.map(worker, shards))

    return {
        "field": field,
        "fired": len(payloads),
        "authenticated": authenticated,
        "server_errors": server_errors,
        "transport_errors": transport_errors,
        "status_counts": dict(sorted(status_counts.items())),
    }


def _fire_at_vulnerable(server: AppServer, payloads: list[str],
                        field: str) -> dict[str, object]:
    bypassed: list[str] = []
    db_errors = 0
    status_counts: dict[int, int] = {}
    http = requests.Session()

    for payload in payloads:
        if field == "username":
            data = {"username": payload, "password": "irrelevant"}
        else:
            data = {"username": "demo_victim", "password": payload}
        try:
            response = http.post(server.base + "/demo/vulnerable/login",
                                 data=data, timeout=30)
        except requests.RequestException:
            continue
        status_counts[response.status_code] = \
            status_counts.get(response.status_code, 0) + 1
        body = {}
        try:
            body = response.json()
        except ValueError:
            pass
        if body.get("authenticated"):
            bypassed.append(payload)
        if body.get("db_error"):
            db_errors += 1

    return {
        "field": field,
        "fired": len(payloads),
        "bypassed": bypassed,
        "db_errors": db_errors,
        "status_counts": dict(sorted(status_counts.items())),
    }


def run(suite: Suite) -> dict[str, object]:
    payloads, per_source, notes = fetch_payloads()
    suite.section("Payload corpus")
    for note in notes:
        suite.note(note)
    for name, count in per_source.items():
        suite.note(f"{name}: {count} payloads")
    suite.note(f"total after dedup: {len(payloads)}")
    suite.check_true("corpus is non-trivial (>= 100 payloads)", len(payloads) >= 100)

    os.makedirs(os.path.dirname(EVIDENCE_PATH), exist_ok=True)
    with open(EVIDENCE_PATH, "w", encoding="utf-8") as fh:
        fh.write("# Exact payload corpus fired by tests/test_sqli.py\n")
        for url in SOURCES:
            fh.write(f"# source: {url}\n")
        fh.write(f"# deduplicated payload count: {len(payloads)}\n")
        for payload in payloads:
            # URL-quote on write so a payload containing a newline-ish byte
            # cannot corrupt the one-payload-per-line evidence file.
            fh.write(urllib.parse.quote(payload) + "\n")
    suite.note(f"corpus written to {EVIDENCE_PATH} (percent-encoded, one per line)")

    results: dict[str, object] = {"corpus": {"sources": SOURCES,
                                            "per_source": per_source,
                                            "deduped_total": len(payloads),
                                            "notes": notes}}

    # --- A. the real endpoint -------------------------------------------------
    suite.section("Target A: POST /login (parameterised queries)")
    with AppServer(extra_args=["--no-rate-limit", "--no-breach-check"],
                   label="hardened") as server:
        client = Client(server)
        reg = client.register(VICTIM_USER, TEST_PASSWORD)
        suite.check("victim account created for the password-field pass",
                    reg.status_code, 201)

        real_results = {}
        for field in ("username", "password"):
            outcome = _fire_at_real(server, payloads, field)
            real_results[field] = outcome
            suite.note(f"{field} field: {outcome['fired']} payloads, "
                       f"status counts {outcome['status_counts']}")
            suite.check(f"no payload authenticated via the {field} field",
                        len(outcome["authenticated"]), 0)
            suite.check(f"no payload caused a 5xx via the {field} field",
                        len(outcome["server_errors"]), 0)
            suite.check(f"no transport errors via the {field} field",
                        len(outcome["transport_errors"]), 0)
            if outcome["authenticated"]:
                for p in outcome["authenticated"][:5]:
                    suite.note(f"BYPASS via {field}: {p!r}")
            if outcome["server_errors"]:
                for p, code, text in outcome["server_errors"][:5]:
                    suite.note(f"5xx via {field}: {p!r} -> {code} {text!r}")

        # The account must still work afterwards. If a payload had corrupted or
        # dropped the table, this is where it shows.
        after = Client(server)
        after.register("post_sqli_probe", TEST_PASSWORD)
        login_after = after.login("post_sqli_probe", TEST_PASSWORD)
        suite.check("database still intact: a fresh account can log in "
                    "after the whole corpus",
                    login_after.json().get("authenticated"), True)
        results["real_endpoint"] = {
            field: {k: (len(v) if isinstance(v, list) else v)
                    for k, v in outcome.items()}
            for field, outcome in real_results.items()}

    # --- B. the deliberately vulnerable control group ------------------------
    suite.section("Target B: POST /demo/vulnerable/login (string-concatenated SQL)")
    with AppServer(extra_args=["--no-rate-limit", "--no-breach-check",
                               "--demo-vulnerable"], label="vulnerable") as server:
        vuln_results = {}
        for field in ("username", "password"):
            outcome = _fire_at_vulnerable(server, payloads, field)
            vuln_results[field] = outcome
            bypassed = outcome["bypassed"]
            suite.note(f"{field} field: {outcome['fired']} payloads, "
                       f"{len(bypassed)} authenticated, "
                       f"{outcome['db_errors']} raised a driver error")
            suite.check_true(
                f"the same corpus DOES bypass the vulnerable {field} field",
                len(bypassed) > 0)
            for p in bypassed[:5]:
                suite.note(f"working bypass via {field}: {p!r}")
        results["vulnerable_endpoint"] = {
            field: {"fired": outcome["fired"],
                    "bypassed": len(outcome["bypassed"]),
                    "bypass_examples": outcome["bypassed"][:10],
                    "db_errors": outcome["db_errors"],
                    "status_counts": outcome["status_counts"]}
            for field, outcome in vuln_results.items()}

    suite.section("Contrast")
    real_total = sum(len(r["authenticated"]) for r in real_results.values())
    vuln_total = sum(len(r["bypassed"]) for r in vuln_results.values())
    suite.note(f"parameterised endpoint: {real_total} bypasses out of "
               f"{2 * len(payloads)} requests")
    suite.note(f"concatenated endpoint:  {vuln_total} bypasses out of "
               f"{2 * len(payloads)} requests")
    suite.check("parameterised endpoint bypass count", real_total, 0)
    suite.check_true("concatenated endpoint bypass count is non-zero", vuln_total > 0)
    results["summary"] = {"requests_per_target": 2 * len(payloads),
                          "parameterised_bypasses": real_total,
                          "concatenated_bypasses": vuln_total}
    return results


if __name__ == "__main__":
    suite = Suite("SQL injection: SecLists corpus vs parameterised queries")
    run(suite)
    sys.exit(suite.finish())
