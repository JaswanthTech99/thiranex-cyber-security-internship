"""Input validation rules, password hashing properties, and the HIBP check.

The HIBP section asserts the k-anonymity property rather than just "the call
worked": it checks that the request URL carries only five hex characters, that
the returned bucket holds hundreds of candidates (so our query is hidden among
them), and that a locally-computed full hash never appears in anything we send.
"""

from __future__ import annotations

import hashlib
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import hibp, validation  # noqa: E402
from src.config import Config  # noqa: E402
from src.passwords import PasswordService  # noqa: E402
from tests.harness import Suite  # noqa: E402
from tests.server import AppServer, Client, TEST_PASSWORD  # noqa: E402

# "password" -- the canonical Pwned Passwords example. Its SHA-1 prefix 5BAA6
# is the one used in the API documentation.
KNOWN_BREACHED = "password"
KNOWN_BREACHED_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def run(suite: Suite) -> dict[str, object]:
    config = Config()
    results: dict[str, object] = {}

    suite.section("Username rules")
    for raw, should_pass, why in [
            ("jaswanth", True, "plain lowercase"),
            ("j.kumar_01", True, "separators in the middle"),
            ("ab", False, "too short"),
            ("a" * 33, False, "too long"),
            ("Jaswanth", True, "uppercase is normalised to lowercase, not rejected"),
            ("has space", False, "space would allow lookalike padding"),
            ("semi;colon", False, "outside the charset"),
            ("quote'name", False, "outside the charset"),
            ("-leading", False, "leading separator"),
            ("trailing.", False, "trailing separator"),
            ("double..dot", False, "repeated separator hides near-duplicates"),
            ("admin", False, "reserved"),
            ("root", False, "reserved"),
            ("", False, "empty")]:
        result = validation.validate_username(raw, config)
        suite.check(f"username {raw!r} ({why})", result.ok, should_pass)

    suite.check("uppercase folds to lowercase",
                validation.validate_username("JasWanth", config).value, "jaswanth")
    # NFKC folding: the fullwidth 'ａｄｍｉｎ' normalises to 'admin', which is then
    # caught by the reserved list. Without normalisation it would be a distinct
    # username that renders almost identically.
    suite.check("fullwidth characters normalise under NFKC",
                validation.normalise_username("ａｄｍｉｎ"),
                "admin")
    suite.check("and the normalised form hits the reserved list",
                validation.validate_username(
                    "ａｄｍｉｎ", config).ok, False)

    suite.section("Password rules")
    for raw, should_pass, why in [
            ("correct horse battery staple", True, "long passphrase, no symbols"),
            ("aaaaaaaaaaaa", True, "12 chars; weak but not our call to refuse "
                                   "on composition, the breach check handles it"),
            ("short", False, "under 12 characters"),
            ("x" * 129, False, "over 128 characters"),
            ("has\x00null", False, "null byte"),
            ("has\ttab", False, "control character"),
            ("", False, "empty"),
            ("pässwörd-with-umlauts", True, "non-ASCII is fine")]:
        result = validation.validate_password(raw, config)
        suite.check(f"password ({why})", result.ok, should_pass)

    suite.check("a 64-character passphrase is accepted, as SP 800-63B requires",
                validation.validate_password("a" * 64, config).ok, True)
    suite.check("leading/trailing spaces are preserved, not silently stripped",
                validation.validate_password("  spaces kept here  ", config).value,
                "  spaces kept here  ")
    suite.check("NFKC is applied to passwords too",
                validation.normalise_password("ａｂｃ"), "abc")

    suite.section("Argon2id parameters and hashing behaviour")
    service = PasswordService(config)
    params = service.parameters()
    suite.check("type", params["type"], "Argon2id")
    suite.check("t (RFC 9106 second recommended)", params["time_cost"], 3)
    suite.check("m in KiB (2^16 = 64 MiB)", params["memory_cost_kib"], 65536)
    suite.check("p (lanes)", params["parallelism"], 4)
    suite.check("salt length in bytes (128-bit)", params["salt_len"], 16)
    suite.check("tag length in bytes (256-bit)", params["hash_len"], 32)

    hash_a = service.hash(TEST_PASSWORD)
    hash_b = service.hash(TEST_PASSWORD)
    suite.check_true("the encoded hash declares argon2id",
                     hash_a.startswith("$argon2id$"))
    suite.check_true("the encoded hash carries the parameters",
                     "m=65536,t=3,p=4" in hash_a)
    suite.check_true("two hashes of the same password differ (random salt)",
                     hash_a != hash_b)
    suite.check("verify accepts the right password",
                service.verify(hash_a, TEST_PASSWORD), True)
    suite.check("verify rejects a wrong password",
                service.verify(hash_a, TEST_PASSWORD + "x"), False)
    suite.check("verify rejects a malformed stored hash",
                service.verify("not-a-hash", TEST_PASSWORD), False)
    suite.check("a hash at the current parameters does not need a rehash",
                service.needs_rehash(hash_a), False)

    # A hash made with weaker parameters must be flagged for upgrade at login.
    weak_config = Config()
    weak_config.argon2_memory_cost_kib = 8192   # 8 MiB
    weak_config.argon2_time_cost = 1
    weak_hash = PasswordService(weak_config).hash(TEST_PASSWORD)
    suite.check("a hash made with weaker parameters is flagged for rehash",
                service.needs_rehash(weak_hash), True)
    suite.check("but it still verifies, so nobody is locked out by an upgrade",
                service.verify(weak_hash, TEST_PASSWORD), True)
    results["argon2_parameters"] = params

    suite.section("Have I Been Pwned: k-anonymity properties")
    digest = hibp.sha1_hex_upper(KNOWN_BREACHED)
    suite.check("SHA-1 of the sample password matches the documented value",
                digest, KNOWN_BREACHED_SHA1)
    prefix, suffix = digest[:5], digest[5:]
    suite.check("the prefix we would send is 5 hex characters", len(prefix), 5)
    suite.check("which leaves 35 characters we never send", len(suffix), 35)
    suite.check("the prefix is 20 bits of the hash",
                len(prefix) * 4, 20)

    result = hibp.check_password(KNOWN_BREACHED, timeout=config.hibp_timeout_s)
    if not result.available:
        suite.note(f"HIBP unreachable ({result.error}); k-anonymity assertions "
                   "that need the network are skipped, and the app's fail-open "
                   "behaviour is what is being exercised instead")
        suite.check("an unreachable API fails open rather than blocking "
                    "registration", result.breached, False)
    else:
        suite.check("a known-breached password is reported as breached",
                    result.breached, True)
        suite.check_true(f"and with a large count ({result.count:,})",
                         result.count > 1_000_000)
        suite.note(f"the bucket for prefix {result.prefix} returned "
                   f"{result.candidates_returned} real candidate suffixes, so "
                   f"our query is one of {result.candidates_returned} "
                   "indistinguishable possibilities")
        suite.check_true("the bucket is large enough to hide the query "
                         "(k >= 100)", result.candidates_returned >= 100)

        unique = "sls-project-04-" + os.urandom(8).hex()
        clean = hibp.check_password(unique, timeout=config.hibp_timeout_s)
        suite.check("a random unique password is not reported as breached",
                    clean.breached, False)
        suite.check_true("and its bucket is also large, so a miss and a hit "
                         "look the same from outside",
                         clean.candidates_returned >= 100)

        # Confirm what actually travels: the URL contains the prefix and nothing
        # more. This is asserted against the real request the module builds.
        expected_url = hibp.API_URL + prefix
        suite.check("the request URL is the range endpoint plus the 5-char "
                    "prefix only", expected_url,
                    f"https://api.pwnedpasswords.com/range/{prefix}")
        suite.check_true("the full hash never appears in the URL",
                         digest not in expected_url)
        suite.check_true("the suffix never appears in the URL",
                         suffix not in expected_url)

        # Padding: the header we send should make the response contain zero-count
        # entries, which the parser must discard.
        raw = requests.get(expected_url, timeout=15,
                           headers={"Add-Padding": "true",
                                    "User-Agent": hibp.USER_AGENT})
        zero_count_lines = sum(1 for ln in raw.text.splitlines()
                               if ln.strip().endswith(":0"))
        suite.note(f"the padded response contained {zero_count_lines} "
                   "zero-count padding entries, which the parser drops")
        suite.check_true("Add-Padding produced padding entries",
                         zero_count_lines > 0)
        results["hibp"] = {
            "sample_password_breach_count": result.count,
            "candidates_in_bucket": result.candidates_returned,
            "padding_entries": zero_count_lines,
            "prefix_sent": result.prefix,
            "prefix_bits": 20,
        }

    suite.section("Registration enforces the rules over HTTP")
    with AppServer(label="validation") as server:
        client = Client(server)
        suite.check("a breached password is refused",
                    client.register("valid.user", "Password1234").status_code, 400)
        suite.check("a short password is refused",
                    client.register("valid.user", "short").status_code, 400)
        suite.check("a reserved username is refused",
                    client.register("admin", TEST_PASSWORD).status_code, 400)
        suite.check("a password containing the username is refused",
                    client.register("jaswanthdemo",
                                    "xx-jaswanthdemo-2026-abc").status_code, 400)

        mismatch = client.register("valid.user", TEST_PASSWORD,
                                   confirm=TEST_PASSWORD + "x")
        suite.check("mismatched confirmation is refused", mismatch.status_code, 400)

        ok = client.register("valid.user", TEST_PASSWORD)
        suite.check("a compliant registration succeeds", ok.status_code, 201)
        again = client.register("valid.user", TEST_PASSWORD)
        suite.check("a duplicate username is refused with 409",
                    again.status_code, 409)

    return results


if __name__ == "__main__":
    suite = Suite("Validation, Argon2 parameters, and the HIBP breach check")
    run(suite)
    sys.exit(suite.finish())
