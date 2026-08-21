"""Breach check against Have I Been Pwned's Pwned Passwords range API.

How the k-anonymity works, and why it is safe to call a third party with
something derived from a password:

  1. We compute SHA-1(password) and uppercase the hex. Say it is
     21BD10018A45C4D1DEF81644B54AB7F969B88D65 (the SHA-1 of "password123").
  2. We send only the FIRST FIVE hex characters -- 21BD1 -- as the URL path.
     Twenty bits. Nothing else leaves the machine: not the password, not the
     full hash, not the username, not any identifier.
  3. The server returns every suffix it holds under that prefix, each with a
     breach count. There are ~850 such buckets' worth of entries per prefix in
     the current corpus, so the answer contains on the order of 800 to 1000
     candidate hashes.
  4. We look for our own 35-character suffix in that list, locally.

The privacy property: the server learns that someone asked about one of the
~1000 passwords sharing that 20-bit prefix, and cannot tell which. That is the
k in k-anonymity -- our query is indistinguishable from k-1 others. It is not
zero-knowledge (the prefix is real information, and a prefix is a 1-in-1048576
narrowing of SHA-1 space), but combined with the fact that we send nothing
identifying, an observer cannot map a query back to a user or a password.

`Add-Padding: true` is requested because response size would otherwise leak:
buckets have different numbers of entries, and an eavesdropper watching TLS
record lengths could narrow down which prefix was asked for even without seeing
the URL. With padding the server adds random zero-count entries so every
response is a similar size. Padding entries carry a count of 0, which is why the
parser below drops them -- a real breached password always has count >= 1.

SHA-1 is used because that is the API's index. It is not being relied on for
security here; a collision would only cause a false "breached" answer, which
fails safe.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import requests

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "secure-login-system/1.0 (thiranex internship project; python-requests)"


@dataclass
class BreachResult:
    breached: bool
    count: int
    prefix: str
    candidates_returned: int
    available: bool          # False when the API could not be reached
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "breached": self.breached,
            "count": self.count,
            "prefix": self.prefix,
            "candidates_returned": self.candidates_returned,
            "available": self.available,
            "error": self.error,
        }


def sha1_hex_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password(password: str, timeout: float = 5.0,
                   session: requests.Session | None = None) -> BreachResult:
    digest = sha1_hex_upper(password)
    prefix, suffix = digest[:5], digest[5:]

    http = session or requests
    try:
        response = http.get(
            API_URL + prefix,
            headers={"Add-Padding": "true", "User-Agent": USER_AGENT},
            timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        # Fail open, and say so.
        #
        # This is a deliberate trade-off. Failing closed means a HIBP outage
        # takes down registration for everybody, which converts someone else's
        # availability problem into ours; the check is defence in depth on top of
        # a 12-character minimum and Argon2id, not the thing holding the door.
        # For a system where account takeover is expensive (banking, admin
        # consoles) I would fail closed instead and accept the outage. The caller
        # can tell the two cases apart via `available`, and the app logs it.
        return BreachResult(False, 0, prefix, 0, available=False, error=str(exc))

    count = 0
    candidates = 0
    for line in response.text.splitlines():
        if ":" not in line:
            continue
        candidate_suffix, _, raw_count = line.partition(":")
        candidate_suffix = candidate_suffix.strip().upper()
        try:
            candidate_count = int(raw_count.strip().replace(",", ""))
        except ValueError:
            continue
        if candidate_count == 0:
            # Padding entry injected because we asked for Add-Padding.
            continue
        candidates += 1
        # compare_digest, not ==, so the loop does not run in data-dependent
        # time. The threat here is small (a local attacker who can time this
        # loop already has the process), but the fix is one function call.
        if hmac.compare_digest(candidate_suffix, suffix):
            count = candidate_count

    return BreachResult(bool(count), count, prefix, candidates, available=True)
