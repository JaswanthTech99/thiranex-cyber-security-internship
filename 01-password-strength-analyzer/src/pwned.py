"""Breach lookup against Have I Been Pwned, without disclosing the password.

The k-anonymity range API takes the first five hex characters of the SHA-1 of the
candidate and returns every suffix sharing that prefix - on the order of 800
hashes. The full hash never leaves this process, and the server cannot tell which
of the ~800 candidates was being asked about.

That design choice is the whole reason this check is safe to ship. Posting the
password, or even its complete hash, to a third party in order to grade it would
be a worse outcome than the weak password it was trying to prevent.

`Add-Padding: true` asks HIBP to pad the response to a uniform length, so an
observer who can see the encrypted response size cannot infer the prefix's
popularity. Padding entries carry a count of 0 and are dropped below.
"""
from __future__ import annotations

import hashlib

import requests

API = "https://api.pwnedpasswords.com/range/"
HEADERS = {
    "User-Agent": "password-strength-analyzer/1.0 (+https://github.com/JaswanthTech99)",
    "Add-Padding": "true",
}


class PwnedClient:
    def __init__(self, timeout: int = 20) -> None:
        self.session = requests.Session()
        self.timeout = timeout
        self._cache: dict[str, dict[str, int]] = {}
        self.requests_made = 0

    def _range(self, prefix: str) -> dict[str, int]:
        if prefix in self._cache:
            return self._cache[prefix]
        r = self.session.get(API + prefix, headers=HEADERS, timeout=self.timeout)
        r.raise_for_status()
        self.requests_made += 1
        out: dict[str, int] = {}
        for line in r.text.splitlines():
            if ":" not in line:
                continue
            suffix, count = line.split(":", 1)
            try:
                n = int(count)
            except ValueError:
                continue
            if n > 0:  # 0 means it is padding, not a real observation
                out[suffix.strip().upper()] = n
        self._cache[prefix] = out
        return out

    def count(self, password: str) -> int:
        """How many times this password appears in HIBP's breach corpus."""
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        return self._range(prefix).get(suffix, 0)

    def range_size(self, password: str) -> int:
        """Number of real hashes returned for this password's prefix - the size
        of the crowd the query hid in."""
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return len(self._range(digest[:5]))


if __name__ == "__main__":
    import sys

    c = PwnedClient()
    for pw in sys.argv[1:] or ["password", "correct horse battery staple"]:
        print(f"{pw!r}: seen {c.count(pw):,} times (hidden among {c.range_size(pw)} hashes)")
