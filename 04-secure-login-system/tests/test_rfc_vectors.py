"""Check the local HOTP/TOTP implementation against the published test vectors.

Sources, transcribed from the RFC texts at rfc-editor.org:
  RFC 4226 Appendix D  -- HOTP, secret = ASCII "12345678901234567890",
                          counters 0..9, 6 digits, plus the intermediate HMAC
                          values and the truncated values from Tables 1 and 2.
  RFC 6238 Appendix B  -- TOTP, 8 digits, X=30, T0=0, SHA1/SHA256/SHA512.

Note on the RFC 6238 SHA256/SHA512 rows: the prose above Appendix B Table 1
says the shared secret is the 20-byte ASCII string "12345678901234567890", but
the values in the table were produced by the Java reference implementation in
Appendix A, which uses a 32-byte seed for SHA256 and a 64-byte seed for SHA512
(seed32/seed64 in that listing). This is a known erratum against RFC 6238
(Errata ID 2866). We use the reference implementation's seeds, because those are
what actually reproduce the published numbers, and we assert the discrepancy
explicitly at the end so nobody has to rediscover it.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import totp as T  # noqa: E402
from tests.harness import Suite  # noqa: E402

# RFC 4226 Appendix D, "Secret = 0x3132...3930" (ASCII "12345678901234567890").
RFC4226_SECRET = bytes.fromhex("3132333435363738393031323334353637383930")

# Appendix D Table 1: count -> hex HMAC-SHA-1(secret, count).
RFC4226_HMAC = [
    "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
    "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
    "0bacb7fa082fef30782211938bc1c5e70416ff44",
    "66c28227d03a2d5529262ff016a1e6ef76557ece",
    "a904c900a64b35909874b33e61c5938a8e15ed1c",
    "a37e783d7b7233c083d4f62926c7a25f238d0316",
    "bc9cd28561042c83f219324d3c607256c03272ae",
    "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
    "1b3c89f65e6c9e883012052823443f048b4332db",
    "1637409809a679dc698207310c8c7fc07290d9e5",
]

# Appendix D Table 2: count -> (truncated hex, truncated decimal, HOTP).
RFC4226_TRUNCATED = [
    ("4c93cf18", 1284755224, "755224"),
    ("41397eea", 1094287082, "287082"),
    ("082fef30", 137359152, "359152"),
    ("66ef7655", 1726969429, "969429"),
    ("61c5938a", 1640338314, "338314"),
    ("33c083d4", 868254676, "254676"),
    ("7256c032", 1918287922, "287922"),
    ("04e5b397", 82162583, "162583"),
    ("2823443f", 673399871, "399871"),
    ("2679dc69", 645520489, "520489"),
]

# RFC 6238 Appendix A reference implementation seeds.
RFC6238_SEEDS = {
    "sha1": bytes.fromhex("3132333435363738393031323334353637383930"),
    "sha256": bytes.fromhex(
        "3132333435363738393031323334353637383930" "313233343536373839303132"),
    "sha512": bytes.fromhex(
        "3132333435363738393031323334353637383930"
        "3132333435363738393031323334353637383930"
        "3132333435363738393031323334353637383930" "31323334"),
}

# RFC 6238 Appendix B Table 1: (unix time, expected T hex, algorithm, TOTP).
RFC6238_VECTORS = [
    (59, "0000000000000001", "sha1", "94287082"),
    (59, "0000000000000001", "sha256", "46119246"),
    (59, "0000000000000001", "sha512", "90693936"),
    (1111111109, "00000000023523EC", "sha1", "07081804"),
    (1111111109, "00000000023523EC", "sha256", "68084774"),
    (1111111109, "00000000023523EC", "sha512", "25091201"),
    (1111111111, "00000000023523ED", "sha1", "14050471"),
    (1111111111, "00000000023523ED", "sha256", "67062674"),
    (1111111111, "00000000023523ED", "sha512", "99943326"),
    (1234567890, "000000000273EF07", "sha1", "89005924"),
    (1234567890, "000000000273EF07", "sha256", "91819424"),
    (1234567890, "000000000273EF07", "sha512", "93441116"),
    (2000000000, "0000000003F940AA", "sha1", "69279037"),
    (2000000000, "0000000003F940AA", "sha256", "90698825"),
    (2000000000, "0000000003F940AA", "sha512", "38618901"),
    (20000000000, "0000000027BC86AA", "sha1", "65353130"),
    (20000000000, "0000000027BC86AA", "sha256", "77737706"),
    (20000000000, "0000000027BC86AA", "sha512", "47863826"),
]


def _hmac_hex(key: bytes, counter: int, algorithm: str) -> str:
    import hmac as _hmac
    import struct as _struct
    return _hmac.new(key, _struct.pack(">Q", counter), algorithm).hexdigest()


def run(suite: Suite) -> None:
    suite.section("RFC 4226 Appendix D, Table 1: intermediate HMAC-SHA-1")
    for counter, expected in enumerate(RFC4226_HMAC):
        suite.check(f"HMAC-SHA-1 count={counter}",
                    _hmac_hex(RFC4226_SECRET, counter, "sha1"), expected)

    suite.section("RFC 4226 Appendix D, Table 2: dynamic truncation and HOTP")
    for counter, (hex_trunc, dec_trunc, expected_hotp) in enumerate(RFC4226_TRUNCATED):
        # Recompute the truncation the same way the module does, so a wrong
        # offset or a missing sign mask shows up here and not only in the digits.
        digest = bytes.fromhex(RFC4226_HMAC[counter])
        offset = digest[-1] & 0x0F
        snum = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
        suite.check(f"Sbits count={counter}", f"{snum:08x}", hex_trunc)
        suite.check(f"Snum count={counter}", snum, dec_trunc)
        suite.check(f"HOTP count={counter}",
                    T.hotp(RFC4226_SECRET, counter), expected_hotp)

    suite.section("RFC 6238 Appendix B: TOTP, 8 digits, X=30, T0=0")
    for unix_time, expected_t_hex, algorithm, expected_code in RFC6238_VECTORS:
        counter = T.counter_for_time(unix_time)
        suite.check(f"T at t={unix_time}", f"{counter:016X}", expected_t_hex)
        suite.check(
            f"TOTP t={unix_time} {algorithm}",
            T.totp(RFC6238_SEEDS[algorithm], for_time=unix_time, digits=8,
                   algorithm=algorithm),
            expected_code)

    suite.section("RFC 6238 Errata 2866: the prose seed does NOT reproduce "
                  "the SHA256/SHA512 rows")
    # Asserting the erratum rather than just commenting on it: if a future
    # library or RFC revision changes this, the suite says so out loud.
    prose_seed = RFC6238_SEEDS["sha1"]
    suite.check(
        "20-byte prose seed mismatches the SHA256 row at t=59 (expected mismatch)",
        T.totp(prose_seed, for_time=59, digits=8, algorithm="sha256") != "46119246",
        True)
    suite.check(
        "20-byte prose seed mismatches the SHA512 row at t=59 (expected mismatch)",
        T.totp(prose_seed, for_time=59, digits=8, algorithm="sha512") != "90693936",
        True)

    suite.section("Local behaviour required by RFC 4226 section 7.2 and "
                  "RFC 6238 section 5.2")
    key = T.new_secret()
    now = 1_700_000_000  # fixed instant so the assertions below are stable

    ok, counter = T.verify(key, T.totp(key, for_time=now), for_time=now)
    suite.check("current code accepted", ok, True)
    suite.check("accepted counter is T", counter, T.counter_for_time(now))

    # Skew window: one step either side accepted, two steps rejected.
    prev_code = T.totp(key, for_time=now - T.DEFAULT_STEP_SECONDS)
    next_code = T.totp(key, for_time=now + T.DEFAULT_STEP_SECONDS)
    far_code = T.totp(key, for_time=now + 2 * T.DEFAULT_STEP_SECONDS)
    suite.check("T-1 accepted", T.verify(key, prev_code, for_time=now)[0], True)
    suite.check("T+1 accepted", T.verify(key, next_code, for_time=now)[0], True)
    suite.check("T+2 rejected", T.verify(key, far_code, for_time=now)[0], False)

    # Replay: the same code must not be honoured twice.
    code = T.totp(key, for_time=now)
    ok1, used = T.verify(key, code, for_time=now)
    ok2, _ = T.verify(key, code, last_counter=used, for_time=now)
    suite.check("first use of a code accepted", ok1, True)
    suite.check("replay of the same code rejected", ok2, False)

    # A code from an earlier step must not be replayable after a later one was
    # used, otherwise the skew window reopens every spent code.
    ok3, _ = T.verify(key, prev_code, last_counter=used, for_time=now)
    suite.check("older in-window code rejected once a newer one is spent", ok3, False)

    suite.section("Input handling")
    suite.check("wrong length rejected", T.verify(key, "12345", for_time=now)[0], False)
    suite.check("non-numeric rejected", T.verify(key, "abcdef", for_time=now)[0], False)
    suite.check("spaces tolerated",
                T.verify(key, " ".join([code[:3], code[3:]]), for_time=now)[0], True)
    suite.check("base32 round-trip", T.b32decode(T.b32encode(key)), key)
    suite.check("short secret refused",
                suite.raises(ValueError, T.new_secret, 8), True)
    suite.check("str key refused",
                suite.raises(TypeError, T.hotp, "not-bytes", 0), True)


if __name__ == "__main__":
    suite = Suite("RFC 4226 / RFC 6238 test vectors")
    run(suite)
    sys.exit(suite.finish())
