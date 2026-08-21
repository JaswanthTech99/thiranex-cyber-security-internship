"""HOTP (RFC 4226) and TOTP (RFC 6238) built from `hmac`, `hashlib` and `struct`.

Written from the specifications rather than pulled from a library so that the
implementation can be checked against the published test vectors
(RFC 4226 Appendix D, RFC 6238 Appendix B) in tests/test_rfc_vectors.py.
Those vectors are the only reason to trust this file.

Vocabulary used below follows the RFCs:
  K  shared secret (raw bytes)
  C  8-byte counter, big-endian (RFC 4226 section 5.1)
  T  time-based counter, floor((now - T0) / X)   (RFC 6238 section 4.2)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

# RFC 6238 section 4.1: X defaults to 30 seconds, T0 to the Unix epoch.
DEFAULT_STEP_SECONDS = 30
DEFAULT_T0 = 0
DEFAULT_DIGITS = 6
DEFAULT_ALGORITHM = "sha1"

# RFC 4226 section 5.3 defines the modulo table for 6..8 digits. We refuse
# anything outside 6..10 because the dynamic truncation only yields a 31-bit
# value (max 2147483647), so 10 digits is the point where extra digits stop
# adding entropy and start being misleading.
_MIN_DIGITS, _MAX_DIGITS = 6, 10

_ALLOWED_ALGORITHMS = {"sha1", "sha256", "sha512"}


def hotp(key: bytes, counter: int, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """HOTP value for `counter` per RFC 4226 section 5.3.

    Steps, named as in the RFC:
      1. HS = HMAC-SHA-1(K, C)
      2. Sbits = DT(HS)              -- dynamic truncation
      3. Snum  = StToNum(Sbits)
      4. D = Snum mod 10^Digit
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be raw bytes, not a base32 string")
    if counter < 0:
        raise ValueError("counter must be non-negative")
    if not _MIN_DIGITS <= digits <= _MAX_DIGITS:
        raise ValueError(f"digits must be in [{_MIN_DIGITS}, {_MAX_DIGITS}]")
    if algorithm not in _ALLOWED_ALGORITHMS:
        raise ValueError(f"algorithm must be one of {sorted(_ALLOWED_ALGORITHMS)}")

    # Step 1. ">Q" is exactly the 8-byte big-endian counter the RFC specifies.
    hs = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()

    # Step 2, DT(). The low 4 bits of the last byte select the offset. This
    # data-dependent offset is the whole point of "dynamic" truncation: it stops
    # an attacker from attacking a fixed slice of the MAC.
    offset = hs[-1] & 0x0F
    # Masking the top bit with 0x7FFFFFFF avoids the sign ambiguity the RFC
    # calls out (some languages have no unsigned 32-bit type).
    snum = struct.unpack(">I", hs[offset:offset + 4])[0] & 0x7FFFFFFF

    # Steps 3 and 4. zfill keeps leading zeros, which are significant: dropping
    # them is a classic interop bug that silently rejects ~10% of valid codes.
    return str(snum % (10 ** digits)).zfill(digits)


def counter_for_time(for_time: float | None = None,
                     step: int = DEFAULT_STEP_SECONDS,
                     t0: int = DEFAULT_T0) -> int:
    """T = floor((current Unix time - T0) / X), RFC 6238 section 4.2."""
    if step <= 0:
        raise ValueError("step must be positive")
    now = time.time() if for_time is None else for_time
    # Integer floor division, so this is correct for times before T0 too.
    return int((int(now) - t0) // step)


def totp(key: bytes, for_time: float | None = None,
         step: int = DEFAULT_STEP_SECONDS, t0: int = DEFAULT_T0,
         digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """TOTP value: HOTP applied to the time counter (RFC 6238 section 4.2)."""
    return hotp(key, counter_for_time(for_time, step, t0), digits, algorithm)


def verify(key: bytes, code: str, *, last_counter: int | None = None,
           for_time: float | None = None, skew_steps: int = 1,
           step: int = DEFAULT_STEP_SECONDS, t0: int = DEFAULT_T0,
           digits: int = DEFAULT_DIGITS,
           algorithm: str = DEFAULT_ALGORITHM) -> tuple[bool, int | None]:
    """Verify `code`, returning (accepted, counter_that_matched).

    `skew_steps` is the RFC 6238 section 5.2 resynchronisation window: we accept
    T-1 .. T+1 (one step either side, so a 90 second acceptance window at
    X=30). Reasoning for one step and not more:
      - The RFC tells validators to keep the window "as small as possible" and
        explicitly warns that a larger window is a larger attack surface: a
        window of W steps multiplies an online guesser's success probability per
        attempt by (2W+1).
      - One step tolerates the two things that actually happen in practice, a
        user typing a code just as it rolls over and a phone clock a few tens of
        seconds out. Anything worse than that is a broken client clock, and the
        honest fix is NTP on the client, not a looser server.

    `last_counter` is the replay guard. A code is a bearer token for its whole
    step, so a code observed in transit (shoulder-surfed, phished, logged by a
    proxy) can be replayed within the window unless the server remembers the
    highest counter it has already honoured. RFC 4226 section 7.2 requires
    exactly this. We reject any counter <= last_counter, which also means a
    single code can never be used twice even inside the skew window.

    Comparison uses hmac.compare_digest, not `==`. The value is not
    high-entropy secret material, but a variable-time compare against a 6 digit
    code is a free win to remove and there is no reason to leave it in.
    """
    if skew_steps < 0:
        raise ValueError("skew_steps must be non-negative")
    if not isinstance(code, str):
        return (False, None)
    submitted = code.strip().replace(" ", "")
    # Length/charset check first: this is input validation, not the secret
    # comparison, so short-circuiting here leaks nothing useful.
    if len(submitted) != digits or not submitted.isdigit():
        return (False, None)

    centre = counter_for_time(for_time, step, t0)
    # Search newest-first. Ordering does not change the result, but on the happy
    # path (a freshly generated code) it means one HMAC instead of three.
    candidates = [centre]
    for delta in range(1, skew_steps + 1):
        candidates.extend([centre + delta, centre - delta])

    for counter in candidates:
        if counter < 0:
            continue
        if last_counter is not None and counter <= last_counter:
            # Already spent. Keep scanning: a later candidate may still be fresh.
            continue
        expected = hotp(key, counter, digits, algorithm)
        if hmac.compare_digest(expected, submitted):
            return (True, counter)
    return (False, None)


def new_secret(num_bytes: int = 20) -> bytes:
    """Fresh shared secret.

    20 bytes = 160 bits, which is the HMAC-SHA-1 block-appropriate length RFC
    4226 section 4 R6 recommends ("The algorithm MUST use a strong shared
    secret. The length of the shared secret MUST be at least 128 bits. This
    document RECOMMENDs a shared secret length of 160 bits"). `secrets` is used
    rather than `random` because this is key material; the fixed experiment seed
    used elsewhere in this project is deliberately never applied here.
    """
    if num_bytes < 16:
        raise ValueError("RFC 4226 requires at least 128 bits of secret")
    return secrets.token_bytes(num_bytes)


def b32encode(secret: bytes) -> str:
    """Base32, no padding -- the encoding authenticator apps expect."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def b32decode(text: str) -> bytes:
    """Accept user-typed base32: case-insensitive, spaces and padding optional."""
    cleaned = text.strip().replace(" ", "").replace("-", "").upper()
    # b32decode demands the padding it emitted, so put it back.
    padding = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * padding, casefold=True)


def provisioning_uri(secret: bytes, account: str, issuer: str,
                     digits: int = DEFAULT_DIGITS,
                     step: int = DEFAULT_STEP_SECONDS,
                     algorithm: str = DEFAULT_ALGORITHM) -> str:
    """otpauth:// URI for QR enrolment (Key Uri Format, google-authenticator wiki).

    The label carries the issuer as a prefix as well as the `issuer` parameter
    because older clients read only one of the two.
    """
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    params = urllib.parse.urlencode({
        "secret": b32encode(secret),
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": step,
    })
    return f"otpauth://totp/{label}?{params}"
