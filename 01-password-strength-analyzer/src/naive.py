"""The two meters this project exists to discredit.

Both are reproduced faithfully, because the point of the evaluation is to show
what they do to *real* breached passwords - not to a strawman.

1. `composition_score` is the signup-form meter: points for length and for each
   character class present. Every shopping site ships a version of this.
2. `charset_entropy_bits` is length x log2(charset), the figure people call
   "entropy" and band with the table that came out of NIST SP 800-63
   Appendix A (withdrawn in 2017, still quoted everywhere).

Neither function looks at whether the password has ever been seen before, which
is the only question that actually predicts whether it survives an attack.
"""
from __future__ import annotations

from math import log2

LOWER, UPPER, DIGITS, SYMBOLS = 26, 26, 10, 33


def classes_present(pw: str) -> dict[str, bool]:
    return {
        "lower": any(c.islower() for c in pw),
        "upper": any(c.isupper() for c in pw),
        "digit": any(c.isdigit() for c in pw),
        "symbol": any(not c.isalnum() for c in pw),
    }


def composition_score(pw: str) -> tuple[int, str]:
    """0-6 points, the way a signup form does it. >=5 is shown as 'Strong'."""
    cls = classes_present(pw)
    score = sum(cls.values())
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 12:
        score += 1
    labels = {0: "Very weak", 1: "Very weak", 2: "Weak", 3: "Medium",
              4: "Medium", 5: "Strong", 6: "Very strong"}
    return score, labels[min(score, 6)]


def composition_says_strong(pw: str) -> bool:
    return composition_score(pw)[0] >= 5


def charset_entropy_bits(pw: str) -> float:
    """length x log2(charset). The classic overestimate."""
    size = 0
    cls = classes_present(pw)
    if cls["lower"]:
        size += LOWER
    if cls["upper"]:
        size += UPPER
    if cls["digit"]:
        size += DIGITS
    if cls["symbol"]:
        size += SYMBOLS
    if size == 0:
        return 0.0
    return len(pw) * log2(size)


def entropy_band(bits: float) -> str:
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 128:
        return "Strong"
    return "Very strong"


def entropy_says_strong(pw: str) -> bool:
    return charset_entropy_bits(pw) >= 60


def passes_policy(pw: str, min_len: int = 8, required_classes: int = 4) -> bool:
    """The composition policy almost every corporate password rule encodes:
    a minimum length plus N of the four character classes."""
    return len(pw) >= min_len and sum(classes_present(pw).values()) >= required_classes
