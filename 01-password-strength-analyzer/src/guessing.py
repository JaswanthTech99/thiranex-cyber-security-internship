"""Guess-number estimation: how many attempts an informed attacker needs.

This is a from-scratch implementation of the guess-number idea described in
D. Wheeler, "zxcvbn: Low-Budget Password Strength Estimation" (USENIX Security
2016). It is not a port of that library - the matchers, the per-pattern guess
counts and the minimum-decomposition search below were written for this project,
and the dictionaries are the real breach and vocabulary corpora loaded by
src/corpus.py.

The quantity produced here is an estimate of the number of guesses an attacker
who owns the same public breach corpora would need. That is the number that
decides whether a password survives, and it is exactly what a character-class
"entropy" score cannot express: `P@ssw0rd1` uses four character classes and nine
characters, and it is in the breach corpus at a low rank.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from math import comb, factorial, log2

# Anything above this is "will not be guessed"; keeps products from overflowing.
MAX_GUESSES = 1e300


def _fact(n: int) -> float:
    """factorial as a float, saturating instead of raising on absurd lengths."""
    try:
        return float(factorial(n))
    except OverflowError:
        return MAX_GUESSES

# Leet substitutions seen in real cracking rulesets (hashcat best64, John's rules).
LEET: dict[str, str] = {
    "a": "@4", "b": "8", "c": "(", "e": "3", "g": "69", "i": "1!|",
    "l": "1|", "o": "0", "s": "$5", "t": "+7", "z": "2",
}
LEET_REVERSE: dict[str, str] = {}
for _letter, _subs in LEET.items():
    for _s in _subs:
        LEET_REVERSE[_s] = LEET_REVERSE.get(_s, "") + _letter

# Physical QWERTY layout, unshifted and shifted characters of the same key in the
# same column. The single leading space on the lower three rows puts `q`, `a` and
# `z` in one column, which is where they sit on a real board: measured in key
# widths from the left edge, `q` is at 1.5, `a` at 1.75 and `z` at 2.25, so all
# three fall against `1` rather than marching one full key right per row.
QWERTY_ROWS = [
    "`1234567890-=",
    " qwertyuiop[]\\",
    " asdfghjkl;'",
    " zxcvbnm,./",
]
SHIFTED_ROWS = [
    "~!@#$%^&*()_+",
    " QWERTYUIOP{}|",
    ' ASDFGHJKL:"',
    " ZXCVBNM<>?",
]

# Because each row is offset a fraction of a key to the right of the one above,
# a key touches two keys on the row above and two on the row below, not three:
# six neighbours, not eight. This is the slanted-grid model zxcvbn uses, and it
# is why the offsets are asymmetric. A plain eight-neighbour square grid invents
# edges that no physical keyboard has - it made `a` adjacent to `e`, which are a
# key and a half apart - and inflates the average degree by about a third.
NEIGHBOUR_OFFSETS = ((-1, 0), (1, 0), (0, -1), (1, -1), (0, 1), (-1, 1))


def _build_adjacency() -> tuple[dict[str, set[str]], set[str], int, float]:
    """Adjacency over characters, but starts and degree over physical keys.

    The matcher needs characters: `1qaz` is a walk whatever the shift state of
    each key. The guess count needs keys, because `spatial_matches` charges the
    shift choice separately - counting both shift states in the degree as well
    would pay for the same decision twice.
    """
    keys: dict[tuple[int, int], list[str]] = {}
    shifted: set[str] = set()
    for r, (row, srow) in enumerate(zip(QWERTY_ROWS, SHIFTED_ROWS)):
        for c, ch in enumerate(row):
            if ch == " ":
                continue
            chars = [ch]
            if c < len(srow) and srow[c] != " ":
                chars.append(srow[c])
                shifted.add(srow[c])
            keys[(c, r)] = chars
    adj: dict[str, set[str]] = {}
    degrees: list[int] = []
    for (c, r), chars in keys.items():
        neighbours = [keys[(c + dc, r + dr)] for dc, dr in NEIGHBOUR_OFFSETS
                      if (c + dc, r + dr) in keys]
        degrees.append(len(neighbours))
        reachable = {ch for key in neighbours for ch in key}
        for ch in chars:
            adj.setdefault(ch, set()).update(reachable)
    return adj, shifted, len(keys), sum(degrees) / max(len(keys), 1)


# How many keys an attacker could start a walk on, and the mean number of onward
# keys at each step. Both are per key; `spatial_matches` adds the shift factor.
ADJACENCY, SHIFTED_KEYS, KEYBOARD_STARTS, KEYBOARD_AVG_DEGREE = _build_adjacency()

LOWER, UPPER, DIGITS = 26, 26, 10
SYMBOLS = 33  # printable ASCII that is neither a letter nor a digit


@dataclass
class Match:
    """One recognised pattern covering password[i:j+1]."""

    i: int
    j: int
    token: str
    pattern: str
    guesses: float
    detail: str = ""


@dataclass
class Estimate:
    password_length: int
    guesses: float
    log10_guesses: float
    score: int
    label: str
    sequence: list[Match] = field(default_factory=list)


def charset_size(s: str) -> int:
    size = 0
    if any(c.islower() for c in s):
        size += LOWER
    if any(c.isupper() for c in s):
        size += UPPER
    if any(c.isdigit() for c in s):
        size += DIGITS
    if any(not c.isalnum() for c in s):
        size += SYMBOLS
    return max(size, 1)


def bruteforce_guesses(segment: str) -> float:
    """Cost of guessing this run with no structure to exploit."""
    try:
        return min(float(charset_size(segment)) ** len(segment), MAX_GUESSES)
    except OverflowError:
        # float ** int raises rather than returning inf, and every substring of
        # the candidate reaches here, so a 156-character password used to take
        # the whole estimator down. Saturate the way _fact does.
        return MAX_GUESSES


def case_variations(token: str) -> float:
    """Extra work created by the capitalisation of a dictionary hit.

    all-lower costs nothing; a single leading capital or ALL CAPS is one of the
    two shapes an attacker tries first; anything genuinely mixed multiplies by
    the number of ways those capitals could have been placed.
    """
    letters = [c for c in token if c.isalpha()]
    if not letters:
        return 1.0
    if token == token.lower():
        return 1.0
    if token == token.upper() or token == token.capitalize():
        return 2.0
    up = sum(1 for c in letters if c.isupper())
    lo = len(letters) - up
    total = sum(comb(len(letters), k) for k in range(1, min(up, lo) + 1))
    return float(min(max(total, 2), 10**6))


def leet_variations(subs_used: int) -> float:
    """Extra work created by leet substitution: each swapped char could have
    been left alone, so the attacker walks a 2^n space of mangling choices."""
    if subs_used == 0:
        return 1.0
    return float(min(2**subs_used, 10**6))


def _leet_normalise(token: str) -> tuple[str, int]:
    """Fold leet characters back to letters; also report how many were folded."""
    out, subs = [], 0
    for ch in token:
        low = ch.lower()
        if low in LEET_REVERSE:
            out.append(LEET_REVERSE[low][0])
            subs += 1
        else:
            out.append(low)
    return "".join(out), subs


def dictionary_matches(
    password: str,
    dictionaries: dict[str, dict[str, int]],
    min_len: int = 3,
) -> list[Match]:
    """Every substring that appears in a ranked corpus, plus its mangling cost."""
    out: list[Match] = []
    n = len(password)
    for i in range(n):
        for j in range(i + min_len - 1, n):
            token = password[i : j + 1]
            lowered = token.lower()
            normalised, subs = _leet_normalise(token)
            for dname, ranks in dictionaries.items():
                # An exact-case hit costs the rank and nothing more: an attacker
                # walking this corpus in rank order finds the token itself at
                # that position, with no mangling left to pay for. The folded
                # paths below are different - there the corpus holds a plainer
                # form and the attacker has to re-derive the capitalisation and
                # the leet substitutions, so those are charged.
                rank = ranks.get(token)
                used_case, used_subs = False, 0
                if rank is None:
                    rank = ranks.get(lowered)
                    used_case = rank is not None
                if rank is None and subs:
                    rank = ranks.get(normalised)
                    if rank is not None:
                        used_case, used_subs = True, subs
                if rank is None:
                    continue
                g = float(rank)
                if used_case:
                    g *= case_variations(token)
                g *= leet_variations(used_subs)
                out.append(
                    Match(
                        i, j, token, f"dictionary:{dname}",
                        min(max(g, 1.0), MAX_GUESSES),
                        f"rank {rank}" + (f", {used_subs} leet sub(s)" if used_subs else ""),
                    )
                )
    return out


def spatial_matches(password: str, min_len: int = 3) -> list[Match]:
    """Keyboard walks such as `qwerty`, `1qaz2wsx`, `asdfgh`."""
    out: list[Match] = []
    i = 0
    n = len(password)
    while i < n - 1:
        j = i
        while j + 1 < n and password[j + 1] in ADJACENCY.get(password[j], ()):
            j += 1
        length = j - i + 1
        if length >= min_len:
            token = password[i : j + 1]
            shifted = sum(1 for c in token if c in SHIFTED_KEYS)
            try:
                g = KEYBOARD_STARTS * (KEYBOARD_AVG_DEGREE ** (length - 1))
            except OverflowError:  # a walk of ~290 keys or more
                g = MAX_GUESSES
            if shifted:
                g *= min(2**shifted, 10**4)
            out.append(Match(i, j, token, "spatial", min(g, MAX_GUESSES), "keyboard walk"))
            i = j
        else:
            i += 1
    return out


def sequence_matches(password: str, min_len: int = 3) -> list[Match]:
    """Runs with a constant codepoint step: `abc`, `123`, `987`, `aceg`."""
    out: list[Match] = []
    n = len(password)
    i = 0
    while i < n - 1:
        delta = ord(password[i + 1]) - ord(password[i])
        if abs(delta) not in (1, 2):
            i += 1
            continue
        j = i + 1
        while j + 1 < n and ord(password[j + 1]) - ord(password[j]) == delta:
            j += 1
        if j - i + 1 >= min_len:
            token = password[i : j + 1]
            base = DIGITS if token[0].isdigit() else 26
            g = base * len(token) * (2 if delta < 0 else 1) * (2 if abs(delta) == 2 else 1)
            out.append(Match(i, j, token, "sequence", min(float(g), MAX_GUESSES), f"step {delta}"))
            i = j
        else:
            i += 1
    return out


def repeat_matches(password: str, dictionaries: dict[str, dict[str, int]]) -> list[Match]:
    """`aaaa`, `abcabcabc`: cost of the unit times the number of repeats."""
    out: list[Match] = []
    for m in re.finditer(r"(.+?)\1+", password):
        unit = m.group(1)
        repeats = len(m.group(0)) // len(unit)
        unit_guesses = bruteforce_guesses(unit)
        for ranks in dictionaries.values():
            r = ranks.get(unit.lower())
            if r:
                unit_guesses = min(unit_guesses, float(r))
        out.append(
            Match(
                m.start(), m.end() - 1, m.group(0), "repeat",
                min(unit_guesses * repeats, MAX_GUESSES),
                f"{unit!r} x{repeats}",
            )
        )
    return out


def date_matches(password: str) -> list[Match]:
    """Years and compact dates - the most common human suffix by a wide margin."""
    out: list[Match] = []
    for m in re.finditer(r"(?:19[0-9]{2}|20[0-4][0-9])", password):
        out.append(
            Match(m.start(), m.end() - 1, m.group(0), "date",
                  float(1950 + 100 - 1900), "4-digit year")
        )
    # Longer alternative first: regex alternation is ordered, so `\d{6}|\d{8}`
    # matched the first six digits of `01011990` and the 8-digit branch could
    # never fire at all.
    for m in re.finditer(r"\d{8}|\d{6}", password):
        out.append(
            Match(m.start(), m.end() - 1, m.group(0), "date",
                  float(31 * 12 * 130), "compact date")
        )
    return out


def omnimatch(password: str, dictionaries: dict[str, dict[str, int]]) -> list[Match]:
    return (
        dictionary_matches(password, dictionaries)
        + spatial_matches(password)
        + sequence_matches(password)
        + repeat_matches(password, dictionaries)
        + date_matches(password)
    )


SCORE_THRESHOLDS = [1e3, 1e6, 1e8, 1e10]
SCORE_LABELS = ["Very weak", "Weak", "Moderate", "Strong", "Very strong"]


def score_for(guesses: float) -> tuple[int, str]:
    s = sum(1 for t in SCORE_THRESHOLDS if guesses >= t)
    return s, SCORE_LABELS[s]


def most_guessable(password: str, dictionaries: dict[str, dict[str, int]]) -> Estimate:
    """Search all ways of carving the password into patterns, keep the cheapest.

    An attacker pays the product of the per-pattern guess counts, plus the cost
    of not knowing the order the patterns were assembled in - hence the k!
    factor. Exact search: the DP keeps the best product for every (prefix,
    pattern-count) pair, so the k! term is applied to the right product rather
    than being folded into a greedy choice.
    """
    n = len(password)
    if n == 0:
        return Estimate(0, 1.0, 0.0, 0, SCORE_LABELS[0], [])

    matches = omnimatch(password, dictionaries)
    by_end: dict[int, list[Match]] = {}
    for m in matches:
        by_end.setdefault(m.j + 1, []).append(m)
    # Every substring is also available as an unstructured brute-force run.
    for k in range(1, n + 1):
        for i in range(k):
            seg = password[i:k]
            by_end.setdefault(k, []).append(
                Match(i, k - 1, seg, "bruteforce", bruteforce_guesses(seg))
            )

    INF = float("inf")
    best: list[dict[int, float]] = [dict() for _ in range(n + 1)]
    back: list[dict[int, Match]] = [dict() for _ in range(n + 1)]
    best[0][0] = 1.0
    for k in range(1, n + 1):
        for m in by_end.get(k, ()):
            for count, prod in best[m.i].items():
                cand = min(prod * m.guesses, MAX_GUESSES)
                if cand < best[k].get(count + 1, INF):
                    best[k][count + 1] = cand
                    back[k][count + 1] = m

    best_total, best_count = INF, 1
    for count, prod in best[n].items():
        total = min(prod * _fact(count), MAX_GUESSES)
        if total < best_total:
            best_total, best_count = total, count

    seq: list[Match] = []
    k, count = n, best_count
    while k > 0 and count in back[k]:
        m = back[k][count]
        seq.append(m)
        k, count = m.i, count - 1
    seq.reverse()

    guesses = max(best_total, 1.0)
    score, label = score_for(guesses)
    return Estimate(n, guesses, log2(guesses) / log2(10), score, label, seq)
