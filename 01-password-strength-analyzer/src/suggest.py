"""Generates stronger alternatives.

One decision here needs defending, because it is the opposite of what most
"suggest a stronger password" features do: this module never offers a mutated
version of the password the user just typed.

Mangling a weak password - capitalising the first letter, appending `123`,
swapping `a` for `@` - is precisely the transformation attackers apply. hashcat's
`best64.rule` and John's default rules exist to walk that space. A suggestion
derived from a guessed root inherits the root's weakness and hands the user a
false sense of improvement. So every candidate below is drawn independently from
a CSPRNG (`secrets`, i.e. the OS entropy source), and its guess space is stated
up front rather than estimated after the fact.

Suggestions are optionally checked against HIBP before being shown, because a
CSPRNG can in principle emit a passphrase someone has already used.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from math import log2

from .corpus import load_eff_wordlist
from .pwned import PwnedClient

# All 32 printable ASCII characters that are neither a letter nor a digit. The
# charset assumption elsewhere in the project says 33 because it counts the
# space, which is deliberately not generated here.
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~`|<>" + "'\"\\"


@dataclass
class Suggestion:
    password: str
    kind: str
    guess_space: float
    bits: float
    rationale: str
    pwned_count: int | None = None


def diceware(words: list[str], n_words: int = 4, separator: str = "-") -> Suggestion:
    """A passphrase drawn uniformly from the EFF large wordlist."""
    picked = [secrets.choice(words) for _ in range(n_words)]
    space = float(len(words)) ** n_words
    return Suggestion(
        password=separator.join(picked),
        kind=f"diceware-{n_words}",
        guess_space=space,
        bits=log2(space),
        rationale=(
            f"{n_words} words drawn uniformly from the {len(words)}-word EFF list. "
            f"The guess space is {len(words)}^{n_words} even when the attacker knows "
            "the exact method and wordlist, which they should be assumed to."
        ),
    )


def random_string(length: int = 16, use_symbols: bool = True) -> Suggestion:
    """A uniform random string over an explicit alphabet."""
    alphabet = string.ascii_letters + string.digits + (SYMBOLS if use_symbols else "")
    pw = "".join(secrets.choice(alphabet) for _ in range(length))
    space = float(len(alphabet)) ** length
    return Suggestion(
        password=pw,
        kind=f"random-{length}",
        guess_space=space,
        bits=log2(space),
        rationale=(
            f"{length} characters drawn uniformly from a {len(alphabet)}-character "
            "alphabet. Intended for a password manager, not for memorising."
        ),
    )


def suggest(n: int = 3, check_pwned: bool = True,
            client: PwnedClient | None = None) -> list[Suggestion]:
    words = load_eff_wordlist()
    out = [diceware(words, 4), diceware(words, 6), random_string(20)][:n]
    if check_pwned:
        c = client or PwnedClient()
        for s in out:
            try:
                s.pwned_count = c.count(s.password)
            except Exception:  # offline is not a reason to withhold the suggestion
                s.pwned_count = None
    return out


NEVER_DO_THIS = (
    "This tool will not offer a patched-up version of your current password. "
    "Appending digits, capitalising the first letter and swapping a->@ are the "
    "first rules in every public cracking ruleset, so a password repaired that "
    "way is no harder to guess than the one it replaced."
)
