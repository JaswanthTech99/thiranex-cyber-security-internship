"""Command line entry point: analyse one password.

    python -m src.analyze                       # prompts, nothing hits the shell history
    python -m src.analyze --password "hunter2"  # for demos only; warns
    python -m src.analyze --password X --user alice --history data/history.db
    python -m src.analyze --password X --offline # no network, corpus checks only

Reports, in order: the guess-number estimate and what the two naive meters say
about the same string, crack times under three attack models, the pattern
decomposition that produced the estimate, the HIBP breach count, a NIST SP
800-63B checklist, personal re-use, and three generated alternatives.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from math import log10
from pathlib import Path

from . import naive
from .benchmark import human_time, scenarios
from .corpus import load_breach_ranks, load_eff_wordlist, load_english_ranks
from .guessing import most_guessable
from .history import PasswordHistory
from .pwned import PwnedClient
from .suggest import NEVER_DO_THIS, suggest

ROOT = Path(__file__).resolve().parents[1]


def build_dictionaries(breach_limit: int | None = None) -> dict[str, dict[str, int]]:
    """The corpora the estimator assumes the attacker also owns.

    The EFF diceware list is in here deliberately. This tool hands out EFF
    passphrases, so an attacker targeting its users would start with that list;
    scoring passphrases as if the wordlist were secret would be self-serving.
    """
    return {
        "breach": load_breach_ranks(breach_limit),
        "english": load_english_ranks(),
        "eff": {w: i for i, w in enumerate(load_eff_wordlist(), start=1)},
    }


def nist_checklist(pw: str, pwned_count: int | None) -> list[tuple[bool, str]]:
    """NIST SP 800-63B section 3.1.1.2 memorized-secret requirements.

    Note what is *not* on this list: mandatory character-class composition and
    mandatory rotation. Both were removed from the guidance because they push
    users toward predictable patterns, and this tool does not reinstate them.
    """
    out = [
        (len(pw) >= 8, "at least 8 characters (verifier minimum)"),
        (len(pw) >= 15, "at least 15 characters (recommended)"),
        (all(c.isprintable() for c in pw), "all characters printable (spaces allowed)"),
        (len(pw) <= 64, "within the 64-character minimum-supported maximum"),
    ]
    if pwned_count is not None:
        out.append((pwned_count == 0, "not present in a known breach corpus"))
    return out


def analyze(pw: str, args) -> dict:
    dicts = build_dictionaries(args.breach_limit)
    est = most_guessable(pw, dicts)

    comp_score, comp_label = naive.composition_score(pw)
    bits = naive.charset_entropy_bits(pw)

    pwned_count = None
    range_size = None
    if not args.offline:
        try:
            client = PwnedClient()
            pwned_count = client.count(pw)
            range_size = client.range_size(pw)
        except Exception as e:  # noqa: BLE001
            print(f"  (breach check unavailable: {e})", file=sys.stderr)

    result = {
        "length": len(pw),
        "guesses": est.guesses,
        "log10_guesses": round(est.log10_guesses, 2),
        "verdict": est.label,
        "score_0_4": est.score,
        "naive_composition": {"score_0_6": comp_score, "label": comp_label,
                              "says_strong": naive.composition_says_strong(pw)},
        "naive_charset_entropy": {"bits": round(bits, 1), "band": naive.entropy_band(bits),
                                  "says_strong": naive.entropy_says_strong(pw)},
        "pwned_count": pwned_count,
        "hibp_range_size": range_size,
        "patterns": [
            {"token_len": len(m.token), "pattern": m.pattern,
             "guesses": m.guesses, "detail": m.detail}
            for m in est.sequence
        ],
    }

    print(f"\n  Password length : {len(pw)}")
    print(f"  Verdict         : {est.label}  (guess-number score {est.score}/4)")
    print(f"  Estimated guesses: 10^{est.log10_guesses:.1f}")
    print("\n  What the naive meters say about the same string")
    print(f"    signup-form composition meter : {comp_label} ({comp_score}/6)"
          f"{'   <-- calls it strong' if naive.composition_says_strong(pw) else ''}")
    print(f"    charset 'entropy'             : {bits:.1f} bits, {naive.entropy_band(bits)}"
          f"{'   <-- calls it strong' if naive.entropy_says_strong(pw) else ''}")

    print("\n  Time to guess")
    for label, rate in scenarios():
        print(f"    {label:<62} {human_time(est.guesses / max(rate, 1e-9))}")

    print("\n  Why (cheapest decomposition an attacker would use)")
    for m in est.sequence:
        detail = f"  [{m.detail}]" if m.detail else ""
        print(f"    {len(m.token):>2} char(s)  {m.pattern:<22} "
              f"10^{log10(max(m.guesses, 1.0)):.1f} guesses{detail}")

    if pwned_count is not None:
        if pwned_count:
            print(f"\n  Breach check    : FOUND {pwned_count:,} times in HIBP "
                  f"(query hidden among {range_size} hashes)")
            print("                    This password is already on wordlists. "
                  "Strength scoring is irrelevant; it must not be used.")
        else:
            print(f"\n  Breach check    : not found in HIBP "
                  f"(query hidden among {range_size} hashes)")

    print("\n  NIST SP 800-63B checklist")
    for ok, text in nist_checklist(pw, pwned_count):
        print(f"    [{'x' if ok else ' '}] {text}")

    if args.history:
        hist = PasswordHistory(args.history)
        h = hist.check(args.user, pw)
        result["history"] = h
        print(f"\n  Personal history ({h['history_size']} retired password(s) for "
              f"{args.user!r})")
        if h["exact_reuse"]:
            print("    REJECT: exact re-use of a retired password")
        elif h["near_reuse"]:
            print(f"    REJECT: shares a root with retired password(s) "
                  f"{h['near_match_ids']} - suffix-increment re-use")
        else:
            print("    OK: no exact or root-level re-use detected")
        hist.close()

    if args.suggest:
        print("\n  Stronger alternatives")
        for s in suggest(3, check_pwned=not args.offline):
            seen = "" if s.pwned_count in (0, None) else (
                f"  (breached {s.pwned_count}x - regenerate)")
            print(f"    {s.password}")
            print(f"      {s.kind}: guess space 10^{log10(s.guess_space):.0f} "
                  f"({s.bits:.0f} bits){seen}")
        print(f"\n  Note: {NEVER_DO_THIS}")

    return result


def main() -> None:
    p = argparse.ArgumentParser(description="Password strength analyser (guess-number based)")
    p.add_argument("--password", help="password to analyse; omit to be prompted")
    p.add_argument("--user", default="demo", help="user id for password-history checks")
    p.add_argument("--history", help="path to a password-history sqlite db")
    p.add_argument("--offline", action="store_true", help="skip all network calls")
    p.add_argument("--no-suggest", dest="suggest", action="store_false",
                   help="do not print generated alternatives")
    p.add_argument("--breach-limit", type=int, default=None,
                   help="only load the top N breach entries (faster startup)")
    p.add_argument("--json", help="also write the result to this path as JSON")
    args = p.parse_args()

    if args.password:
        print("warning: --password puts the password in your shell history", file=sys.stderr)
        pw = args.password
    else:
        pw = getpass.getpass("password (not echoed): ")

    result = analyze(pw, args)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n  wrote {args.json}")


if __name__ == "__main__":
    main()
