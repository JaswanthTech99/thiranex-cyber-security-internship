"""End-to-end demo of the password-history checks, transcript included.

Writes outputs/reports/demo_session.txt so the README can quote real output
rather than describing what the code would do.

Run: python -m src.demo
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

from .analyze import build_dictionaries
from .guessing import most_guessable
from .history import PasswordHistory, skeleton

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "outputs" / "reports"
DB = ROOT / "data" / "demo_history.db"

USER = "alice"

# A realistic sequence: a rotation policy forces a change every quarter, and the
# user does the only thing that is easy to remember.
RETIRED = ["Summer2024!", "Autumn2024!", "Winter2025!"]
CANDIDATES = [
    ("Summer2024!", "exact re-use of the oldest retired password"),
    ("Summer2025!", "same word, next year - the classic rotation dodge"),
    ("Summer2024!!", "same root, one more character"),
    ("Summ3r2025!", "same root, leet-mangled"),
    ("Spring2025!", "a different season - the check's blind spot"),
    ("plywood-cactus-ferry-oxidant", "an unrelated generated passphrase"),
]


def run() -> None:
    for stale in (DB, DB.with_suffix(".hmac_key")):
        if stale.exists():
            stale.unlink()

    print("Password history demo - user 'alice', mandatory quarterly rotation")
    print("=" * 72)
    dicts = build_dictionaries(breach_limit=200_000)
    hist = PasswordHistory(DB)

    print("\nRetiring the passwords she has already used:")
    for pw in RETIRED:
        rid = hist.retire(USER, pw)
        print(f"  id {rid}: {pw!r}  ->  skeleton {skeleton(pw)!r}")

    print("\nOnly Argon2id hashes and keyed skeleton HMACs are stored. Row 1 as held:")
    row = hist.conn.execute(
        "SELECT argon2_hash, skeleton_hmac FROM password_history WHERE id = 1"
    ).fetchone()
    print(f"  argon2_hash   {row[0][:62]}...")
    print(f"  skeleton_hmac {row[1][:32]}...")

    print("\nNow she tries to set a new one:")
    for pw, why in CANDIDATES:
        res = hist.check(USER, pw)
        est = most_guessable(pw, dicts)
        if res["exact_reuse"]:
            verdict = f"REJECTED - exact re-use (history id {res['exact_match_id']})"
        elif res["near_reuse"]:
            verdict = f"REJECTED - shares a root with id(s) {res['near_match_ids']}"
        else:
            verdict = "ACCEPTED by history check"
        print(f"\n  {pw!r}  ({why})")
        print(f"    skeleton : {res['skeleton']!r}")
        print(f"    history  : {verdict}")
        print(f"    strength : {est.label}, 10^{est.log10_guesses:.1f} guesses")

    print("\n" + "=" * 72)
    print("What the two stored values each buy, and what neither buys:")
    print()
    print("  The Argon2id hash catches only the first candidate. 'Summer2025!' is")
    print("  not a re-use of anything by hash - it matches no stored row - and a")
    print("  history table holding hashes alone would have accepted it. That is the")
    print("  first mutation any cracking rule applies to a known old password, so")
    print("  missing it defeats the point of keeping history at all. The skeleton")
    print("  HMAC catches it, along with the extra-punctuation and leet variants,")
    print("  because all four reduce to the root 'summer'.")
    print()
    print("  'Spring2025!' is the honest limitation. Root matching compares roots,")
    print("  and 'spring' is not 'summer', so it is accepted here even though a")
    print("  human would call it obvious rotation. Catching it would mean storing")
    print("  something that survives changing the word itself - a similarity")
    print("  sketch over the plaintext - and that leaks materially more about the")
    print("  old passwords than a root HMAC does. The line is drawn deliberately:")
    print("  block the mutation the rulesets automate, and do not pretend to solve")
    print("  semantic similarity from data the server should not be keeping.")
    hist.close()


def main() -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        run()
    text = buf.getvalue()
    sys.stdout.write(text)
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "demo_session.txt").write_text(text, encoding="utf-8")
    print(f"\nwrote {REPORTS / 'demo_session.txt'}")


if __name__ == "__main__":
    main()
