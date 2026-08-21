"""Downloads and caches the real password corpora this analyser depends on.

Every list here is a published artefact from a real breach compilation or a real
published wordlist. There are no synthetic passwords anywhere in this project.

Run `python -m src.corpus` to populate data/raw/.
"""
from __future__ import annotations

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"

SECLISTS = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

SOURCES: dict[str, str] = {
    # ~1M passwords ranked by observed frequency across public breach compilations.
    # This is the "known-bad" corpus the analyser matches against.
    "breach_top1m.txt": SECLISTS + "Passwords/Common-Credentials/Pwdb_top-1000000.txt",
    # A different dump (2017 dark-web collection), kept strictly as the held-out
    # evaluation set so the analyser is never scored on its own training corpus.
    "darkweb_top10k.txt": SECLISTS + "Passwords/Common-Credentials/darkweb2017_top-10000.txt",
    # Frequency-ranked English vocabulary, used for dictionary pattern matching.
    "english_10k.txt": (
        "https://raw.githubusercontent.com/first20hours/google-10000-english/"
        "master/google-10000-english.txt"
    ),
    # EFF's diceware list: the source of the generated passphrase suggestions.
    "eff_large_wordlist.txt": "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt",
}

UA = {"User-Agent": "password-strength-analyzer/1.0 (+https://github.com/JaswanthTech99)"}


def fetch(force: bool = False) -> None:
    """Download every corpus into data/raw/ unless it is already cached."""
    RAW.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        dest = RAW / name
        if dest.exists() and not force:
            print(f"cached   {name:<26} {dest.stat().st_size:>10,} bytes")
            continue
        print(f"fetching {name:<26} {url}")
        r = requests.get(url, headers=UA, timeout=180)
        r.raise_for_status()
        dest.write_bytes(r.content)
        print(f"saved    {name:<26} {dest.stat().st_size:>10,} bytes")


def _lines(path: Path) -> list[str]:
    # Breach dumps contain bytes that are not valid UTF-8; dropping them is correct
    # here because such lines cannot be typed at a login prompt anyway.
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [ln.rstrip("\r\n") for ln in text.splitlines()]


def load_ranked(filename: str, limit: int | None = None) -> dict[str, int]:
    """Load a frequency-ordered list as {token: rank}, rank 1 = most common."""
    path = RAW / filename
    if not path.exists():
        raise FileNotFoundError(f"{path} missing - run `python -m src.corpus` first")
    ranks: dict[str, int] = {}
    for i, tok in enumerate(_lines(path), start=1):
        if not tok:
            continue
        # Keep the first (most frequent) occurrence of any duplicate.
        if tok not in ranks:
            ranks[tok] = i
        if limit and len(ranks) >= limit:
            break
    return ranks


def load_breach_ranks(limit: int | None = None) -> dict[str, int]:
    return load_ranked("breach_top1m.txt", limit)


def load_english_ranks() -> dict[str, int]:
    return load_ranked("english_10k.txt")


def load_heldout() -> list[str]:
    """The independent evaluation corpus, in frequency order."""
    return [p for p in _lines(RAW / "darkweb_top10k.txt") if p]


def load_eff_wordlist() -> list[str]:
    """EFF large wordlist: lines are '<5 dice digits>\\t<word>'."""
    words = []
    for ln in _lines(RAW / "eff_large_wordlist.txt"):
        if "\t" in ln:
            words.append(ln.split("\t", 1)[1].strip())
    if len(words) != 7776:
        print(f"warning: expected 7776 EFF words, got {len(words)}", file=sys.stderr)
    return words


if __name__ == "__main__":
    fetch(force="--force" in sys.argv)
