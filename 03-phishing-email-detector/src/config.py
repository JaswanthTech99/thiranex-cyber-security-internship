"""Paths, seeds and the corpus manifest.

Everything that another module might want to tweak lives here so that no
downstream file has to hardcode a URL or a magic number.
"""
from __future__ import annotations

from pathlib import Path

# One seed, used everywhere. Any sklearn estimator or splitter that takes a
# random_state gets this value, so two runs of `python -m src.train` must
# produce byte-identical summary_stats.json.
SEED = 20260821

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
FIGURES = ROOT / "outputs" / "figures"
REPORTS = ROOT / "outputs" / "reports"

for _d in (DATA_RAW, DATA_PROCESSED, FIGURES, REPORTS):
    _d.mkdir(parents=True, exist_ok=True)

SA_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
NAZARIO_BASE = "https://monkey.org/~jose/phishing/"

# --- Legitimate mail ("ham") -------------------------------------------------
# Only the 2003-02-28 revision of the SpamAssassin ham sets is used. The
# 2002-10-10 archives are an earlier cut of largely the same messages; taking
# both would inject thousands of exact duplicates into the negative class and
# quietly inflate every score.
HAM_ARCHIVES = [
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
]

# --- Phishing mail -----------------------------------------------------------
# The Nazario corpus is split across many files. We take the 2004-2007 era
# files only. The phishing-2015..phishing-2025 files are reachable but are
# deliberately excluded: the ham is all from 2002-2003, and pairing it with
# 2020s phish would widen the temporal gap that is itself the main source of
# label leakage (see outputs/reports/findings.md).
PHISH_ARCHIVES = [
    "phishing0.mbox",
    "phishing1.mbox",
    "phishing2.mbox",
    "phishing3.mbox",
    "20051114.mbox",
]

# --- Generic spam, held out as a probe, never trained on ---------------------
# Used once, at the end, to ask whether the classifier learned "phishing" or
# merely "not-ham". A phishing detector that flags all generic spam is a spam
# filter with a misleading name.
SPAM_ARCHIVES = [
    "20030228_spam.tar.bz2",
    "20030228_spam_2.tar.bz2",
]

# Header fields that exist only because of how these corpora were assembled,
# or that trivially encode collection time/place. Removing them is the
# "headers_scrubbed" view. The list is prefix-matched, case-insensitively.
COLLECTION_ARTIFACT_HEADERS = [
    "received",
    "return-path",
    "delivered-to",
    "x-original-to",
    "envelope-to",
    "x-envelope",
    "message-id",
    "date",
    "x-spam",
    "x-status",
    "x-keywords",
    "x-uid",
    "x-uidl",
    "status",
    "x-mozilla",
    "x-sieve",
    "x-sanitizer",
    "x-virus",
    "x-scanned",
    "received-spf",
    "x-originating-ip",
    "x-mailscanner",
    "list-",
    "x-mailman",
    "x-beenthere",
    "sender",
    "errors-to",
    "precedence",
    "x-loop",
    "x-list",
    "mailing-list",
    "x-been-there",
    "x-apparently-to",
    "x-from",
    "x-mailer-version",
]

# Tokens that identify the *collection* rather than the message, found in the
# body text after the header experiment was run (see findings.md, Finding 3).
# Almost all of the ham is traffic from a handful of 2002 mailing lists, and
# the list's own name, archive host and footer appear in the body.
#
# This is deliberately the same kind of enumerate-and-remove blocklist that
# Finding 2 shows to be inadequate for headers. It is included because it is
# the honest thing to try and because the residual score after applying it is
# a useful upper bound on how much of the signal is real -- not because a
# blocklist is a sound way to remove leakage.
CORPUS_ARTIFACT_TERMS = [
    "exmh", "ilug", "zzzzteana", "razor-users", "spamassassin", "spambayes",
    "sourceforge", "yahoogroups", "netnoteinc", "taint.org", "isotf",
    "c2report", "newsisfree", "linux.ie", "xent.com", "egroups",
    "diveintomark", "boingboing", "aquick.org", "deersoft", "sadev",
    "mailman", "majordomo", "listinfo", "beetapiale",
]
# Not on the list: "fork" (the FoRK mailing list is a ham source, but the word
# is too common in ordinary English to blanket-remove) and "paypal"/"ebay"
# (brand names are genuine phishing signal, not collection artifacts, even
# though they are also strongly class-correlated here).

# Body text is truncated before being written to data/processed so that the
# committed artifact stays a sane size. 20k characters covers the whole body
# for the overwhelming majority of messages in both corpora.
BODY_CHAR_LIMIT = 20_000

# Near-duplicate clustering. 0.70 Jaccard over 5-word shingles: loose enough
# to catch one phishing campaign re-sent with a different victim name and a
# rotated payload host, tight enough not to merge unrelated PayPal lures just
# because they share boilerplate.
SHINGLE_SIZE = 5
MINHASH_PERMUTATIONS = 128
LSH_BANDS = 32  # 32 bands x 4 rows; ~0.6 similarity threshold for candidacy
JACCARD_THRESHOLD = 0.70

TEST_SIZE = 0.25
CV_FOLDS = 5

# Operating point. On real mail a false positive (a legitimate message thrown
# in the phishing bin) is far more damaging than a missed phish, so the
# threshold is chosen to hold the false-positive rate at or below this value
# on cross-validated training data, not at the sklearn default of 0.5.
TARGET_FPR = 0.005
