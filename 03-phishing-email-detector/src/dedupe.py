"""Near-duplicate clustering, so that one phishing campaign cannot straddle
the train/test boundary.

Run: python -m src.dedupe   ->  data/processed/groups.csv

Why this matters more than it sounds: the Nazario corpus is an archive of
campaigns, not of individual messages. One eBay lure was collected dozens of
times with only the victim address and the payload host rotated. Under a random
split, copies of the same message end up on both sides and the test score
measures memorisation, not generalisation.

Method: MinHash over 5-word shingles of the normalised body, banded LSH to
find candidates, exact Jaccard to confirm, union-find to build clusters.
MinHash rather than exact hashing because the copies are near-identical, not
identical; LSH because 9,160 x 9,160 exact comparisons is 42M Jaccard
computations for no benefit.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from collections import defaultdict

import numpy as np

from .config import (
    DATA_PROCESSED,
    JACCARD_THRESHOLD,
    LSH_BANDS,
    MINHASH_PERMUTATIONS,
    SEED,
    SHINGLE_SIZE,
)
from .features import NORM_PUNCT, NORM_WS, normalised_body
from .parse import load

PRIME = 4294967311  # smallest prime above 2**32
_ROWS = MINHASH_PERMUTATIONS // LSH_BANDS
# A bucket bigger than this is unioned wholesale instead of pairwise-verified.
# Members already agree on 4 independent minhash values, so the false-merge
# risk is small and the quadratic blow-up is not worth paying.
BUCKET_VERIFY_LIMIT = 120


def _h32(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=4).digest(), "big")


def shingles(rec: dict) -> "set[int]":
    """5-word shingles of the normalised body.

    Short or empty bodies fall back to subject + body so that the ~110
    attachment-only phishing messages do not all collapse into one cluster
    purely for being empty."""
    text = normalised_body(rec)
    words = text.split()
    if len(words) < SHINGLE_SIZE:
        subj = NORM_WS.sub(" ", NORM_PUNCT.sub(" ", rec["subject"].lower())).strip()
        words = (subj + " " + text).split()
    if not words:
        return set()
    if len(words) < SHINGLE_SIZE:
        return {_h32(" ".join(words))}
    return {
        _h32(" ".join(words[i:i + SHINGLE_SIZE]))
        for i in range(len(words) - SHINGLE_SIZE + 1)
    }


class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))
        self.r = [0] * n

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.r[ra] < self.r[rb]:
            ra, rb = rb, ra
        self.p[rb] = ra
        if self.r[ra] == self.r[rb]:
            self.r[ra] += 1


def minhash_signatures(sets: "list[set[int]]") -> np.ndarray:
    rng = np.random.default_rng(SEED)
    a = rng.integers(1, 1 << 31, size=MINHASH_PERMUTATIONS, dtype=np.uint64)
    b = rng.integers(0, 1 << 31, size=MINHASH_PERMUTATIONS, dtype=np.uint64)
    sig = np.full((len(sets), MINHASH_PERMUTATIONS), PRIME, dtype=np.uint64)
    for i, s in enumerate(sets):
        if not s:
            continue
        x = np.fromiter(sorted(s), dtype=np.uint64, count=len(s))
        # a and x are both < 2**32 so a*x stays inside uint64.
        sig[i] = ((a[:, None] * x[None, :] + b[:, None]) % PRIME).min(axis=1)
    return sig


def cluster(recs: "list[dict]") -> "tuple[list[int], dict]":
    sets = [shingles(r) for r in recs]
    sig = minhash_signatures(sets)
    uf = UnionFind(len(recs))

    n_pairs_checked = 0
    n_merges = 0
    n_bulk_buckets = 0
    for band in range(LSH_BANDS):
        buckets = defaultdict(list)
        block = sig[:, band * _ROWS:(band + 1) * _ROWS]
        for i in range(len(recs)):
            if not sets[i]:
                continue  # no content at all: stays a singleton
            buckets[(band, block[i].tobytes())].append(i)
        for members in buckets.values():
            if len(members) < 2:
                continue
            if len(members) > BUCKET_VERIFY_LIMIT:
                n_bulk_buckets += 1
                for j in members[1:]:
                    uf.union(members[0], j)
                    n_merges += 1
                continue
            for x in range(len(members)):
                for y in range(x + 1, len(members)):
                    i, j = members[x], members[y]
                    if uf.find(i) == uf.find(j):
                        continue
                    n_pairs_checked += 1
                    si, sj = sets[i], sets[j]
                    inter = len(si & sj)
                    if inter and inter / (len(si) + len(sj) - inter) >= JACCARD_THRESHOLD:
                        uf.union(i, j)
                        n_merges += 1

    # Relabel roots to dense, deterministic integer ids ordered by first
    # appearance so the group column is stable across runs.
    remap, groups = {}, []
    for i in range(len(recs)):
        root = uf.find(i)
        if root not in remap:
            remap[root] = len(remap)
        groups.append(remap[root])

    sizes = defaultdict(int)
    for g in groups:
        sizes[g] += 1
    counts = sorted(sizes.values(), reverse=True)
    stats = {
        "n_records": len(recs),
        "n_groups": len(remap),
        "n_singleton_groups": sum(1 for c in counts if c == 1),
        "largest_group_size": counts[0] if counts else 0,
        "top10_group_sizes": counts[:10],
        "pct_records_in_multi_member_groups": round(
            100.0 * sum(c for c in counts if c > 1) / max(len(recs), 1), 2
        ),
        "candidate_pairs_verified": n_pairs_checked,
        "merges": n_merges,
        "oversized_buckets_bulk_merged": n_bulk_buckets,
        "jaccard_threshold": JACCARD_THRESHOLD,
        "shingle_size": SHINGLE_SIZE,
    }
    # Per-class duplication, because it is the phishing side we expect to be
    # heavily duplicated and that asymmetry is the point.
    for lab, name in ((0, "ham"), (1, "phish")):
        idx = [i for i, r in enumerate(recs) if r["label"] == lab]
        gs = defaultdict(int)
        for i in idx:
            gs[groups[i]] += 1
        c = sorted(gs.values(), reverse=True)
        stats[f"{name}_n_groups"] = len(c)
        stats[f"{name}_n_records"] = len(idx)
        stats[f"{name}_largest_group"] = c[0] if c else 0
        stats[f"{name}_pct_in_multi_member_groups"] = round(
            100.0 * sum(x for x in c if x > 1) / max(len(idx), 1), 2
        )
    return groups, stats


def main() -> int:
    recs = load()
    groups, stats = cluster(recs)
    out = DATA_PROCESSED / "groups.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["id", "label", "group_id"])
        for r, g in zip(recs, groups):
            w.writerow([r["id"], r["label"], g])
    for k, v in stats.items():
        print(f"{k:42s} {v}")
    print(f"wrote {out}")
    return 0


def load_groups() -> "dict[str, int]":
    path = DATA_PROCESSED / "groups.csv"
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        return {row["id"]: int(row["group_id"]) for row in rd}


if __name__ == "__main__":
    sys.exit(main())
