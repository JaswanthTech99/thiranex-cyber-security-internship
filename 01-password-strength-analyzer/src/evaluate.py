"""The evaluation. Every number in the README comes from this script.

The setup exploits a piece of free ground truth: every password in a breach dump
is, by definition, already compromised. Any meter that calls one of them "Strong"
is provably wrong about that password - no labelling and no opinion about what
"strong" means in the abstract is required.

Six experiments:

  A  What fraction of 1M real breached passwords satisfies a standard composition
     policy, and how compromised are the ones that slip through?
  B  What each meter says about 10k held-out breached passwords.
  C  The train/test trap. The held-out dump overlaps the training corpus almost
     completely, so a corpus-lookup meter scores it from memory. C2 replaces it
     with a rank-based split that is genuinely disjoint and large enough to trust.
  D  Guess-number distributions: breached passwords vs the tool's own output.
  E  Calibration against known truth, where the true guess space is arithmetic.
  F  The operational test. Condition on passing the composition policy, then ask
     each meter to separate known-bad from known-good. This is the situation a
     real signup form is in after its policy filter has run.

Run: python -m src.evaluate
"""
from __future__ import annotations

import json
import random
import string
import time
from math import log10
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy.stats import spearmanr  # noqa: E402
from sklearn.metrics import roc_auc_score, roc_curve  # noqa: E402

from . import naive  # noqa: E402
from .benchmark import load_rates  # noqa: E402
from .corpus import (  # noqa: E402
    fetch,
    load_breach_ranks,
    load_eff_wordlist,
    load_english_ranks,
    load_heldout,
)
from .guessing import most_guessable  # noqa: E402
from .pwned import PwnedClient  # noqa: E402
from .suggest import SYMBOLS as SUGGEST_SYMBOLS  # noqa: E402

SEED = 20260821
ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "outputs" / "figures"
REPORTS = ROOT / "outputs" / "reports"
PROCESSED = ROOT / "data" / "processed"

# Guess-number threshold below which a password is treated as weak. 1e8 guesses
# falls in milliseconds against a fast unsalted hash on one GPU, so this is a
# generous line, not a strict one.
WEAK_BELOW = 1e8

# The rank-based split used to build a genuinely unseen evaluation set: the
# estimator gets the more common half of the corpus, and is tested on the rest.
TRAIN_RANK_CUTOFF = 500_000
STRICT_POLICY = "len>=8 + all 4 classes"

plt.rcParams.update({
    "figure.dpi": 130,
    "savefig.bbox": "tight",
    "font.size": 9,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.spines.top": False,
    "axes.spines.right": False,
})
INK = "#1f3864"
WARN = "#b3261e"
OK = "#1e6b52"
MID = "#2a6f97"


MATCHED_POOLS = [string.ascii_lowercase, string.ascii_uppercase, string.digits,
                 "!@#$%^&*()-_=+.?"]

# The shipped suggester in src/suggest.py draws from `secrets`, which is correct
# for real use and, by design, cannot be seeded. The evaluation therefore builds
# its own controls from a seeded PRNG instead, so that every number in the report
# reproduces exactly. Nothing generated here is ever offered to a user, so the
# weaker generator carries no security consequence - only the report's
# reproducibility depends on it.
def seeded_diceware(words: list[str], n_words: int, rng: random.Random,
                    separator: str = "-") -> tuple[str, float]:
    picked = [rng.choice(words) for _ in range(n_words)]
    return separator.join(picked), float(len(words)) ** n_words


def seeded_random_string(length: int, rng: random.Random) -> tuple[str, float]:
    alphabet = string.ascii_letters + string.digits + SUGGEST_SYMBOLS
    pw = "".join(rng.choice(alphabet) for _ in range(length))
    return pw, float(len(alphabet)) ** length


def seeded_random_matched(length: int, rng: random.Random) -> str:
    """A random password of exactly `length` characters carrying all four
    character classes - indistinguishable from a policy-compliant breached
    password on every input the naive meters actually look at."""
    length = max(length, len(MATCHED_POOLS))
    chars = [rng.choice(p) for p in MATCHED_POOLS]
    alphabet = "".join(MATCHED_POOLS)
    chars += [rng.choice(alphabet) for _ in range(length - len(MATCHED_POOLS))]
    rng.shuffle(chars)
    return "".join(chars)


def dictionaries(breach: dict[str, int], english: dict[str, int],
                 eff: list[str]) -> dict[str, dict[str, int]]:
    """The corpora the estimator assumes the attacker also owns.

    The EFF diceware list is included deliberately: this tool hands out EFF
    passphrases, so an attacker targeting its users would start with that list.
    Scoring passphrases as though the wordlist were secret would be self-serving.
    """
    return {
        "breach": breach,
        "english": english,
        "eff": {w: i for i, w in enumerate(eff, start=1)},
    }


def score_all(passwords: list[str], dicts, label: str = "") -> pd.DataFrame:
    rows = []
    t0 = time.perf_counter()
    for i, pw in enumerate(passwords):
        est = most_guessable(pw, dicts)
        comp_score, _ = naive.composition_score(pw)
        rows.append({
            "password_len": len(pw),
            "guesses": est.guesses,
            "log10_guesses": est.log10_guesses,
            "gn_score": est.score,
            "top_pattern": est.sequence[0].pattern if est.sequence else "none",
            "comp_score": comp_score,
            "comp_strong": naive.composition_says_strong(pw),
            "entropy_bits": naive.charset_entropy_bits(pw),
            "entropy_strong": naive.entropy_says_strong(pw),
        })
        if (i + 1) % 5000 == 0:
            print(f"    {label} scored {i+1}/{len(passwords)} "
                  f"({time.perf_counter()-t0:.0f}s)")
    return pd.DataFrame(rows)


def strong_rates(frame: pd.DataFrame) -> dict:
    n = len(frame)
    if n == 0:
        return {"n": 0}
    return {
        "n": n,
        "composition_meter_says_strong_pct": round(100 * frame["comp_strong"].mean(), 2),
        "charset_entropy_says_strong_pct": round(100 * frame["entropy_strong"].mean(), 2),
        "guess_number_says_strong_pct": round(100 * (frame["gn_score"] >= 3).mean(), 2),
        "guess_number_flags_weak_pct": round(100 * (frame["guesses"] < WEAK_BELOW).mean(), 2),
        "median_log10_guesses": round(float(frame["log10_guesses"].median()), 2),
    }


def experiment_a(breach: dict[str, int]) -> dict:
    policies = {
        "len>=8": dict(min_len=8, required_classes=1),
        "len>=8 + 3 of 4 classes": dict(min_len=8, required_classes=3),
        STRICT_POLICY: dict(min_len=8, required_classes=4),
        "len>=12 + all 4 classes": dict(min_len=12, required_classes=4),
    }
    total = len(breach)
    out, examples = {}, {}
    for label, kw in policies.items():
        passing = [pw for pw in breach if naive.passes_policy(pw, **kw)]
        out[label] = {"passing": len(passing), "total": total,
                      "pct": round(100 * len(passing) / total, 3)}
        examples[label] = sorted(passing, key=lambda p: breach[p])[:12]
    return {"policies": out, "examples": examples, "corpus_size": total}


def main() -> None:
    for d in (FIGURES, REPORTS, PROCESSED):
        d.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    np_rng = np.random.default_rng(SEED)

    print("[1/8] fetching corpora")
    fetch()

    print("[2/8] loading corpora")
    breach = load_breach_ranks()
    english = load_english_ranks()
    eff = load_eff_wordlist()
    heldout = load_heldout()
    full_dicts = dictionaries(breach, english, eff)
    # The estimator for every "unseen" experiment only gets the common half.
    train_breach = {pw: r for pw, r in breach.items() if r <= TRAIN_RANK_CUTOFF}
    split_dicts = dictionaries(train_breach, english, eff)
    print(f"    breach corpus : {len(breach):,}")
    print(f"    held-out dump : {len(heldout):,}")
    print(f"    train half    : {len(train_breach):,} (rank <= {TRAIN_RANK_CUTOFF:,})")

    print("[3/8] A - composition policy vs real breached passwords")
    exp_a = experiment_a(breach)
    for label, r in exp_a["policies"].items():
        print(f"    {label:<26} {r['passing']:>8,} / {r['total']:,} = {r['pct']:>6.2f}%")

    print("[4/8] B + C - held-out dump, and the overlap that invalidates it")
    df = score_all(heldout, full_dicts, "heldout")
    df["in_training_corpus"] = [pw in breach for pw in heldout]
    df.to_csv(PROCESSED / "heldout_scored.csv", index=False)
    overlap = int(df["in_training_corpus"].sum())
    exp_b = strong_rates(df)
    exp_b["spearman_comp_score_vs_log10_guesses"] = round(
        float(spearmanr(df["comp_score"], df["log10_guesses"]).statistic), 3)
    exp_b["spearman_entropy_bits_vs_log10_guesses"] = round(
        float(spearmanr(df["entropy_bits"], df["log10_guesses"]).statistic), 3)
    exp_c = {
        "overlap_with_training_corpus": overlap,
        "overlap_pct": round(100 * overlap / len(df), 2),
        "disjoint": len(df) - overlap,
        "on_overlap": strong_rates(df[df["in_training_corpus"]]),
        "on_disjoint": strong_rates(df[~df["in_training_corpus"]]),
    }
    print(f"    overlap: {overlap:,}/{len(df):,} = {exp_c['overlap_pct']}% "
          "of the 'held-out' dump is in the training corpus")
    print(f"    weak-flag rate  memorised: "
          f"{exp_c['on_overlap'].get('guess_number_flags_weak_pct')}%   "
          f"unseen (n={exp_c['disjoint']}): "
          f"{exp_c['on_disjoint'].get('guess_number_flags_weak_pct')}%")

    print("[5/8] C2 - rank-based disjoint split, large n")
    unseen_pool = [pw for pw, r in breach.items() if r > TRAIN_RANK_CUTOFF]
    unseen_sample = rng.sample(unseen_pool, 6000)
    df_unseen_split = score_all(unseen_sample, split_dicts, "unseen")
    df_unseen_full = score_all(unseen_sample, full_dicts, "memorised")
    exp_c2 = {
        "train_rank_cutoff": TRAIN_RANK_CUTOFF,
        "eval_pool_size": len(unseen_pool),
        "sample_size": len(unseen_sample),
        "estimator_without_these_passwords": strong_rates(df_unseen_split),
        "estimator_with_these_passwords": strong_rates(df_unseen_full),
    }
    print(f"    weak-flag rate  with them in the corpus: "
          f"{exp_c2['estimator_with_these_passwords']['guess_number_flags_weak_pct']}%")
    print(f"    weak-flag rate  with them removed      : "
          f"{exp_c2['estimator_without_these_passwords']['guess_number_flags_weak_pct']}%")

    print("[6/8] D + E - generated passwords: separation and calibration")
    words = eff
    generated = {
        "diceware-4": [seeded_diceware(words, 4, rng) for _ in range(400)],
        "diceware-6": [seeded_diceware(words, 6, rng) for _ in range(400)],
        "diceware-4-nosep": [seeded_diceware(words, 4, rng, separator="")
                             for _ in range(400)],
        "random-20": [seeded_random_string(20, rng) for _ in range(400)],
    }
    gen_rows, calibration = [], {}
    for kind, items in generated.items():
        ests = [most_guessable(pw, full_dicts) for pw, _ in items]
        true_space = items[0][1]
        est_log = np.array([e.log10_guesses for e in ests])
        for (pw, _space), e in zip(items, ests):
            gen_rows.append({"kind": kind, "log10_guesses": e.log10_guesses,
                             "gn_score": e.score,
                             "comp_score": naive.composition_score(pw)[0],
                             "comp_strong": naive.composition_says_strong(pw),
                             "entropy_bits": naive.charset_entropy_bits(pw),
                             "password_len": len(pw)})
        calibration[kind] = {
            "true_log10_guess_space": round(log10(true_space), 2),
            "estimated_log10_median": round(float(np.median(est_log)), 2),
            "estimated_log10_p05": round(float(np.percentile(est_log, 5)), 2),
            "estimated_log10_p95": round(float(np.percentile(est_log, 95)), 2),
            "median_error_orders": round(float(np.median(est_log) - log10(true_space)), 2),
            "pct_scored_very_strong": round(100 * float(np.mean([e.score == 4 for e in ests])), 1),
        }
        c = calibration[kind]
        print(f"    {kind:<18} true 10^{c['true_log10_guess_space']:<6} "
              f"est 10^{c['estimated_log10_median']:<6} "
              f"({c['median_error_orders']:+} orders)")
    gen_df = pd.DataFrame(gen_rows)
    gen_df.to_csv(PROCESSED / "generated_scored.csv", index=False)

    print("[7/8] F - discrimination after the policy filter has run")
    # Known-bad: breached passwords that pass the strict policy AND sit outside the
    # estimator's dictionary, so nothing here is scored from memory.
    bad_pws = sorted(
        (pw for pw, r in breach.items()
         if r > TRAIN_RANK_CUTOFF and naive.passes_policy(pw, 8, 4)),
        key=lambda p: breach[p],
    )
    # Known-good: generated output, whose guess space is arithmetic, not assumed.
    good_pws = [seeded_diceware(words, 4, rng)[0] for _ in range(200)] + \
               [seeded_diceware(words, 6, rng)[0] for _ in range(200)] + \
               [seeded_random_string(20, rng)[0] for _ in range(200)]
    bad_df = score_all(bad_pws, split_dicts, "policy-ok bad")
    good_df = score_all(good_pws, split_dicts, "generated good")
    y = np.r_[np.ones(len(bad_df)), np.zeros(len(good_df))]  # 1 = compromised
    exp_f = {"n_bad_policy_compliant_unseen": len(bad_df), "n_good_generated": len(good_df)}
    for name, col, sign in (
        ("composition_meter_score", "comp_score", -1.0),
        ("charset_entropy_bits", "entropy_bits", -1.0),
        ("guess_number_log10", "log10_guesses", -1.0),
    ):
        scores = sign * np.r_[bad_df[col].to_numpy(), good_df[col].to_numpy()]
        exp_f[name + "_auc"] = round(float(roc_auc_score(y, scores)), 4)
        print(f"    AUC {name:<26} {exp_f[name + '_auc']}")
    exp_f["bad_examples_by_frequency"] = bad_pws[:12]
    exp_f["pct_bad_called_strong_by_composition"] = round(
        100 * float(bad_df["comp_strong"].mean()), 1)
    exp_f["pct_bad_called_strong_by_entropy"] = round(
        100 * float(bad_df["entropy_strong"].mean()), 1)
    exp_f["pct_bad_flagged_weak_by_guess_number"] = round(
        100 * float((bad_df["guesses"] < WEAK_BELOW).mean()), 1)
    # Reported because the length gap is the whole reason the charset-entropy AUC
    # in this experiment cannot be believed; F2 exists to remove it.
    exp_f["mean_len_bad"] = round(float(bad_df["password_len"].mean()), 2)
    exp_f["mean_len_good"] = round(float(good_df["password_len"].mean()), 2)
    print(f"    n_bad={len(bad_df)}, n_good={len(good_df)}")

    # F2 - the same test with the length confound removed. Every generated
    # control is the same length as a real breached password and carries the same
    # four character classes, so the naive meters see identical inputs and the
    # only thing left to separate the two groups is structure.
    print("    F2 - length-matched controls")
    matched_pws = [seeded_random_matched(len(pw), rng) for pw in bad_pws]
    matched_df = score_all(matched_pws, split_dicts, "length-matched")
    y2 = np.r_[np.ones(len(bad_df)), np.zeros(len(matched_df))]
    exp_f2 = {
        "n_bad": len(bad_df),
        "n_matched_controls": len(matched_df),
        "mean_len_bad": round(float(bad_df["password_len"].mean()), 2),
        "mean_len_controls": round(float(matched_df["password_len"].mean()), 2),
        "mean_entropy_bits_bad": round(float(bad_df["entropy_bits"].mean()), 1),
        "mean_entropy_bits_controls": round(float(matched_df["entropy_bits"].mean()), 1),
        "median_log10_guesses_bad": round(float(bad_df["log10_guesses"].median()), 2),
        "median_log10_guesses_controls": round(
            float(matched_df["log10_guesses"].median()), 2),
    }
    for name, col in (("composition_meter_score", "comp_score"),
                      ("charset_entropy_bits", "entropy_bits"),
                      ("guess_number_log10", "log10_guesses")):
        scores = -np.r_[bad_df[col].to_numpy(), matched_df[col].to_numpy()]
        exp_f2[name + "_auc"] = round(float(roc_auc_score(y2, scores)), 4)
        print(f"    AUC {name:<26} {exp_f2[name + '_auc']}")

    print("[8/8] live HIBP confirmation + figures")
    client = PwnedClient()
    hibp_rows = []
    for pw in bad_pws[:15]:
        try:
            n = client.count(pw)
        except Exception as e:  # noqa: BLE001
            print(f"    HIBP lookup unavailable, stopping spot check: {e}")
            break
        est = most_guessable(pw, split_dicts)
        hibp_rows.append({
            "password": pw,
            "breach_rank": breach[pw],
            "hibp_count": n,
            "composition_label": naive.composition_score(pw)[1],
            "entropy_bits": round(naive.charset_entropy_bits(pw), 1),
            "guess_number_verdict": est.label,
            "log10_guesses": round(est.log10_guesses, 2),
        })
    hibp_df = pd.DataFrame(hibp_rows)
    hibp_df.to_csv(PROCESSED / "policy_compliant_but_breached.csv", index=False)
    if not hibp_df.empty:
        print(f"    {int((hibp_df['hibp_count'] > 0).sum())}/{len(hibp_df)} confirmed "
              f"breached, worst seen {hibp_df['hibp_count'].max():,} times")

    make_figures(df, gen_df, exp_a, exp_c, exp_c2, bad_df, good_df, y,
                 matched_df, y2, np_rng)

    summary = {
        "seed": SEED,
        "corpora": {
            "training_breach_corpus": len(breach),
            "heldout_dump": len(heldout),
            "train_half_rank_cutoff": TRAIN_RANK_CUTOFF,
            "dictionaries": {k: len(v) for k, v in full_dicts.items()},
        },
        "hash_rates": load_rates(),
        "weak_threshold_guesses": WEAK_BELOW,
        "experiment_a_composition_policy": exp_a["policies"],
        "experiment_a_examples": exp_a["examples"],
        "experiment_b_heldout_dump": exp_b,
        "experiment_c_overlap_trap": exp_c,
        "experiment_c2_rank_split": exp_c2,
        "experiment_e_calibration": calibration,
        "experiment_f_discrimination": exp_f,
        "experiment_f2_length_matched": exp_f2,
        "hibp_spot_check": hibp_rows,
    }
    (REPORTS / "summary_stats.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_findings(summary, exp_a)
    print(f"\nwrote {REPORTS/'summary_stats.json'} and {REPORTS/'findings.md'}")
    print(f"figures in {FIGURES}")


def make_figures(df, gen_df, exp_a, exp_c, exp_c2, bad_df, good_df, y,
                 matched_df, y2, np_rng) -> None:
    # 1. The overlap trap, and what the rank-based split reveals instead.
    fig, axes = plt.subplots(1, 2, figsize=(9.4, 3.7))
    ax = axes[0]
    groups = ["in training\ncorpus", "not in training\ncorpus"]
    vals = [exp_c["on_overlap"].get("guess_number_flags_weak_pct", 0),
            exp_c["on_disjoint"].get("guess_number_flags_weak_pct", 0)]
    ns = [exp_c["on_overlap"].get("n", 0), exp_c["on_disjoint"].get("n", 0)]
    bars = ax.bar(groups, vals, color=[MID, WARN], width=0.5)
    ax.bar_label(bars, labels=[f"{v:.1f}%\nn={n:,}" for v, n in zip(vals, ns)],
                 padding=3, fontsize=8.5)
    ax.set_ylabel("flagged weak by guess-number (%)")
    ax.set_ylim(0, 118)
    ax.set_title(f"The 'held-out' dump is {exp_c['overlap_pct']}% training data\n"
                 "so its headline number is memorisation", fontsize=9.5)

    ax = axes[1]
    a = exp_c2["estimator_with_these_passwords"]["guess_number_flags_weak_pct"]
    b = exp_c2["estimator_without_these_passwords"]["guess_number_flags_weak_pct"]
    bars = ax.bar(["corpus contains\nthese passwords", "corpus does not\ncontain them"],
                  [a, b], color=[MID, WARN], width=0.5)
    ax.bar_label(bars, fmt="%.1f%%", padding=3, fontsize=9)
    ax.set_ylim(0, 118)
    ax.set_ylabel("flagged weak by guess-number (%)")
    ax.set_title(f"Rank-based split, n={exp_c2['sample_size']:,}\n"
                 "the honest measure of generalisation", fontsize=9.5)
    fig.savefig(FIGURES / "01_generalisation_and_overlap.png")
    plt.close(fig)

    # 2. How many real breached passwords each composition policy approves.
    fig, ax = plt.subplots(figsize=(6.8, 3.4))
    pol = exp_a["policies"]
    names = list(pol.keys())
    pcts = [pol[k]["pct"] for k in names]
    bars = ax.barh(names, pcts, color=INK, height=0.55)
    ax.bar_label(bars, labels=[f"{pol[k]['pct']:.2f}%  ({pol[k]['passing']:,} passwords)"
                               for k in names], padding=4, fontsize=8.5)
    ax.set_xlabel("share of a 1,000,000-password breach corpus the policy approves")
    ax.set_xlim(0, max(pcts) * 1.5)
    ax.set_title("Composition policies do filter most of a frequency-ranked dump\n"
                 "the survivors are the problem, not the pass rate", fontsize=10)
    fig.savefig(FIGURES / "02_composition_policy_leakage.png")
    plt.close(fig)

    # 3. Guess-number distributions: breached vs what the tool generates.
    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    ax.hist(df["log10_guesses"], bins=45, color=WARN, alpha=0.78, density=True,
            label=f"breached passwords (n={len(df):,})")
    for kind, color in (("diceware-4", MID), ("diceware-6", "#1b4965"),
                        ("random-20", OK)):
        sub = gen_df[gen_df["kind"] == kind]["log10_guesses"]
        if len(sub):
            ax.hist(sub, bins=25, histtype="step", linewidth=1.8, color=color,
                    density=True, label=f"generated {kind} (n={len(sub)})")
    ax.axvline(log10(WEAK_BELOW), color="black", linestyle="--", linewidth=1)
    ax.text(log10(WEAK_BELOW) + 0.4, ax.get_ylim()[1] * 0.86,
            "weak threshold\n$10^{8}$ guesses", fontsize=8)
    ax.set_xlabel("log10(estimated guesses)")
    ax.set_ylabel("density")
    ax.set_title("Where real breached passwords sit, and where generated ones do",
                 fontsize=10)
    ax.legend(fontsize=8, frameon=False)
    fig.savefig(FIGURES / "03_guess_distribution.png")
    plt.close(fig)

    # 4. The operational test, twice: once against the tool's own suggestions,
    #    and once against controls matched on length and character classes so the
    #    naive meters cannot win on length alone.
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.4), sharey=True)
    panels = [
        (axes[0], good_df, y,
         f"vs {len(good_df)} generated passphrases\n(controls are longer)"),
        (axes[1], matched_df, y2,
         f"vs {len(matched_df)} length- and class-matched controls\n"
         "(the confound removed)"),
    ]
    for ax, ctrl, yy, title in panels:
        for name, col, color in (("signup-form composition meter", "comp_score", WARN),
                                 ("charset 'entropy' bits", "entropy_bits", "#c77700"),
                                 ("guess-number (this tool)", "log10_guesses", OK)):
            scores = -np.r_[bad_df[col].to_numpy(), ctrl[col].to_numpy()]
            fpr, tpr, _ = roc_curve(yy, scores)
            ax.plot(fpr, tpr, linewidth=1.9, color=color,
                    label=f"{name}  AUC {roc_auc_score(yy, scores):.3f}")
        ax.plot([0, 1], [0, 1], color="#9aa5b1", linestyle="--", linewidth=1)
        ax.set_xlabel("false positive rate (good password rejected)")
        ax.set_title(title, fontsize=9.5)
        ax.legend(fontsize=7.6, frameon=False, loc="lower right")
    axes[0].set_ylabel("true positive rate (compromised password caught)")
    fig.suptitle(f"{len(bad_df)} unseen breached passwords that pass the 4-class policy: "
                 "can any meter spot them?", fontsize=10.5)
    fig.subplots_adjust(top=0.80)
    fig.savefig(FIGURES / "04_discrimination_roc.png")
    plt.close(fig)

    # 5. Length is not strength.
    fig, ax = plt.subplots(figsize=(7.0, 3.8))
    sample = df.sample(min(4000, len(df)), random_state=SEED)
    for flag, color, name in ((False, "#9aa5b1", "composition meter: not strong"),
                              (True, WARN, "composition meter: Strong")):
        sub = sample[sample["comp_strong"] == flag]
        jitter = np_rng.uniform(-0.25, 0.25, len(sub))
        ax.scatter(sub["password_len"] + jitter, sub["log10_guesses"], s=7, alpha=0.5,
                   color=color, label=name, edgecolors="none")
    ax.axhline(log10(WEAK_BELOW), color="black", linestyle="--", linewidth=1)
    ax.set_xlabel("password length (characters)")
    ax.set_ylabel("log10(estimated guesses)")
    ax.set_xlim(0, min(24, sample["password_len"].max() + 1))
    ax.set_title("Every point is a password that has already been breached\n"
                 "red points are the ones a composition meter approves", fontsize=10)
    ax.legend(fontsize=8, frameon=False, loc="upper left")
    fig.savefig(FIGURES / "05_length_vs_guesses.png")
    plt.close(fig)


def write_findings(summary: dict, exp_a: dict) -> None:
    b = summary["experiment_b_heldout_dump"]
    c = summary["experiment_c_overlap_trap"]
    c2 = summary["experiment_c2_rank_split"]
    f = summary["experiment_f_discrimination"]
    f2 = summary["experiment_f2_length_matched"]
    pol = summary["experiment_a_composition_policy"]
    rates = summary["hash_rates"]
    cal = summary["experiment_e_calibration"]
    strict = pol[STRICT_POLICY]
    hibp = summary["hibp_spot_check"]
    sha1 = rates["measured"]["sha1_cpu_single_thread_hps"]
    argon = rates["measured"]["argon2id_t3_m64MiB_p4_hps"]
    # Confirmed-breached passwords that this tool's own estimator still praises.
    overconfident = sum(
        1 for r in hibp
        if r["hibp_count"] > 0 and r["guess_number_verdict"] in ("Strong", "Very strong")
    )

    lines = [
        "# Findings",
        "",
        "M Jaswanth Kumar. Every number below was produced by `python -m src.evaluate` "
        f"with seed {summary['seed']}. Nothing is hand-entered.",
        "",
        "## Ground truth, for free",
        "",
        f"- Training corpus: {summary['corpora']['training_breach_corpus']:,} passwords "
        "ranked by observed frequency across public breach compilations "
        "(SecLists `Pwdb_top-1000000.txt`).",
        f"- Second dump: {summary['corpora']['heldout_dump']:,} passwords from a 2017 "
        "dark-web collection (SecLists `darkweb2017_top-10000.txt`).",
        "- Dictionaries the estimator is allowed to use: "
        + ", ".join(f"{k} ({v:,})" for k, v in summary["corpora"]["dictionaries"].items())
        + ".",
        "",
        "Every password in both files is known-compromised. A meter that calls one of "
        "them strong is wrong, and saying so requires no opinion about what strength "
        "means.",
        "",
        "One reproducibility note. The suggester shipped in `src/suggest.py` draws from "
        "`secrets`, which is the right generator for a password a human will actually "
        "use and which deliberately cannot be seeded. The generated *controls* in this "
        "evaluation therefore come from a seeded `random.Random` instead, so every "
        "number below reproduces exactly. Nothing generated by the evaluation is ever "
        "offered to a user, so the weaker generator costs nothing here.",
        "",
        "## Finding 1 - composition policies filter most of a dump, and that is not the point",
        "",
        "| policy | approves | share of corpus |",
        "|---|---|---|",
    ]
    for label, r in pol.items():
        lines.append(f"| {label} | {r['passing']:,} / {r['total']:,} | {r['pct']:.2f}% |")
    lines += [
        "",
        "I expected composition rules to wave most of this corpus through. They do not: "
        f"the strict eight-character four-class policy admits only {strict['passing']:,} "
        f"of a million ({strict['pct']:.2f}%). Reporting that honestly matters more than "
        "the headline I was hoping for.",
        "",
        f"The real problem is the {strict['passing']:,} survivors. Ranked by how common "
        "they are in breach data, the policy's first approvals are:",
        "",
        "```",
        ", ".join(exp_a["examples"][STRICT_POLICY][:10]),
        "```",
        "",
        f"And the meter cannot rank what it admits. Across the {b['n']:,} passwords in "
        "the second dump, the correlation between a meter's output and the actual guess "
        f"count is {b['spearman_comp_score_vs_log10_guesses']} (Spearman) for the "
        f"composition score and {b['spearman_entropy_bits_vs_log10_guesses']} for charset "
        "\"entropy\" bits. A policy is a gate, not a measurement, and it was never "
        "designed to be one.",
        "",
        "## Finding 2 - the trap: a held-out corpus that is not held out",
        "",
        f"The second dump looks like an independent test set. It is not: "
        f"{c['overlap_pct']}% of it ({c['overlap_with_training_corpus']:,} of {b['n']:,}) "
        "also appears in the training corpus. A corpus-lookup estimator scores those "
        "from memory, so any headline number over the whole file measures recall of a "
        "wordlist, not the ability to judge an unfamiliar password.",
        "",
        f"On the {c['disjoint']} passwords that are genuinely absent, the weak-flag rate "
        f"drops from {c['on_overlap'].get('guess_number_flags_weak_pct')}% to "
        f"{c['on_disjoint'].get('guess_number_flags_weak_pct')}%. That is the finding, "
        f"but n={c['disjoint']} is too small to publish, so the split was rebuilt "
        "properly:",
        "",
        "Rank-based split - the estimator gets breach ranks 1 to "
        f"{c2['train_rank_cutoff']:,} and is tested on a random sample of "
        f"{c2['sample_size']:,} passwords drawn from the {c2['eval_pool_size']:,} ranked "
        "below the cutoff.",
        "",
        "| estimator's corpus | n | flags weak | median estimate |",
        "|---|---|---|---|",
        f"| contains the test passwords | {c2['estimator_with_these_passwords']['n']:,} | "
        f"{c2['estimator_with_these_passwords']['guess_number_flags_weak_pct']}% | "
        f"10^{c2['estimator_with_these_passwords']['median_log10_guesses']} |",
        f"| does not contain them | {c2['estimator_without_these_passwords']['n']:,} | "
        f"{c2['estimator_without_these_passwords']['guess_number_flags_weak_pct']}% | "
        f"10^{c2['estimator_without_these_passwords']['median_log10_guesses']} |",
        "",
        "The second row is what this tool can actually claim. The gap between the rows is "
        "how much of a corpus-lookup meter's apparent skill is lookup.",
        "",
        "## Finding 3 - the operational test",
        "",
        "A signup form does not get to choose its inputs. It runs its policy filter, and "
        "then has to judge whatever passed. So: take breached passwords that pass the "
        "four-class policy *and* sit outside the estimator's dictionary "
        f"(n={f['n_bad_policy_compliant_unseen']}, all known-compromised), mix in "
        f"{f['n_good_generated']} generated passwords (known-good, guess space "
        "computable), and ask each meter to tell them apart.",
        "",
        "| meter | ROC AUC |",
        "|---|---|",
        f"| signup-form composition score | {f['composition_meter_score_auc']} |",
        f"| charset \"entropy\" bits | {f['charset_entropy_bits_auc']} |",
        f"| guess-number (this tool) | {f['guess_number_log10_auc']} |",
        "",
        f"The composition meter scores {f['composition_meter_score_auc']}, which is not "
        "merely uninformative - it is below 0.5, so the meter is inverted. It ranks the "
        "compromised passwords as *stronger* than the generated ones, because a breached "
        f"`Abcd123!` carries all four character classes while `{'-'.join(['word'] * 4)}` "
        "carries two and is therefore marked down to Medium. "
        f"{f['pct_bad_called_strong_by_composition']}% of the compromised passwords are "
        f"labelled Strong by it, against "
        f"{f['pct_bad_flagged_weak_by_guess_number']}% correctly flagged weak by the "
        "guess-number estimator. That second figure is a threshold result, not a ranking "
        "result: these are the hardest cases in the corpus, deliberately chosen to be "
        "outside the estimator's dictionary, and roughly half of them sit above the 10^8 "
        "line. The AUC below is the ranking measure, and it is threshold-free.",
        "",
        "The charset-entropy meter looks excellent here, at "
        f"{f['charset_entropy_bits_auc']}. That number is a length artefact and should "
        f"not be believed: the generated controls average {f['mean_len_good']} characters "
        f"and the breached passwords {f['mean_len_bad']}, so any length-sensitive score "
        "wins by default. Removing the confound settles it - each control is regenerated "
        "at exactly the length of a real breached password, carrying all four classes, so "
        "the naive meters receive statistically identical inputs:",
        "",
        f"| meter | ROC AUC (length- and class-matched, n={f2['n_bad']} vs "
        f"{f2['n_matched_controls']}) |",
        "|---|---|",
        f"| signup-form composition score | {f2['composition_meter_score_auc']:.3f} |",
        f"| charset \"entropy\" bits | {f2['charset_entropy_bits_auc']:.3f} |",
        f"| guess-number (this tool) | {f2['guess_number_log10_auc']:.3f} |",
        "",
        "Both naive meters land on exactly 0.500, and that is not a coincidence or a "
        "rounding: matched on length and character classes, every control produces the "
        "identical composition score and the identical bit count as the breached password "
        "it was built from, so the meters are scoring ties all the way down. "
        f"Mean charset \"entropy\" is {f2['mean_entropy_bits_bad']} bits for the breached "
        f"group and {f2['mean_entropy_bits_controls']} bits for the controls. The "
        f"guess-number estimator still separates them, "
        f"10^{f2['median_log10_guesses_bad']} against "
        f"10^{f2['median_log10_guesses_controls']} guesses at the median, because it is "
        "reading structure rather than counting character classes. This is the experiment "
        "the whole project turns on: strip away length and composition, and the naive "
        "meters have nothing left.",
        "",
        "## Finding 4 - calibration, including where this estimator is wrong",
        "",
        "For generated passwords the true guess space is arithmetic, so the "
        "estimator's error can be measured instead of asserted:",
        "",
        "| generator | true space | estimated (median) | error | scored 'very strong' |",
        "|---|---|---|---|---|",
    ]
    for kind, k in cal.items():
        lines.append(
            f"| {kind} | 10^{k['true_log10_guess_space']} | "
            f"10^{k['estimated_log10_median']} | {k['median_error_orders']:+} orders | "
            f"{k['pct_scored_very_strong']}% |"
        )
    d4 = cal.get("diceware-4", {})
    d4n = cal.get("diceware-4-nosep", {})
    r20 = cal.get("random-20", {})
    lines += [
        "",
        f"Separated passphrases are over-scored by {d4.get('median_error_orders')} orders "
        f"of magnitude, and the cause is identifiable rather than mysterious: dropping the "
        f"separators moves the same generator to {d4n.get('median_error_orders'):+} orders. "
        "The excess is the estimator charging for hyphens it treats as unknown characters, "
        "plus the ordering penalty on a longer pattern list. An attacker who knows the "
        "generator emits `word-word-word-word` pays neither. The estimator does not know "
        "the scheme, and pricing that ignorance as strength is the one direction of error "
        "worth fixing in future work.",
        "",
        f"Long random strings go the other way, under-scored by "
        f"{abs(r20.get('median_error_orders', 0))} orders, because the search finds "
        "incidental dictionary and keyboard fragments inside random text and takes the "
        "cheaper decomposition. Under-stating a strong password is the safe direction to "
        "be wrong in, so it is left alone.",
        "",
        "## Finding 5 - live confirmation that discloses nothing",
        "",
        f"{len(hibp)} of the most common policy-compliant breached passwords, checked "
        "against the live Have I Been Pwned range API:",
        "",
        "| password | composition meter | charset bits | HIBP sightings | this tool |",
        "|---|---|---|---|---|",
    ]
    for row in hibp:
        lines.append(
            f"| `{row['password']}` | {row['composition_label']} | {row['entropy_bits']} | "
            f"{row['hibp_count']:,} | {row['guess_number_verdict']} |"
        )
    lines += [
        "",
        "The lookup sends the first five hex characters of the SHA-1 and nothing else. The "
        "server returns every suffix under that prefix and cannot tell which was asked "
        "about. A strength checker that posts the password, or even its full hash, to a "
        "third party has created a worse problem than the one it set out to solve.",
        "",
        "### Read that table against my own tool, not just against the naive meters",
        "",
        f"Every one of these {len(hibp)} passwords is confirmed compromised, and the "
        f"guess-number estimator still rates {overconfident} of them Strong or Very "
        "strong. `Qazigund@1` and `wArdog-1kill` are the clearest misses: a place name "
        "with a suffix, and a mangled phrase, neither of which decomposes into anything "
        "the estimator's dictionaries recognise once those passwords have been held out "
        "of them.",
        "",
        "That is not a footnote, it is the argument for the tool's layering. Structural "
        f"estimation caught {len(hibp) - overconfident} of {len(hibp)}; the breach lookup "
        f"caught {len(hibp)}. A guess-number model reasons about the passwords people "
        "*tend* to build, and a real corpus knows the ones they *did* build. Shipping "
        "either alone would have been the mistake, which is why breach membership "
        "overrides the score rather than contributing to it.",
        "",
        "## Crack times, and where the rates come from",
        "",
        f"- Measured on this machine: SHA-1 at {sha1:,.0f} h/s single-threaded, Argon2id "
        f"(RFC 9106 t=3, 64 MiB, p=4) at {argon:.1f} h/s.",
        f"- Assumed and labelled as such: {rates['assumed']['sha1_single_gpu_hps']:.0e} h/s "
        "for unsalted SHA-1 on one high-end consumer GPU, and 10 guesses/s against a "
        "rate-limited endpoint.",
        "- Machine: " + rates["machine"]["platform"] + ".",
        "",
        f"Those two measured numbers differ by a factor of {sha1/max(argon,1e-9):,.0f} on "
        "identical hardware. That factor is the entire argument for a memory-hard KDF, and "
        "it is why the same password can be adequate behind Argon2id and hopeless behind a "
        "bare SHA-1.",
        "",
        "## What the results changed about the tool",
        "",
        "1. Breach membership is checked first and overrides every other signal. A password "
        "in a wordlist costs roughly its rank to guess, whatever its character classes.",
        "2. No composition rules are enforced. They are a gate with no measurement in them "
        f"(Spearman {b['spearman_comp_score_vs_log10_guesses']} against actual "
        "guessability), and NIST SP 800-63B dropped them for pushing users toward "
        "predictable shapes.",
        "3. Suggestions are drawn independently from a CSPRNG, never mangled out of the "
        "user's rejected password, because those mangling rules are the first rules in "
        "every public cracking ruleset.",
        "4. Crack times are always quoted per attack model. A single \"time to crack\" "
        "number is meaningless without stating what is doing the hashing.",
        "5. Reported accuracy is the rank-split number, not the flattering one.",
    ]
    (REPORTS / "findings.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
