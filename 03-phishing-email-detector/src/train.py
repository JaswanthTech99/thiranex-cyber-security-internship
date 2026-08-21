"""The whole experiment.

Run: python -m src.train

Order of business:
  1. dataset description and class balance
  2. a model-free demonstration that the headers give the label away
  3. the leakage grid: 3 text views x 2 split strategies, one model
  4. model comparison and feature ablation on the honest configuration
  5. the held-out generic-spam probe
  6. figures, findings.md, summary_stats.json
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import (
    StratifiedGroupKFold,
    StratifiedKFold,
    cross_val_predict,
)

from . import plots
from .config import (
    CV_FOLDS,
    DATA_PROCESSED,
    REPORTS,
    SEED,
    TARGET_FPR,
)
from .dedupe import load_groups
from .evaluate import metrics, scores_of, threshold_for_fpr
from .features import VIEWS, featurise
from .models import MODEL_NAMES, build, build_ablation
from .parse import load

HEADLINE_VIEW = "content_hardened"
HEADLINE_SPLIT = "grouped"
VIEW_ORDER = ["full", "headers_scrubbed", "content", "content_hardened"]
LEAKY_KEY = "full|random"
SCRUB_KEY = "headers_scrubbed|random"
DEFAULT_KEY = "at_default_0.5"
YEAR_RE = re.compile(r"\b(19\d\d|20[0-2]\d)\b")
# Minimum training-document frequency for a token to appear in the reported
# coefficient lists. Without it the ranking is dominated by tokens occurring in
# three messages, which is an overfitting artifact, not a finding.
MIN_DF_FOR_REPORT = 30


# --------------------------------------------------------------------- data
def build_frames(recs):
    feats = [featurise(r) for r in recs]
    numeric_cols = sorted(feats[0])
    X = pd.DataFrame(feats, columns=numeric_cols).astype("float64")
    X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    X.insert(0, "text", "")
    y = np.array([r["label"] for r in recs], dtype=int)
    views = {name: [fn(r) for r in recs] for name, fn in VIEWS.items()}
    return X, y, numeric_cols, views


def format_confound(recs, y):
    """How cleanly does "does this message have an HTML part" separate the two
    corpora? This turned out to be the single biggest residual confound, so it
    gets counted explicitly rather than left implicit in a coefficient."""
    by_src = defaultdict(lambda: [0, 0])
    for r in recs:
        src = r["source_file"].split("/")[0]
        by_src[src][0] += 1
        by_src[src][1] += int(bool(r["body_html"].strip()))
    html = np.array([bool(r["body_html"].strip()) for r in recs])
    return {
        "pct_phishing_with_html_part": round(100.0 * float(html[y == 1].mean()), 2),
        "pct_legitimate_with_html_part": round(100.0 * float(html[y == 0].mean()), 2),
        "n_html_phishing": int(html[y == 1].sum()),
        "n_html_legitimate": int(html[y == 0].sum()),
        "n_plaintext_phishing": int((~html[y == 1]).sum()),
        "n_plaintext_legitimate": int((~html[y == 0]).sum()),
        "by_source": {k: {"n": v[0], "n_html": v[1],
                          "pct_html": round(100.0 * v[1] / v[0], 2)}
                      for k, v in sorted(by_src.items())},
        "accuracy_of_has_html_as_a_single_rule": round(
            float(((html == (y == 1)).mean())), 4),
    }


def body_artifact_prevalence(recs, y):
    """Named body-level collection tells, counted. These are what motivated the
    content_hardened view."""
    pats = {
        "body starts with RSS 'URL:/Date:' digest prefix": r"(?im)\A\s*URL:\s*\S+\s*$",
        "body names its own mailing list": r"(?i)\b(exmh|ilug|zzzzteana|razor-users|spamassassin|spambayes)\b",
        "body contains a listinfo/mailman URL": r"(?i)lists?\.[\w.-]+/(?:mailman/)?listinfo",
        "body contains 'sourceforge'": r"(?i)sourceforge",
        "body contains the year 2002": r"\b2002\b",
        "body contains the year 2005, 2006 or 2007": r"\b200[567]\b",
        "body contains an email address": r"[\w.+-]+@[\w-]+\.[\w.-]+",
    }
    out = {}
    for label, pat in pats.items():
        rx = re.compile(pat)
        a = sum(1 for r, l in zip(recs, y) if l == 0 and rx.search(r["body_text"]))
        b = sum(1 for r, l in zip(recs, y) if l == 1 and rx.search(r["body_text"]))
        out[label] = {
            "legitimate_pct": round(100.0 * a / int((y == 0).sum()), 2),
            "phishing_pct": round(100.0 * b / int(y.sum()), 2),
            "legitimate_n": a, "phishing_n": b,
        }
    return out


def dataset_stats(recs, y, views, numeric_cols, X):
    years = defaultdict(Counter)
    for r in recs:
        m = YEAR_RE.search(r["date_raw"])
        years["phish" if r["label"] else "ham"][m.group(1) if m else "unparsed"] += 1
    empty_content = {
        "phish": sum(1 for r, t in zip(recs, views["content"])
                     if r["label"] == 1 and len(t.strip()) <= len("SUBJECT:")),
        "ham": sum(1 for r, t in zip(recs, views["content"])
                   if r["label"] == 0 and len(t.strip()) <= len("SUBJECT:")),
    }
    per_source = Counter(r["source_file"].split("/")[0] for r in recs)
    rates = {}
    for col in ("has_ip_url", "has_at_in_url", "has_punycode", "has_shortener",
                "n_forms", "has_javascript_uri", "anchor_host_mismatch",
                "has_html", "brand_host_abuse", "has_obfuscated_ip",
                "has_risky_path_ext", "has_nonstd_port"):
        v = X[col].to_numpy()
        rates[col] = {
            "phish_pct_nonzero": round(100.0 * float((v[y == 1] > 0).mean()), 2),
            "ham_pct_nonzero": round(100.0 * float((v[y == 0] > 0).mean()), 2),
        }
    return {
        "n_messages": int(len(recs)),
        "n_phishing": int(y.sum()),
        "n_legitimate": int((y == 0).sum()),
        "phishing_share": round(float(y.mean()), 4),
        "n_numeric_features": len(numeric_cols),
        "numeric_features": numeric_cols,
        "messages_per_source": dict(sorted(per_source.items())),
        "year_distribution": {k: dict(sorted(v.items())) for k, v in years.items()},
        "messages_with_no_usable_content": empty_content,
        "feature_prevalence": rates,
        "format_confound": format_confound(recs, y),
        "body_artifact_prevalence": body_artifact_prevalence(recs, y),
    }


# ------------------------------------------------- model-free leakage check
def header_leakage(recs, y):
    """No model, no training. Just: which header names appear on one class and
    not the other, and how far does a single one of them get you?"""
    pres = defaultdict(lambda: [0, 0])
    for r in recs:
        for h in r["header_names"]:
            pres[h][r["label"]] += 1
    n_ham, n_ph = int((y == 0).sum()), int(y.sum())
    rows = []
    for h, (c0, c1) in pres.items():
        if c0 + c1 < 50:
            continue
        p0, p1 = c0 / n_ham, c1 / n_ph
        # "Header present => phishing" and its complement; take whichever
        # direction is the better rule and score it as a classifier.
        acc_pos = (c1 + (n_ham - c0)) / (n_ham + n_ph)
        acc_neg = (c0 + (n_ph - c1)) / (n_ham + n_ph)
        rows.append({
            "header": h,
            "pct_of_phishing": round(100 * p1, 2),
            "pct_of_ham": round(100 * p0, 2),
            "abs_diff_pct": round(100 * abs(p1 - p0), 2),
            "best_single_rule_accuracy": round(max(acc_pos, acc_neg), 4),
            "rule_direction": "present=>phishing" if acc_pos >= acc_neg else "absent=>phishing",
        })
    rows.sort(key=lambda d: -d["abs_diff_pct"])
    return rows[:15]


# ----------------------------------------------------------------- splits
def make_split(y, groups, kind):
    """One 25% test fold, either group-aware or not.

    Both branches use a 4-fold stratified splitter and take fold 0, so the two
    strategies differ in exactly one respect -- whether a near-duplicate
    cluster is allowed to span the boundary -- and nothing else."""
    if kind == "random":
        cv = StratifiedKFold(n_splits=4, shuffle=True, random_state=SEED)
        tr, te = next(iter(cv.split(np.zeros(len(y)), y)))
    elif kind == "grouped":
        cv = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=SEED)
        tr, te = next(iter(cv.split(np.zeros(len(y)), y, groups=groups)))
    else:
        raise ValueError(kind)
    return np.sort(tr), np.sort(te)


def inner_cv(kind):
    if kind == "random":
        return StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=SEED)
    return StratifiedGroupKFold(n_splits=CV_FOLDS, shuffle=True, random_state=SEED)


def split_leakage_stats(y, groups, tr, te):
    """How many test messages have a near-duplicate sitting in train? This is
    the number that explains the whole random-vs-grouped gap."""
    tr_groups = set(groups[tr])
    contaminated = [i for i in te if groups[i] in tr_groups]
    return {
        "n_train": int(len(tr)),
        "n_test": int(len(te)),
        "test_phish_share": round(float(y[te].mean()), 4),
        "test_messages_with_a_near_duplicate_in_train": int(len(contaminated)),
        "pct_test_contaminated": round(100.0 * len(contaminated) / len(te), 2),
        "pct_test_phish_contaminated": round(
            100.0 * sum(1 for i in contaminated if y[i] == 1) / max(int(y[te].sum()), 1), 2),
        "pct_test_ham_contaminated": round(
            100.0 * sum(1 for i in contaminated if y[i] == 0) / max(int((y[te] == 0).sum()), 1), 2),
    }


# ------------------------------------------------------------------- fitting
def fit_and_score(pipe, X, y, groups, tr, te, split_kind, keep_scores=False):
    """Fit on train, pick the threshold from out-of-fold training scores only,
    then score the test fold once."""
    Xtr, Xte = X.iloc[tr], X.iloc[te]
    cv = inner_cv(split_kind)
    kw = {"groups": groups[tr]} if split_kind == "grouped" else {}
    oof = cross_val_predict(pipe, Xtr, y[tr], cv=cv, method="predict_proba", **kw)[:, 1]
    thr = threshold_for_fpr(y[tr], oof, TARGET_FPR)
    pipe.fit(Xtr, y[tr])
    s = scores_of(pipe, Xte)
    res = metrics(y[te], s, thr)
    res["oof_threshold_source"] = {
        "target_fpr": TARGET_FPR,
        "chosen_threshold": round(float(thr), 6),
        "oof_fpr_at_threshold": round(
            float(((oof >= thr) & (y[tr] == 0)).sum() / max(int((y[tr] == 0).sum()), 1)), 6),
        "oof_recall_at_threshold": round(
            float(((oof >= thr) & (y[tr] == 1)).sum() / max(int(y[tr].sum()), 1)), 6),
    }
    res["at_default_0.5"] = metrics(y[te], s, 0.5)
    del res["at_default_0.5"]["prec_at_fpr_0.005"]
    del res["at_default_0.5"]["prec_at_fpr_0.001"]
    if keep_scores:
        res["_scores"] = s
    return res, pipe


def top_coefs(pipe, Xtr, k=22, min_df=MIN_DF_FOR_REPORT):
    """Largest coefficients, restricted to features that actually occur.

    The first run of this taught me something about reading coefficient tables:
    the raw top-20 was full of tokens appearing in three training messages
    ("beetapiale", "c2report", "evil gerald"). A linear model with min_df=3
    will happily assign a huge weight to a token it saw three times, and that
    tells you about regularisation, not about the corpus. Restricting the
    report to tokens with >= min_df training documents gives a list that
    describes the data rather than the fit. Both lists are returned so the
    difference is visible."""
    ct = pipe.named_steps["feat"]
    names = ct.get_feature_names_out()
    coef = np.asarray(pipe.named_steps["clf"].coef_).ravel()

    Xt = ct.transform(Xtr)
    df = np.asarray((Xt != 0).sum(axis=0)).ravel() if hasattr(Xt, "nnz") else \
        (Xt != 0).sum(axis=0)

    def pretty(n):
        return "[engineered] " + n[5:] if n.startswith("num__") else n.split("__", 1)[-1]

    def rank(mask, sign):
        idx = np.flatnonzero(mask)
        idx = idx[np.argsort(sign * coef[idx])][:k]
        return [(pretty(names[i]), round(float(coef[i]), 4), int(df[i])) for i in idx]

    common = df >= min_df
    return {
        "pushes_toward_phishing": rank(common, -1),
        "pushes_toward_safe": rank(common, +1),
        "pushes_toward_phishing_unfiltered": rank(np.ones(len(coef), bool), -1),
        "min_train_document_frequency": min_df,
        "n_features_total": int(len(coef)),
        "n_features_above_min_df": int(common.sum()),
    }


def subset_control(name, mask, X, y, groups, numeric_cols, description):
    """Re-run the honest configuration on a subset of the corpus.

    The format confound (4.5% of ham is HTML against 93.4% of phishing) cannot
    be removed by editing text, because it is a property of the messages. The
    only clean way to measure it is to hold format constant and see what is
    left."""
    idx = np.flatnonzero(mask)
    Xs, ys, gs = X.iloc[idx].reset_index(drop=True), y[idx], groups[idx]
    if min(int((ys == 0).sum()), int(ys.sum())) < 60:
        return {"skipped": "too few messages in one class", "n": int(len(idx))}
    tr, te = make_split(ys, gs, HEADLINE_SPLIT)
    res, _ = fit_and_score(build("logreg", numeric_cols), Xs, ys, gs, tr, te,
                           HEADLINE_SPLIT)
    res["subset"] = name
    res["description"] = description
    res["n_messages"] = int(len(idx))
    res["n_phishing"] = int(ys.sum())
    res["n_legitimate"] = int((ys == 0).sum())
    return res


def fp_by_source(recs, y, te, scores, threshold):
    """Which legitimate messages does the model get wrong? Broken down by ham
    archive, because hard_ham is deliberately the HTML/commercial mail that
    looks most like an attack."""
    out = defaultdict(lambda: [0, 0])
    for pos, i in enumerate(te):
        if y[i] != 0:
            continue
        src = recs[i]["source_file"].split("/")[0]
        out[src][0] += 1
        out[src][1] += int(scores[pos] >= threshold)
    return {k: {"n_legitimate_in_test": v[0], "false_positives": v[1],
                "fpr": round(v[1] / v[0], 4) if v[0] else 0.0}
            for k, v in sorted(out.items())}


def rf_numeric_importance(pipe, k=22):
    names = pipe.named_steps["feat"].get_feature_names_out()
    imp = pipe.named_steps["clf"].feature_importances_
    num = [(n[5:], float(v)) for n, v in zip(names, imp) if n.startswith("num__")]
    txt_share = float(sum(v for n, v in zip(names, imp) if not n.startswith("num__")))
    num.sort(key=lambda t: -t[1])
    return [(n, round(v, 6)) for n, v in num[:k]], round(txt_share, 4), round(1 - txt_share, 4)


# ------------------------------------------------------------------- main
def main() -> int:
    t0 = time.time()
    recs = load()
    gmap = load_groups()
    groups = np.array([gmap[r["id"]] for r in recs], dtype=int)

    print("featurising...")
    X, y, numeric_cols, views = build_frames(recs)
    out = {"meta": {
        "seed": SEED,
        "python": sys.version.split()[0],
        "sklearn": sklearn.__version__,
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "headline_configuration": f"{HEADLINE_VIEW} view, {HEADLINE_SPLIT} split",
    }}

    out["dataset"] = dataset_stats(recs, y, views, numeric_cols, X)
    print(f"  {out['dataset']['n_messages']} messages, "
          f"{out['dataset']['n_phishing']} phishing / {out['dataset']['n_legitimate']} ham, "
          f"{len(numeric_cols)} engineered features")

    # Persist the engineered features so the table is inspectable without
    # re-running the regex pass.
    feat_out = X.drop(columns=["text"]).copy()
    feat_out.insert(0, "label", y)
    feat_out.insert(0, "group_id", groups)
    feat_out.insert(0, "id", [r["id"] for r in recs])
    feat_out.to_csv(DATA_PROCESSED / "features.csv.gz", index=False,
                    compression={"method": "gzip", "mtime": 0})

    out["header_leakage_no_model"] = header_leakage(recs, y)
    best_rule = out["header_leakage_no_model"][0]
    print(f"  single-header rule '{best_rule['header']}' alone: "
          f"{best_rule['best_single_rule_accuracy']:.4f} accuracy")

    splits = {k: make_split(y, groups, k) for k in ("random", "grouped")}
    out["splits"] = {k: split_leakage_stats(y, groups, *v) for k, v in splits.items()}

    # ---- 3. leakage grid --------------------------------------------------
    grid, fitted = {}, {}
    for view in VIEW_ORDER:
        X["text"] = views[view]
        for split_kind, (tr, te) in splits.items():
            key = f"{view}|{split_kind}"
            t = time.time()
            res, pipe = fit_and_score(build("logreg", numeric_cols), X, y, groups,
                                      tr, te, split_kind, keep_scores=True)
            fitted[key] = (pipe, res.pop("_scores"), te, tr, view)
            grid[key] = res
            print(f"  {key:32s} AUC {res['roc_auc']:.4f}  acc {res['accuracy']:.4f}  "
                  f"({time.time() - t:.1f}s)", flush=True)
    out["leakage_grid"] = grid

    for key in (LEAKY_KEY, SCRUB_KEY, "content|grouped",
                f"{HEADLINE_VIEW}|{HEADLINE_SPLIT}"):
        pipe, _, _, tr_idx, view = fitted[key]
        X["text"] = views[view]
        out.setdefault("top_coefficients", {})[key] = top_coefs(pipe, X.iloc[tr_idx])

    # ---- 4. model comparison + ablations on the honest configuration ------
    X["text"] = views[HEADLINE_VIEW]
    tr, te = splits[HEADLINE_SPLIT]
    comparison, comp_scores, rf_pipe = {}, {}, None
    for name in MODEL_NAMES:
        t = time.time()
        res, pipe = fit_and_score(build(name, numeric_cols), X, y, groups, tr, te,
                                  HEADLINE_SPLIT, keep_scores=True)
        comp_scores[name] = res.pop("_scores")
        comparison[name] = res
        if name == "random_forest":
            rf_pipe = pipe
        print(f"  {name:26s} AUC {res['roc_auc']:.4f}  acc {res['accuracy']:.4f}  "
              f"recall@0.5%FPR {res['prec_at_fpr_0.005']['recall']:.4f}  "
              f"({time.time() - t:.1f}s)", flush=True)
    out["model_comparison"] = comparison

    abl = {}
    for kind in ("tfidf_only", "numeric_only"):
        res, _ = fit_and_score(build_ablation(kind, numeric_cols), X, y, groups,
                               tr, te, HEADLINE_SPLIT)
        abl[kind] = res
        print(f"  ablation {kind:16s} AUC {res['roc_auc']:.4f}  "
              f"acc {res['accuracy']:.4f}", flush=True)
    abl["both"] = comparison["logreg"]
    out["ablations"] = abl

    # ---- format-confound controls ----------------------------------------
    has_html = np.array([bool(r["body_html"].strip()) for r in recs])
    out["format_controls"] = {
        "plaintext_only": subset_control(
            "plaintext_only", ~has_html, X, y, groups, numeric_cols,
            "messages with no HTML part on either side, so 'is it HTML' "
            "carries no information"),
        "html_only": subset_control(
            "html_only", has_html, X, y, groups, numeric_cols,
            "messages with an HTML part on either side"),
    }
    for k, v in out["format_controls"].items():
        if "roc_auc" in v:
            print(f"  control {k:16s} n={v['n_messages']:5d} "
                  f"({v['n_legitimate']} ham / {v['n_phishing']} phish)  "
                  f"AUC {v['roc_auc']:.4f}  acc {v['accuracy']:.4f}", flush=True)

    num_imp, txt_share, num_share = rf_numeric_importance(rf_pipe)
    out["random_forest_importance"] = {
        "top_engineered_features": num_imp,
        "total_importance_text_block": txt_share,
        "total_importance_engineered_block": num_share,
    }

    # Headline model: best recall at the FPR budget, AUC as tie-break.
    best = max(MODEL_NAMES,
               key=lambda n: (comparison[n]["prec_at_fpr_0.005"]["recall"],
                              comparison[n]["roc_auc"]))
    out["headline"] = {
        "configuration": (f"{HEADLINE_VIEW} view (subject + body, body-level "
                          f"collection artifacts removed), {HEADLINE_SPLIT} split"),
        "model": best,
        "why_this_one": ("highest recall at the 0.5% false-positive budget among the "
                         "four candidates, on the configuration with no header "
                         "leakage, no near-duplicate leakage and the named "
                         "body-level artifacts removed"),
        "metrics": comparison[best],
        "false_positives_by_ham_source": fp_by_source(
            recs, y, te, comp_scores[best], comparison[best]["threshold"]),
        "leaky_counterpart_for_contrast": grid[LEAKY_KEY],
    }
    print(f"\nHEADLINE  model={best}  acc={comparison[best]['accuracy']:.4f}  "
          f"AUC={comparison[best]['roc_auc']:.4f}")
    print(f"LEAKY     full headers + random split  "
          f"acc={grid[LEAKY_KEY]['accuracy']:.4f}  "
          f"AUC={grid[LEAKY_KEY]['roc_auc']:.4f}", flush=True)

    # ---- 5. generic-spam probe -------------------------------------------
    out["spam_probe"] = spam_probe(numeric_cols, X, y, groups, tr, best)

    # ---- 6. figures -------------------------------------------------------
    print("figures:")
    figs = [
        plots.leakage_comparison(grid),
        plots.confusion_pair(
            grid[LEAKY_KEY], comparison[best],
            "LEAKY: full headers, random split",
            "HONEST: hardened content, grouped split"),
        plots.roc_pr([
            ("full headers + random split", y[fitted[LEAKY_KEY][2]],
             fitted[LEAKY_KEY][1], plots.C_LEAK),
            ("scrubbed headers + random split", y[fitted[SCRUB_KEY][2]],
             fitted[SCRUB_KEY][1], plots.C_MID),
        ] + [
            (f"{n} (hardened content, grouped)", y[te], comp_scores[n], c)
            for n, c in zip(MODEL_NAMES, plots.PALETTE)
        ]),
        plots.model_comparison(comparison),
        plots.numeric_importance(
            num_imp, "Engineered URL/HTML/text features that the forest actually used\n"
                     f"(they hold {num_share:.1%} of total importance; TF-IDF terms hold the rest)"),
        plots.duplicate_clusters(recs, groups, dup_stats()),
    ]
    tc = out["top_coefficients"]
    figs.append(plots.top_features(
        [("full email, headers included", tc[LEAKY_KEY]["pushes_toward_phishing"]),
         ("subject + body", tc["content|grouped"]["pushes_toward_phishing"]),
         ("subject + body, hardened",
          tc[f"{HEADLINE_VIEW}|{HEADLINE_SPLIT}"]["pushes_toward_phishing"])],
        "fig7_top_tokens.png",
        "What pushes a message toward \"phishing\" in each view "
        f"(tokens in >= {MIN_DF_FOR_REPORT} training messages; "
        "the number after each token is its training document frequency)"))
    out["figures"] = [f.replace("\\", "/").split("/outputs/")[-1] for f in figs]
    out["duplicates"] = dup_stats()

    path = REPORTS / "summary_stats.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path}")

    from .report import write_findings
    write_findings(out)
    print(f"total {time.time() - t0:.1f}s")
    return 0


def dup_stats():
    """Recompute the clustering statistics from groups.csv rather than
    re-running MinHash."""
    import csv
    rows = list(csv.DictReader(open(DATA_PROCESSED / "groups.csv", encoding="utf-8")))
    sizes = Counter(r["group_id"] for r in rows)
    per_label = {0: Counter(), 1: Counter()}
    for r in rows:
        per_label[int(r["label"])][r["group_id"]] += 1
    s = {
        "n_records": len(rows),
        "n_groups": len(sizes),
        "largest_group_size": max(sizes.values()),
        "top10_group_sizes": sorted(sizes.values(), reverse=True)[:10],
        "pct_records_in_multi_member_groups": round(
            100 * sum(v for v in sizes.values() if v > 1) / len(rows), 2),
    }
    for lab, name in ((0, "ham"), (1, "phish")):
        c = per_label[lab]
        n = sum(c.values())
        s[f"{name}_n_records"] = n
        s[f"{name}_n_groups"] = len(c)
        s[f"{name}_largest_group"] = max(c.values())
        s[f"{name}_pct_in_multi_member_groups"] = round(
            100 * sum(v for v in c.values() if v > 1) / n, 2)
    return s


def spam_probe(numeric_cols, X, y, groups, tr, model_name):
    """Score 1,897 SpamAssassin spam messages -- never seen in training, and
    not phishing -- with the honest model.

    The question: did we build a phishing detector or a spam detector? If
    almost every generic spam trips the threshold, the model has learned
    "unsolicited bulk mail", which is a different and easier problem than the
    one the brief asks for."""
    probe = load(DATA_PROCESSED / "spam_probe.jsonl.gz")
    Xp, _, _, vp = build_frames(probe)
    Xp = Xp[X.columns]
    Xp["text"] = vp[HEADLINE_VIEW]

    pipe = build(model_name, numeric_cols)
    pipe.fit(X.iloc[tr], y[tr])
    thr = None
    cv = inner_cv(HEADLINE_SPLIT)
    oof = cross_val_predict(build(model_name, numeric_cols), X.iloc[tr], y[tr],
                            cv=cv, groups=groups[tr], method="predict_proba")[:, 1]
    thr = threshold_for_fpr(y[tr], oof, TARGET_FPR)
    s = scores_of(pipe, Xp)
    flagged = int((s >= thr).sum())
    return {
        "n_generic_spam": len(probe),
        "threshold_used": round(float(thr), 6),
        "flagged_as_phishing": flagged,
        "flagged_pct": round(100.0 * flagged / len(probe), 2),
        "median_score": round(float(np.median(s)), 6),
        "interpretation_note": (
            "These are 1,897 SpamAssassin spam messages: unsolicited bulk mail, "
            "not credential phishing. They were never in the training set. A high "
            "flag rate would mean the model learned 'spam' rather than 'phishing'."),
    }


if __name__ == "__main__":
    sys.exit(main())
