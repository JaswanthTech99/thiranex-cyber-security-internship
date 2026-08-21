"""Figure generation. Every figure is drawn from the same result dicts that
feed summary_stats.json, so a chart and the reported number cannot disagree.
"""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")  # no display on this machine; also keeps output stable

import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import precision_recall_curve, roc_curve

from .config import FIGURES

plt.rcParams.update({
    "figure.dpi": 130,
    "savefig.dpi": 130,
    "font.size": 9,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.autolayout": False,
})

C_LEAK = "#b3261e"
C_HONEST = "#1b6ca8"
C_MID = "#b8860b"
PALETTE = ["#1b6ca8", "#b3261e", "#2e7d32", "#6a1b9a", "#b8860b"]

VIEW_LABEL = {
    "full": "full email\n(headers + body)",
    "headers_scrubbed": "headers minus known\nartifact fields",
    "content": "subject + body",
    "content_hardened": "subject + body,\nbody artifacts removed",
}
VIEW_ORDER = ["full", "headers_scrubbed", "content", "content_hardened"]


def _save(fig, name):
    path = FIGURES / name
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  figure {path.name}")
    return str(path)


def leakage_comparison(grid: dict) -> str:
    views = VIEW_ORDER
    splits = ["random", "grouped"]
    fig, axes = plt.subplots(1, 3, figsize=(13.0, 3.9))
    metrics = [("roc_auc", "ROC-AUC"), ("accuracy", "Accuracy at chosen threshold"),
               ("recall", "Recall at FPR <= 0.5%")]
    x = np.arange(len(views))
    w = 0.36
    for ax, (key, title) in zip(axes, metrics):
        for k, split in enumerate(splits):
            vals = []
            for v in views:
                r = grid[f"{v}|{split}"]
                vals.append(r["prec_at_fpr_0.005"]["recall"] if key == "recall" else r[key])
            ax.bar(x + (k - 0.5) * w, vals, w,
                   label=f"{split} split",
                   color=(C_LEAK if split == "random" else C_HONEST))
            for xi, vv in zip(x + (k - 0.5) * w, vals):
                ax.text(xi, vv + 0.006, f"{vv:.3f}", ha="center", va="bottom", fontsize=6.5)
        ax.set_xticks(x)
        ax.set_xticklabels([VIEW_LABEL[v] for v in views], fontsize=7)
        lo = min(min(grid[f"{v}|{s}"]["prec_at_fpr_0.005"]["recall"]
                     if key == "recall" else grid[f"{v}|{s}"][key]
                     for v in views) for s in splits)
        ax.set_ylim(max(0.0, lo - 0.04), 1.03)
        ax.set_title(title, fontsize=9.5)
    axes[0].set_ylabel("score")
    axes[0].legend(fontsize=7.5, loc="lower left")
    fig.suptitle(
        "Same model, same data: what the text view and the split strategy are worth\n"
        "(logistic regression; left to right = progressively less leakage)",
        fontsize=10)
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    return _save(fig, "fig1_leakage_comparison.png")


def confusion_pair(leaky: dict, honest: dict, leaky_title: str, honest_title: str) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.6))
    for ax, res, title, colour in (
        (axes[0], leaky, leaky_title, C_LEAK),
        (axes[1], honest, honest_title, C_HONEST),
    ):
        cm = res["confusion_matrix"]
        m = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
        ax.imshow(m / m.sum(axis=1, keepdims=True), cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                frac = m[i, j] / m[i].sum()
                ax.text(j, i, f"{m[i, j]}\n{frac:.1%}", ha="center", va="center",
                        fontsize=10, color="white" if frac > 0.5 else "black")
        ax.set_xticks([0, 1], ["pred Safe", "pred Phishing"])
        ax.set_yticks([0, 1], ["true Safe", "true Phishing"])
        ax.set_title(f"{title}\nacc {res['accuracy']:.4f}  AUC {res['roc_auc']:.4f}",
                     fontsize=9, color=colour)
        ax.grid(False)
    fig.suptitle("Confusion matrices at the chosen operating point", fontsize=10.5)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    return _save(fig, "fig2_confusion_matrices.png")


def roc_pr(curves: "list[tuple[str, np.ndarray, np.ndarray, str]]") -> str:
    """curves: (label, y_true, scores, colour)."""
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 4.0))
    for label, y, s, colour in curves:
        fpr, tpr, _ = roc_curve(y, s)
        axes[0].plot(fpr, tpr, label=label, color=colour, lw=1.5)
        prec, rec, _ = precision_recall_curve(y, s)
        axes[1].plot(rec, prec, label=label, color=colour, lw=1.5)
    axes[0].plot([0, 1], [0, 1], "k--", lw=0.7, alpha=0.5)
    axes[0].set_xscale("symlog", linthresh=1e-3)
    axes[0].set_xlabel("false-positive rate (log scale)")
    axes[0].set_ylabel("true-positive rate")
    axes[0].set_title("ROC. Log x-axis because the only\npart of this curve we can ship is the left edge",
                      fontsize=9)
    axes[0].set_ylim(0, 1.02)
    axes[0].axvline(0.005, color=C_MID, ls=":", lw=1.2)
    axes[0].text(0.0055, 0.06, "FPR budget 0.5%", fontsize=7, color=C_MID, rotation=90)
    axes[1].set_xlabel("recall")
    axes[1].set_ylabel("precision")
    axes[1].set_title("Precision-recall", fontsize=9)
    axes[1].set_ylim(0, 1.02)
    axes[0].legend(fontsize=7.5, loc="lower right")
    fig.tight_layout()
    return _save(fig, "fig3_roc_pr.png")


def top_features(panels: "list[tuple[str, list[tuple[str, float, int]]]]", fname: str,
                 suptitle: str) -> str:
    fig, axes = plt.subplots(1, len(panels), figsize=(4.9 * len(panels), 5.4))
    if len(panels) == 1:
        axes = [axes]
    for ax, (title, feats) in zip(axes, panels):
        feats = feats[::-1]
        names = [f"{f[0]}  ({f[2]})" if len(f) > 2 else f[0] for f in feats]
        vals = [f[1] for f in feats]
        colours = [C_LEAK if v > 0 else C_HONEST for v in vals]
        ax.barh(np.arange(len(vals)), vals, color=colours)
        ax.set_yticks(np.arange(len(vals)))
        ax.set_yticklabels(names, fontsize=7, family="monospace")
        ax.axvline(0, color="black", lw=0.8)
        ax.set_title(title, fontsize=9)
        ax.set_xlabel("logistic-regression coefficient")
    fig.suptitle(suptitle, fontsize=10.5)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    return _save(fig, fname)


def numeric_importance(pairs: "list[tuple[str, float]]", title: str) -> str:
    pairs = pairs[::-1]
    fig, ax = plt.subplots(figsize=(6.4, 6.4))
    ax.barh(np.arange(len(pairs)), [p[1] for p in pairs], color=C_HONEST)
    ax.set_yticks(np.arange(len(pairs)))
    ax.set_yticklabels([p[0] for p in pairs], fontsize=7.5, family="monospace")
    ax.set_xlabel("mean decrease in impurity (random forest)")
    ax.set_title(title, fontsize=9.5)
    fig.tight_layout()
    return _save(fig, "fig5_numeric_feature_importance.png")


def duplicate_clusters(recs, groups, dup_stats: dict) -> str:
    from collections import Counter
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.8))
    for lab, name, colour in ((0, "legitimate (ham)", C_HONEST), (1, "phishing", C_LEAK)):
        sizes = Counter()
        for r, g in zip(recs, groups):
            if r["label"] == lab:
                sizes[g] += 1
        counts = Counter(sizes.values())
        xs = sorted(counts)
        axes[0].plot(xs, [counts[x] for x in xs], "o-", ms=3.5, lw=1.2,
                     color=colour, label=name)
    axes[0].set_xscale("log")
    axes[0].set_yscale("log")
    axes[0].set_xlabel("near-duplicate cluster size (messages)")
    axes[0].set_ylabel("number of clusters")
    axes[0].set_title("Cluster-size distribution", fontsize=9.5)
    axes[0].legend(fontsize=8)

    names = ["legitimate\n(ham)", "phishing"]
    vals = [dup_stats["ham_pct_in_multi_member_groups"],
            dup_stats["phish_pct_in_multi_member_groups"]]
    axes[1].bar(names, vals, color=[C_HONEST, C_LEAK], width=0.5)
    for i, v in enumerate(vals):
        axes[1].text(i, v + 1, f"{v:.1f}%", ha="center", fontsize=9)
    axes[1].set_ylim(0, 100)
    axes[1].set_ylabel("% of messages sharing a cluster")
    axes[1].set_title(
        f"Duplication is one-sided:\n{dup_stats['phish_n_records']} phishing messages "
        f"are {dup_stats['phish_n_groups']} campaigns", fontsize=9.5)
    fig.tight_layout()
    return _save(fig, "fig6_duplicate_clusters.png")


def model_comparison(comp: dict) -> str:
    names = list(comp)
    fig, axes = plt.subplots(1, 3, figsize=(11.0, 3.6))
    for ax, (key, title) in zip(axes, [("roc_auc", "ROC-AUC"),
                                      ("average_precision", "Average precision"),
                                      ("recall", "Recall at FPR <= 0.5%")]):
        vals = [(comp[n]["prec_at_fpr_0.005"]["recall"] if key == "recall" else comp[n][key])
                for n in names]
        ax.bar(np.arange(len(names)), vals, color=PALETTE[:len(names)], width=0.6)
        for i, v in enumerate(vals):
            ax.text(i, v + 0.004, f"{v:.4f}", ha="center", fontsize=7.5)
        ax.set_xticks(np.arange(len(names)))
        ax.set_xticklabels([n.replace("_", "\n") for n in names], fontsize=7.5)
        ax.set_ylim(min(vals) - 0.05, min(1.02, max(vals) + 0.03))
        ax.set_title(title, fontsize=9.5)
    fig.suptitle("Model comparison on the honest configuration "
                 "(subject + body only, grouped split)", fontsize=10.5)
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    return _save(fig, "fig4_model_comparison.png")
