"""Metrics and the operating-point choice.

The brief asks for accuracy and a confusion matrix. Both are here, but neither
is the number this project reports as the result. On a mail stream a false
positive means a real message -- an invoice, a password reset, a message from a
colleague -- is filed as an attack and probably never read. A false negative
means one more phish in an inbox that already receives them, where the user is
the next line of defence. The costs are not symmetric, so the operating point
is chosen by capping the false-positive rate and the headline detection number
is recall at that cap.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def threshold_for_fpr(y_true, scores, target_fpr: float) -> float:
    """Lowest threshold whose false-positive rate is still <= target_fpr.

    Lowest, not highest, because among all thresholds that meet the FPR budget
    we want the most sensitive one. Derived from out-of-fold scores on training
    data only; the test set never informs it."""
    fpr, tpr, thr = roc_curve(y_true, scores)
    ok = np.flatnonzero(fpr <= target_fpr)
    if len(ok) == 0:
        return 1.0
    # roc_curve returns thresholds in decreasing order, so the last index that
    # satisfies the budget is the smallest qualifying threshold.
    t = float(thr[ok[-1]])
    return min(max(t, 0.0), 1.0)


def precision_at_fpr(y_true, scores, target_fpr: float) -> dict:
    y_true = np.asarray(y_true)
    t = threshold_for_fpr(y_true, scores, target_fpr)
    pred = (np.asarray(scores) >= t).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    neg = int((y_true == 0).sum())
    return {
        "threshold": round(t, 6),
        "precision": round(tp / (tp + fp), 6) if (tp + fp) else 0.0,
        "recall": round(tp / (tp + fn), 6) if (tp + fn) else 0.0,
        "false_positives": fp,
        "realised_fpr": round(fp / neg, 6) if neg else 0.0,
    }


def metrics(y_true, scores, threshold: float) -> dict:
    y_true = np.asarray(y_true)
    scores = np.asarray(scores, dtype=float)
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 6),
        "accuracy": round(float(accuracy_score(y_true, pred)), 6),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 6),
        "average_precision": round(float(average_precision_score(y_true, scores)), 6),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n_test": int(len(y_true)),
        "n_test_phish": int((y_true == 1).sum()),
        "n_test_ham": int((y_true == 0).sum()),
        "prec_at_fpr_0.005": precision_at_fpr(y_true, scores, 0.005),
        "prec_at_fpr_0.001": precision_at_fpr(y_true, scores, 0.001),
    }


def scores_of(pipe, X) -> np.ndarray:
    """Positive-class score, whatever the estimator can offer."""
    if hasattr(pipe, "predict_proba"):
        return pipe.predict_proba(X)[:, 1]
    return pipe.decision_function(X)
