"""sklearn pipelines.

All four models see exactly the same input: one text column (whichever view is
under test) and the numeric URL/HTML/text features. Keeping the feature side
identical is what makes the model comparison and the leakage comparison
readable -- only one thing changes at a time.
"""
from __future__ import annotations

from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler, StandardScaler
from sklearn.svm import LinearSVC

from .config import SEED

# Default sklearn tokenisation (\b\w\w+\b) would shred exactly the tokens that
# matter for the leakage story: "x-keywords" becomes "keywords",
# "username@domain.com" becomes three tokens, "netnoteinc.com" becomes two.
# This pattern keeps dotted hostnames, hyphenated header names and addresses
# intact so the coefficient plots can name the real culprit.
TOKEN_PATTERN = r"(?u)[A-Za-z0-9][\w.\-@:/$]{1,60}"


def make_tfidf(max_features: int = 200_000) -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        token_pattern=TOKEN_PATTERN,
        ngram_range=(1, 2),
        min_df=3,          # a token seen twice in 9k messages is noise
        max_df=0.85,       # drop near-universal boilerplate
        sublinear_tf=True, # one word repeated 50x is not 50x the evidence
        max_features=max_features,
    )


def _linear_features(numeric_cols):
    return ColumnTransformer(
        [
            ("text", make_tfidf(), "text"),
            # StandardScaler on the numeric block only. TF-IDF rows are already
            # L2-normalised, so scaling the numerics puts both blocks on a
            # comparable footing for a regularised linear model.
            ("num", StandardScaler(), list(numeric_cols)),
        ],
        sparse_threshold=1.0,
    )


def _tree_features(numeric_cols):
    # A forest cannot cope with 200k sparse columns in reasonable time, so the
    # text block is reduced to the 2,000 most label-associated terms by chi2.
    # MaxAbsScaler instead of StandardScaler because chi2 and sparse storage
    # both need non-negative, uncentred input.
    return ColumnTransformer(
        [
            (
                "text",
                Pipeline([("tfidf", make_tfidf(50_000)),
                          ("select", SelectKBest(chi2, k=2000))]),
                "text",
            ),
            ("num", MaxAbsScaler(), list(numeric_cols)),
        ],
        sparse_threshold=1.0,
    )


def build(name: str, numeric_cols) -> Pipeline:
    if name == "logreg":
        clf = LogisticRegression(
            solver="liblinear", C=4.0, max_iter=2000,
            class_weight="balanced", random_state=SEED,
        )
        return Pipeline([("feat", _linear_features(numeric_cols)), ("clf", clf)])

    if name == "linear_svc_calibrated":
        # LinearSVC has no probabilities. Platt scaling on 3 inner folds gives
        # a calibrated score, which we need because the operating point is
        # chosen on a probability, not on a signed margin.
        base = LinearSVC(C=0.5, class_weight="balanced", random_state=SEED, max_iter=5000)
        clf = CalibratedClassifierCV(
            base, method="sigmoid",
            cv=StratifiedKFold(3, shuffle=True, random_state=SEED),
        )
        return Pipeline([("feat", _linear_features(numeric_cols)), ("clf", clf)])

    if name == "sgd_modified_huber":
        # modified_huber is the one SGD loss with a native predict_proba.
        clf = SGDClassifier(
            loss="modified_huber", penalty="l2", alpha=1e-5,
            max_iter=3000, tol=1e-4, class_weight="balanced",
            random_state=SEED,
        )
        return Pipeline([("feat", _linear_features(numeric_cols)), ("clf", clf)])

    if name == "random_forest":
        clf = RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced_subsample", n_jobs=-1, random_state=SEED,
        )
        return Pipeline([("feat", _tree_features(numeric_cols)), ("clf", clf)])

    raise ValueError(f"unknown model {name!r}")


MODEL_NAMES = ["logreg", "linear_svc_calibrated", "sgd_modified_huber", "random_forest"]


def build_ablation(kind: str, numeric_cols) -> Pipeline:
    """Same logistic regression, one half of the feature set removed, to see
    how much of the honest score comes from the TF-IDF text and how much from
    the hand-built URL/HTML features."""
    clf = LogisticRegression(
        solver="liblinear", C=4.0, max_iter=2000,
        class_weight="balanced", random_state=SEED,
    )
    if kind == "tfidf_only":
        feat = ColumnTransformer([("text", make_tfidf(), "text")], sparse_threshold=1.0)
    elif kind == "numeric_only":
        feat = ColumnTransformer([("num", StandardScaler(), list(numeric_cols))])
    else:
        raise ValueError(kind)
    return Pipeline([("feat", feat), ("clf", clf)])
