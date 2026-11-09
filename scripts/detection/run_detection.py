#!/usr/bin/env python3
"""
run_detection.py — SecLogTrace Phase 3 (Paper B detection study)

Per-class binary detection (normal vs. attack) on the FROZEN corpus, across
three modality arms — trace-only, log-only, combined — with three detectors:
  rule    : shallow decision tree (max_depth=3), the interpretable rule baseline
  iforest : Isolation Forest, unsupervised (fit on NORMAL only)
  rf      : random forest, the supervised classifier
This answers RQ1 (detectability), RQ2 (which arm), RQ3 (per-class signal locus).
The deep baseline (DeepTraLog-style) is a separate, larger task, not here.

Method notes (kept honest, matching the project's standing rules):
  - One feature row per trace, so a stratified k-fold split never puts the
    same trace in train and test (the "grouped split" the paper requires is
    satisfied by construction).
  - Trace and log features are joined per request on trace_id (left join onto
    the labelled traces; traces with no log line get zero-filled log features).
  - Metrics are precision/recall/F1 for the ATTACK class, averaged over folds.
  - Resource-exhaustion is expected to be near-undetectable in the trace arm
    (identical per-trace structure) — that is a finding, not a bug.

Usage:
    python3 scripts/detection/run_detection.py \
        --combined-dir data/processed/combined \
        --logs-dir data/processed/logs \
        --out results/tables/detection_results.csv
"""

import argparse
import os
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import (IsolationForest, RandomForestClassifier,
                              HistGradientBoostingClassifier)
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_recall_fscore_support

warnings.filterwarnings("ignore")
RANDOM_STATE = 42
N_FOLDS = 5

CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion",
           "injection", "data_exfiltration"]

# non-feature trace columns to drop; the rest (numeric) are the trace arm
DROP = {"trace_id", "path_signature", "root_service", "root_operation",
        "label", "infra_noise", "experiment_id"}
LOG_FEATURES = ["log_line_count", "error_count", "warn_count", "log_service_count"]


def load_class(cls, combined_dir, logs_dir):
    """Return X_trace, X_log, y for one class (normal=0, attack=1)."""
    frames = []
    for label, y in (("normal", 0), ("attack", 1)):
        f = os.path.join(combined_dir, f"{cls}_{label}_features.csv")
        df = pd.read_csv(f)
        # join per-trace log features (superset; left join keeps labelled traces)
        lf = os.path.join(logs_dir, f"{cls}_{label}", "logs_by_trace.csv")
        logs = pd.read_csv(lf)[["trace_id", "log_line_count", "error_count",
                                "warn_count", "service_count"]]
        logs = logs.rename(columns={"service_count": "log_service_count"})
        logs = logs.drop_duplicates("trace_id")
        df = df.merge(logs, on="trace_id", how="left")
        df[LOG_FEATURES] = df[LOG_FEATURES].fillna(0)
        df["_y"] = y
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    y = data["_y"].to_numpy()
    trace_cols = [c for c in data.columns
                  if c not in DROP and c not in LOG_FEATURES and c != "_y"
                  and pd.api.types.is_numeric_dtype(data[c])]
    X_trace = data[trace_cols].fillna(0).to_numpy()
    X_log = data[LOG_FEATURES].fillna(0).to_numpy()
    return X_trace, X_log, y, trace_cols


def eval_supervised(clf_factory, X, y):
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    P, R, F = [], [], []
    for tr, te in skf.split(X, y):
        clf = clf_factory()
        clf.fit(X[tr], y[tr])
        pred = clf.predict(X[te])
        p, r, f, _ = precision_recall_fscore_support(
            y[te], pred, average="binary", pos_label=1, zero_division=0)
        P.append(p); R.append(r); F.append(f)
    return np.mean(P), np.mean(R), np.mean(F)


def eval_iforest(X, y):
    """Unsupervised: fit on NORMAL rows of the train fold, flag anomalies in test."""
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    P, R, F = [], [], []
    for tr, te in skf.split(X, y):
        Xn = X[tr][y[tr] == 0]
        if len(Xn) < 5:
            continue
        iso = IsolationForest(random_state=RANDOM_STATE, n_estimators=200)
        iso.fit(Xn)
        pred = (iso.predict(X[te]) == -1).astype(int)  # -1 anomaly -> attack=1
        p, r, f, _ = precision_recall_fscore_support(
            y[te], pred, average="binary", pos_label=1, zero_division=0)
        P.append(p); R.append(r); F.append(f)
    return (np.mean(P), np.mean(R), np.mean(F)) if F else (0.0, 0.0, 0.0)


DETECTORS = {
    "rule":    lambda X, y: eval_supervised(
        lambda: DecisionTreeClassifier(max_depth=3, random_state=RANDOM_STATE), X, y),
    "iforest": lambda X, y: eval_iforest(X, y),
    "rf":      lambda X, y: eval_supervised(
        lambda: RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE), X, y),
    "hgb":     lambda X, y: eval_supervised(
        lambda: HistGradientBoostingClassifier(random_state=RANDOM_STATE), X, y),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--combined-dir", default="data/processed/combined")
    ap.add_argument("--logs-dir", default="data/processed/logs")
    ap.add_argument("--out", default="results/tables/detection_results.csv")
    a = ap.parse_args()

    rows = []
    for cls in CLASSES:
        X_trace, X_log, y, trace_cols = load_class(cls, a.combined_dir, a.logs_dir)
        arms = {"trace": X_trace, "log": X_log,
                "combined": np.hstack([X_trace, X_log])}
        for arm, X in arms.items():
            for det, fn in DETECTORS.items():
                p, r, f = fn(X, y)
                rows.append({"class": cls, "arm": arm, "detector": det,
                             "n": len(y), "precision": round(p, 3),
                             "recall": round(r, 3), "f1": round(f, 3)})

    res = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    res.to_csv(a.out, index=False)
    print(f"Wrote {a.out} ({len(res)} rows)\n")

    # RQ1/RQ2 headline: supervised (rf) F1 by class x arm
    print("== F1 by class x arm (supervised random forest) ==")
    piv = res[res.detector == "rf"].pivot(index="class", columns="arm", values="f1")
    piv = piv[["trace", "log", "combined"]]
    print(piv.to_string())
    print("\n== best arm per class (rf F1) ==")
    for cls in CLASSES:
        row = piv.loc[cls]
        best = row.idxmax()
        print(f"  {cls:<20} trace={row['trace']:.2f} log={row['log']:.2f} "
              f"combined={row['combined']:.2f}  -> best: {best}")


if __name__ == "__main__":
    main()
