#!/usr/bin/env python3
"""
run_detection_sut2.py — SecLogTrace Phase 3, SUT2 (TeaStore) cross-system arm.

SUT2 v2 (2026-10 corpus) now carries per-request APPLICATION LOGS, added via
request-boundary instrumentation (see TeaStore LOGGING_INSTRUMENTATION.md and
docs/SUT2_LOG_MODALITY_DECISION_20260914.md, reversed 2026-10-16). So SUT2 now
runs the SAME three modality arms as SUT1 — trace / log / combined — not the
trace-only arm of the v1 corpus.

This script REUSES run_detection.py's detector functions (eval_supervised,
eval_iforest, DETECTORS), DROP, and LOG_FEATURES UNCHANGED, so the SUT2 numbers
come from the exact same evaluation (same detectors, same StratifiedKFold seed,
same attack-class P/R/F1) as SUT1. Only data loading differs:
  - SUT2's per-class feature table is a SINGLE file (sut2v2_<class>_features.csv,
    both labels) rather than SUT1's split <class>_{normal,attack}_features.csv;
  - SUT2's per-trace log features live in ONE dir per class
    (data/processed/logs/sut2v2_<class>/logs_by_trace.csv), both windows joined.

Usage:
    python3 scripts/detection/run_detection_sut2.py \
        --combined-dir data/processed/combined \
        --logs-dir data/processed/logs \
        --out results/tables/detection_results_sut2_v2.csv
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_detection import DROP, LOG_FEATURES, DETECTORS, CLASSES  # noqa: E402

PREFIX = "sut2v2_"


def load_class_sut2(cls, combined_dir, logs_dir):
    """Return X_trace, X_log, y, trace_cols for one SUT2 v2 class (normal=0, attack=1)."""
    df = pd.read_csv(os.path.join(combined_dir, f"{PREFIX}{cls}_features.csv"))
    df = df[df["label"].isin(["normal", "attack"])].copy()
    # per-trace log features (one dir per class, both windows); left join keeps
    # labelled traces — traces with no log line (e.g. injection rejected before
    # the method runs) get zero-filled log features.
    lf = os.path.join(logs_dir, f"{PREFIX}{cls}", "logs_by_trace.csv")
    logs = (pd.read_csv(lf)[["trace_id", "log_line_count", "error_count",
                             "warn_count", "service_count"]]
            .rename(columns={"service_count": "log_service_count"})
            .drop_duplicates("trace_id"))
    df = df.merge(logs, on="trace_id", how="left")
    df[LOG_FEATURES] = df[LOG_FEATURES].fillna(0)
    y = (df["label"] == "attack").astype(int).to_numpy()
    trace_cols = [c for c in df.columns
                  if c not in DROP and c not in LOG_FEATURES
                  and pd.api.types.is_numeric_dtype(df[c])]
    X_trace = df[trace_cols].fillna(0).to_numpy()
    X_log = df[LOG_FEATURES].fillna(0).to_numpy()
    return X_trace, X_log, y, trace_cols


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--combined-dir", default="data/processed/combined")
    ap.add_argument("--logs-dir", default="data/processed/logs")
    ap.add_argument("--out", default="results/tables/detection_results_sut2_v2.csv")
    a = ap.parse_args()

    rows = []
    for cls in CLASSES:
        path = os.path.join(a.combined_dir, f"{PREFIX}{cls}_features.csv")
        if not os.path.exists(path):
            print(f"  SKIP {cls}: {path} not found")
            continue
        X_trace, X_log, y, _ = load_class_sut2(cls, a.combined_dir, a.logs_dir)
        n_pos, n_neg = int(y.sum()), int((y == 0).sum())
        arms = {"trace": X_trace, "log": X_log,
                "combined": np.hstack([X_trace, X_log])}
        for arm, X in arms.items():
            for det, fn in DETECTORS.items():
                p, r, f = fn(X, y)
                rows.append({"class": cls, "sut": "sut2", "arm": arm,
                             "detector": det, "n": len(y),
                             "n_normal": n_neg, "n_attack": n_pos,
                             "precision": round(p, 3), "recall": round(r, 3),
                             "f1": round(f, 3)})

    res = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    res.to_csv(a.out, index=False)
    print(f"Wrote {a.out} ({len(res)} rows)\n")

    print("== SUT2 v2 F1 by class x arm (supervised random forest) ==")
    piv = res[res.detector == "rf"].pivot(index="class", columns="arm", values="f1")
    piv = piv[["trace", "log", "combined"]]
    print(piv.to_string())
    print("\n== best arm per class (rf F1) ==")
    for cls in piv.index:
        row = piv.loc[cls]
        best = row.idxmax()
        print(f"  {cls:<20} trace={row['trace']:.2f} log={row['log']:.2f} "
              f"combined={row['combined']:.2f}  -> best: {best}")


if __name__ == "__main__":
    main()
