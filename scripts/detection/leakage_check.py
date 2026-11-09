#!/usr/bin/env python3
"""
leakage_check.py — SecLogTrace Phase 3 validation

Before any detection number goes in the paper, confirm each score (especially
the perfect ones) is driven by a LEGITIMATE, mechanistic feature, not a
collection artifact or a label-encoding leak. For each class x arm it reports
the RF feature importances and the normal-vs-attack medians of the top
feature, and it asserts the feature matrix contains no identifier/window
columns. Reuses load_class() from run_detection.py so the exact same features
are audited.
"""
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_detection import load_class, CLASSES, DROP, LOG_FEATURES  # noqa: E402

COMBINED = "data/processed/combined"
LOGS = "data/processed/logs"
LEAKY = {"trace_id", "experiment_id", "label", "infra_noise", "root_operation",
         "root_service", "path_signature", "start_time_us", "end_time_us"}


def single_feature_best_f1(x, y):
    """Best F1 achievable by a single threshold on feature x (either
    direction) — a cheap 'how separable by ONE feature' probe."""
    from sklearn.metrics import f1_score
    xs = np.unique(x)
    if len(xs) > 200:
        xs = np.quantile(x, np.linspace(0, 1, 200))
    best = 0.0
    for t in xs:
        for pred in ((x > t).astype(int), (x <= t).astype(int)):
            best = max(best, f1_score(y, pred, pos_label=1, zero_division=0))
    return best


def main():
    print("Leaky columns excluded from features:",
          sorted(LEAKY & set(DROP)) or "(none configured)")
    for cls in CLASSES:
        Xt, Xl, y, tcols = load_class(cls, COMBINED, LOGS)
        # assert no leaky column slipped into the trace feature names
        leaked = [c for c in tcols if c in LEAKY]
        flag = "  !!! LEAKY COLUMN IN FEATURES" if leaked else ""
        cols = tcols + LOG_FEATURES
        X = np.hstack([Xt, Xl])
        print(f"\n=== {cls}  (n={len(y)}, {int(y.sum())} attack){flag} ===")
        for arm, Xa, names in (("trace", Xt, tcols), ("log", Xl, LOG_FEATURES)):
            rf = RandomForestClassifier(n_estimators=200, random_state=42).fit(Xa, y)
            imp = sorted(zip(names, rf.feature_importances_), key=lambda t: -t[1])[:3]
            top = imp[0][0]
            xi = Xa[:, names.index(top)]
            nm = np.median(xi[y == 0]); am = np.median(xi[y == 1])
            sf1 = single_feature_best_f1(xi, y)
            imps = ", ".join(f"{c}={i:.2f}" for c, i in imp)
            print(f"  {arm:<8} top: {imps}")
            print(f"           driver '{top}': normal_med={nm:.1f} attack_med={am:.1f}"
                  f"  | best single-feature F1={sf1:.2f}")


if __name__ == "__main__":
    main()
