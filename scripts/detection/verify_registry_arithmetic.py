#!/usr/bin/env python3
"""Independent recheck of the registry: are the F1=0 cells a bug or real?

Checks, in order:
  1. Internal arithmetic. Recompute precision/recall/F1/balanced accuracy from
     each cell's own confusion matrix and compare with the reported values.
  2. Confusion totals. tp+fp+fn+tn must equal n.
  3. Feature degeneracy. For every F1=0 cell, test whether the two labels are
     distinguishable at all on that arm's features.
  4. Perfect cells. For every F1=1.0 cell, confirm a genuine separating feature
     exists rather than a pipeline artifact.
"""
import sys
import numpy as np
import pandas as pd
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location(
    "brr", "/mnt/user-data/outputs/build_results_registry.py")
brr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brr)

P = Path("/mnt/user-data/uploads/SecLogTrace/data/processed")
reg = pd.read_csv("/mnt/user-data/outputs/audit/results_registry_canonical.csv")

# ---------------------------------------------------------------- 1 and 2
print("=" * 72)
print("1-2. INTERNAL ARITHMETIC AND CONFUSION TOTALS")
print("=" * 72)
bad_tot, bad_arith = [], []
for _, r in reg.iterrows():
    tp, fp, fn, tn, n = r.tp, r.fp, r.fn, r.tn, r.n
    if tp + fp + fn + tn != n:
        bad_tot.append((r.system, r.scenario, r.arm, r.model))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    bal = (tpr + tnr) / 2
    for nm, got, exp in (("precision", r.precision_pooled, prec),
                         ("recall", r.recall_pooled, rec),
                         ("f1", r.f1_pooled, f1),
                         ("balacc", r.balanced_acc_pooled, bal)):
        if abs(got - exp) > 0.0006:
            bad_arith.append((r.system, r.scenario, r.arm, r.model, nm, got, exp))
print(f"  confusion totals != n : {len(bad_tot)} of {len(reg)}")
print(f"  metric mismatches     : {len(bad_arith)} of {len(reg) * 4} checks")
for b in bad_arith[:10]:
    print("   ", b)

# ---------------------------------------------------------------- 3
print()
print("=" * 72)
print("3. EVERY F1=0 CELL: ARE THE LABELS DISTINGUISHABLE ON THAT ARM AT ALL?")
print("=" * 72)
zeros = reg[reg.f1_pooled == 0]
print(f"  cells with pooled F1 == 0: {len(zeros)}\n")

cache = {}
for _, r in zeros.iterrows():
    key = (r.system, r.scenario)
    if key not in cache:
        data, _ = brr.load(P, r.system, r.scenario)
        folds, y = brr.assign_folds(data)
        arms, _ = brr.matrices(data)
        cache[key] = (data, folds, y, arms)
    data, folds, y, arms = cache[key]
    X = arms[r.arm]

    n_feat = X.shape[1]
    # Are the two label groups identical as multisets of feature rows?
    rows_norm = {tuple(v) for v in X[y == 0]}
    rows_atk = {tuple(v) for v in X[y == 1]}
    identical_support = rows_norm == rows_atk
    # Per-feature: does any single feature have a different value set?
    differing = []
    for j in range(n_feat):
        a, b = set(np.unique(X[y == 0, j])), set(np.unique(X[y == 1, j]))
        if a != b:
            differing.append(j)
    # Best achievable single-feature split
    best = 0.5
    for j in range(n_feat):
        a, b = X[y == 0, j], X[y == 1, j]
        for t in np.unique(X[:, j]):
            acc = 0.5 * ((a <= t).mean() + (b > t).mean())
            best = max(best, acc, 1 - acc)
    print(f"  {r.system}/{r.scenario}/{r.arm}/{r.model}")
    print(f"     features={n_feat}  distinct feature-row sets identical between "
          f"labels: {identical_support}")
    print(f"     features whose value set differs by label: {len(differing)} "
          f"of {n_feat}")
    print(f"     best achievable single-feature split (balanced acc): {best:.4f}")
    print(f"     reported: predicted_positive={r.predicted_positive}, "
          f"balanced_acc={r.balanced_acc_pooled}")

# ---------------------------------------------------------------- 4
print()
print("=" * 72)
print("4. EVERY F1=1.0 CELL: IS THERE A GENUINE SEPARATING FEATURE?")
print("=" * 72)
ones = reg[(reg.f1_pooled >= 0.9999) & (reg.model == "rf")]
print(f"  rf cells with pooled F1 == 1.0: {len(ones)}\n")
for _, r in ones.iterrows():
    key = (r.system, r.scenario)
    if key not in cache:
        data, _ = brr.load(P, r.system, r.scenario)
        folds, y = brr.assign_folds(data)
        arms, _ = brr.matrices(data)
        cache[key] = (data, folds, y, arms)
    data, folds, y, arms = cache[key]
    X = arms[r.arm]
    names = ([c for c in data.columns
              if c not in brr.DROP and c not in brr.LOG_FEATURES
              and pd.api.types.is_numeric_dtype(data[c])]
             if r.arm == "trace" else
             brr.LOG_FEATURES if r.arm == "log" else
             [c for c in data.columns
              if c not in brr.DROP and c not in brr.LOG_FEATURES
              and pd.api.types.is_numeric_dtype(data[c])] + brr.LOG_FEATURES)
    perfect = []
    for j in range(X.shape[1]):
        a, b = X[y == 0, j], X[y == 1, j]
        if set(np.unique(a)).isdisjoint(set(np.unique(b))):
            perfect.append((names[j], f"{a.min():.0f}-{a.max():.0f}",
                            f"{b.min():.0f}-{b.max():.0f}"))
    print(f"  {r.system}/{r.scenario}/{r.arm}: "
          f"{len(perfect)} perfectly separating feature(s)")
    for nm, ra, rb in perfect[:4]:
        print(f"     {nm:24s} normal {ra:>12s}  attack {rb:>12s}")
    if not perfect:
        print("     WARNING: F1=1.0 with no single disjoint feature")
