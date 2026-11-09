#!/usr/bin/env python3
"""Corrected separability recheck.

The earlier test called a feature "perfectly separating" when the two labels
shared no exactly equal value. For a continuous feature that is almost always
true and says nothing: two heavily overlapping duration distributions share no
exact float. The correct test is whether the value RANGES are disjoint, i.e.
max(one label) < min(the other).

This rechecks which features genuinely separate each F1=1.0 cell, and
separates structural (integer, count-like) from timing features.
"""
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

TIMING = {"trace_duration_us", "span_dur_mean", "span_dur_median",
          "span_dur_p95", "span_dur_max", "span_dur_std"}


def feat_names(data, arm):
    t = [c for c in data.columns
         if c not in brr.DROP and c not in brr.LOG_FEATURES
         and pd.api.types.is_numeric_dtype(data[c])]
    return t if arm == "trace" else (brr.LOG_FEATURES if arm == "log"
                                     else t + brr.LOG_FEATURES)


cache = {}
rows = []
print("=" * 78)
print("GENUINELY SEPARATING FEATURES (disjoint RANGES, not just unequal floats)")
print("=" * 78)

for (system, scenario, arm), _ in reg[reg.f1_pooled >= 0.9999].groupby(
        ["system", "scenario", "arm"]):
    key = (system, scenario)
    if key not in cache:
        data, _ = brr.load(P, system, scenario)
        folds, y = brr.assign_folds(data)
        arms, _ = brr.matrices(data)
        cache[key] = (data, folds, y, arms)
    data, folds, y, arms = cache[key]
    X, names = arms[arm], feat_names(data, arm)

    sep_struct, sep_time, exact_only = [], [], 0
    for j, nm in enumerate(names):
        a, b = X[y == 0, j], X[y == 1, j]
        range_disjoint = (a.max() < b.min()) or (b.max() < a.min())
        value_disjoint = set(np.unique(a)).isdisjoint(set(np.unique(b)))
        if range_disjoint:
            (sep_time if nm in TIMING else sep_struct).append(
                (nm, f"{a.min():.0f}..{a.max():.0f}", f"{b.min():.0f}..{b.max():.0f}"))
        elif value_disjoint:
            exact_only += 1

    print(f"\n{system}/{scenario}/{arm}")
    print(f"   range-disjoint: {len(sep_struct)} structural, {len(sep_time)} timing"
          f"   | unequal-floats-only (not separating): {exact_only}")
    for nm, ra, rb in (sep_struct + sep_time)[:5]:
        kind = "TIMING" if nm in TIMING else "struct"
        print(f"     [{kind}] {nm:24s} normal {ra:>18s}  attack {rb:>18s}")
    if not sep_struct and not sep_time:
        print("     NONE -- F1=1.0 rests on a feature combination, not one feature")
    rows.append(dict(system=system, scenario=scenario, arm=arm,
                     n_struct=len(sep_struct), n_timing=len(sep_time),
                     n_exact_only=exact_only,
                     top_struct=sep_struct[0][0] if sep_struct else ""))

df = pd.DataFrame(rows)
df.to_csv("/mnt/user-data/outputs/audit/separating_features.csv", index=False)

print()
print("=" * 78)
print("SUMMARY: does every F1=1.0 cell rest on a STRUCTURAL separator?")
print("=" * 78)
print(df.to_string(index=False))
print(f"\n  cells with >=1 structural separator: "
      f"{int((df.n_struct > 0).sum())} of {len(df)}")
print(f"  cells resting on timing alone      : "
      f"{int(((df.n_struct == 0) & (df.n_timing > 0)).sum())}")
print(f"  cells with no single separator      : "
      f"{int(((df.n_struct == 0) & (df.n_timing == 0)).sum())}")

print()
print("=" * 78)
print("NO-SIGNAL CELLS: what F1 does each model report on identical features?")
print("=" * 78)
for system, scenario in [("SUT2", "resource_exhaustion"), ("SUT2", "data_exfiltration")]:
    sub = reg[(reg.system == system) & (reg.scenario == scenario) & (reg.arm == "log")]
    print(f"\n  {system}/{scenario}/log  (all 4 log features identical by label)")
    print(sub[["model", "f1_pooled", "balanced_acc_pooled", "predicted_positive",
               "predicted_positive_rate"]].to_string(index=False))
    print("     F1 here is decided by which class the model defaults to,")
    print("     not by any discrimination. Balanced accuracy 0.5 is the real result.")
