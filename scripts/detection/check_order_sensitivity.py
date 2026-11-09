#!/usr/bin/env python3
"""How much do scores move when training-row order changes, folds held fixed?

The fold manifest makes the split order-independent. Model fitting is a
separate question: a random forest draws bootstrap indices in row order, so a
permuted training set yields a different ensemble even under a fixed seed.
This measures the size of that effect so the release can state it.
"""
import sys
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.insert(0, "/mnt/user-data/outputs")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "brr", "/mnt/user-data/outputs/build_results_registry.py")
brr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brr)

P = Path("/mnt/user-data/uploads/SecLogTrace/data/processed")
rows = []
for system in ["SUT1", "SUT2"]:
    for cls in brr.CLASSES:
        data, _ = brr.load(P, system, cls)
        folds, y = brr.assign_folds(data)
        arms, _ = brr.matrices(data)
        fmap = dict(zip(data["record_id"], folds))
        for arm in ["trace", "log", "combined"]:
            for model in ["rule", "iforest", "rf", "hgb"]:
                base, pf = brr.evaluate(arms[arm], y, folds, model)
                f1_base = float(pf[:, 2].mean())
                f1s, diffs = [], []
                for seed in (7, 13, 29):
                    perm = np.random.default_rng(seed).permutation(len(data))
                    sh = data.iloc[perm].reset_index(drop=True)
                    f2 = sh["record_id"].map(fmap).to_numpy()
                    y2 = (sh["label"] == "attack").astype(int).to_numpy()
                    a2, _ = brr.matrices(sh)
                    p2, pf2 = brr.evaluate(a2[arm], y2, f2, model)
                    f1s.append(float(pf2[:, 2].mean()))
                    inv = dict(zip(data["record_id"], base))
                    exp = sh["record_id"].map(inv).to_numpy()
                    diffs.append(int((p2 != exp).sum()))
                rows.append(dict(system=system, scenario=cls, arm=arm, model=model,
                                 n=len(y), f1_canonical=round(f1_base, 4),
                                 f1_min=round(min(f1s), 4), f1_max=round(max(f1s), 4),
                                 f1_spread=round(max(f1s) - min(f1s), 4),
                                 max_abs_dev=round(max(abs(f - f1_base) for f in f1s), 4),
                                 max_pred_changed=max(diffs),
                                 pred_changed_pct=round(100.0 * max(diffs) / len(y), 2)))

df = pd.DataFrame(rows)
df.to_csv("/mnt/user-data/outputs/audit/order_sensitivity.csv", index=False)

print("=== score sensitivity to training-row order, folds held fixed ===")
print("   three permutations per cell; folds read from the manifest\n")
for model in ["rule", "iforest", "rf", "hgb"]:
    s = df[df.model == model]
    print(f"  {model:8s} cells={len(s):3d}  "
          f"max |F1 deviation|={s.max_abs_dev.max():.4f}  "
          f"max predictions changed={s.max_pred_changed.max():4d} "
          f"({s.pred_changed_pct.max():.2f}% of traces)  "
          f"cells with any change={(s.max_pred_changed > 0).sum()}")

print("\n=== cells where F1 moves by more than 0.005 under permutation ===")
m = df[df.max_abs_dev > 0.005].sort_values("max_abs_dev", ascending=False)
print(m[["system", "scenario", "arm", "model", "f1_canonical", "f1_min",
         "f1_max", "max_abs_dev", "pred_changed_pct"]].to_string(index=False)
      if len(m) else "  none")
print(f"\nwrote order_sensitivity.csv")
