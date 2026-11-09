#!/usr/bin/env python3
"""Complete the SUT2 detector grid: the hgb arm was never run there.

Uses run_detection_sut2's own loader and run_detection's detector definitions,
so the new cells follow the published protocol exactly (seed 42, 5-fold
stratified, same DROP list).
"""
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, "/mnt/user-data/uploads/SecLogTrace/scripts/detection")
from run_detection import DETECTORS, CLASSES  # noqa: E402
from run_detection_sut2 import load_class_sut2  # noqa: E402

CDIR = "/mnt/user-data/uploads/SecLogTrace/data/processed/combined"
LDIR = "/mnt/user-data/uploads/SecLogTrace/data/processed/logs"

rows = []
for cls in CLASSES:
    Xt, Xl, y, tcols = load_class_sut2(cls, CDIR, LDIR)
    arms = {"trace": Xt, "log": Xl, "combined": np.hstack([Xt, Xl])}
    for arm, X in arms.items():
        for det in ["rf", "hgb"]:
            p, r, f1 = DETECTORS[det](X, y)
            rows.append({"class": cls, "arm": arm, "detector": det,
                         "n": len(y), "precision": round(p, 3),
                         "recall": round(r, 3), "f1": round(f1, 3)})

new = pd.DataFrame(rows)

pub = pd.read_csv("/mnt/user-data/uploads/SecLogTrace/results/tables/detection_results_sut2_v2.csv")
pub_rf = pub[pub.detector == "rf"][["class", "arm", "f1"]].rename(columns={"f1": "f1_published_rf"})

print("=== SUT2: rf reproduction check and the 15 new hgb cells ===")
piv = new.pivot_table(index=["class", "arm"], columns="detector", values="f1").reset_index()
chk = piv.merge(pub_rf, on=["class", "arm"], how="left")
chk["rf_matches_published"] = (chk["rf"] - chk["f1_published_rf"]).abs() < 0.0015
chk["hgb_minus_rf"] = (chk["hgb"] - chk["rf"]).round(3)
print(chk.to_string(index=False))

print(f"\n  rf reproduces the published SUT2 values: "
      f"{int(chk.rf_matches_published.sum())}/{len(chk)} cells")
print(f"  max |hgb - rf| on SUT2 : {chk.hgb_minus_rf.abs().max():.3f}")
print(f"  mean |hgb - rf| on SUT2: {chk.hgb_minus_rf.abs().mean():.3f}")

sut1 = pd.read_csv("/mnt/user-data/uploads/SecLogTrace/results/tables/detection_results.csv")
s1 = sut1[sut1.detector.isin(["rf", "hgb"])].pivot_table(
    index=["class", "arm"], columns="detector", values="f1").reset_index()
s1["hgb_minus_rf"] = (s1["hgb"] - s1["rf"]).round(3)
print(f"\n  for comparison, SUT1 max |hgb - rf|: {s1.hgb_minus_rf.abs().max():.3f}")

print("\n=== the specific numbers CROSS_SYSTEM_ANALYSIS.md §4 attributes to SUT2 ===")
print("  doc says: 'SUT2 resource_exhaustion trace rf 0.955 / hgb 0.945;"
      " combined rf 0.96 / hgb 0.948'")
for arm in ["trace", "combined"]:
    a2 = chk[(chk["class"] == "resource_exhaustion") & (chk.arm == arm)]
    a1 = s1[(s1["class"] == "resource_exhaustion") & (s1.arm == arm)]
    print(f"  resource_exhaustion/{arm:8s}  SUT2 actual rf={a2.rf.iloc[0]:.3f} "
          f"hgb={a2.hgb.iloc[0]:.3f}   |   SUT1 actual rf={a1.rf.iloc[0]:.3f} "
          f"hgb={a1.hgb.iloc[0]:.3f}")

new.to_csv("/mnt/user-data/outputs/audit/detection_results_sut2_hgb_completion.csv",
           index=False)
print("\nwrote detection_results_sut2_hgb_completion.csv")
