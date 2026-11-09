#!/usr/bin/env python3
"""
build_cross_system.py — merge the SUT1 and SUT2 v2 detection results into one
cross-system table (RF F1 per class x arm, with the SUT2-SUT1 delta).

Reads the two result CSVs produced by run_detection.py (SUT1) and
run_detection_sut2.py (SUT2 v2); writes results/tables/cross_system_comparison.csv.
"""
import argparse
import pandas as pd

ARMS = ["trace", "log", "combined"]


def rf_f1(path):
    df = pd.read_csv(path)
    df = df[df["detector"] == "rf"]
    return df.set_index(["class", "arm"])["f1"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sut1", default="results/tables/detection_results.csv")
    ap.add_argument("--sut2", default="results/tables/detection_results_sut2_v2.csv")
    ap.add_argument("--out", default="results/tables/cross_system_comparison.csv")
    a = ap.parse_args()

    s1, s2 = rf_f1(a.sut1), rf_f1(a.sut2)
    rows = []
    for (cls, arm) in sorted(set(s1.index) | set(s2.index)):
        if arm not in ARMS:
            continue
        f1_1, f1_2 = s1.get((cls, arm)), s2.get((cls, arm))
        rows.append({"class": cls, "arm": arm,
                     "sut1_rf_f1": f1_1, "sut2_rf_f1": f1_2,
                     "delta": round(f1_2 - f1_1, 3)
                     if f1_1 is not None and f1_2 is not None else None})
    res = pd.DataFrame(rows)
    res.to_csv(a.out, index=False)
    print(f"Wrote {a.out} ({len(res)} rows)\n")
    print(res.pivot(index="class", columns="arm", values="delta")[ARMS].to_string())


if __name__ == "__main__":
    main()
