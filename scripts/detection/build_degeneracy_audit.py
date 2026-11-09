#!/usr/bin/env python3
"""
build_degeneracy_audit.py — can the labels be discriminated on each arm at all?

A reported F1 is only meaningful if the arm's features carry label information.
Where the two labels have identical feature values, no classifier can exceed
chance, and the F1 a model reports is decided by which class it defaults to,
not by any discrimination:

    all four log-count features identical by label
      -> decision tree, random forest, gradient boosting  predict all-normal
         -> precision 0, recall 0, F1 0.0000
      -> isolation forest                                 predicts all-attack
         -> precision 0.5, recall 1.0, F1 0.6667

Both outcomes describe the same condition: balanced accuracy 0.500, no
discrimination. Reporting either F1 as a result would mislead, so this audit
emits an explicit flag and the registry carries it.

For each (system, scenario, arm) it records:
  features_identical_by_label   every feature has the same value set in both
                                labels, so the arm carries no label information
  n_features_differing          how many features have differing value sets
  best_single_feature_split     the best balanced accuracy any one feature can
                                reach, found by scanning all thresholds
  range_disjoint_structural     count of structural features whose value RANGES
                                do not overlap
  range_disjoint_timing         same, for span-duration features
  value_disjoint_only           features sharing no exactly equal value but
                                with overlapping ranges. These do NOT separate.
                                A continuous feature almost always lands here,
                                which is why exact-value comparison must not be
                                used as a separability test.

Usage:
    python3 scripts/detection/build_degeneracy_audit.py \
        --processed-dir data/processed \
        --registry results/audit/results_registry_canonical.csv \
        --out-dir results/audit
"""
import argparse
import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

TIMING = {"trace_duration_us", "span_dur_mean", "span_dur_median",
          "span_dur_p95", "span_dur_max", "span_dur_std"}


def load_builder(path):
    spec = importlib.util.spec_from_file_location("brr", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def best_split(a, b, col):
    best = 0.5
    for t in np.unique(col):
        acc = 0.5 * ((a <= t).mean() + (b > t).mean())
        best = max(best, acc, 1.0 - acc)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--registry",
                    default="results/audit/results_registry_canonical.csv")
    ap.add_argument("--builder",
                    default="scripts/detection/build_results_registry.py")
    ap.add_argument("--out-dir", default="results/audit")
    a = ap.parse_args()

    brr = load_builder(a.builder)
    P = Path(a.processed_dir)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for system in ["SUT1", "SUT2"]:
        for cls in brr.CLASSES:
            data, _ = brr.load(P, system, cls)
            y = (data["label"] == "attack").astype(int).to_numpy()
            arms, tcols = brr.matrices(data)
            names = {"trace": tcols, "log": brr.LOG_FEATURES,
                     "combined": tcols + brr.LOG_FEATURES}
            for arm in ["trace", "log", "combined"]:
                X, nm = arms[arm], names[arm]
                differing, struct, timing, exact_only = [], 0, 0, 0
                best = 0.5
                for j, name in enumerate(nm):
                    an, at = X[y == 0, j], X[y == 1, j]
                    sn, sa = set(np.unique(an)), set(np.unique(at))
                    if sn != sa:
                        differing.append(name)
                    rng = (an.max() < at.min()) or (at.max() < an.min())
                    if rng:
                        if name in TIMING:
                            timing += 1
                        else:
                            struct += 1
                    elif sn.isdisjoint(sa):
                        exact_only += 1
                    best = max(best, best_split(an, at, X[:, j]))
                rows.append(dict(
                    system=system, scenario=cls, arm=arm,
                    n_features=len(nm),
                    features_identical_by_label=(len(differing) == 0),
                    n_features_differing=len(differing),
                    best_single_feature_split=round(best, 4),
                    range_disjoint_structural=struct,
                    range_disjoint_timing=timing,
                    value_disjoint_only=exact_only,
                    discrimination_possible=bool(best > 0.52),
                ))

    deg = pd.DataFrame(rows)
    deg.to_csv(out / "feature_degeneracy_audit.csv", index=False)

    print("=== feature degeneracy by (system, scenario, arm) ===")
    print(deg[["system", "scenario", "arm", "features_identical_by_label",
               "n_features_differing", "best_single_feature_split",
               "range_disjoint_structural", "range_disjoint_timing",
               "value_disjoint_only"]].to_string(index=False))

    dead = deg[deg.features_identical_by_label]
    print(f"\n  arms where every feature is identical by label: {len(dead)}")
    print(dead[["system", "scenario", "arm"]].to_string(index=False) if len(dead)
          else "   none")

    # ------- merge the flag into the registry without refitting anything -------
    reg = pd.read_csv(a.registry)
    keep = ["system", "scenario", "arm", "features_identical_by_label",
            "best_single_feature_split", "discrimination_possible",
            "range_disjoint_structural", "range_disjoint_timing"]
    for c in keep[3:]:
        if c in reg.columns:
            reg = reg.drop(columns=c)
    reg = reg.merge(deg[keep], on=["system", "scenario", "arm"], how="left")

    # F1 is uninterpretable where no discrimination is possible: on identical
    # features the score reflects only the model's default class.
    reg["f1_interpretable"] = ~reg["features_identical_by_label"]
    reg.loc[reg.features_identical_by_label, "interpretation_flags"] = (
        reg.loc[reg.features_identical_by_label, "interpretation_flags"]
        .fillna("").apply(lambda s: ";".join(
            [x for x in (s.split(";") if s else []) if x]
            + ["features_identical_by_label"])))
    reg.loc[reg.features_identical_by_label, "suitable_for_showcase_figure"] = False
    reg.to_csv(out / "results_registry_canonical.csv", index=False)

    print(f"\n  registry rows with f1_interpretable == False: "
          f"{int((~reg.f1_interpretable).sum())}")
    print(f"  suitable_for_showcase_figure after the merge: "
          f"{int(reg.suitable_for_showcase_figure.sum())} of {len(reg)}")

    print("\n=== the no-discrimination cells, as reported ===")
    nd = reg[~reg.f1_interpretable]
    print(nd[["system", "scenario", "arm", "model", "f1_pooled",
              "balanced_acc_pooled", "predicted_positive_rate"]].to_string(index=False))
    print("\n  F1 differs across models here only because each defaults to a")
    print("  different class. Balanced accuracy 0.5 is the result; report that.")
    print(f"\nWrote {out}/feature_degeneracy_audit.csv and updated the registry")


if __name__ == "__main__":
    main()
