#!/usr/bin/env python3
"""
baseline_stats.py — SecLogTrace Phase 1

Descriptive statistics and plots over the trace-level feature table.

The key behaviour: every attack-vs-normal comparison is reported BOTH
pooled and stratified by root_operation. Pooled numbers are printed with a
warning, because a pooled difference can come entirely from the two classes
exercising different entry points. If a feature separates pooled but not
within-stratum, it is a workload artifact, not an attack signal. Reviewers
at SANER will ask this. Answer it before they do.

Usage:
    python3 baseline_stats.py --features experiment_001_features.csv \
        --outdir results/
    python3 baseline_stats.py --features combined_features.csv \
        --outdir results/ --compare

    # Reliability check: two same-label collections (e.g. experiment_003 vs
    # a re-run experiment_004, both label=normal) have nothing to group by
    # on "label", so pass --group-col experiment_id instead. --features
    # accepts more than one CSV and concatenates them.
    python3 baseline_stats.py \
        --features experiment_003_features.csv experiment_004_features.csv \
        --group-col experiment_id --outdir results/ --compare
"""

import argparse
import os

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NUMERIC_SKIP = {"trace_id", "path_signature", "label", "experiment_id",
                "root_service", "root_operation", "infra_noise"}


def numeric_cols(df):
    return [c for c in df.columns
            if c not in NUMERIC_SKIP and pd.api.types.is_numeric_dtype(df[c])]


def cliffs_delta(a, b):
    """Non-parametric effect size. Robust to the skewed duration/count
    distributions traces produce. |d| < 0.147 negligible, < 0.33 small,
    < 0.474 medium, else large (Romano et al. thresholds)."""
    a, b = np.asarray(a), np.asarray(b)
    if len(a) == 0 or len(b) == 0:
        return np.nan
    gt = sum((a[:, None] > b[None, :]).sum(axis=1))
    lt = sum((a[:, None] < b[None, :]).sum(axis=1))
    return (gt - lt) / (len(a) * len(b))


def describe(df, outdir):
    cols = numeric_cols(df)
    desc = df[cols].describe(percentiles=[0.5, 0.9, 0.95, 0.99]).T
    desc["iqr"] = df[cols].quantile(0.75) - df[cols].quantile(0.25)
    desc["zero_frac"] = (df[cols] == 0).mean()
    path = os.path.join(outdir, "tables", "baseline_summary.csv")
    desc.to_csv(path)
    print(f"\n== Baseline summary ({len(df)} traces) ==")
    print(desc[["mean", "50%", "95%", "std", "zero_frac"]].to_string())
    print(f"\nWritten: {path}")

    # Features with no variance carry no information. Drop them in Phase 3.
    dead = [c for c in cols if df[c].nunique() <= 1]
    if dead:
        print(f"\nZero-variance features (drop these before modelling): {dead}")
    return desc


def per_operation(df, outdir):
    if "root_operation" not in df.columns:
        return
    g = df.groupby("root_operation").agg(
        n=("trace_id", "count"),
        span_median=("span_count", "median"),
        span_iqr=("span_count", lambda s: s.quantile(.75) - s.quantile(.25)),
        dur_median=("trace_duration_us", "median"),
        svc_median=("service_count", "median"),
        err_rate=("error_span_rate", "mean"),
    ).sort_values("n", ascending=False)
    path = os.path.join(outdir, "tables", "baseline_by_root_operation.csv")
    g.to_csv(path)
    print("\n== Per-root-operation breakdown ==")
    print(g.to_string())
    print(f"\nWritten: {path}")

    spread = g["span_median"].max() - g["span_median"].min()
    print(f"\nSpan-count median spread across entry points: {spread:.0f}")
    print("If this spread is comparable to any attack-vs-normal gap you")
    print("report, the gap may be workload mix rather than attack signal.")


def compare(df, outdir, group_col="label"):
    if group_col not in df.columns or df[group_col].nunique() < 2:
        print(f"\nFewer than two distinct values in '{group_col}'; skipping comparison.")
        return
    cols = numeric_cols(df)
    labels = sorted(df[group_col].dropna().unique())
    a_lab, b_lab = labels[0], labels[1]
    A, B = df[df[group_col] == a_lab], df[df[group_col] == b_lab]

    print(f"\n== Pooled comparison: {a_lab} (n={len(A)}) vs {b_lab} (n={len(B)}) ==")
    print("WARNING: pooled results are confounded if the two classes")
    print("exercise different entry points. Read the stratified table below.\n")

    rows = []
    for c in cols:
        rows.append({
            "feature": c,
            f"{a_lab}_median": A[c].median(),
            f"{b_lab}_median": B[c].median(),
            "cliffs_delta": cliffs_delta(A[c].dropna(), B[c].dropna()),
        })
    pooled = pd.DataFrame(rows).sort_values(
        "cliffs_delta", key=abs, ascending=False)
    print(pooled.to_string(index=False))
    pooled.to_csv(os.path.join(outdir, "tables", "pooled_comparison.csv"),
                  index=False)

    # Overlap check: do both classes even share entry points?
    if "root_operation" in df.columns:
        shared = set(A.root_operation) & set(B.root_operation)
        print(f"\nEntry points in {a_lab}: {A.root_operation.nunique()}")
        print(f"Entry points in {b_lab}: {B.root_operation.nunique()}")
        print(f"Shared entry points: {len(shared)}")
        if not shared:
            print("\nNO SHARED ENTRY POINTS. The two classes are not")
            print("comparable as collected. Any measured difference is a")
            print("workload difference. Re-collect per checklist item 8.")
            return

        strat = []
        for op in shared:
            sa, sb = A[A.root_operation == op], B[B.root_operation == op]
            if len(sa) < 5 or len(sb) < 5:
                continue
            for c in cols:
                strat.append({
                    "root_operation": op, "feature": c,
                    "n_a": len(sa), "n_b": len(sb),
                    "cliffs_delta": cliffs_delta(sa[c].dropna(), sb[c].dropna()),
                })
        if strat:
            s = pd.DataFrame(strat)
            s.to_csv(os.path.join(outdir, "tables", "stratified_comparison.csv"),
                     index=False)
            best = s.reindex(s.cliffs_delta.abs().sort_values(
                ascending=False).index).head(20)
            print("\n== Stratified comparison (top 20 by |delta|) ==")
            print(best.to_string(index=False))
            print("\nThese are the features that survive control. Build the")
            print("Phase 3 detectors on these, not on the pooled ranking.")


def plots(df, outdir, group_col="label"):
    figdir = os.path.join(outdir, "figures")
    for feat in ["span_count", "service_count", "trace_duration_us",
                 "max_depth", "error_span_rate"]:
        if feat not in df.columns:
            continue
        fig, ax = plt.subplots(figsize=(7, 4))
        if group_col in df.columns and df[group_col].nunique() > 1:
            for lab, g in df.groupby(group_col):
                ax.hist(g[feat].dropna(), bins=40, alpha=0.55, label=str(lab))
            ax.legend()
        else:
            ax.hist(df[feat].dropna(), bins=40, color="#444")
        ax.set_xlabel(feat)
        ax.set_ylabel("traces")
        ax.set_title(f"{feat} distribution")
        fig.tight_layout()
        fig.savefig(os.path.join(figdir, f"dist_{feat}.png"), dpi=150)
        plt.close(fig)

    if "root_operation" in df.columns and "span_count" in df.columns:
        top = df.root_operation.value_counts().head(8).index
        sub = df[df.root_operation.isin(top)]
        fig, ax = plt.subplots(figsize=(9, 5))
        data = [sub[sub.root_operation == o].span_count.dropna() for o in top]
        try:
            ax.boxplot(data, tick_labels=[o[:28] for o in top])
        except TypeError:  # matplotlib < 3.9
            ax.boxplot(data, labels=[o[:28] for o in top])
        ax.set_ylabel("span_count")
        ax.set_title("span_count by entry point (stratification basis)")
        plt.xticks(rotation=40, ha="right")
        fig.tight_layout()
        fig.savefig(os.path.join(figdir, "span_count_by_root_operation.png"),
                    dpi=150)
        plt.close(fig)

    print(f"\nFigures written to {figdir}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--features", required=True, nargs="+",
                    help="one or more features CSVs; multiple files are "
                         "concatenated (e.g. a baseline + its reliability re-run)")
    p.add_argument("--outdir", default="results")
    p.add_argument("--compare", action="store_true")
    p.add_argument("--group-col", default="label",
                    help="column compare()/plots() split groups on. Use "
                         "'label' for normal-vs-attack, or 'experiment_id' "
                         "for a reliability check comparing two same-label "
                         "collections from different days")
    a = p.parse_args()

    os.makedirs(os.path.join(a.outdir, "tables"), exist_ok=True)
    os.makedirs(os.path.join(a.outdir, "figures"), exist_ok=True)

    df = pd.concat([pd.read_csv(f) for f in a.features], ignore_index=True)
    describe(df, a.outdir)
    per_operation(df, a.outdir)
    if a.compare:
        compare(df, a.outdir, a.group_col)
    plots(df, a.outdir, a.group_col)


if __name__ == "__main__":
    main()
