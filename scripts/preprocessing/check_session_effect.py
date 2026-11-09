#!/usr/bin/env python3
"""B2, decisive test: does a session effect exist independent of the label?

SUT1 injection/normal and resource_exhaustion/normal both exercise
POST /api/v1/travelservice/trips/left with legitimate input. Both are
normal-labelled. They were collected in different sessions, hours apart.

If a feature separates these two same-label, same-endpoint sets, that
separation is a session effect, not a security signal. This isolates what the
label-wise audit cannot.
"""
import numpy as np
import pandas as pd
from pathlib import Path

D = Path("/mnt/user-data/uploads/SecLogTrace/data/processed/combined")

PAIRS = [
    # (name, file A, file B) — same label, same endpoint, different sessions
    ("SUT1  injection/normal  vs  resource_exhaustion/normal",
     "injection_normal_features.csv", "resource_exhaustion_normal_features.csv"),
    ("SUT2  injection/normal  vs  resource_exhaustion/normal",
     "sut2v2_injection_features.csv", "sut2v2_resource_exhaustion_features.csv"),
]


def best_split(xn, xa):
    vals = np.unique(np.concatenate([xn, xa]))
    best = 0.5
    for t in vals:
        acc = 0.5 * ((xn <= t).mean() + (xa > t).mean())
        best = max(best, acc, 1 - acc)
    return best


for name, fa_, fb_ in PAIRS:
    A = pd.read_csv(D / fa_, dtype={"trace_id": str})
    B = pd.read_csv(D / fb_, dtype={"trace_id": str})
    # SUT2 tables hold both labels in one file; keep only normal.
    A = A[A.label == "normal"]
    B = B[B.label == "normal"]
    print(f"=== {name} ===")
    print(f"  A: {fa_}  n={len(A)}  root_operation={dict(A.root_operation.value_counts())}")
    print(f"  B: {fb_}  n={len(B)}  root_operation={dict(B.root_operation.value_counts())}")
    print(f"  both labelled: A={set(A.label)} B={set(B.label)}")
    print(f"  span_count: A={dict(A.span_count.value_counts())} "
          f"B={dict(B.span_count.value_counts())}")
    print()
    rows = []
    for col in A.columns:
        if col in ("trace_id", "label", "experiment_id", "infra_noise",
                   "path_signature", "root_service", "root_operation"):
            continue
        if not pd.api.types.is_numeric_dtype(A[col]) or col not in B.columns:
            continue
        xn, xa = A[col].dropna().to_numpy(), B[col].dropna().to_numpy()
        if len(xn) == 0 or len(xa) == 0:
            continue
        sa, sb = set(np.unique(xn)), set(np.unique(xa))
        ov = len(sa & sb) / max(1, len(sa | sb))
        bs = best_split(xn, xa)
        kind = ("STRUCTURAL" if col in (
            "span_count", "service_count", "operation_count", "max_depth",
            "max_fanout", "edge_count", "unique_edge_count", "db_span_count",
            "http_span_count", "distinct_http_targets", "distinct_db_statements",
            "distinct_http_methods", "error_span_count", "error_span_rate",
            "http_4xx_count", "http_5xx_count") else "TIMING")
        rows.append((col, kind, round(ov, 3), round(bs, 3),
                     f"[{xn.min():.0f}, {xn.max():.0f}]",
                     f"[{xa.min():.0f}, {xa.max():.0f}]"))
    r = pd.DataFrame(rows, columns=["feature", "kind", "value_overlap",
                                    "best_split_bal_acc", "range_A", "range_B"])
    r = r.sort_values("best_split_bal_acc", ascending=False)
    print(r.to_string(index=False))

    tim = r[r.kind == "TIMING"]
    struct = r[r.kind == "STRUCTURAL"]
    print(f"\n  TIMING features with a near-perfect split (>=0.95): "
          f"{int((tim.best_split_bal_acc >= 0.95).sum())} of {len(tim)}")
    print(f"  STRUCTURAL features with a near-perfect split (>=0.95): "
          f"{int((struct.best_split_bal_acc >= 0.95).sum())} of {len(struct)}")
    print("\n  Interpretation: both sets are normal-labelled traffic to the same")
    print("  endpoint with the same call-graph shape. Any separation here is a")
    print("  property of the collection session, not of the request.")
