#!/usr/bin/env python3
"""
build_results_registry.py — canonical, row-order-independent results registry

Produces one row per (system, scenario, arm, model) for both systems under
test: 2 systems x 5 scenarios x 3 arms x 4 models = 120 unique keys.

Determinism
-----------
Cross-validation folds are assigned once, on a canonical ordering, and written
to a fold manifest keyed by an immutable record identifier. Every evaluation
reads folds from that manifest. Results therefore do not depend on the row
order of any input file.

The earlier approach relied on scikit-learn's StratifiedKFold shuffling by row
position, so re-saving a feature table in a different order silently changed
every reported score. The manifest removes that dependency, and
--verify-order-independence proves it by shuffling the inputs and confirming
the predictions are unchanged.

    record_id = sha256("<system>|<scenario>|<label>|<trace_id>")[:32]

Collisions are checked, not assumed.

Reported fields
---------------
Status is not a single exclusive label. Four independent fields are emitted so
a reader can separate a data-quality fact from a screening heuristic from an
interpretation risk:

  data_quality_status
      complete | source_not_instrumented | log_capture_not_interpretable

  balanced_acc_above_0p52_screen
      pass | fail. A named screening heuristic, nothing more. It reports
      whether pooled balanced accuracy exceeds 0.52, i.e. the 0.500 of a
      constant classifier plus a 0.02 margin. It is not a significance test
      and carries no uncertainty interval. The constant-classifier baselines
      are reported alongside on the same metrics so any comparison is explicit.

  interpretation_flags
      Semicolon-separated, possibly several per row, possibly none:
      session_confounded_possible, dependent_traces, presence_only,
      selection_bias, log_absence_not_interpretable.

  suitable_for_showcase_figure
      A recorded human decision, computed by the documented rule in
      FIGURE_RULE below. Rows excluded by it remain in the file.

Precision, recall and F1 appear twice. The *_foldmean columns average each
metric independently across folds, which is what the original scripts did. The
*_pooled columns compute each metric once from the concatenated out-of-fold
predictions. A fold-averaged F1 need not equal the harmonic mean of
fold-averaged precision and recall, so both are kept and the column names say
which is which.

Usage:
    python3 scripts/detection/build_results_registry.py \
        --processed-dir data/processed \
        --out-dir results/audit \
        --verify-order-independence
"""
import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import (IsolationForest, RandomForestClassifier,
                              HistGradientBoostingClassifier)
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import precision_recall_fscore_support, balanced_accuracy_score

RANDOM_STATE = 42
N_FOLDS = 5
SCREEN_THRESHOLD = 0.52
CONSTANT_CLASSIFIER_BALANCED_ACC = 0.50

CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion",
           "injection", "data_exfiltration"]
ARMS = ["trace", "log", "combined"]
MODELS = ["rule", "iforest", "rf", "hgb"]

DROP = {"trace_id", "record_id", "path_signature", "root_service",
        "root_operation", "label", "infra_noise", "experiment_id"}
LOG_FEATURES = ["log_line_count", "error_count", "warn_count", "log_service_count"]

# ---------------------------------------------------------------- provenance
# Scenario strata whose log capture cannot be interpreted per trace. The SSRF
# sink on SUT1 is a Flask application that logs errors without trace context,
# so an absent join cannot be read as an absent log record.
LOG_NOT_INTERPRETABLE = {("SUT1", "ssrf")}

# Timing features on SUT2 separate two same-label, shape-matched control
# sessions at about 0.95 balanced accuracy. Scenario/arm combinations whose
# discrimination rests on timing rather than structure therefore carry a
# possible session confound.
SESSION_CONFOUNDED = {("SUT2", "credential_abuse"), ("SUT2", "resource_exhaustion")}

# One generator operation yields several separately-rooted trace fragments, so
# rows are not independent observations.
DEPENDENT_TRACES = {("SUT2", "credential_abuse")}

# Retaining only complete-shape traces excludes the requests most affected by
# the load, which biases this stratum.
SELECTION_BIAS = {("SUT1", "resource_exhaustion")}

# The log arm separates these labels on a single presence bit, not on content.
PRESENCE_ONLY = {("SUT2", "injection", "log")}

FIGURE_RULE = ("data_quality_status == complete AND "
               "balanced_acc_above_0p52_screen == pass AND "
               "no flag in {session_confounded_possible, presence_only, "
               "log_absence_not_interpretable}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def record_id(system, scenario, label, trace_id):
    key = f"{system}|{scenario}|{label}|{trace_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def exclusion_keep(system, cls, label, f):
    """Traces not attributable to a generated request (SUT1 only)."""
    keep = pd.Series(True, index=f.index)
    if system != "SUT1":
        return keep
    if cls == "data_exfiltration":
        keep &= f["root_operation"] != "POST /* /api/v1/users/login"
    if cls == "ssrf" and label == "normal":
        keep &= ~((f["error_span_count"] > 0) | (f["http_5xx_count"] > 0))
    return keep


def load(processed, system, cls):
    """Post-exclusion rows in canonical order, with input hashes."""
    cols = ["trace_id", "log_line_count", "error_count", "warn_count", "service_count"]
    frames, srcs = [], []

    if system == "SUT1":
        for label in ("normal", "attack"):
            fp = processed / "combined" / f"{cls}_{label}_features.csv"
            lp = processed / "logs" / f"{cls}_{label}" / "logs_by_trace.csv"
            f = pd.read_csv(fp, dtype={"trace_id": str})
            f = f[exclusion_keep(system, cls, label, f)].copy()
            f["label"] = label
            logs = (pd.read_csv(lp, dtype={"trace_id": str})[cols]
                    .rename(columns={"service_count": "log_service_count"})
                    .drop_duplicates("trace_id"))
            d = f.merge(logs, on="trace_id", how="left")
            d[LOG_FEATURES] = d[LOG_FEATURES].fillna(0)
            frames.append(d)
            srcs += [fp, lp]
    else:
        fp = processed / "combined" / f"sut2v2_{cls}_features.csv"
        lp = processed / "logs" / f"sut2v2_{cls}" / "logs_by_trace.csv"
        allf = pd.read_csv(fp, dtype={"trace_id": str})
        allf = allf[allf["label"].isin(["normal", "attack"])].copy()
        logs = (pd.read_csv(lp, dtype={"trace_id": str})[cols]
                .rename(columns={"service_count": "log_service_count"})
                .drop_duplicates("trace_id"))
        d = allf.merge(logs, on="trace_id", how="left")
        d[LOG_FEATURES] = d[LOG_FEATURES].fillna(0)
        frames.append(d)
        srcs += [fp, lp]

    data = pd.concat(frames, ignore_index=True)
    data["record_id"] = [record_id(system, cls, l, t)
                         for l, t in zip(data["label"], data["trace_id"])]
    if data["record_id"].duplicated().any():
        raise SystemExit(f"record_id collision in {system}/{cls}")

    # Canonical order: label then record_id. Independent of input row order.
    data = data.sort_values(["label", "record_id"]).reset_index(drop=True)
    return data, {p.name: sha256_file(p) for p in sorted(set(srcs))}


def assign_folds(data):
    """Fold ids on the canonical ordering. Written to the manifest."""
    y = (data["label"] == "attack").astype(int).to_numpy()
    folds = np.full(len(y), -1, dtype=int)
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    for k, (_, te) in enumerate(skf.split(np.zeros((len(y), 1)), y)):
        folds[te] = k
    assert (folds >= 0).all()
    return folds, y


def matrices(data):
    tcols = [c for c in data.columns
             if c not in DROP and c not in LOG_FEATURES
             and pd.api.types.is_numeric_dtype(data[c])]
    Xt = data[tcols].fillna(0).to_numpy()
    Xl = data[LOG_FEATURES].fillna(0).to_numpy()
    return {"trace": Xt, "log": Xl, "combined": np.hstack([Xt, Xl])}, tcols


def make(model):
    if model == "rule":
        return DecisionTreeClassifier(max_depth=3, random_state=RANDOM_STATE)
    if model == "rf":
        return RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE)
    if model == "hgb":
        return HistGradientBoostingClassifier(random_state=RANDOM_STATE)
    raise ValueError(model)


def evaluate(X, y, folds, model):
    """Out-of-fold predictions using the stored fold assignment."""
    pooled = np.full(len(y), -1, dtype=int)
    per_fold = []
    for k in range(N_FOLDS):
        te = np.flatnonzero(folds == k)
        tr = np.flatnonzero(folds != k)
        if model == "iforest":
            Xn = X[tr][y[tr] == 0]
            if len(Xn) < 5:
                continue
            clf = IsolationForest(random_state=RANDOM_STATE, n_estimators=200)
            clf.fit(Xn)
            pred = (clf.predict(X[te]) == -1).astype(int)
        else:
            clf = make(model)
            clf.fit(X[tr], y[tr])
            pred = clf.predict(X[te])
        pooled[te] = pred
        p, r, f, _ = precision_recall_fscore_support(
            y[te], pred, average="binary", pos_label=1, zero_division=0)
        per_fold.append((p, r, f))
    return pooled, np.array(per_fold) if per_fold else np.zeros((1, 3))


def pooled_metrics(y, pred, prefix=""):
    p, r, f, _ = precision_recall_fscore_support(
        y, pred, average="binary", pos_label=1, zero_division=0)
    return {
        f"{prefix}precision_pooled": round(p, 4),
        f"{prefix}recall_pooled": round(r, 4),
        f"{prefix}f1_pooled": round(f, 4),
        f"{prefix}balanced_acc_pooled": round(balanced_accuracy_score(y, pred), 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--out-dir", default="results/audit")
    ap.add_argument("--verify-order-independence", action="store_true")
    args = ap.parse_args()

    processed = Path(args.processed_dir)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    code_hash = sha256_file(Path(__file__))
    env = {"python": platform.python_version(), "sklearn": sklearn.__version__,
           "numpy": np.__version__, "pandas": pd.__version__}

    rows, manifest, verify = [], [], []

    for system in ["SUT1", "SUT2"]:
        for cls in CLASSES:
            data, hashes = load(processed, system, cls)
            folds, y = assign_folds(data)
            arms, tcols = matrices(data)

            manifest.append(pd.DataFrame({
                "record_id": data["record_id"], "system": system,
                "scenario": cls, "label": data["label"], "fold_id": folds}))

            # Constant-classifier baselines on this stratum's labels.
            base = {}
            for nm, pred in (("all_attack", np.ones_like(y)),
                             ("all_normal", np.zeros_like(y))):
                base[nm] = pooled_metrics(y, pred, prefix=f"baseline_{nm}_")

            for arm in ARMS:
                for model in MODELS:
                    pooled, pf = evaluate(arms[arm], y, folds, model)
                    m = pooled_metrics(y, pooled)
                    tp = int(((pooled == 1) & (y == 1)).sum())
                    fp = int(((pooled == 1) & (y == 0)).sum())
                    fn = int(((pooled == 0) & (y == 1)).sum())
                    tn = int(((pooled == 0) & (y == 0)).sum())

                    # --- the four independent fields ---
                    if (system, cls) in LOG_NOT_INTERPRETABLE and arm in ("log", "combined"):
                        dq = "log_capture_not_interpretable"
                    else:
                        dq = "complete"

                    screen = ("pass" if m["balanced_acc_pooled"] > SCREEN_THRESHOLD
                              else "fail")

                    flags = []
                    if (system, cls) in SESSION_CONFOUNDED and arm in ("trace", "combined"):
                        flags.append("session_confounded_possible")
                    if (system, cls) in DEPENDENT_TRACES:
                        flags.append("dependent_traces")
                    if (system, cls, arm) in PRESENCE_ONLY:
                        flags.append("presence_only")
                    if (system, cls) in SELECTION_BIAS:
                        flags.append("selection_bias")
                    if dq == "log_capture_not_interpretable":
                        flags.append("log_absence_not_interpretable")

                    blocking = {"session_confounded_possible", "presence_only",
                                "log_absence_not_interpretable"}
                    figure = (dq == "complete" and screen == "pass"
                              and not (set(flags) & blocking))

                    rows.append(dict(
                        system=system, scenario=cls, arm=arm, model=model,
                        n=len(y), n_normal=int((y == 0).sum()),
                        n_attack=int((y == 1).sum()),
                        precision_foldmean=round(float(pf[:, 0].mean()), 4),
                        recall_foldmean=round(float(pf[:, 1].mean()), 4),
                        f1_foldmean=round(float(pf[:, 2].mean()), 4),
                        **m,
                        f1_foldmean_minus_pooled=round(
                            float(pf[:, 2].mean()) - m["f1_pooled"], 4),
                        tp=tp, fp=fp, fn=fn, tn=tn,
                        predicted_positive=int((pooled == 1).sum()),
                        predicted_positive_rate=round(float((pooled == 1).mean()), 4),
                        **base["all_attack"], **base["all_normal"],
                        balanced_acc_minus_constant_classifier=round(
                            m["balanced_acc_pooled"] - CONSTANT_CLASSIFIER_BALANCED_ACC, 4),
                        f1_pooled_minus_all_attack_f1=round(
                            m["f1_pooled"] - base["all_attack"]["baseline_all_attack_f1_pooled"], 4),
                        data_quality_status=dq,
                        balanced_acc_above_0p52_screen=screen,
                        screen_threshold=SCREEN_THRESHOLD,
                        screen_definition="pooled balanced accuracy > 0.52; "
                                          "heuristic screen, not a significance test",
                        interpretation_flags=";".join(flags),
                        suitable_for_showcase_figure=bool(figure),
                        figure_rule=FIGURE_RULE,
                        random_seed=RANDOM_STATE, n_folds=N_FOLDS,
                        fold_assignment="stored_manifest_by_record_id",
                        canonical_order="sort by (label, record_id)",
                        grouped_folds="unavailable_no_operation_id",
                        code_sha256=code_hash,
                        library_versions=json.dumps(env, sort_keys=True),
                        input_sha256=json.dumps(hashes, sort_keys=True),
                    ))

            # --------- order-independence verification for this stratum ---------
            if args.verify_order_independence:
                perm = np.random.default_rng(7).permutation(len(data))
                shuffled = data.iloc[perm].reset_index(drop=True)
                fmap = dict(zip(data["record_id"], folds))
                f2 = shuffled["record_id"].map(fmap).to_numpy()
                y2 = (shuffled["label"] == "attack").astype(int).to_numpy()
                arms2, _ = matrices(shuffled)
                for arm in ARMS:
                    for model in ["rule", "rf"]:
                        p1, _ = evaluate(arms[arm], y, folds, model)
                        p2, _ = evaluate(arms2[arm], y2, f2, model)
                        inv = dict(zip(data["record_id"], p1))
                        expected = shuffled["record_id"].map(inv).to_numpy()
                        verify.append(dict(system=system, scenario=cls, arm=arm,
                                           model=model,
                                           identical=bool((p2 == expected).all())))

    reg = pd.DataFrame(rows)
    reg.to_csv(out / "results_registry_canonical.csv", index=False)
    pd.concat(manifest, ignore_index=True).to_csv(out / "fold_manifest.csv", index=False)

    print("=== canonical results registry (row-order independent) ===")
    print(f"  rows {len(reg)}   unique keys "
          f"{len(reg[['system','scenario','arm','model']].drop_duplicates())}   expected 120")
    print(f"  fold manifest rows: {sum(len(m) for m in manifest)}")

    print("\n  data_quality_status:")
    print(reg.data_quality_status.value_counts().to_string())
    print("\n  balanced_acc_above_0p52_screen:")
    print(reg.balanced_acc_above_0p52_screen.value_counts().to_string())
    print("\n  interpretation_flags (rows carrying each flag):")
    allf = [f for s in reg.interpretation_flags for f in (s.split(";") if s else [])]
    print(pd.Series(allf).value_counts().to_string() if allf else "   none")
    print(f"\n  suitable_for_showcase_figure: "
          f"{int(reg.suitable_for_showcase_figure.sum())} of {len(reg)}")
    print(f"  rule: {FIGURE_RULE}")

    gaps = reg[reg.f1_foldmean_minus_pooled.abs() > 0.01]
    print(f"\n=== fold-mean vs pooled F1, gaps > 0.01: {len(gaps)} cells, "
          f"max {reg.f1_foldmean_minus_pooled.abs().max():.4f} ===")
    print(gaps[["system", "scenario", "arm", "model", "f1_foldmean", "f1_pooled",
                "f1_foldmean_minus_pooled"]].to_string(index=False))

    if verify:
        v = pd.DataFrame(verify)
        v.to_csv(out / "order_independence_check.csv", index=False)
        print(f"\n=== R5-04 order-independence verification ===")
        print(f"  checks run: {len(v)}   identical predictions: "
              f"{int(v.identical.sum())}/{len(v)}")
        if not v.identical.all():
            print(v[~v.identical].to_string(index=False))
        else:
            print("  shuffling the input rows leaves every prediction unchanged.")

    print(f"\nWrote {out}/results_registry_canonical.csv, {out}/fold_manifest.csv")


if __name__ == "__main__":
    main()
