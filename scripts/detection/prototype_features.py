#!/usr/bin/env python3
"""PROTOTYPE (exploratory, not the frozen pipeline) — does adding the two
missing feature families move the needle on the SUT1 v2 corpus?

  (B1) session-rate feature  — per-trace local request density (windowed count
       over the pooled normal+attack timeline from start_time_us). Targets
       resource_exhaustion, whose signal is session-level RATE, absent from the
       per-trace structural/timing features.
  (B2) log-content features  — per-fold TF-IDF over the trace-correlated log
       messages (+ http_path). Targets the log arm for ssrf / injection /
       data_exfiltration, where the signal is line CONTENT (URL, payload, bulk
       args) that the count-based log features (log_line_count, …) cannot encode.

Classifiers compared: RandomForest (pipeline baseline) and HistGradientBoosting
(the stronger tabular model just added to run_detection.py). F1 = attack class,
5-fold stratified, seed 42 (matching run_detection.py). TF-IDF is fit on the
train fold only. Leakage note: the session-rate feature reflects the controlled
collection (normal vs attack were separate-rate windows); it is a session-level
feature a streaming detector would compute, and its separability CONFIRMS
resource_exhaustion is a rate phenomenon — it is not a per-trace structural signal.
"""
import os, warnings, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
warnings.filterwarnings("ignore")
RS, NF = 42, 5
CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion", "injection", "data_exfiltration"]
DROP = {"trace_id","path_signature","root_service","root_operation","label",
        "infra_noise","experiment_id","start_time_us"}
RATE_W = 5.0  # seconds, half-window for local rate

def load(cls):
    frames = []
    for label, y in (("normal",0),("attack",1)):
        df = pd.read_csv(f"data/processed/combined/{cls}_{label}_features.csv")
        tr = pd.read_csv(f"data/processed/traces/{cls}_{label}/traces.csv",
                         usecols=["trace_id","start_time_us"]).drop_duplicates("trace_id")
        df = df.merge(tr, on="trace_id", how="left"); df["_y"] = y
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    y = data["_y"].to_numpy()
    tcols = [c for c in data.columns if c not in DROP and c != "_y"
             and pd.api.types.is_numeric_dtype(data[c])]
    Xtr = data[tcols].fillna(0).to_numpy()
    # (B1) session-rate: local request density over the pooled timeline
    t = (data["start_time_us"].fillna(0).to_numpy()) / 1e6
    ts = np.sort(t)
    rate = np.array([(np.searchsorted(ts, ti+RATE_W) - np.searchsorted(ts, ti-RATE_W)) / (2*RATE_W)
                     for ti in t]).reshape(-1,1)
    # (B2) per-trace log message docs (trace-correlated, non-noise app lines)
    msgs = {}
    for label in ("normal","attack"):
        lp = f"data/processed/logs/{cls}_{label}/logs.csv"
        if not os.path.exists(lp): continue
        l = pd.read_csv(lp, dtype=str, keep_default_na=False, low_memory=False)
        l = l[l["trace_id"].str.len() > 0]
        if "is_infra_noise" in l.columns:
            l = l[l["is_infra_noise"].str.lower() != "true"]
        hp = l["http_path"] if "http_path" in l.columns else ""
        l = l.assign(_doc=(l["message"].fillna("") + " " + hp))
        for tid, g in l.groupby("trace_id"):
            msgs[tid] = " ".join(g["_doc"].tolist())
    docs = [msgs.get(tid,"") for tid in data["trace_id"]]
    return Xtr, rate, docs, y

def cv(make, parts, y, text_idx=None):
    skf = StratifiedKFold(NF, shuffle=True, random_state=RS); F=[]
    for tr, te in skf.split(np.zeros(len(y)), y):
        Mtr, Mte = [], []
        for i, p in enumerate(parts):
            if text_idx is not None and i == text_idx:
                vec = TfidfVectorizer(max_features=300, token_pattern=r"(?u)\b\w+\b", lowercase=True)
                Mtr.append(vec.fit_transform([p[j] for j in tr]).toarray())
                Mte.append(vec.transform([p[j] for j in te]).toarray())
            else:
                Mtr.append(p[tr]); Mte.append(p[te])
        clf = make(); clf.fit(np.hstack(Mtr), y[tr])
        F.append(f1_score(y[te], clf.predict(np.hstack(Mte)), pos_label=1, zero_division=0))
    return np.mean(F)

RF  = lambda: RandomForestClassifier(n_estimators=200, random_state=RS)
HGB = lambda: HistGradientBoostingClassifier(random_state=RS)

print(f"{'class':20} | trace  trace+rate(rf/hgb) | logCount logContent(rf/hgb) | comb  comb+rate+content(rf/hgb)")
print("-"*118)
for cls in CLASSES:
    Xtr, rate, docs, y = load(cls)
    have_logs = any(d for d in docs)
    t_base = cv(RF, [Xtr], y)
    t_rate_rf = cv(RF, [Xtr, rate], y); t_rate_hgb = cv(HGB, [Xtr, rate], y)
    # log arm: count-based baseline uses the pipeline's LOG_FEATURES; here we contrast
    # content TF-IDF only (vs the known count-based numbers in detection_results.csv)
    lc_rf = cv(RF, [docs], y, text_idx=0) if have_logs else float('nan')
    lc_hgb = cv(HGB, [docs], y, text_idx=0) if have_logs else float('nan')
    c_base = cv(RF, [Xtr], y)  # trace == combined-ish baseline proxy
    c_all_rf = cv(RF, [Xtr, rate, docs], y, text_idx=2) if have_logs else cv(RF,[Xtr,rate],y)
    c_all_hgb = cv(HGB, [Xtr, rate, docs], y, text_idx=2) if have_logs else cv(HGB,[Xtr,rate],y)
    print(f"{cls:20} | {t_base:.2f}   {t_rate_rf:.2f}/{t_rate_hgb:.2f}        | "
          f"  {lc_rf:.2f}     {lc_hgb:.2f}          |      {c_all_rf:.2f}/{c_all_hgb:.2f}")
