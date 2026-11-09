#!/usr/bin/env python3
"""PROTOTYPE — de-leaked log-content feature for the SUT1 v2 log arm.

The naive TF-IDF over log messages leaked (resource_exhaustion scored 1.00 even
though its normal/attack logs are token-for-token identical) via two channels:
  1. collection-window tokens — dates (2026-10-31), times, trace/span ids;
  2. per-trace line COUNT — a trace with 172 repeated log lines amplifies term
     frequency, proxying request volume.

De-leak:
  (1) strip date / time / long-hex-id / long-int tokens (collection artifacts),
      but KEEP ips, payload chars and security keywords;
  (2) TfidfVectorizer(binary=True) — presence, not counts, so line volume cannot
      leak.
Validation: a correct de-leak should push resource_exhaustion to ~chance
(identical content) while preserving genuine content signal where it exists
(ssrf url, injection payloads, exfil args). Count-based log F1 (from the frozen
pipeline) is shown for reference. RF, 5-fold, seed 42; TF-IDF fit on train only.
"""
import os, re, warnings, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
warnings.filterwarnings("ignore")
RS, NF = 42, 5
CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion", "injection", "data_exfiltration"]
# count-based log-arm F1 from results/tables/detection_results.csv (reference)
COUNT_REF = {"ssrf":0.67,"credential_abuse":1.00,"resource_exhaustion":0.22,
             "injection":1.00,"data_exfiltration":0.67}

STRIP = [re.compile(r"\d{4}-\d{2}-\d{2}"),          # dates
         re.compile(r"\d{2}:\d{2}:\d{2}[.,\d]*"),    # times
         re.compile(r"\b[0-9a-f]{16,}\b"),           # trace/span ids, long hex
         re.compile(r"\b\d{10,}\b")]                 # epoch-ish long ints
def norm(m):
    m = m.lower()
    for p in STRIP: m = p.sub(" ", m)
    return m

def docs_and_y(cls, deleak):
    msgs = {}
    for label in ("normal","attack"):
        lp = f"data/processed/logs/{cls}_{label}/logs.csv"
        if not os.path.exists(lp): continue
        l = pd.read_csv(lp, dtype=str, keep_default_na=False, low_memory=False)
        l = l[l["trace_id"].str.len() > 0]
        if "is_infra_noise" in l.columns:
            l = l[l["is_infra_noise"].str.lower() != "true"]
        hp = l["http_path"] if "http_path" in l.columns else ""
        raw = (l["message"].fillna("") + " " + hp)
        l = l.assign(_d=[norm(x) for x in raw] if deleak else list(raw))
        for tid, g in l.groupby("trace_id"):
            # de-leak also de-dups identical lines (set) to further kill volume
            lines = set(g["_d"]) if deleak else list(g["_d"])
            msgs[tid] = " ".join(lines)
    ids, y = [], []
    for label, yy in (("normal",0),("attack",1)):
        df = pd.read_csv(f"data/processed/combined/{cls}_{label}_features.csv", usecols=["trace_id"])
        for t in df["trace_id"]:
            ids.append(t); y.append(yy)
    return [msgs.get(t,"") for t in ids], np.array(y)

def cv_text(docs, y, binary):
    skf = StratifiedKFold(NF, shuffle=True, random_state=RS); F=[]
    for tr, te in skf.split(np.zeros(len(y)), y):
        vec = TfidfVectorizer(max_features=400, binary=binary, token_pattern=r"(?u)\b\w+\b")
        Xtr = vec.fit_transform([docs[i] for i in tr])
        Xte = vec.transform([docs[i] for i in te])
        clf = RandomForestClassifier(n_estimators=200, random_state=RS)
        clf.fit(Xtr, y[tr]); F.append(f1_score(y[te], clf.predict(Xte), pos_label=1, zero_division=0))
    return np.mean(F)

print(f"{'class':20} | count-ref | naive-content | DE-LEAKED | verdict")
print("-"*78)
for cls in CLASSES:
    dn, y = docs_and_y(cls, deleak=False)
    dd, _ = docs_and_y(cls, deleak=True)
    naive = cv_text(dn, y, binary=False)
    deleaked = cv_text(dd, y, binary=True)
    ref = COUNT_REF[cls]
    verdict = ("rate class → should be ~chance" if cls=="resource_exhaustion"
               else f"{'+' if deleaked>ref+0.03 else '='} vs count-ref")
    print(f"{cls:20} |   {ref:.2f}    |     {naive:.2f}      |   {deleaked:.2f}    | {verdict}")
