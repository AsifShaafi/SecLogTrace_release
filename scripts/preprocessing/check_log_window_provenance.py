#!/usr/bin/env python3
"""B4 / R3-09: raw-log time-window provenance across all SUT1 scenarios.

For each collection window, compare the time range of the raw log records
against the generator transcript's own window. The nginx access log from
ts-ui-dashboard records every gateway request with a timestamp, method, path
and status, so it is an independent probe of what the capture actually holds.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter

RAW = Path("/mnt/user-data/uploads/SecLogTrace/sut1_data/data/raw/logs")
TRAFFIC = Path("/mnt/user-data/uploads/SecLogTrace/data/raw/traffic")

# nginx combined: 127.0.0.1 - - [29/Oct/2026:11:15:28 +0800] "GET /path HTTP/1.1" 403 148 "..." "..."
NGINX = re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})')
# Spring Boot app line
APP = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d{3}\s+trace_id=([0-9a-f]*)")
# Flask
FLASK = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\]")

WINDOWS = ["ssrf", "credential_abuse", "resource_exhaustion", "injection",
           "data_exfiltration"]
SERVER_UTC_OFFSET = timedelta(hours=8)   # research server logs in UTC+8


def generator_window(cls, label):
    """(start, end) in UTC from the generator transcript."""
    best = None
    for fp in TRAFFIC.glob("*.jsonl"):
        n = fp.stem
        if n.startswith("sut2") or not n.startswith(cls):
            continue
        recs = [json.loads(l) for l in open(fp) if l.strip()]
        recs = [r for r in recs if r.get("http_status") is not None]
        if not recs:
            continue
        labs = {r.get("class_label") for r in recs}
        lab = "normal" if labs == {"normal"} else "attack"
        if lab != label:
            continue
        ts = sorted(r["ts"] for r in recs)
        start = datetime.fromisoformat(ts[0]).astimezone(timezone.utc)
        end = datetime.fromisoformat(ts[-1]).astimezone(timezone.utc)
        if best is None or len(recs) > best[2]:
            best = (start, end, len(recs))
    return best


def local_to_utc(dt_naive):
    return dt_naive.replace(tzinfo=timezone.utc) - SERVER_UTC_OFFSET


def scan(path):
    """Return (nginx records, app-line times UTC, flask times UTC)."""
    ng, app, fl = [], [], []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = NGINX.search(line)
            if m:
                t = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S")
                off = m.group(2)
                sign = 1 if off[0] == "+" else -1
                delta = timedelta(hours=int(off[1:3]), minutes=int(off[3:5])) * sign
                ng.append((t.replace(tzinfo=timezone.utc) - delta,
                           m.group(3), m.group(4), m.group(5)))
                continue
            m = APP.match(line)
            if m:
                app.append(local_to_utc(
                    datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")))
                continue
            m = FLASK.match(line)
            if m:
                fl.append(local_to_utc(
                    datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")))
    return ng, app, fl


def fmt(dt):
    return dt.strftime("%m-%d %H:%M:%S") if dt else "-"


print("=== B4: raw-log window provenance, SUT1 (all times UTC) ===\n")
print(f"{'stratum':30s} {'generator window':>26s}  {'probe':14s} "
      f"{'records':>8s} {'record range':>26s}  verdict")
print("-" * 130)

rows = []
for cls in WINDOWS:
    for label in ["normal", "attack"]:
        gw = generator_window(cls, label)
        wdir = RAW / f"{cls}_{label}"
        gstr = f"{fmt(gw[0])}→{fmt(gw[1])}" if gw else "?"
        for probe, fname in [("nginx/ui-dash", "ts-ui-dashboard-785f7697b6-tzwtz.log"),
                             ("flask/avatar", "ts-avatar-service-6f8d8794f6-t9djl.log"),
                             ("app/order", "ts-order-service-5dc5fbbc74-b4mn2.log")]:
            p = wdir / fname
            if not p.exists():
                continue
            ng, app, fl = scan(p)
            times = [t for t, *_ in ng] if probe.startswith("nginx") else (fl if probe.startswith("flask") else app)
            if not times:
                print(f"{cls + '/' + label:30s} {gstr:>26s}  {probe:14s} "
                      f"{0:>8d} {'-':>26s}  no timestamped records")
                continue
            lo, hi = min(times), max(times)
            if gw:
                before = sum(t < gw[0] - timedelta(seconds=30) for t in times)
                after = sum(t > gw[1] + timedelta(seconds=30) for t in times)
                if before == 0 and after == 0:
                    verdict = "within named window"
                elif before and after:
                    verdict = f"SPANS BEYOND BOTH ENDS ({before} before, {after} after)"
                elif after:
                    verdict = f"EXTENDS PAST END ({after} records)"
                else:
                    verdict = f"STARTS BEFORE WINDOW ({before} records)"
            else:
                verdict = "no generator window"
            print(f"{cls + '/' + label:30s} {gstr:>26s}  {probe:14s} "
                  f"{len(times):>8d} {fmt(lo) + '→' + fmt(hi):>26s}  {verdict}")
            rows.append((cls, label, probe, len(times), lo, hi, verdict))
    print()

print("\n=== nginx request mix per window (independent cross-check of the generator) ===")
for cls in WINDOWS:
    for label in ["normal", "attack"]:
        p = RAW / f"{cls}_{label}" / "ts-ui-dashboard-785f7697b6-tzwtz.log"
        if not p.exists():
            continue
        ng, _, _ = scan(p)
        gw = generator_window(cls, label)
        inwin = [r for r in ng if gw and gw[0] <= r[0] <= gw[1]]
        paths = Counter(f"{m} {pa.split('?')[0]}" for _, m, pa, _ in inwin)
        status = Counter(s for *_, s in inwin)
        print(f"\n  {cls}/{label}: {len(ng)} nginx records, {len(inwin)} inside the generator window")
        print(f"    status in-window: {dict(status)}")
        for k, v in paths.most_common(6):
            print(f"      {v:6d}  {k[:84]}")
