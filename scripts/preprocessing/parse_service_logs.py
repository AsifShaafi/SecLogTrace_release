#!/usr/bin/env python3
"""
parse_service_logs.py — raw ts-* application logs -> logs.csv + logs_by_trace.csv

Phase 1 (Baseline Pipeline). Spec: docs/HANDOFF_20260818.md (unchanged from
the 2026-08-07 original). Converts the raw per-pod log files in
data/raw/logs/<experiment>/ (one file per pod, named
<service>-<replicaset-hash>-<pod-hash>.log) into:

  - logs.csv          : one row per log line, joinable against traces.csv /
                         spans.csv (parse_jaeger_traces.py's output) on
                         `trace_id`.
  - logs_by_trace.csv : one row per distinct non-empty `trace_id` — line
                         count, error/warn counts, and the set of services
                         that logged under that trace. The log-side feature
                         table Paper B's log-only detector trains on.

Pass --traces-csv (parse_jaeger_traces.py's traces.csv) to also get a
join-rate report: what fraction of REAL (non-infra-noise) trace_ids in
traces.csv have at least one matching log line, and vice versa. A low rate
means the log window and trace window don't line up, or a service logs
without trace context — it is NOT a defect for a trace to have zero log
lines if the session never exercised that service (confirmed 2026-08-07:
seven services legitimately showed none).

Line formats seen in the raw data (confirmed against
data/raw/logs/experiment_002/, 41 populated files, 2026-08-19):

  1. Application log line, request-scoped (the join-relevant case):
     2026-08-19 00:38:31.590 trace_id=b787...bcac span_id=6e33...171c
     trace_flags=01  INFO 7 --- [io-12346-exec-5]
     travel.controller.TravelController       : [adminQueryAll][...]

     `LOGGING_PATTERN_LEVEL` (rolled out 2026-08-07) puts trace_id/span_id/
     trace_flags on every line via MDC, but background-thread lines not
     bound to a request (23 confirmed in experiment_002, e.g. Ribbon's
     "Flipping property: ...ActiveConnectionsLimit" on the loadbalancer's
     own updater thread) have them present but EMPTY:
     "trace_id= span_id= trace_flags=  INFO ...". These parse as ordinary
     app rows with trace_id="" (unjoinable, correctly excluded from any
     trace-id-based join) rather than being merged into the previous
     record as a continuation line — that was the first bug found while
     building this script against real data.

  2. OTel Java agent noise, NOT request-scoped (metrics-export warnings
     printed on a ~1/min timer regardless of traffic):
     [otel.javaagent 2026-08-19 00:35:21:125 +0800] [OkHttp ...] WARN
     io.opentelemetry.exporter.internal.grpc.GrpcExporter - Failed to
     export metrics. ...
     Carries no trace_id — kept in the output (is_infra_noise=True) rather
     than silently dropped, mirroring how parse_jaeger_traces.py keeps
     NacosWatch spans instead of discarding them at parse time.

  3. Nginx/access-combined log line from ts-ui-dashboard (the gateway's
     reverse proxy) — a THIRD format, not a Spring Boot log at all:
     127.0.0.1 - - [19/Aug/2026:00:38:31 +0800] "GET
     /api/v1/adminorderservice/adminorder HTTP/1.1" 403 148 "http://..."
     "Mozilla/5.0 ..."
     No trace_id (this layer sits in front of the OTel-instrumented
     services), but http_status/http_method/http_path are pulled into
     their own columns because this is the only place the two 403s on
     admin.html flagged in phase_log_20260818.md (admintravelservice/
     admintravel, adminorderservice/adminorder) are visible at all.

  4. `kubectl`'s own CLI banner, NOT pod output at all: "Defaulted container
     "ts-x-service" out of: ts-x-service, agent-container (init)". kubectl
     prints this to stderr once per invocation on any multi-container pod
     when `-c` isn't given -- every ts-* pod qualifies (app container +
     the OTel agent's init container), so it appears exactly once per file
     on ANY collection that redirects `kubectl logs ... 2>&1` into the raw
     log file (confirmed 2026-08-21, `experiment_003`/`attack_demo_003`: 44
     of 44 populated files, one line each). The collection script should
     redirect kubectl's stderr away from the data file instead
     (`2>/dev/null`, not `2>&1`) so this doesn't recur -- recognized here
     anyway because past captures already have it baked into `data/raw/`,
     which this project never hand-edits after the fact.

  5. Anything else (kept in case a future collection has stack traces or a
     line format not seen here): treated as a continuation of the previous
     record if one exists in the same file (message appended), otherwise
     emitted as its own row with level=UNPARSED so nothing is silently
     lost.

Usage:
    python3 parse_service_logs.py \
        --input-dir ../../data/raw/logs/experiment_002 \
        --output-dir ../../data/processed/logs \
        --experiment-id experiment_002 \
        --traces-csv ../../data/processed/traces/traces.csv
"""
import argparse
import csv
import glob
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

APP_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"trace_id=(?P<trace_id>[0-9a-f]*)\s+"
    r"span_id=(?P<span_id>[0-9a-f]*)\s+"
    r"trace_flags=(?P<trace_flags>[0-9a-f]*)\s+"
    r"(?P<level>\w+)\s+"
    r"(?P<pid>\d+)\s+---\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<logger>\S+)\s*:\s*"
    r"(?P<message>.*)$"
)

# TeaStore (SUT2) Logback format. The request-boundary aspect logs through
# Logback with the pattern
#   %d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level trace_id=%X{trace_id:-} span_id=%X{span_id:-} %logger{36} - %msg
# i.e. level and thread come BEFORE trace_id, and there is no trace_flags/pid
# field (unlike SUT1's Spring Boot format above). trace_id/span_id are empty on
# lines emitted with no active span (startup), which parse as unjoinable rows.
TEASTORE_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<level>\w+)\s+"
    r"trace_id=(?P<trace_id>[0-9a-f]*)\s+"
    r"span_id=(?P<span_id>[0-9a-f]*)\s+"
    r"(?P<logger>\S+)\s+-\s+"
    r"(?P<message>.*)$"
)

# Metrics-export noise from the OTel Java agent itself — not tied to any
# request, and carries no trace_id. Timestamp uses HH:MM:SS:mmm (colon, not
# dot, before the millis) unlike the app format above.
OTEL_NOISE_RE = re.compile(
    r"^\[otel\.javaagent (?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):\d+ "
    r"[+-]\d{4}\]\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<level>\w+)\s+"
    r"(?P<logger>\S+)\s*-\s*"
    r"(?P<message>.*)$"
)

# Nginx/access-combined format from ts-ui-dashboard's reverse proxy.
ACCESS_LOG_RE = re.compile(
    r"^(?P<remote_addr>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<http_method>\S+)\s+(?P<http_path>\S+)\s+\S+"\s+'
    r"(?P<http_status>\d+)\s+(?P<bytes_sent>\S+)\s+"
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"$'
)

# kubectl's own stderr banner on a multi-container pod without -c, not pod
# output -- see docstring point 4.
KUBECTL_BANNER_RE = re.compile(r'^Defaulted container "[^"]+" out of: .*$')

# Kubernetes pod-name suffix: -<replicaset-hash>-<pod-hash>, e.g.
# ts-travel-service-d6b7c5644-tzq5x -> ts-travel-service
POD_SUFFIX_RE = re.compile(r"-[0-9a-f]{6,10}-[a-z0-9]{5}$")

FIELDNAMES = [
    "timestamp", "trace_id", "span_id", "trace_flags", "level",
    "service", "logger", "thread", "message", "has_trace_context",
    "pid", "is_infra_noise",
    "http_method", "http_path", "http_status", "bytes_sent",
    "pod_name", "source_file", "experiment_id",
]

# Columns every row gets by default; format-specific parsing overrides a
# subset of these per row.
BASE_ROW = {
    "trace_id": "", "span_id": "", "trace_flags": "", "timestamp": "",
    "level": "", "pid": "", "thread": "", "logger": "", "message": "",
    "is_infra_noise": False,
    "http_method": "", "http_path": "", "http_status": "", "bytes_sent": "",
}


def service_from_pod(pod_id: str) -> str:
    stripped = POD_SUFFIX_RE.sub("", pod_id)
    return stripped if stripped != pod_id else pod_id


def infer_experiment_id(input_dir: str) -> str:
    base = os.path.basename(os.path.normpath(input_dir))
    m = re.match(r"(experiment_\d+|attack_demo_\d+)", base)
    return m.group(1) if m else base


def parse_file(filepath: str, service: str, pod_name: str,
                experiment_id: str, rows: list) -> dict:
    source_file = os.path.basename(filepath)
    stats = {"lines": 0, "app": 0, "otel_noise": 0, "access": 0,
              "kubectl_banner": 0, "unparsed": 0, "continuation": 0}
    last_row = None

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            stats["lines"] += 1

            if KUBECTL_BANNER_RE.match(line):
                row = dict(BASE_ROW,
                           level="META", message=line, is_infra_noise=True,
                           has_trace_context=False,
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                last_row = row
                stats["kubectl_banner"] += 1
                continue

            m = APP_LINE_RE.match(line)
            if m:
                d = m.groupdict()
                row = dict(BASE_ROW,
                           trace_id=d["trace_id"], span_id=d["span_id"],
                           trace_flags=d["trace_flags"], timestamp=d["timestamp"],
                           level=d["level"], pid=d["pid"], thread=d["thread"],
                           logger=d["logger"], message=d["message"],
                           has_trace_context=bool(d["trace_id"]),
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                last_row = row
                stats["app"] += 1
                continue

            m = TEASTORE_LINE_RE.match(line)
            if m:
                d = m.groupdict()
                row = dict(BASE_ROW,
                           trace_id=d["trace_id"], span_id=d["span_id"],
                           trace_flags="", timestamp=d["timestamp"],
                           level=d["level"], pid="", thread=d["thread"],
                           logger=d["logger"], message=d["message"],
                           has_trace_context=bool(d["trace_id"]),
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                last_row = row
                stats["app"] += 1
                continue

            m = OTEL_NOISE_RE.match(line)
            if m:
                d = m.groupdict()
                row = dict(BASE_ROW,
                           timestamp=d["timestamp"], level=d["level"],
                           thread=d["thread"], logger=d["logger"],
                           message=d["message"], is_infra_noise=True,
                           has_trace_context=False,
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                last_row = row
                stats["otel_noise"] += 1
                continue

            m = ACCESS_LOG_RE.match(line)
            if m:
                d = m.groupdict()
                row = dict(BASE_ROW,
                           timestamp=d["timestamp"], level="ACCESS",
                           message=line, has_trace_context=False,
                           http_method=d["http_method"], http_path=d["http_path"],
                           http_status=d["http_status"], bytes_sent=d["bytes_sent"],
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                last_row = row
                stats["access"] += 1
                continue

            # None of the known formats: treat as a continuation of the
            # previous record (e.g. a wrapped stack trace line) if one
            # exists in this file, otherwise keep it as its own unparsed
            # row so nothing is silently dropped.
            if last_row is not None:
                last_row["message"] += "\n" + line
                stats["continuation"] += 1
            else:
                row = dict(BASE_ROW,
                           level="UNPARSED", message=line, has_trace_context=False,
                           service=service, pod_name=pod_name,
                           source_file=source_file, experiment_id=experiment_id)
                rows.append(row)
                stats["unparsed"] += 1

    return stats


def write_csv(rows: list, path: str, fieldnames: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


TRACE_AGG_FIELDNAMES = [
    "trace_id", "log_line_count", "error_count", "warn_count",
    "service_count", "services", "experiment_id",
]


def build_logs_by_trace(rows: list) -> list:
    """One row per distinct non-empty trace_id: line count, error/warn
    counts, and the set of services that logged under that trace — the
    log-side feature table for Paper B's log-only detector."""
    by_trace = defaultdict(lambda: {
        "log_line_count": 0, "error_count": 0, "warn_count": 0,
        "services": set(), "experiment_id": "",
    })
    for r in rows:
        tid = r["trace_id"]
        if not tid:
            continue
        agg = by_trace[tid]
        agg["log_line_count"] += 1
        level = r["level"].upper()
        if level == "ERROR":
            agg["error_count"] += 1
        elif level == "WARN":
            agg["warn_count"] += 1
        agg["services"].add(r["service"])
        agg["experiment_id"] = r["experiment_id"]

    out = []
    for tid, agg in by_trace.items():
        out.append({
            "trace_id": tid,
            "log_line_count": agg["log_line_count"],
            "error_count": agg["error_count"],
            "warn_count": agg["warn_count"],
            "service_count": len(agg["services"]),
            "services": "|".join(sorted(agg["services"])),
            "experiment_id": agg["experiment_id"],
        })
    return out


def join_rate_report(logs_rows: list, traces_csv_path: str) -> None:
    """Report what fraction of REAL (non-infra-noise) trace_ids in
    traces.csv have >=1 matching log line, and vice versa. A trace with
    zero log lines because the session never hit its service is expected,
    not a defect — this is a diagnostic, not a pass/fail gate."""
    with open(traces_csv_path, "r", encoding="utf-8") as f:
        trace_rows = list(csv.DictReader(f))
    if not trace_rows:
        print(f"  traces-csv {traces_csv_path} has no rows; skipping join-rate check")
        return

    all_trace_ids = {r["trace_id"] for r in trace_rows if r.get("trace_id")}
    noise_col = "is_infra_noise_only" if "is_infra_noise_only" in trace_rows[0] else None
    if noise_col:
        real_trace_ids = {
            r["trace_id"] for r in trace_rows
            if r.get("trace_id") and str(r.get(noise_col, "")).lower() not in ("true", "1")
        }
    else:
        real_trace_ids = all_trace_ids

    log_trace_ids = {r["trace_id"] for r in logs_rows if r["trace_id"]}

    joined = real_trace_ids & log_trace_ids
    print()
    print("  Join-rate check against traces.csv")
    print(f"    REAL traces in traces.csv    : {len(real_trace_ids)}")
    print(f"    distinct trace_id in logs.csv: {len(log_trace_ids)}")
    if real_trace_ids:
        pct = 100 * len(joined) / len(real_trace_ids)
        print(f"    REAL traces with >=1 log line: {len(joined)}/{len(real_trace_ids)} ({pct:.1f}%)")
    if log_trace_ids:
        pct2 = 100 * len(joined) / len(log_trace_ids)
        print(f"    logged trace_ids also in traces.csv: {len(joined)}/{len(log_trace_ids)} ({pct2:.1f}%)")
    print("    NOTE: a real trace with zero log lines is not necessarily a "
          "defect — it may belong to a service the session never exercised.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True,
                     help="directory of raw per-pod *.log files, e.g. data/raw/logs/experiment_002")
    ap.add_argument("--output-dir", required=True,
                     help="directory to write logs.csv / logs_by_trace.csv")
    ap.add_argument("--experiment-id", default=None,
                     help="defaults to the input-dir basename (e.g. experiment_002)")
    ap.add_argument("--traces-csv", default=None,
                     help="optional traces.csv from parse_jaeger_traces.py; "
                          "if given, reports the trace<->log join rate")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.input_dir, "*.log")))
    if not files:
        print(f"No .log files found in {args.input_dir}")
        return

    experiment_id = args.experiment_id or infer_experiment_id(args.input_dir)

    rows = []
    empty_files = []
    zero_trace_files = []
    totals = {"lines": 0, "app": 0, "otel_noise": 0, "access": 0,
              "kubectl_banner": 0, "unparsed": 0, "continuation": 0}

    for fp in files:
        pod_name = os.path.splitext(os.path.basename(fp))[0]
        service = service_from_pod(pod_name)
        stats = parse_file(fp, service, pod_name, experiment_id, rows)
        for k in totals:
            totals[k] += stats[k]

        if stats["lines"] == 0:
            empty_files.append(pod_name)
            print(f"  {pod_name}: empty")
            continue

        n_app = stats["app"]
        if n_app == 0 and stats["access"] == 0:
            zero_trace_files.append(pod_name)
        print(f"  {pod_name}: {stats['lines']} line(s) -> {n_app} app / "
              f"{stats['otel_noise']} otel-noise / {stats['access']} access / "
              f"{stats['kubectl_banner']} kubectl-banner / {stats['unparsed']} unparsed")

    logs_path = os.path.join(args.output_dir, "logs.csv")
    write_csv(rows, logs_path, FIELDNAMES)

    by_trace_rows = build_logs_by_trace(rows)
    by_trace_path = os.path.join(args.output_dir, "logs_by_trace.csv")
    write_csv(by_trace_rows, by_trace_path, TRACE_AGG_FIELDNAMES)

    distinct_traces = len({r["trace_id"] for r in rows if r["trace_id"]})
    print()
    print(f"Done. {len(files)} file(s), {totals['lines']} line(s) read.")
    print(f"  app (Spring Boot fmt)  : {totals['app']}")
    print(f"  otel-agent noise       : {totals['otel_noise']}")
    print(f"  access (nginx, no trace_id) : {totals['access']}")
    print(f"  kubectl CLI banner     : {totals['kubectl_banner']}")
    print(f"  unparsed               : {totals['unparsed']}")
    print(f"  continuation lines     : {totals['continuation']}")
    print(f"  distinct trace_id      : {distinct_traces}")
    if empty_files:
        print(f"  empty files ({len(empty_files)}): {', '.join(sorted(empty_files))}")
    if zero_trace_files:
        print(f"  non-empty but zero app/access lines ({len(zero_trace_files)}): "
              f"{', '.join(sorted(zero_trace_files))}")
    if totals["unparsed"]:
        print(f"  WARNING: {totals['unparsed']} line(s) matched neither known "
              f"format — inspect logs.csv rows with level=UNPARSED before "
              f"trusting coverage claims.")
    print(f"Wrote: {logs_path} ({len(rows)} rows)")
    print(f"Wrote: {by_trace_path} ({len(by_trace_rows)} rows)")

    if args.traces_csv:
        join_rate_report(rows, args.traces_csv)

    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()
