#!/usr/bin/env python3
"""
parse_jaeger_traces.py — raw Jaeger export JSON -> feature CSVs.

Phase 1 (Baseline Pipeline). Converts the raw exports in data/raw/jaeger/
(or data/raw/attack_demo/, see generate_attack_traffic.py) into two CSVs:

  - spans.csv  : one row per span (fine-grained: HTTP/DB/RPC detail)
  - traces.csv : one row per trace (aggregated: duration, span/service
                 counts, error flag — the level most detection models will
                 actually train on)

Usage:
    python3 parse_jaeger_traces.py \
        --input-dir ../../data/raw/jaeger \
        --output-dir ../../data/processed/traces \
        --label normal

    python3 parse_jaeger_traces.py \
        --input-dir ../../data/raw/attack_demo \
        --output-dir ../../data/processed/traces \
        --label attack --append

--label sets the label column when it can't be inferred from the filename.
Filenames matching *_normal_* or *_attack_* auto-detect; --label is the
fallback (and an explicit override if you pass it).

--append writes to the same CSVs instead of overwriting — use this to add
attack-demo traces to an existing normal-traffic CSV for a combined
dev/test file (NOT the official Phase 2 frozen corpus — this is for
early parser development and sanity-checking only).
"""
import argparse
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stratification import best_url_tag  # noqa: E402


def get_tag(tags: list, key: str, default=None):
    for t in tags or []:
        if t.get("key") == key:
            return t.get("value")
    return default


# Infra/service-discovery noise confirmed unrelated to real request traffic
# (NacosWatch polling) — everything else is classified, not discarded.
INFRA_NOISE_PATTERNS = ("NacosWatch",)

# Services that are collection/observability INFRASTRUCTURE, not part of the
# Train-Ticket system under test. A trace involving only these is not real
# request traffic and is filtered exactly like NacosWatch noise. The key case:
# `jaeger-query` traces are created by export_jaeger_traces.sh's OWN calls to
# the Jaeger API; when a collection script runs the export immediately after
# an attack burst, those query traces land inside the attack window's pad and
# would otherwise be miscounted as attack traffic (found 2026-09-04, corpus
# collection). Filtering by root/only-service keeps them out regardless.
INFRA_SERVICES = {"jaeger-query", "jaeger-all-in-one"}


def classify_span(operation: str, http_method: str, http_url: str = "") -> str:
    """Categorize a span so rows can be filtered analytically later without
    losing data at parse time. One of:
      http_endpoint   - has an HTTP method/path (the request boundary)
      controller      - Spring controller method (e.g. OrderController.createNewOrder)
      repository      - JPA/repository call (e.g. OrderRepository.save)
      db_query        - raw SQL span (e.g. "SELECT ts.orders")
      infra_noise     - confirmed non-request noise (NacosWatch, etc.)
      framework       - everything else (FilteringWebHandler, Transaction.commit, etc.)
    """
    if any(p in operation for p in INFRA_NOISE_PATTERNS):
        return "infra_noise"
    # SUT2 (TeaStore) registry-heartbeat / service-discovery noise. Unlike
    # SUT1's NacosWatch (distinctive operationName), OTel names these spans
    # with a BARE HTTP verb ("GET"/"PUT") and attaches no http.url tag at all
    # — whereas every real request span's operationName carries its path
    # (e.g. "GET /tools.descartes.teastore.persistence/rest/products"), so an
    # exact bare-verb match cannot hit a real request. Verified 2026-09-17
    # against real captured data (260/260 single-span noise traces matched,
    # zero real requests). The `not http_url` guard is defense-in-depth for a
    # future SUT where a bare-verb operation might legitimately carry a URL.
    if operation in ("GET", "PUT") and not http_url:
        return "infra_noise"
    if http_method:
        return "http_endpoint"
    if operation.upper().startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ")):
        return "db_query"
    if "Repository." in operation:
        return "repository"
    if "Controller." in operation:
        return "controller"
    return "framework"


def infer_label(filename: str, fallback: str) -> str:
    lower = filename.lower()
    if "_attack_" in lower or "attack_" in lower:
        return "attack"
    if "_normal_" in lower:
        return "normal"
    return fallback


def infer_experiment_id(filename: str) -> str:
    m = re.match(r"(experiment_\d+|attack_demo_\d+)", os.path.basename(filename))
    return m.group(1) if m else "unknown"


def parse_file(filepath: str, default_label: str, span_rows: list, trace_rows: list) -> int:
    with open(filepath, "r") as f:
        payload = json.load(f)

    data = payload.get("data", payload if isinstance(payload, list) else [])
    label = infer_label(filepath, default_label)
    experiment_id = infer_experiment_id(filepath)
    source_file = os.path.basename(filepath)
    n_traces = 0

    for trace in data:
        trace_id = trace.get("traceID")
        spans = trace.get("spans", [])
        processes = trace.get("processes", {})
        if not spans:
            continue
        n_traces += 1

        services_seen = set()
        operations_seen = set()
        span_types_seen = set()
        error_count = 0
        max_status = 0
        starts, ends = [], []
        root_span = None

        for s in spans:
            tags = s.get("tags", [])
            proc = processes.get(s.get("processID", ""), {})
            service_name = proc.get("serviceName", "unknown")
            operation = s.get("operationName", "")
            start_us = s.get("startTime", 0)
            duration_us = s.get("duration", 0)
            end_us = start_us + duration_us

            http_method = get_tag(tags, "http.method")
            # Was get_tag(tags, "http.url") or get_tag(tags, "http.target") --
            # the opposite preference order from stratification.py's URL_TAGS
            # (http.target first), a latent third divergence found while
            # extracting that module 2026-08-20. Unified here so spans.csv's
            # http_url column (which build_feature_table.py stratifies on)
            # can't drift from corpus_audit.py's choice again.
            http_url = best_url_tag(tags)
            http_status = get_tag(tags, "http.status_code")
            span_kind = get_tag(tags, "span.kind")
            db_statement = get_tag(tags, "db.statement")
            error_tag = get_tag(tags, "error", False)
            span_type = classify_span(operation, http_method, http_url)
            span_types_seen.add(span_type)
            is_error = bool(error_tag) or (isinstance(http_status, int) and http_status >= 400)

            # Infra noise (NacosWatch polling) is kept in spans.csv for
            # completeness but excluded from trace-level aggregates so it
            # doesn't skew service/operation counts for real request traces.
            if span_type != "infra_noise":
                services_seen.add(service_name)
                operations_seen.add(operation)
            if is_error:
                error_count += 1
            if isinstance(http_status, int):
                max_status = max(max_status, http_status)
            starts.append(start_us)
            ends.append(end_us)

            if not s.get("references"):
                root_span = s

            span_rows.append({
                "trace_id": trace_id,
                "span_id": s.get("spanID"),
                "parent_span_id": (s.get("references") or [{}])[0].get("spanID", ""),
                "service_name": service_name,
                "operation_name": operation,
                "span_type": span_type,
                "start_time_us": start_us,
                "duration_us": duration_us,
                "span_kind": span_kind or "",
                "http_method": http_method or "",
                "http_url": http_url or "",
                "http_status_code": http_status if http_status is not None else "",
                "db_statement": (db_statement or "")[:200],  # truncate long queries
                "is_error": is_error,
                "label": label,
                "experiment_id": experiment_id,
                "source_file": source_file,
            })

        trace_start = min(starts) if starts else 0
        trace_end = max(ends) if ends else 0
        is_noise_only = (span_types_seen == {"infra_noise"}
                         or (bool(services_seen)
                             and services_seen.issubset(INFRA_SERVICES)))
        trace_rows.append({
            "trace_id": trace_id,
            "root_service": processes.get(root_span.get("processID"), {}).get("serviceName", "unknown") if root_span else "unknown",
            "root_operation": root_span.get("operationName", "") if root_span else "",
            "start_time_us": trace_start,
            "duration_us": trace_end - trace_start,
            "num_spans": len(spans),
            "num_services": len(services_seen),
            "services": "|".join(sorted(services_seen)),
            "num_unique_operations": len(operations_seen),
            "error_count": error_count,
            "has_error": error_count > 0,
            "max_http_status": max_status,
            "is_infra_noise_only": is_noise_only,
            "label": label,
            "experiment_id": experiment_id,
            "source_file": source_file,
        })

    return n_traces


def write_csv(rows: list, path: str, append: bool):
    if not rows:
        return
    mode = "a" if append and os.path.exists(path) else "w"
    write_header = mode == "w"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, help="directory of raw Jaeger export *.json files")
    ap.add_argument("--output-dir", required=True, help="directory to write spans.csv / traces.csv")
    ap.add_argument("--label", default="normal", choices=["normal", "attack"],
                     help="fallback label when it can't be inferred from filename")
    ap.add_argument("--append", action="store_true",
                     help="append to existing CSVs instead of overwriting")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.input_dir, "*.json")))
    if not files:
        print(f"No .json files found in {args.input_dir}")
        return

    span_rows, trace_rows = [], []
    total_traces = 0
    for fp in files:
        try:
            n = parse_file(fp, args.label, span_rows, trace_rows)
            total_traces += n
            print(f"  parsed {os.path.basename(fp)}: {n} trace(s)")
        except Exception as e:
            print(f"  ERROR parsing {fp}: {e}")

    spans_path = os.path.join(args.output_dir, "spans.csv")
    traces_path = os.path.join(args.output_dir, "traces.csv")
    write_csv(span_rows, spans_path, args.append)
    write_csv(trace_rows, traces_path, args.append)

    noise_only_count = sum(1 for r in trace_rows if r["is_infra_noise_only"])
    print(f"\nDone. {total_traces} traces / {len(span_rows)} spans parsed from {len(files)} file(s).")
    if total_traces > 0:
        pct = 100 * noise_only_count / total_traces
        print(f"  -> {noise_only_count}/{total_traces} traces ({pct:.1f}%) are pure infra noise "
              f"(NacosWatch polling, zero real request content) — filter these out "
              f"(is_infra_noise_only == False) before computing baseline statistics.")
    print(f"Wrote: {spans_path} ({len(span_rows)} rows)")
    print(f"Wrote: {traces_path} ({len(trace_rows)} rows)")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()