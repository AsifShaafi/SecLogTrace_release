# Data Schema — SecLogTrace corpus

One row per **trace**. The feature-table header is **identical across both
SUTs** (Train-Ticket and TeaStore). Per-trace log features live in a separate
table joined on `trace_id`.

## Feature table — `data/processed/combined/<name>_features.csv`

`<name>` is `sut1v2_<class>` / `sut2v2_<class>` (combined labels) or, for SUT1,
the split `<class>_{normal,attack}` pair. 29 columns.

### Identity / labels
| Column | Type | Description |
|---|---|---|
| `trace_id` | string | Unique trace id; the join key to the log table. |
| `label` | enum | Ground-truth class: `normal` or `attack`. |
| `experiment_id` | string | Provenance stamp: `sut1v2_<class>` or `sut2v2_<class>`. |
| `infra_noise` | bool | True if the trace is service-discovery/registry heartbeat noise (filtered out of the analysed set). |

### Structural (call-graph shape)
| Column | Type | Description |
|---|---|---|
| `span_count` | int | Number of spans in the trace. |
| `service_count` | int | Distinct services touched. |
| `operation_count` | int | Distinct operation names. |
| `max_depth` | int | Depth of the deepest span in the parent→child tree. |
| `max_fanout` | int | Max number of direct children of any one span. |
| `edge_count` | int | Count of cross-service parent→child call edges. |
| `unique_edge_count` | int | Distinct `caller>callee` service edges. |
| `path_signature` | string | SHA-1 (16 hex) of the sorted set of service edges — a stable shape fingerprint. |
| `root_service` | string | Service of the root span. |
| `root_operation` | string | Normalised root operation (operation name + URL template). |

### Timing (microseconds)
| Column | Type | Description |
|---|---|---|
| `trace_duration_us` | float | Wall-clock span of the trace (max end − min start). |
| `span_dur_mean` | float | Mean span duration. |
| `span_dur_median` | float | Median span duration. |
| `span_dur_p95` | float | 95th-percentile span duration. |
| `span_dur_max` | float | Max span duration. |
| `span_dur_std` | float | Std. dev. of span duration. |

### Error / HTTP
| Column | Type | Description |
|---|---|---|
| `error_span_count` | int | Spans flagged as errors. |
| `error_span_rate` | float | `error_span_count / span_count`. |
| `http_4xx_count` | int | Spans with HTTP status 400–499. |
| `http_5xx_count` | int | Spans with HTTP status ≥ 500. |

> **SUT2 note:** TeaStore spans carry no `http.status_code`/`http.method` tag, so
> `http_4xx_count`, `http_5xx_count`, `error_span_count`, `error_span_rate` are
> inert (all 0/NA) on SUT2 — a documented cross-system instrumentation
> difference, not missing data (see `DATA_STATEMENT.md §3`, `CROSS_SYSTEM_ANALYSIS.md §7`).

### Interaction mix
| Column | Type | Description |
|---|---|---|
| `db_span_count` | int | Spans that are database operations. |
| `http_span_count` | int | Spans that are HTTP calls. |
| `distinct_http_targets` | int | Distinct HTTP targets called. |
| `distinct_db_statements` | int | Distinct DB statements issued. |
| `distinct_http_methods` | int | Distinct HTTP methods used. |

## Per-trace log features — `data/processed/logs/<experiment>/logs_by_trace.csv`

One row per trace that has at least one application log line. Left-joined onto
the feature table by `trace_id`; traces with no log line are zero-filled
(e.g. SUT2 injection attacks, rejected before the handler runs).

| Column | Type | Description |
|---|---|---|
| `trace_id` | string | Join key. |
| `log_line_count` | int | Application log lines correlated to this trace. |
| `error_count` | int | Lines at ERROR level. |
| `warn_count` | int | Lines at WARN level. |
| `service_count` | int | Distinct services that logged for this trace. |
| `services` | string | Comma-separated list of those services. |
| `experiment_id` | string | Provenance stamp (as above). |

## Labels and sub-types
`label` is the binary ground truth. Attack sub-types (recorded in the
collection transcripts / metadata) are: `cred_bruteforce` / `cred_userenum`;
`resource_flood`; `inj_{sqli,nosqli,pathtrav,jndi,xss}`;
`exfil_{orders,travels,users,contacts}`;
`ssrf_{db_reach,internal_svc,closed_port}` (SUT1) and the SUT2 equivalents in
`metadata/sut2v2_<class>.md`.

Raw traces (`data/raw/jaeger/`) and raw logs (`data/raw/logs/`) are the DOI
archive bulk; the feature tables, per-trace log features, and traffic session
logs are the citable git core (see `DATA_STATEMENT.md §9`).
