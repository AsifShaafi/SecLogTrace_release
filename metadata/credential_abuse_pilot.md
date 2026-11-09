# credential_abuse_pilot — Credential Abuse (CWE-307), pilot

> **Status: clean pilot (N=15+15), method-validating, not corpus scale.**
> First of the three no-code-change attack classes collected with the new
> `scripts/collection/generate_abuse_traffic.py`, following the SSRF
> template. Zero multi-label traces. Validates the class and its signal;
> scale to ~150+/class before citing detection numbers. Second of the five
> Phase 2 attack classes to reach a clean pilot (SSRF was first).

## Before collection
- Date/time windows (UTC), from the `035705` run's session logs:
  - normal: 2026-09-03T08:57:05 – 08:57:34 (15 requests, ~2s human pace)
  - 60s gap (script-enforced)
  - attack: 2026-09-03T08:58:36 – 08:58:39 (15 requests, unpaced burst)
- Endpoint (both classes, controlled within-endpoint comparison):
  `POST /api/v1/users/login`
- Purpose: pilot the credential-abuse class — repeated failed logins vs.
  legitimate logins at the same endpoint — and validate a clean,
  zero-leakage collection with the new multi-class generator.
- Actions performed:
  `generate_abuse_traffic.py --class credential_abuse --mode pilot`
  - normal: 15 successful, human-paced logins of the demo user
    (`fdse_microservice`), all HTTP 200 / `resp_status=1`
  - attack: 15 auth failures, two sub-types (weighted 3:1) —
    `cred_bruteforce` (11: wrong passwords against the REAL demo username)
    and `cred_userenum` (4: logins for non-existent usernames), all HTTP
    200 / `resp_status=0`
  - **never** targets `admin`/`admin` (that trips the injected
    `INVALID_PASSWORD_LENGTH_FAULT`)
- Collector: run on the server (gateway/Jaeger/kubectl reachable there).
- Session logs (the exported run): `data/raw/traffic/credential_abuse_pilot_normal_20260903_035705.jsonl`,
  `..._attack_20260903_035705.jsonl`.
- NOTE: an earlier run (`035617`) also exists in `data/raw/traffic/` and in
  Jaeger. It was **not** exported (its windows fall outside the exported
  `035705` windows, and the audit's exact 15+15 count confirms no leak-in).
  It also had only a ~2s normal→attack gap, not 60s, so it was correctly not
  used. Candidate for deletion to avoid confusion.

## During collection
- Gap between the normal and attack windows: 60s (script-enforced) — the
  discipline `experiment_001`'s postmortem found missing.
- All 30 requests completed; normal all `resp_status=1`, attack all
  `resp_status=0` (bad login is rejected at the body level, HTTP still 200).

## After collection
### Trace export
- Commands: `export_jaeger_traces.sh --label {normal,attack} --experiment
  credential_abuse_pilot --start <ISO> --end <ISO> --limit 20000`
  (windows padded ~10s each side — deliberately less than the 60s gap so the
  windows can't overlap).
- normal: sum 95 (never cite) / **distinct 80** / 65 dropped as infra noise
  → **15 real**
- attack: sum 58 (never cite) / **distinct 43** / 28 dropped as infra noise
  → **15 real**

### Joint corpus audit (the mandatory gate)
`corpus_audit.py 'data/raw/jaeger/credential_abuse_pilot_normal/*.json'
'data/raw/jaeger/credential_abuse_pilot_attack/*.json' --by-filename-label`:
- Combined distinct: 123, infra-noise-only: 93 (75.6%), real: 30 (15+15)
- **Traces carrying more than one label: 0** — passes the gate.
- Root operations: attack=1, normal=1, shared=1 — both classes hit
  `POST /* /api/v1/users/login` only, a clean controlled comparison.

### Signal characterization (within the shared endpoint — the only valid one)
Feature medians, normal (n=15) vs attack (n=15) at `POST /api/v1/users/login`:

| feature | normal | attack | reading |
|---|---|---|---|
| span_count | 12 | **8** | attack **aborts early** — opposite of SSRF (which adds spans) |
| db_span_count | 3 | **1** | headline discriminator: success verifies+loads+issues token (3 DB ops); failure stops at the user lookup (1) |
| service_count | 2 | 2 | same |
| max_depth | 6 | 6 | same |
| http_span_count | 3 | 3 | same |
| operation_count | 9 | 8 | ~same |
| error_span_count / http_5xx | 0 | 0 | **no error-code signal** — bad logins are HTTP 200 |
| trace_duration_us | 90,623 | 175,215 | attack *slower* despite fewer spans (plausibly the password-hash still runs on a wrong password); TIMING feature — treat cautiously per project rule, small N |

**One-paragraph signature:** Credential abuse is a *fewer-spans, fewer-DB-
spans* signal at a shared endpoint (8 vs 12 spans, 1 vs 3 DB spans), with
**no** status-code or error-rate separation because Train-Ticket returns
HTTP 200 with a body-level failure flag on a bad login. Detection must rely
on trace structure + log content, not error rate — exactly the case the
combined (trace+log) arm is meant to help. Direction (*aborts early*)
contrasts cleanly with SSRF (*adds spans*) for the RQ3 per-class analysis.

### Parsing
`parse_jaeger_traces.py`: normal 95 traces / 425 spans; attack (43 distinct
after dedup) / 268 spans. Infra-noise flagged and dropped downstream.
`build_feature_table.py`: 15 retained each, 29 features/trace.
Output: `data/processed/combined/credential_abuse_pilot_{normal,attack}_features.csv`.

### Log capture and join
- `data/raw/logs/credential_abuse_pilot_{normal,attack}/`: 46 files each,
  both windows captured (UTC).
- `parse_service_logs.py --traces-csv`: **15/15 (100%)** real traces have
  ≥1 log line for both classes; **100%** of logged trace_ids resolve to a
  real trace.
- Attack window carries more WARN-level log lines than normal (1632 vs
  1439) — consistent with auth-failure logging; the log-content side of the
  signal, to characterize more precisely at scale.
- Output: `data/processed/logs/credential_abuse_pilot_{normal,attack}/{logs,logs_by_trace}.csv`.
- **Known parser gap (not this class's fault):** `ts-avatar-service`
  (the SSRF-injected Python/Flask service) logs come back UNPARSED (170
  normal / 195 attack) because `parse_service_logs.py` only knows Spring
  Boot / otel / nginx formats. Avatar-service is untouched by auth traffic,
  so the 100% join is unaffected; flagged for a future parser update.

## Label
- Label: attack (paired with the normal window)
- Attack class: `credential_abuse` (CWE-307); sub-types `cred_bruteforce`,
  `cred_userenum`

## Notes for Phase 2
- **Corpus-ready to scale.** Method + signal validated; next is
  `--mode normal/attack --count 150` (separate windows, same
  export/audit/parse), then a scaled metadata file.
- Do NOT cite the N=15 medians as detection results — pilot only.
- Full generator/design detail: `docs/design/ABUSE_CLASSES_COLLECTION_DESIGN.md`;
  pipeline overview: `docs/DATA_COLLECTION_PIPELINE.md`; session:
  `docs/phase_logs/phase_log_20260903.md`.
