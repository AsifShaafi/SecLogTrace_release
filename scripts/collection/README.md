# Traffic generation + collection — scripts/collection/

Generates labelled normal/attack traffic through a live SUT, then exports the
traces (and, for SUT2, logs) Jaeger captured, audits for label leakage, and
hands off to the preprocessing/feature pipeline. Last updated 2026-11-02.

**Authoritative status is `docs/PHASE_STATUS.md`, not this file.** SUT1 v1 is
frozen (2026-09-04); SUT2 v1 trace-only is done (N=150, 2026-09-18); corpus v2
(N=500, both SUTs, trace+log) is in progress on branch `corpus-v2`.

## The collection discipline (every class, every SUT)

normal window → 60s gap → attack window → windowed export → **zero-multi-label
audit gate** → parse traces/logs → feature table. The audit gate is
non-negotiable — it is the exact check that caught the 81%-contaminated
`experiment_001`. Pilot 15+15 first; require ZERO multi-label traces before
scaling. Same endpoint for normal and attack where possible, so the only
difference is input/timing (controlled comparison).

## Files

### Shared client / helpers
- `ts_client.py` — SUT1 Train-Ticket API client (login, booking flow,
  station/route browsing). Built from `merged_openapi_spec.yaml`. Gateway
  `http://<research-host>:32677`.
- `check_trip_catalog.py` — SUT1 only. Verifies the trip catalog is seeded
  before booking traffic. (The old "empty catalog" blocker was root-caused and
  fixed 2026-07-28 — catalog is seeded with 6 trips.)
- `session_log.py` — manual timestamp logger for hand-driven coverage sweeps.
- `init_workspace.sh`, `check_jaeger_services.sh` — one-off setup helpers.

### SUT1 (Train-Ticket) traffic generators
- `generate_baseline_traffic.py` — normal user sessions (register/login →
  browse → search → book/query). Extended 2026-08-20 for the full endpoint
  inventory (assurance, food, consign, cancel, rebook, execute, inside-payment).
- `generate_abuse_traffic.py` — the 3 no-code-change attack classes
  (credential_abuse CWE-307, resource_exhaustion CWE-400, injection CWE-89),
  `--mode normal|attack|pilot`, per-sub-type labels, controlled within-endpoint
  comparison. (data_exfiltration also runs through here.)
- `generate_ssrf_traffic.py` — SUT1 SSRF (CWE-918) against the injected
  `src_url` sink in `ts-avatar-service`. Hit **directly** on port 17001 (not
  gateway-routed). Normal = base64 upload (1 span); attack = outbound fetch
  (2–8 spans). Normal-class image must be a real face (`external/pic.jpg`) —
  the placeholder PNG 500s (dlib rejects it).
- `generate_attack_traffic.py` — **superseded demo**, kept for reference only.
  Produced the contaminated `attack_demo_001`. Do not use for corpus data.

### SUT2 (TeaStore) traffic generator
- `generate_sut2_traffic.py` — all 5 classes in one script, `--class <c>
  --mode normal|attack|pilot`. Discovers real seed IDs/usernames at runtime
  (`discover_seed_data` — TeaStore IDs are non-sequential and usernames are
  shuffled; do not hardcode). SSRF sink `image/rest/image/fetchFromUrl`
  (injected, verified 2026-09-18). Requires persistence (8081) and image
  (8082) published in the compose file.

### Corpus-scale wrappers (full pipeline, one command)
- `collect_abuse_corpus.sh <class> [count]` — SUT1 no-code-change classes.
  Run on the server from `~/SecLogTrace`. Default count 150/label.
- `collect_ssrf_corpus.sh [count] [image]` — SUT1 SSRF (own generator, direct
  port 17001, larger export pad for the ~10s closed-port timeouts).
- `collect_sut2_corpus.sh <class> [count] [pace]` — SUT2 **traces + logs**.
  Local OTel Jaeger (`http://localhost:16686/api`), logs from `docker compose
  logs`. Namespaced `sut2v2_` so v2 never collides with frozen v1. Default
  count 15 (pilot); use 500 for the v2 corpus.
- `export_jaeger_traces.sh` — the export engine every wrapper calls. Sweeps
  all services from `/api/services`, uses explicit microsecond `--start`/`--end`,
  sends an explicit `--limit` and **warns loudly on truncation**, writes a
  manifest with the DISTINCT trace count (the only count that belongs in a
  paper). Flags: `--experiment --label --start --end --limit --jaeger-api`
  (or `--minutes N`). Pass `--jaeger-api "http://localhost:16686/api"` for SUT2.
- `run_reliability_check.sh` — SUT1 cross-day reliability re-run (Phase 1).

## Usage

```bash
# SUT1 — one no-code-change class, full pipeline, on the server:
./scripts/collection/collect_abuse_corpus.sh injection 150

# SUT1 — SSRF (separate generator, direct port):
./scripts/collection/collect_ssrf_corpus.sh 150 external/pic.jpg

# SUT2 — pilot a class (traces+logs), then scale once the audit gate is clean:
TEASTORE_COMPOSE=../TeaStore/examples/docker/docker-compose_otel.yaml \
  ./scripts/collection/collect_sut2_corpus.sh ssrf 15      # pilot
  ./scripts/collection/collect_sut2_corpus.sh ssrf 500     # v2 corpus

# Pilot a class by hand (traffic only), inspect, then audit:
python scripts/collection/generate_sut2_traffic.py --class ssrf --mode pilot
```

## Setup

```bash
pip install -r scripts/collection/requirements.txt   # requests
```

The wrappers auto-pick an interpreter that actually imports `requests` (on
Windows `python3` can be a non-functional Store stub). `jq`, `docker`, and
`curl` must be on PATH. Collection runs under Git Bash on Windows; if a
Bash-tool shell can't find git/python/docker/jq, its PATH is Windows-format —
rebuild a Unix PATH first.

## Environment facts (don't rediscover)

- SUT1 gateway `http://<research-host>:32677`; Jaeger API
  `http://<research-host>:30005/jaeger/ui/api` (base path `/jaeger/ui`,
  Badger-persistent storage, 720h TTL).
- SUT1 credentials: `fdse_microservice`/`111111`, admin `admin`/`222222`.
  **Never send `admin`/`admin`** — triggers an injected
  `INVALID_PASSWORD_LENGTH_FAULT`.
- SUT2 (TeaStore) and the working copy both run **locally, off cloud-sync**
  (Box/OneDrive breaks Docker mounts and bash `chdir`). Jaeger API
  `http://localhost:16686/api`.
- Station table has leftover junk (`empirestatebuilding`, `12345678901`,
  `shinkansenbullettrain`) — not real stations; source pairs from
  `routeservice/routes` chains.

## Data-quality rules baked into these scripts

- **Never sum per-service trace counts** — Jaeger returns a trace per
  participating service, so they overlap. Dedup on distinct `trace_id`. The
  export manifest's distinct count is authoritative.
- **Infra noise is filtered, two mechanisms:** SUT1's `NacosWatch$$Lambda$.run`
  (distinctive op name) and jaeger-query self-noise by `NOISE_OPS`; SUT2's
  registry-poll noise has no distinctive name, so it's matched as a bare
  `GET`/`PUT` with no `http_url`, single-span only. Do not add generic verbs to
  `NOISE_OPS`.
- `parse_jaeger_traces.py`'s attack-label call needs `--append` or it
  overwrites the normal output. The wrappers already pass it.
