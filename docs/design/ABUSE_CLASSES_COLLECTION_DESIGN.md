# Abuse-Class Collection Design & Playbook (2026-09-03, exfil added 2026-09-04)

Covers the four **no-code-change** Phase 2 attack classes — credential abuse,
resource exhaustion, injection, and data exfiltration — built together in one
generator, `scripts/collection/generate_abuse_traffic.py`, following the SSRF
template (`generate_ssrf_traffic.py`). SSRF (CWE-918) is done separately. All
five classes now have clean pilots (zero label leakage).

Pair with `docs/HANDOFF_20260827_attack_classes.md` (the task spec) and
`docs/design/SSRF_INJECTION_DESIGN.md` (the reference class). For the
end-to-end *why* of the whole trace+log pipeline (generate → export → logs →
audit → parse → feature table), see `docs/DATA_COLLECTION_PIPELINE.md`.

## Why one generator for three classes

All three require **no code change** — they script an abuse of an existing
endpoint — and share the SSRF template's exact shape (normal vs. attack at
the same endpoint, pilot with a 60s gap, per-sub-type labels, explicit
windows). Rather than three near-identical scripts, they are one
parameterized generator: `--class {credential_abuse,resource_exhaustion,
injection}` × `--mode {normal,attack,pilot}`. The reused payloads/request
logic come from the attack-only demo (`generate_attack_traffic.py`, the
tooling that produced the contaminated `attack_demo_001`); the collection
discipline that demo lacked (normal class, pilot/gap, explicit windows,
per-sub-type labels, the audit gate) is what this generator adds.

## The four classes

| Class | CWE | Endpoint | Attack sub-types |
|---|---|---|---|
| credential_abuse | CWE-307 | `POST /api/v1/users/login` | `cred_bruteforce` (wrong pw, real user), `cred_userenum` (non-existent users) |
| resource_exhaustion | CWE-400 | `POST /api/v1/travelservice/trips/left` | `resource_flood` (unpaced burst) |
| injection | CWE-89/943 | `POST /api/v1/travelservice/trips/left` | `inj_sqli`, `inj_nosqli`, `inj_pathtrav`, `inj_jndi`, `inj_xss` |
| data_exfiltration | CWE-200 | `GET /api/v1/admin*service/*` (bulk reads) | `exfil_orders`, `exfil_travels`, `exfil_users`, `exfil_contacts` |

The first three hit the **same endpoint** for normal and attack, differing
only in input and/or timing — a controlled within-endpoint comparison, so the
confound that withdrew the 82-vs-46 span finding is structurally absent.

- **credential_abuse normal:** successful, human-paced demo-user logins.
- **resource_exhaustion / injection normal:** the same fixed trip search
  (`nanjing->shanghai`) — the ONE query, held constant, so resource
  exhaustion isolates RATE and injection isolates the malformed INPUT (an
  earlier version rotated the normal pair and reintroduced a selectivity
  confound — fixed 2026-09-04; both classes now use `PRIMARY_PAIR`).

**data_exfiltration is different** — it needs admin auth and its signal is
an access pattern, not a single-endpoint input difference:
- **normal:** a legit admin reading routine operational dashboards (orders,
  travels) at human pace — never the PII tables.
- **attack:** an admin-credentialed sweep of ALL sensitive tables including
  the PII ones (users, contacts), in a burst. The shared endpoints (orders,
  travels) allow a within-endpoint check; the PII endpoints are attack-only
  (like SSRF's targets). Uses `DEMO_ADMIN` (222222) — never admin/admin.
  The generator logs `resp_bytes`/`record_count` so the data-volume signal
  is captured. **Pilot finding:** the signal is breadth + PII-endpoint
  access + rate, NOT per-trace structure (a bulk read is structurally
  identical whether legit or malicious) and NOT raw bytes.

## Expected signals (to CONFIRM at the pilot, not yet measured)

- **credential_abuse:** Train-Ticket returns **HTTP 200 with a body-level
  `status` flag** on a bad login, not an error code — so status-code /
  error-rate features will **not** separate this class. The signal is
  **request rate/timing** and **auth-failure log content**. Both normal and
  attack produce login-shaped traces; the attack differs by burst timing
  and `status != 1` bodies. State this in the paper accurately.
- **resource_exhaustion:** burst/volume in trace rate and timing at a
  shared endpoint — the clean within-endpoint volume comparison.
- **injection:** the queries are **very likely parameterized**, so expect
  **HTTP 200 with 0 results and no DB error**. The detectable signal is the
  **rejected-input request pattern** (atypical characters in a
  normally-clean field), not a successful injection. Characterize honestly —
  do not claim exploitation the traces don't show.

## Gotchas (baked into the generator)

- **Never target `admin`/`admin`** — trips the injected app-level
  `INVALID_PASSWORD_LENGTH_FAULT`. credential_abuse targets the demo user
  (`fdse_microservice`) with wrong passwords, and random non-existent
  usernames for enumeration — never admin.
- **Trip-search date is computed as today+3** so the legitimate normal
  search returns real trips; a stale hardcoded date returns 0 results and
  makes the normal class structurally thin. Override with `--search-date`.
- **Pacing is the signature:** normal defaults to 2.0s/request (human),
  attack to 0.0s (burst). `--pace` overrides both; don't unless you mean to.
- **One class per invocation.** Cross-class traffic in one window breaks the
  controlled comparison and the audit — each class is its own experiment.

## Collection playbook (run on the server, Baylor VPN, `~/SecLogTrace`)

Do this **per class**. Example uses credential_abuse; repeat for
`resource_exhaustion` and `injection`.

### 0. Validate logic locally first (no server needed)
```
python3 scripts/collection/generate_abuse_traffic.py \
    --class credential_abuse --mode pilot --dry-run
```

### 1. Pilot: 15 normal, 60s gap, 15 attack (two windows)
```
python3 scripts/collection/generate_abuse_traffic.py \
    --class credential_abuse --mode pilot
```
The console prints only the OUTER bounds (`Session start` = normal start,
`Session end` = attack end); it does NOT print the normal-end or attack-start.
The exact per-window bounds are the first/last `ts` field of each JSONL log
(`ts` is **UTC** — the `_HHMMSS` in the filename is local CDT, 5h behind; use
the `ts` fields, not the filename).

### 2. Compute the padded windows, then export each separately
**Pad each edge by only ~10s, NOT 60s** — the pilot gap between the two
windows is 60s, so a 60s pad would make the normal and attack windows
overlap and manufacture the exact label leakage the audit checks for. A
login/search trace completes in ~0.2s, so 10s is ample.
```
f_norm=$(ls -t data/raw/traffic/credential_abuse_pilot_normal_*.jsonl | head -1)
f_atk=$(ls -t data/raw/traffic/credential_abuse_pilot_attack_*.jsonl | head -1)
norm_start=$(date -u -d "$(head -1 "$f_norm" | jq -r .ts) - 10 seconds" +"%Y-%m-%dT%H:%M:%SZ")
norm_end=$(date -u -d "$(tail -1 "$f_norm" | jq -r .ts) + 10 seconds" +"%Y-%m-%dT%H:%M:%SZ")
atk_start=$(date -u -d "$(head -1 "$f_atk"  | jq -r .ts) - 10 seconds" +"%Y-%m-%dT%H:%M:%SZ")
atk_end=$(date -u -d "$(tail -1 "$f_atk"  | jq -r .ts) + 10 seconds" +"%Y-%m-%dT%H:%M:%SZ")
echo "normal: $norm_start -> $norm_end"; echo "attack: $atk_start -> $atk_end"

./scripts/collection/export_jaeger_traces.sh --label normal \
    --experiment credential_abuse_pilot \
    --start "$norm_start" --end "$norm_end" --limit 20000
./scripts/collection/export_jaeger_traces.sh --label attack \
    --experiment credential_abuse_pilot \
    --start "$atk_start" --end "$atk_end" --limit 20000
```

### 3. Capture logs for the SAME windows (UTC; the box is CDT/UTC-5)
```
mkdir -p data/raw/logs/credential_abuse_pilot_normal
for p in $(kubectl get pods -o name -n default | grep '/ts-'); do
  svc=$(basename "$p")
  kubectl logs -n default "$p" --since-time="$norm_start" \
    > "data/raw/logs/credential_abuse_pilot_normal/${svc}.log" 2>/dev/null
done   # repeat with $atk_start into .../credential_abuse_pilot_attack/
```
(`--since-time` takes only a start; the per-window join happens later by
trace_id in parse_service_logs.py, so this is fine.)
(Use `2>/dev/null`, not `2>&1` — `2>&1` leaks kubectl's banner into every
file; see phase_log_20260821.)

### 4. THE GATE — zero multi-label traces
```
python3 scripts/preprocessing/corpus_audit.py \
    'data/raw/jaeger/credential_abuse_pilot_normal/*.json' \
    'data/raw/jaeger/credential_abuse_pilot_attack/*.json' \
    --by-filename-label
```
Must report **Traces carrying MORE THAN ONE label : 0**. If not, the
export windows overlapped — re-export, do not proceed. This is the exact
check that failed on `experiment_001` (81% contaminated).

### 5. Parse → feature table → logs (run for BOTH windows)
Do each of these for `credential_abuse_pilot_normal` AND
`credential_abuse_pilot_attack` (swap the name and `--label`).
```
# 5a. raw Jaeger JSON -> traces.csv + spans.csv (one row per span)
python3 scripts/preprocessing/parse_jaeger_traces.py --label normal \
    --input-dir  data/raw/jaeger/credential_abuse_pilot_normal \
    --output-dir data/processed/traces/credential_abuse_pilot_normal

# 5b. spans/traces CSVs -> ONE feature row per trace (drops infra noise,
#     dedups on (trace_id, span_id); this is what the detectors train on)
python3 scripts/feature_extraction/build_feature_table.py \
    --spans  data/processed/traces/credential_abuse_pilot_normal/spans.csv \
    --traces data/processed/traces/credential_abuse_pilot_normal/traces.csv \
    --out    data/processed/combined/credential_abuse_pilot_normal_features.csv

# 5c. raw pod logs -> logs.csv + logs_by_trace.csv, with a trace_id join rate
python3 scripts/preprocessing/parse_service_logs.py \
    --input-dir  data/raw/logs/credential_abuse_pilot_normal \
    --output-dir data/processed/logs/credential_abuse_pilot_normal \
    --experiment-id credential_abuse_pilot_normal \
    --traces-csv data/processed/traces/credential_abuse_pilot_normal/traces.csv
```
Then characterize the signal **within the shared `root_operation` only**
(never pooled) — compare the two `*_features.csv` medians. Direction
matters for RQ3: SSRF *adds* spans; credential abuse *aborts early* (the
2026-09-03 pilot: normal 12 spans / 3 DB spans vs attack 8 / 1, with NO
error-code difference — bad logins are HTTP 200, so the signal is
structural + log content, not status).

### 6. Scale (~150+/class) and fold into the corpus
```
python3 scripts/collection/generate_abuse_traffic.py --class credential_abuse --mode normal --count 150
# ... 60s+ gap, separate window ...
python3 scripts/collection/generate_abuse_traffic.py --class credential_abuse --mode attack --count 150
```
Export/audit/parse as above, then a `metadata/*.md` file per class and a
phase-log entry. Class is corpus-ready when: metadata written, export
audits to zero leakage, feature table built, signal characterized.

## Prerequisites
- `pandas`/`numpy`/`matplotlib` importable (for parse/feature/stats steps) —
  `pip install -r scripts/feature_extraction/requirements.txt -r scripts/visualization/requirements.txt`
  (added 2026-08-26 after they were found missing mid-run; see
  phase_log_20260826).
- `requests` for the generator itself.
