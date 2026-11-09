# SUT1 (Train-Ticket) v2 corpus collection protocol

**Date:** 2026-10-28. **Run on the server** (`<research-host>`), from
`~/SecLogTrace`. Self-contained.

## Status — EXECUTED 2026-10-28 (on `corpus-v2`; initial corpus committed `8a0fecd`, top-up 2026-10-29 pending commit)

All 5 classes collected on the server; each passed the zero-multi-label gate,
and a corpus-wide audit across all 5 is also clean. Final feature-table counts:
credential_abuse **500/500**, resource_exhaustion **500/500** (topped up 2026-10-29), injection
**500/500**, data_exfiltration **501/501**, ssrf **503/500** (total **5,005**).
resource_exhaustion reached 500/500 by pooling two attack bursts (flood
truncation caps single-burst clean yield ≈38%); see the 2026-10-29 addendum in
the phase log. Infra incidents handled mid-run (MySQL leader, Jaeger
OOM→6 GiB, host disk full→Badger prune, stale port-forward→node-IP export);
full detail in `docs/phase_logs/phase_log_20261028.md` and the Corpus v2 block
of `docs/PHASE_STATUS.md`. Exports used
`JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (host port-forward was
stale). Next: researcher approval to commit; metadata/data-statement v2.

## Goal

Collect a larger **v2** SUT1 corpus at **N=500 requests per label** for all five
attack classes, **without disturbing frozen v1** (1,503 real traces, locked
2026-09-04), which the detection study relies on.

Parameters (see `docs/PHASE_STATUS.md`):
- **N = 500** per label, per class (≈5,000 real traces at SUT1).
- **New v2, preserve v1.** v2 lives on a `corpus-v2` git branch; `master` keeps
  frozen v1 intact.
- SUT1 stays **traces + logs** (unchanged modality).
- The SUT2 v2 collection (trace+log) runs locally in parallel; this protocol
  covers SUT1 only.

## Why the preserve step matters

v1 **raw** telemetry is gitignored (local-only, bound for the Zenodo deposit),
so it is NOT recoverable from git — **move it, never delete it.** v1 **feature
tables** are in git on `master`, so they are safe there. The collect scripts
also **refuse to run** if `data/raw/jaeger/<class>_{normal,attack}` already
exists (a guard against mixing data), so the frozen dirs must be moved aside
first.

## Preconditions

```bash
cd ~/SecLogTrace
kubectl get pods -n default          # all ts-* Running
kubectl get deploy -o yaml | grep -c opentelemetry-javaagent   # > 0 (tracing deployed)
curl -s http://<research-host>:30005/jaeger/ui/api/services | head -c 200
jq --version; python3 -c "import pandas, numpy"
```

If tracing is not deployed, redeploy with the agent (never the default sample):
`~/dev/train-ticket-injection/hack/deploy/deploy.sh --with-tracing`, then verify
the Jaeger manifest with `scripts/infra/verify_otel_manifest.py` (`kubectl diff`
cannot catch a null-volume or overwritten `otel.yml`).

Never send `admin/admin` — it triggers Train-Ticket's built-in
`INVALID_PASSWORD_LENGTH_FAULT`. The generators use the documented test
accounts.

## Step 1 — branch + preserve v1 (once)

```bash
cd ~/SecLogTrace
git status                                  # start clean
git checkout -b corpus-v2

mkdir -p ~/slt_v1_frozen
mv data/raw       ~/slt_v1_frozen/raw_v1    # raw is gitignored → only physical copy, do NOT rm
mv data/processed ~/slt_v1_frozen/processed_v1
mkdir -p data/raw data/processed

ls ~/slt_v1_frozen/raw_v1/jaeger | head     # v1 raw present
ls data/raw data/processed                  # empty
```

On `corpus-v2`, git shows the tracked parts of `data/` as deleted — expected;
`master` still has them. Do not commit to `master`.

## Step 2 — collect each class at N=500 (halt at the first audit failure)

Each run does: normal window → 60s gap → attack window → windowed export → log
capture → zero-multi-label audit → parse → feature table → log parse.

```bash
for c in credential_abuse resource_exhaustion injection data_exfiltration; do
  ./scripts/collection/collect_abuse_corpus.sh "$c" 500 2>&1 \
    | tee "docs/daily_logs/corpus_${c}_v2_$(date -u +%Y%m%d).md"
done

# SSRF (own generator; hits the avatar service directly on :17001; needs the real face image):
./scripts/collection/collect_ssrf_corpus.sh 500 external/pic.jpg 2>&1 \
  | tee "docs/daily_logs/corpus_ssrf_v2_$(date -u +%Y%m%d).md"
```

Timing at N=500 (so nothing looks hung):
- abuse classes: bursts (credential/resource/exfil) or paced (~2s each for
  injection → ~15–20 min/window). Roughly 20–40 min per class end to end.
- **SSRF is the slow one:** weighted across three targets; the closed-port
  target times out ~10s each, so the attack window runs **tens of minutes to
  ~an hour at N=500**. Expected, not a hang.

Halt-at-first-failure: each class prints its own audit. If a class does not
report **zero multi-label traces**, stop — do not run the remaining classes;
diagnose that class first. (This is the gate that caught the 81%-contaminated
`experiment_001`.)

## Step 3 — verification record (per class)

From each `docs/daily_logs/corpus_<class>_v2_*.md`, record for cross-checking:
- the `corpus_audit.py --by-filename-label` summary (distinct / infra-noise /
  real / per-label counts) — confirm **real ≈ 500 normal + 500 attack** and
  **zero multi-label**.
- any non-zero exit or truncation warning from `export_jaeger_traces.sh`.

Do not declare v2 complete until all five classes are cross-checked; re-derive
the counts independently (verify-before-claims) rather than trusting a single
run.

## Step 4 — commit v2 (branch only)

After all five pass audit:

```bash
git add data/processed data/raw/traffic docs/daily_logs/corpus_*_v2_*.md metadata
git commit -m "SUT1 v2 corpus (N=500/label), traces+logs, zero multi-label"
git push -u origin corpus-v2        # keep it OFF master
```

Keep the bulk raw (`data/raw/jaeger`, `data/raw/logs`) out of git (gitignored,
Zenodo at release), same as v1.

## Rollback — v1 is safe

v1 raw is in `~/slt_v1_frozen/`; v1 tracked files are on `master`.

```bash
git checkout master
rm -rf data/raw data/processed
mv ~/slt_v1_frozen/raw_v1 data/raw
mv ~/slt_v1_frozen/processed_v1 data/processed
git branch -D corpus-v2     # only to discard the attempt
```

## Known gotchas

- Deploy only with `--with-tracing`; the default `deploy.yaml.sample` has no
  OTel agent.
- `reset.sh` preserves the Jaeger Badger PVC unless `--delete-trace-data` is
  passed — do not delete it (`standard` storage class is `RECLAIMPOLICY=Delete`).
- If a collect run dies mid-way, remove the partial `data/raw/jaeger/<class>_*`
  before re-running (the guard will otherwise refuse, correctly).
- `parse_jaeger_traces.py`'s attack-label call needs `--append` or it
  overwrites the normal-label output — the collect scripts already handle this;
  only relevant when running steps by hand.
