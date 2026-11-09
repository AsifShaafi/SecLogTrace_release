# Coverage Sweep Protocol — labmate UI session

Purpose: enumerate which Train-Ticket services, endpoints, and root
operations actually produce traces, so the scripted corpus can be built to
cover them. This session produces **development and coverage data, not
corpus data.** See "Why this is not corpus data" at the bottom.

---

## Before the session (Shaafi, on `<research-host>`)

Do all of this first. Every item below restarts pods, and a pod restart
destroys Jaeger's in-memory trace store. Doing any of it after the session
means running the session again.

- [ ] Run `check_log_correlation.sh` — determines whether logs can carry
      `trace_id` at all
- [ ] Switch Jaeger from in-memory to Badger storage, or accept the loss
      risk in writing (see "Jaeger storage" below)
- [ ] Wire `trace_id` into the logging pattern if the OTel agent is present
- [ ] Confirm chaos/fault-injection tooling is off, or record that it is on
- [ ] Redeploy with `--with-tracing`, scoping restarts with `grep '/ts-'`
- [ ] Verify: drive one booking, confirm a `trace_id` in the pod log matches
      a trace in Jaeger
- [ ] Confirm the trace store is empty or note the pre-session baseline count

Only after all seven boxes are ticked should the session start.

## During the session (labmate)

The labmate needs **no server access, no VPN to the API, no scripts**. He
needs the UI at `http://<research-host>:32677/` and a text file.

- [ ] Nobody else touches the system for the whole window. Concurrent
      traffic is indistinguishable from his traffic in the export.
- [ ] Record the **exact start time with timezone** before the first click
- [ ] Work through features in a deliberate order, one at a time
- [ ] After each feature, append one line to the session log:

```
HH:MM:SS±ZZ | feature | account used | outcome (ok / error / blocked)
14:02:11-05:00 | login as fdse_microservice        | fdse_microservice | ok
14:03:40-05:00 | search trips nanjing->shanghai    | fdse_microservice | ok
14:05:02-05:00 | reserve ticket, contact #1        | fdse_microservice | ok
14:07:55-05:00 | pay order                         | fdse_microservice | error 500
14:09:30-05:00 | admin: list stations              | admin             | ok
```

- [ ] Pause 20-30 seconds between features. Adjacent traces with no gap are
      hard to attribute to a feature afterwards.
- [ ] Note anything that errors — those are real findings, not failures
- [ ] Record the **exact end time with timezone**
- [ ] Send Shaafi the session log file. Nothing else.

Do not use the Jaeger UI download button. Per-trace UI downloads have no
manifest, no window record, and no way to detect truncation.

## After the session (Shaafi)

```bash
export TZ=UTC   # or pass explicit offsets in --start/--end
./export_jaeger_traces.sh \
    --label coverage_sweep \
    --experiment experiment_002 \
    --start "2026-07-30T14:00:00-05:00" \
    --end   "2026-07-30T16:30:00-05:00" \
    --limit 5000
```

Pad the window by a few minutes on each end. Then:

- [ ] Check `manifest.json` — `truncated_services` must be empty
- [ ] Record `distinct_trace_count`, never `sum_of_per_service_counts`
- [ ] Capture logs for the same window before they rotate away:
      `for p in $(kubectl get pods -o name | grep '/ts-'); do
         kubectl logs "$p" --since-time=<start> > data/raw/logs/$(basename $p).log
       done`
- [ ] Write `metadata/experiment_002_coverage_sweep.md` with the session log
      pasted in verbatim
- [ ] Run the parser, then `build_feature_table.py --spans <all files>`
- [ ] Read off the distinct `root_operation` list — that is the deliverable

## What the sweep is actually for

The output that matters is not the traces. It is the answer to four
questions:

1. Which of the ~44 services emit spans at all?
2. What is the full set of `root_operation` values?
3. Which features produce traces that cross more than two services?
4. What is the trace-to-feature ratio (how many traces does one UI action
   generate)?

Question 4 settles the open dedup issue directly. If one booking flow
produces 30+ traces, the current 1,374 figure is inflated and you will know
by how much.

---

## Jaeger storage

Jaeger all-in-one defaults to in-memory storage, which loses all data when
the process exits. In-memory storage has no trace limit by default, but a
limit can be set via `--memory.max-traces`, after which the oldest traces
are evicted from the circular buffer.
https://www.jaegertracing.io/docs/1.76/deployment/

Check what this deployment sets:

```bash
kubectl get pod -l app=jaeger -o yaml | grep -iE 'MEMORY_MAX_TRACES|max-traces|SPAN_STORAGE_TYPE'
```

If a limit is set and the sweep exceeds it, the earliest traces are gone
with no error. Badger is the fix and is available in all-in-one — set
`SPAN_STORAGE_TYPE=badger`, `BADGER_EPHEMERAL=false`, and mount a volume for
the key and value directories. Do this before the sweep, not after.

---

## Why this is not corpus data

A hand-clicked UI session cannot be regenerated. Two people following the
same written protocol produce different timing, different orderings, and
different trace counts.

The MSR 2027 Data and Tool Showcase CFP requires a description of the
methodology used to gather the data, and requires that any software written
to collect or generate the dataset ship alongside the paper as citable open
source. "A labmate clicked through the UI" satisfies neither.
https://2027.msrconf.org/track/msr-2027-data-and-tool-showcase-track

So the sweep feeds `generate_baseline_traffic.py`. Every `root_operation`
the sweep discovers becomes a scripted flow. The corpus is then generated by
the script, reproducibly, and the script is what ships with the dataset. The
sweep's own traces stay in `data/raw/` as dev and coverage data, labelled as
such, and are excluded from the frozen corpus.
