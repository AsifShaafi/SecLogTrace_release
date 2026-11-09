# System Setup — Train-Ticket + Jaeger

Filled in during Phase 0 (Environment & Access). Re-run and re-save whenever
the environment changes. Last updated: 2026-07-24 (reformatted; original
data captured 2026-07-13).

## Summary

| Item | Value |
|---|---|
| Host | `<research-host>` |
| OS | RHEL 9.3 (kernel 5.14.0-362.24.1.el9_3.x86_64) |
| K8s distro | Minikube v1.32.0 (node OS image: Ubuntu 22.04.3 LTS — this is the Minikube VM, distinct from the RHEL host above) |
| Minikube IP | <node-ip> |
| K8s node count | 1 (`minikube`, control-plane, Ready) |
| K8s server version | v1.28.3 (client v1.29.3 — minor skew, not a concern) |
| Docker server version | 24.0.7 |
| Namespace | `default` |
| Train-Ticket pods running | 46 (`ts-*`), all healthy |
| Supporting infra pods | 14 (Jaeger, Nacos ×3, Nacos DB ×3, otelcol, Prometheus, Grafana, RabbitMQ, TS DB ×3) |
| Jaeger deployment | all-in-one, in-memory storage |
| Jaeger base path | `/jaeger/ui` (not `/`) |
| Jaeger working API root | `http://<research-host>:30005/jaeger/ui/api` |
| Trip catalog | Empty — needs seeding (see Known Issues) |
| Station/route config | 13 stations, clean (no junk test entries) |

## Host / OS

- OS / kernel: `Linux <research-host> 5.14.0-362.24.1.el9_3.x86_64 #1 SMP PREEMPT_DYNAMIC Thu Feb 15 07:18:13 EST 2024 x86_64 GNU/Linux`
- Date recorded: 2026-07-13T22:44:02-05:00

## Kubernetes

- Distro: Minikube
  - `minikube version`: v1.32.0
  - Commit: `8220a6eb95f0a4d75f7f2d7b14cef975f050512d`
  - Client Version: v1.29.3
- Minikube IP: `<node-ip>`
- `kubectl version` (confirmed 2026-07-24):
  - Client Version: v1.29.3
  - Kustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3
  - Server Version: v1.28.3
- Cluster node count: 1
  - `minikube` — Ready, control-plane, age 197d, OS image Ubuntu 22.04.3 LTS,
    kernel 5.14.0-362.24.1.el9_3.x86_64, container runtime docker://24.0.7

## Docker

- `docker version --format '{{.Server.Version}}'`: `24.0.7`

## Train-Ticket

- Namespace: `default`
- Pods: 46 pods with a `ts-*` prefix, all `Running`, all `1/1 Ready`.
  Full list captured 2026-07-13 in
  `docs/setup_notes/pods_20260713.txt` (attach/confirm this file exists —
  the raw `kubectl get pods` output is long and belongs in its own file,
  not inline here).
- **Note on service count:** 46 `ts-*` pods observed here vs. 44 services
  recorded earlier from the OpenAPI spec inventory
  (`ts service and urls.txt`). Minor discrepancy — not urgent, but worth
  reconciling once you're relocating the OpenAPI specs into the repo (see
  Phase 0 checklist item 3), in case 2 services were added/renamed since
  that spec list was built.
- Supporting infrastructure (non-`ts-*`) pods, 14 total: `grafana` (×1),
  `jaeger` (×1), `nacos` (×3), `nacosdb-mysql` (×3), `otelcol` (×1),
  `prometheus-server` (×1), `rabbitmq` (×1), `tsdb-mysql` (×3).
- Pods in CrashLoopBackOff / Pending: **none** — but see Known Issues below,
  since "Running" doesn't mean "stable."

## Jaeger

- Deployment type: all-in-one (image `jaegertracing/all-in-one:1.45.0`)
- Namespace: `default`
- Pod: `jaeger-5c5d74b479-wg6wk`
- Services:
  - `jaeger-agent` — ClusterIP, ports 5775/UDP, 5778/TCP, 6831/UDP, 6832/UDP
  - `jaeger-collector` — ClusterIP, ports 9411/TCP, 14250/TCP, 14267/TCP, 14268/TCP, 4317/TCP, 4318/TCP
  - `jaeger-query` — NodePort, 16686→30005/TCP, 16685→30302/TCP
- Storage backend: **in-memory** (`SPAN_STORAGE_TYPE: memory`) — flag: this
  means Jaeger data does **not** persist across pod restarts. If the Jaeger
  pod ever restarts, all previously exported-but-not-yet-saved trace history
  in Jaeger itself is gone (your own `data/raw/jaeger/*.json` exports are
  unaffected, since those are already saved to disk).
- Base path: `/jaeger/ui` (confirmed via browser Network tab, 2026-07-13)
- Working API root: `http://<research-host>:30005/jaeger/ui/api`
- Confirmed reachable at: `http://<research-host>:30005/jaeger/ui`

## Known issues / notes

- **Trip catalog is empty — confirmed not a transient/flaky-pod issue.**
  `check_trip_catalog.py`: 120 station-pair/date combinations checked, 0
  hits. Confirmed this persists across a full stack redeploy, ruling out
  stale pod state — the trip-seeding step is not part of this
  deployment's startup and needs to be triggered explicitly (admin panel
  or `admintravelservice`).
- Jaeger storage is in-memory only (`SPAN_STORAGE_TYPE: memory`) —
  confirmed unchanged after the 2026-07-24 config reset. Trace history in
  Jaeger itself does not survive a Jaeger pod restart.
  `data/raw/jaeger/*.json` exports are the only durable copy of trace
  data.

## Action items (to close out this doc)
- [ ] Seed the trip catalog (admin panel / `admintravelservice`) — the one
      remaining open item
- [ ] Optional: reconcile the 46-vs-44 service count discrepancy when
      relocating the OpenAPI spec files
