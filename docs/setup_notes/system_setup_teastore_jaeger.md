# System Setup — TeaStore (SUT2) + Jaeger

Second System-Under-Test for cross-system generalization (Phase 3 / SUT2).
Mirrors `system_setup_train_ticket_jaeger.md` for SUT1. Re-run and re-save
whenever the environment changes. Last updated: 2026-09-18 (Stage 2 done, log modality decided trace-only,
all 5 attack classes design-complete, SSRF injection built and verified).

## Summary

| Item | Value |
|---|---|
| Role | SUT2 — cross-system generalization vs. SUT1 (Train-Ticket) |
| Application | TeaStore (DescartesResearch), IISWC 2018 reference microservice app |
| Source | `github.com/DescartesResearch/TeaStore` (cloned; images from Docker Hub `descartesresearch/*`) |
| Host | Local Windows machine (`Shaafi-HomePC`, x86-64 — native, no ARM emulation). Runtime on a plain local path (`D:\docker`), NOT under Box cloud-sync |
| Deployment | Docker Compose (multi-container), NOT the `teastore-all` single image |
| Compose file (baseline) | `examples/docker/docker-compose_default.yaml` |
| Compose file (instrumented) | `examples/docker/docker-compose_otel.yaml` (SecLogTrace-added) |
| Services | 7: `registry`, `db`, `persistence`, `auth`, `image`, `recommender`, `webui` |
| Java services (traced) | 5: `persistence`, `auth`, `image`, `recommender`, `webui` (+ `registry` is Java but infra) |
| Non-Java | `db` (MySQL/MariaDB — appears as JDBC client spans from `persistence`) |
| App server | Apache Tomcat 8.5.41, Java 1.8.0_212 (Java 8 — matters for OTel agent version) |
| Shipped monitoring | Kieker 1.14 (via `-javaagent:/kieker/agent/agent.jar`), reports Status: 'disabled' out of the box |
| Tracing added | OpenTelemetry Java agent 2.9.0 via `JAVA_TOOL_OPTIONS` (no rebuild; attaches on Java 8 — **confirmed working 2026-09-14**) |
| Trace backend | Jaeger all-in-one, **in-memory** storage (Badger dropped — the 1.50+ image runs non-root and can't write the Badger volume; in-memory is fine for short exported-immediately pilots) |
| WebUI URL | `http://localhost:8080/tools.descartes.teastore.webui/` (trailing path required; root 404s) |
| Jaeger UI | `http://localhost:16686` |
| OTLP endpoint (in-cluster) | `http://jaeger:4317` (gRPC) |
| Host-published ports | webui 8080, db 3306, Jaeger UI 16686, OTLP 4317/4318 |

## Application / deployment

- TeaStore is a Java/servlet microservice benchmark: a web store with
  separate services for auth, persistence, images, recommendations, a
  registry (service discovery), and a WebUI front end. Same architectural
  family as SUT1 Train-Ticket (Java, REST, client-side load balancing over a
  registry) — which is why the SUT1 pipeline transfers.
- Deployed via Docker Compose on a local Windows machine (x86-64). Chosen over
  the shared research server for SUT2 to decouple from SUT1's cluster and
  because native x86 avoids the ARM-Mac emulation that muddies timing.
- **`teastore-all` (single-container all-in-one) is NOT used for collection.**
  It runs all services in one Tomcat JVM, which collapses cross-service
  traces. It was used once for a "does it run" smoke test only. The
  multi-container `docker-compose_default.yaml` is the real deployment.

## Services (the SUT2 equivalent of SUT1's `ts-*` services)

| Service | Role | Notes for the corpus |
|---|---|---|
| `webui` | front end | entry point; the request originator, like a gateway |
| `auth` | authentication | **credential-abuse target** (`/loginAction`) |
| `persistence` | data access + DB | JDBC spans to `db`; **data-exfiltration candidate** |
| `image` | image provider | **SSRF-injection candidate** (analogue of SUT1's avatar service — confirm it fetches by URL / is editable) |
| `recommender` | recommendations | secondary |
| `registry` | service discovery | infra (Ribbon-style client LB target) |
| `db` | MySQL/MariaDB | not instrumented; shows as JDBC client spans |

## Tracing setup (Stage 2) — DONE 2026-09-14

- **Mechanism:** the OTel Java agent (2.9.0) is attached to each Java service
  via `JAVA_TOOL_OPTIONS=-javaagent:/otel/opentelemetry-javaagent.jar`. The jar
  is downloaded once on the host and mounted read-only (an earlier init-container
  download approach failed and blocked the stack — see phase_log_20260914).
- **Verified 2026-09-11:** the TeaStore images honor `JAVA_TOOL_OPTIONS`.
- **Verified 2026-09-14:** the 2.9.0 agent attaches on Java 8 (no rebuild, no
  fallback to the 1.32.x line needed).
- **Cross-service tracing CONFIRMED (the gate).** A login produced a 7-span
  trace `f171853d` crossing `webui → auth → persistence → db`:
  `POST /webui/loginAction` → `POST /auth/rest/useractions/login` →
  `GET /persistence/rest/users/name/user1` → 3× `SELECT teadb.*` →
  `sendRedirect`. W3C context propagates across TeaStore's registry/Ribbon
  calls all the way to the DB. This is the structural analogue of SUT1's
  cross-service chains — the SUT1 pipeline transfers.
- **OTLP export:** each service pushes to `http://jaeger:4317` (gRPC),
  metrics/logs exporters off, `OTEL_PROPAGATORS=tracecontext,baggage`,
  `OTEL_SERVICE_NAME` = service name.
- **Trace backend:** Jaeger all-in-one, **in-memory** (see summary note).
- **Coexistence with Kieker:** images still run Kieker's `-javaagent`; the two
  coexist (Kieker ships `disabled`). No clash observed.

## Infra-noise signature (SUT2 equivalent of SUT1's NacosWatch)

Registry heartbeat / service-discovery polling shows up as **single-span
client GET/PUT with no parent** (e.g. `auth` PUT/GET to the registry). In one
20-trace capture, 19 were this noise, 1 was the real login. **Filter rule for
SUT2:** single-span client GET/PUT to the registry = infra noise. Real request
traces are multi-span and rooted at `webui` (as SUT1's were multi-span rooted
at the gateway). `corpus_audit.py`'s noise filter needs this SUT2 pattern
added — the analogue of `is_infra_noise_only` keying on NacosWatch for SUT1.

## Log modality — SUT2 is TRACE-ONLY (decided 2026-09-14)

TeaStore does not produce per-request application logs (verified: `auth` logs
nothing per login; `persistence` logs only exceptions; boot shows SLF4J bound
to a NOP logger). There is no request-level log content to join to traces, so
the log-only and combined detection arms are SUT1-only. **SUT2 validates the
trace-based method's generalization.** This is a defensible scoping decision
and an RQ2/RQ3 finding (log availability varies by system), not a gap. Full
rationale + paper framing: `docs/SUT2_LOG_MODALITY_DECISION_20260914.md`.
Consequence: no `enable_trace_id_logging.sh`-equivalent, no
`parse_service_logs.py`, no log capture in collection for SUT2.

## Known facts / gotchas (SUT2-specific)

- **Java 8.** TeaStore runs Java 1.8.0_212. The OTel agent 2.x line generally
  supports Java 8, but if attach fails, fall back to the OTel agent 1.32.x
  line, which explicitly supports Java 8. This is the first-boot risk to watch.
- **Login failure signal differs from SUT1.** Both good and bad logins return
  HTTP 302. They differ in the redirect `Location` (`.../webui/` vs
  `.../webui/login`) and the cookie (`teastoreMessageCookie=You_are_logged_in!`
  vs `teastoreErrorMessageCookie=You_used_wrong_credentials!`). So the
  credential-abuse signal on SUT2 is in redirect-target/cookie, not status —
  a cross-system RQ3 point. (SUT1 Train-Ticket returned HTTP 200 on bad login;
  SUT2 returns 302 either way — both are "status doesn't separate," but the
  discriminating feature differs.)
- **Default users:** `user1..userN`, password `password` (TeaStore-generated).
- **`db` publishes 3306 to the host** — if another MySQL is already bound there
  (a stray container caused a `Communications link failure` during the
  all-in-one smoke test), stop it first. In the compose deployment the DB is
  on the compose network at hostname `db`, which is what the services use.
- **The `version:` key in the compose files is obsolete** (Docker warns but
  ignores it) — harmless.

## Endpoint-to-class mapping (to finalize in Stage 3)

| Class | SUT1 endpoint | SUT2 endpoint (status) |
|---|---|---|
| Credential abuse (307) | `/users/login` | `/loginAction` — confirmed; signal in redirect/cookie |
| Resource exhaustion (400) | trip search | a catalog/product-list endpoint — TO CONFIRM (find the expensive one) |
| Injection (89/943) | trip-search station field | a search/query param reaching the DB — TO CONFIRM |
| Data exfiltration (200) | admin bulk reads | persistence/catalog bulk reads — TO CONFIRM (TeaStore admin surface is thinner) |
| SSRF (918, injected) | avatar `src_url` | `image` service `fetchFromUrl` — **injected, built, VERIFIED 2026-09-18** (6-span image->persistence->DB trace confirmed) |

The exfiltration and SSRF mappings are the two that need the most
verification — noted so they're not assumed to fit before checking.

## Pipeline reuse

Once the tracing gate passes (cross-service trace + trace_id-in-logs), the
SUT1 scripts transfer with endpoint-string changes only:
`export_jaeger_traces.sh` (point at this Jaeger), `generate_abuse_traffic.py`
/ `generate_ssrf_traffic.py` (SUT2 endpoints), and unchanged downstream:
`corpus_audit.py`, `parse_jaeger_traces.py`, `build_feature_table.py`,
`stratification.py`, `run_detection.py`. Keeping the feature schema identical
across SUTs is the whole point — it's what makes the cross-system comparison
valid.
