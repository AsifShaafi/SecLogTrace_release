# SSRF Injection Design — SecLogTrace Phase 2

**Repo location:** `docs/design/SSRF_INJECTION_DESIGN.md`
**Status:** finalized against the real fork 2026-08-18. This is also the
seed for the threat-model writeup — see "Writeup skeleton" below.

---

## 1. Why an injected vulnerability

Train-Ticket has no natural SSRF sink — confirmed by spec review
(`merged_openapi_spec.yaml`, 203 endpoints, none accept a user-supplied URL
the server then fetches). SSRF (CWE-918) requires exactly that shape, so it
must be added. This is standard security-benchmark construction (OWASP Juice
Shop, WebGoat, prior microservice-security datasets): inject a realistic,
CWE-mapped vulnerability into otherwise-benign software so labeled attack
traffic can be generated against a system that behaves like production code.

## 2. Target: `ts-avatar-service` — a Python/Flask service

**This target is stronger than any Java alternative**, for three reasons
that only became clear on inspecting the fork:

1. **The service already fetches and processes images server-side.** It is
   a Flask app (`app.py`, gunicorn on :17001) that decodes an image and runs
   face detection. `import urllib` is already present at the top of the
   file. Adding a "fetch the image from a URL" input path is not a bolted-on
   endpoint — it is the single most natural extension of what the service
   already does, and the file even carries a `# TODO` for additional input
   methods. This makes the SSRF cover story *native*, not invented.
2. **It maps onto the canonical real-world SSRF pattern.** The overwhelming
   majority of real SSRF CVEs are exactly this: a Python service using
   `urllib`/`requests` to fetch a user-supplied URL with no destination
   validation. Reviewers will recognize the pattern immediately.
3. **Zero baseline contamination.** ts-avatar-service carried zero traffic
   in every prior collection, so injected traffic here cannot contaminate
   any normal baseline at other services, and there is no pre-existing
   pattern to disentangle it from.

**Injection:** add a `src_url` field to the existing `POST /api/v1/avatar`
handler. When present, the service fetches the image from that URL via the
already-imported `urllib` instead of decoding base64. No scheme restriction,
no host/private-range validation, no port restriction, follows redirects —
the "naive implementation" variant, mirroring the most common real SSRF root
cause. Implementation in the companion `app.py`.

## 3. Critical prerequisite: this service is NOT currently traced

ts-avatar-service never appeared in Jaeger because it is **Python, and the
OpenTelemetry Java agent that instruments the other 40+ services cannot
touch it.** This was the real reason for its zero-trace status — not absence
of traffic.

For a trace-based detection corpus this is make-or-break: an uninstrumented
service produces no traces, so the SSRF class could not participate in the
trace-based RQ. **Resolution: instrument the Flask app with OpenTelemetry**
(companion `Dockerfile`). `opentelemetry-instrument` auto-instruments Flask
(inbound spans) and urllib (the outbound SSRF request — the exact span the
detector should catch), and propagates W3C trace context so these traces
join the rest of the corpus on `trace_id`.

**Paper bonus:** instrumenting one Python service alongside 40 Java ones
demonstrates the pipeline handles a *polyglot* system — a genuine strength,
since most trace-anomaly benchmarks are single-language.

Rejected alternatives: routing SSRF through a Java caller (muddies which
service is vulnerable); accepting SSRF as log-only (removes it from the
central trace-vs-log comparison). Only fall back to log-only if OTel-
instrumenting Flask proves unexpectedly hard in practice.

## 4. Attack surface available inside this cluster

Real internal targets the SSRF payload can reach from inside the pod
network, for attack-traffic generation and the threat-model narrative:

| Target | Address | Why it matters |
|---|---|---|
| Kubernetes API server | `https://kubernetes.default.svc` (~`<cluster-ip>:443`) | Canonical SSRF-to-control-plane target; if the pod's service-account token is mounted, a path to cluster enumeration |
| Nacos discovery API | `http://nacos:8848/nacos/v1/ns/...` | Internal service registry, normally unreachable from outside the mesh |
| Another `ts-*` service directly | e.g. `http://ts-order-service:12031/...` | Bypasses gateway enforcement — mesh-internal lateral movement |
| Loopback / pod-local | `http://127.0.0.1:<port>` | Anything bound only to localhost inside the avatar pod |

Recommendation: use three targets for the corpus — K8s API server (most
severe/realistic), Nacos (clean internal-only signal), and one direct `ts-*`
call (lateral movement). Not exhaustive by design. **Get a one-line advisor
sign-off on hitting the K8s API server on the shared box** — it's read-only
reconnaissance value, not a write path, but worth confirming.

## 5. Safety / scope notes

- Fork of a public benchmark, isolated namespace, no production traffic, no
  real user data. Synthetic vulnerability in synthetic software.
- Attack-class `src_url` targets must stay INSIDE the cluster network — do
  not point at real external hosts you don't control.
- Normal-class traffic should fetch from a single trusted in-cluster image
  host (a one-line nginx serving a static jpg, deployed alongside
  Train-Ticket) so even "normal" SSRF-endpoint traffic never leaves the
  cluster. Until that host exists, `generate_ssrf_traffic.py`'s normal mode
  fails loudly by design rather than sending external traffic.
- Tag the commit clearly: `feat(avatar): inject CWE-918 SSRF sink + OTel
  instrumentation for SecLogTrace research corpus`.

## 6. Implementation checklist

- [x] Confirm target has editable source — yes, Python/Flask `app.py`
- [x] Apply the injected `app.py` (adds the `src_url` SSRF path alongside
      the existing base64 path) into `ts-avatar-service/app.py`
- [x] Apply the OTel-instrumented `Dockerfile` into `ts-avatar-service/`
- [ ] Confirm `OTEL_EXPORTER_OTLP_ENDPOINT` in the Dockerfile matches what
      the Java services use — the value shipped is a guess:
      `kubectl get deploy ts-order-service -o yaml | grep -A1 OTEL_EXPORTER_OTLP`
      Fix the Dockerfile ENV line if it differs (strip any `/v1/traces`
      path for the gRPC endpoint). Wrong endpoint = service runs but emits
      no traces, invisible until the curl test comes back empty in Jaeger.
- [ ] **Rebuild the image, then restart — a plain `rollout restart` does
      NOT pick up code changes, since `app.py` is baked into the image at
      build time.** On this single-node minikube:
      ```
      eval $(minikube docker-env)          # use minikube's docker daemon
      cd ~/dev/train-ticket-injection      # build context = repo root
      # tag must match: kubectl get deploy ts-avatar-service \
      #   -o jsonpath='{.spec.template.spec.containers[0].image}'
      docker build -t <that-exact-tag> -f ts-avatar-service/Dockerfile .
      kubectl rollout restart deployment/ts-avatar-service
      kubectl rollout status deployment/ts-avatar-service --timeout=180s
      ```
      If `imagePullPolicy: Always`, patch it to `IfNotPresent` first or
      minikube ignores the local build.
- [ ] Manual test (simultaneously proves instrumentation AND the sink):
      ```
      curl -X POST http://<research-host>:32677/api/v1/avatar \
        -H 'Content-Type: application/json' \
        -d '{"src_url":"http://nacos:8848/"}'
      ```
      Then confirm a NEW `ts-avatar-service` trace appears in Jaeger. If the
      gateway path 404s, the service is in-cluster-only — reach it on the
      ts-avatar-service ClusterIP:17001 from a pod, or via port-forward, and
      pass `--url` to the traffic generator.
- [ ] Verify the OUTBOUND fetch shows up as a child span (the urllib
      instrumentation) — this is the span the detector keys on, so its
      presence is the real success criterion, not just the inbound span
- [ ] Stand up the in-cluster placeholder image host for normal traffic
- [ ] Run `generate_ssrf_traffic.py --mode pilot`, export the window,
      audit with `corpus_audit.py`, confirm the new endpoint appears
      distinctly in root_operation with zero label overlap
- [ ] Only then fold into the full corpus alongside the other attack classes

## 6a. Backward-compatibility note (regression safety)

The injected `app.py` keeps the original base64 path fully intact — the
`src_url` branch only fires when that field is present. So existing avatar
functionality (if anything calls it) still works, and the base64 path is a
useful control: normal-vs-attack here can also be base64-upload vs.
URL-fetch-to-internal-target, both hitting the same endpoint, which is a
cleaner within-endpoint comparison than two different endpoints would give.

---

## Writeup skeleton (threat-model section) — start this in parallel

The prose depends only on the design being fixed, which it now is. Draft it
while the implementation proceeds.

**3.X SSRF Injection**

- SSRF (CWE-918) chosen as primary attack class [cite OWASP API Security
  Top 10, which lists SSRF]; no natural sink exists in Train-Ticket,
  consistent with it being a demonstration app.
- Target and rationale: `ts-avatar-service`, chosen because it is an
  image-processing service that already performs server-side fetching — the
  archetypal real-world SSRF context — and because it carried zero baseline
  traffic (clean attribution). Note it is one of the few non-Java services,
  which the instrumentation work turns into a polyglot-coverage strength.
- Vulnerability: a `src_url` input added to the existing avatar endpoint,
  fetched via urllib with no allowlist/denylist or private-range blocking —
  the most common real SSRF root cause [cite].
- Instrumentation: Python OTel auto-instrumentation added so the outbound
  fetch is captured as a child span joining the corpus on trace_id; briefly
  note this extends the pipeline to a polyglot setting.
- Attack surface exercised: which internal targets and why (mesh-internal
  reconnaissance vs. control-plane access), mapped to real SSRF impact
  categories.
- Table: normal vs. attack traffic definitions (mirror the "What each
  attack class did" table from the progress update).

4–5 paragraphs is right for a 4-page Showcase paper. Base the numbers (span
counts, target list, request counts) on the actual pilot collection, not
estimates.
