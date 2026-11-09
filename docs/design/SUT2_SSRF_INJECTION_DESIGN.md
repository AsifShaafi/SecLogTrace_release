# SUT2 SSRF Injection Design — TeaStore image service (2026-09-14)

**STATUS: VERIFIED WORKING (2026-09-18).** Built, deployed, and confirmed via
real requests. The headline trace (image -> persistence -> DB, chaining SSRF
into the bulk-read exfiltration endpoint) is captured, 6 spans, ~190ms. See
`docs/phase_logs/phase_log_20260918.md` for the full verification record.

The SUT2 analogue of SUT1's `SSRF_INJECTION_DESIGN.md`. Injects a controlled
CWE-918 sink into TeaStore's image service, mirroring the Train-Ticket avatar
injection. This is the ONE code change SUT2 needs — the other four attack
classes abuse existing endpoints.

---

## 1. Why an injected vulnerability (same reason as SUT1)

TeaStore has no natural SSRF sink. Confirmed from source: `ImageProviderEndpoint`
takes product IDs + image-size strings and serves locally-generated images; it
never fetches a user-supplied URL. Like Train-Ticket, SSRF must be added. This
is standard security-benchmark construction — and doing the SAME injection on a
DIFFERENT system is exactly the generalization the second SUT is for.

## 2. Target: the image service (mirrors SUT1's avatar choice)

- **Why the image service:** an image provider that can import an image from a
  remote URL is ordinary, plausible functionality — so the vulnerability fits
  what the service is *for* (a native cover story, exactly as with avatar).
- **It's already OTel-instrumented.** Unlike SUT1 (where the Python avatar
  service had to have OTel added), TeaStore's image service is one of the five
  Java services already running the OTel agent. The agent auto-instruments
  `java.net.HttpURLConnection`, so the injected outbound fetch is captured as a
  child span automatically — the SUT2 analogue of avatar's urllib span, with
  ZERO extra instrumentation work.

## 3. The injection

Add one endpoint to `ImageProviderEndpoint.java` (companion file). The existing
`getProductImages`/`getWebImages` are untouched and serve as the benign/normal
class (legitimate image serving, no outbound call).

```
POST image/fetchFromUrl
body: the target URL (text/plain or a JSON string)
```

Behavior: the service issues a server-side `GET` to the given URL via
`java.net.HttpURLConnection` and returns a small JSON result (status + bytes).
**No validation** — no scheme restriction, no host/private-range blocking, no
port restriction (CWE-918, naive-implementation variant, the most common
real-world root cause).

Reached through the gateway/WebUI the image service is internal, so — as with
SUT1's avatar — the realistic threat model is an internal/direct-access caller
(the image service's REST endpoint is on the compose network). State this
accurately in the paper; it matches the SUT1 framing.

Implementation notes:
- `HttpURLConnection` is a JDK built-in — no new Maven dependency, so the pom
  is unchanged and the rebuild is minimal.
- The error branch deliberately surfaces the failure type (connection refused
  vs unreachable vs timeout vs 4xx/5xx) — the SSRF fingerprinting oracle, a
  realistic detail and useful discriminative signal.

## 4. Attack surface (SUT2 versions of SUT1's SSRF sub-types)

All internal to the compose network — never leaves it (matches SUT1 safety):

| Sub-type | Target URL | SUT1 analogue |
|---|---|---|
| `ssrf_db_reach` | `http://db:3306` (the MariaDB) | order-service DB reach |
| `ssrf_internal_svc` | `http://registry:8080/tools.descartes.teastore.registry/rest/services` | nacos internal service |
| `ssrf_persistence` | `http://persistence:8080/tools.descartes.teastore.persistence/rest/users?max=-1` | direct internal service call (also touches sensitive data) |
| `ssrf_closed_port` | `http://db:9999` | closed-port timeout |

The `ssrf_persistence` target is notable — it chains SSRF into the same
bulk-read used by the exfiltration class, a realistic "SSRF-to-data" scenario
(the image service made to dump the user table), analogous to SUT1's headline
avatar → order → DB trace.

## 5. Build & deploy (Java/Maven — differs from SUT1's Python swap)

The image Dockerfile is `COPY target/*.war` — it packages a pre-built WAR. So
the cycle is: edit Java → Maven package → rebuild image → restart that one
service.

```
# from the TeaStore repo root (D:\phd_code\TeaStore)

# 1. apply the injected ImageProviderEndpoint.java into:
#    services/tools.descartes.teastore.image/src/main/java/tools/descartes/teastore/image/rest/

# 2. build the WAR. If Maven is installed on the host:
#    (the whole repo builds fast; or build just the image module + its deps)
mvn -q -pl services/tools.descartes.teastore.image -am package -DskipTests

#    If Maven is NOT on the host, build in a Maven container (no host install):
#    docker run --rm -v ${PWD}:/src -w /src maven:3.9-eclipse-temurin-17 `
#      mvn -q -pl services/tools.descartes.teastore.image -am package -DskipTests
#    (match the JDK to TeaStore's — check the parent pom's java version;
#     TeaStore runtime is Java 8 but the build may target a newer JDK.)

# 3. rebuild the image service's Docker image with the new WAR:
cd services/tools.descartes.teastore.image
docker build -t descartesresearch/teastore-image:latest .
cd ../../..

# 4. restart ONLY the image service in the OTel stack:
cd examples/docker
docker compose -f docker-compose_otel.yaml up -d --no-deps --force-recreate image
```

`--no-deps --force-recreate image` rebuilds just that service without touching
the others (or the trace backend).

## 6. Verify (the SUT2 SSRF gate)

```
# reach the image endpoint. It's internal — find how to hit it:
#   - directly on the image container's port (docker compose exec / port), or
#   - via the WebUI if a path proxies to it.
# simplest: exec into another container on the network and curl it, or
# temporarily publish the image service's 8080.

# a reachable internal target (should trace image -> registry):
curl -X POST http://<image-host>/tools.descartes.teastore.image/rest/image/fetchFromUrl `
  -H "Content-Type: text/plain" `
  -d "http://registry:8080/tools.descartes.teastore.registry/rest/services"
```

Then open Jaeger (http://localhost:16686), find the `image` service trace, and
confirm it has an **outbound child span** to the target. That child span is the
SSRF signal — the SUT2 equivalent of confirming avatar's urllib span. If it's
there, SSRF on SUT2 is live and traced.

## 7. Traffic generation

Reuse `generate_ssrf_traffic.py` with:
- endpoint = `.../image/rest/image/fetchFromUrl`
- normal mode = legitimate image serving (`getProductImages`) — 1-span, no
  outbound, the benign class.
- attack mode = the four sub-type targets above, weighted (db_reach /
  persistence highest — the strongest signals), per the SUT1 weighting.

Then the standard pilot: 15+15, 60s gap, explicit windows, `corpus_audit.py
--by-filename-label` zero-leakage gate, then scale.

## 8. Safety / scope (same as SUT1)
- Synthetic vulnerability in a synthetic app on a local isolated Docker
  network. `src_url` attack targets stay INSIDE the compose network — never
  point at real external hosts.
- Tag the fork commit clearly:
  `feat(image): inject CWE-918 SSRF sink for SecLogTrace SUT2 research corpus`.

## 9. Paper framing
The primary attack class (SSRF) realized by the SAME injection method on a
second, independently-developed system — with the bonus that the target
service was already OTel-traced, so the outbound-fetch span came for free. This
is a clean cross-system generalization result for the headline attack class.
