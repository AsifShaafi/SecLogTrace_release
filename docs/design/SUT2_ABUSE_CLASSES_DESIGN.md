# SUT2 (TeaStore) — Attack-Class Collection Design (2026-09-14)

The SUT2 analogue of SUT1's `ABUSE_CLASSES_COLLECTION_DESIGN.md`. Maps the
five attack classes to real TeaStore endpoints (verified against the cloned
source, not guessed). Collection is **trace-only** for SUT2 (see
`SUT2_LOG_MODALITY_DECISION_20260914.md`).

Reuse the SUT1 generators (`generate_abuse_traffic.py`,
`generate_ssrf_traffic.py`) with these endpoints swapped in. Same discipline:
separate normal/attack windows, 60s gap, explicit `--start`/`--end`,
`corpus_audit.py --by-filename-label` zero-leakage gate before scaling.

## Endpoint reference (from source)
- **Login:** `POST webui/loginAction` → `POST auth/rest/useractions/login`
  (confirmed in the gate trace `f171853d`).
- **Persistence CRUD (all entities extend `AbstractCRUDEndpoint`):**
  - `GET persistence/rest/<entity>?start=&max=` — **listAll; `max=-1` returns
    ALL rows** (per the source docstring). Entities: `users`, `products`,
    `categories`, `orders`, `orderitems`.
  - `GET persistence/rest/<entity>/{id}` — find one by numeric id.
- **Image:** `POST image/getProductImages`, `POST image/getWebImages` (take
  product IDs + size strings — NO url fetch), `GET image/regenerateImages`,
  `GET image/state`, `POST image/setCacheSize`.
- **DatabaseGeneration:** `persistence/rest/generatedb` — populates the DB
  (expensive operation).

---

## Class 1 — Credential abuse (CWE-307)  [reuse run_auth_abuse]
- **Target:** `POST webui/loginAction` (username + wrong passwords, no pacing).
- **Normal class:** correct-password logins at human pace.
- **Signal:** burst of failed-login request traces. NOTE (verified 2026-09-11):
  good AND bad logins both return HTTP 302 — status does NOT separate them
  (as on SUT1). The discriminator is the redirect `Location`
  (`.../webui/` vs `.../webui/login`) and the response cookie. **In
  trace-only mode**, the signal is: the request-rate/burst pattern, and
  whether the bad-login trace is *shorter* (fails at auth, never reaches the
  full persistence user-lookup chain) vs. the good-login 7-span
  webui→auth→persistence→DB chain. Characterize during the pilot.
- **Cross-system note:** SUT1's credential-abuse signal locus differs; record
  the SUT2 locus (trace-shape + rate) for RQ3.

## Class 2 — Resource exhaustion (CWE-400)  [reuse run_resource_exhaustion]
- **Target:** an expensive catalog read fired unpaced. Best candidates:
  a category/product listing through the WebUI, or directly
  `GET persistence/rest/products?start=0&max=-1` (return-all is genuinely
  costly). The `POST image/getProductImages` for many IDs is a second
  expensive option (image generation is CPU-heavy).
- **Normal class:** the same read at realistic pacing.
- **Signal:** burst/flood pattern in trace timing and rate; same endpoint as
  normal, so a controlled within-endpoint comparison. (Timing is emulation-
  free on this native-x86 host, but still a laptop — prefer rate/structure
  over absolute latency for cross-SUT comparison, per the standing rule.)

## Class 3 — Injection: SQL/NoSQL (CWE-89/943)  [reuse run_injection_attempt]
- **Target:** metacharacter payloads in a query-constructing parameter. The
  CRUD `?start=&max=` params are integer-parsed (`parseIntQueryParam`) so
  they reject non-numeric input early — good for a *rejected-input* signal but
  not a successful injection. The richer target is any string-valued lookup
  the WebUI passes to persistence (product/category name search, if present in
  the WebUI layer) — grep the webui for search params before finalizing.
- **Normal class:** the same lookups with legitimate values.
- **Signal:** atypical request traces (malformed params) and any error spans.
  NOTE: TeaStore likely uses JPA/EclipseLink (parameterized queries), so like
  SUT1 the payloads probably DON'T achieve real injection — characterize
  honestly as the *attempt/rejected-input* signature, not successful
  exploitation. This matches the SUT1 framing.

## Class 4 — Data exfiltration (200)  [build fresh, minimal]
- **Target:** unbounded bulk enumeration via the CRUD listAll:
  `GET persistence/rest/users?start=0&max=-1` (all users — sensitive),
  `GET persistence/rest/orders?start=0&max=-1` (all orders). The source
  docstring confirms `max=-1` / negative = return everything.
- **Normal class:** a single legitimate read
  (`GET persistence/rest/users/{id}` or a small `max=N` page).
- **Signal:** atypical response breadth / large-result reads vs. normal
  single-record or small-page reads; the exfil traces hit the same endpoint
  but pull the whole table. Structural/response-size signal, not a new
  endpoint — a clean within-endpoint comparison.
- **Note:** this is a NATURAL exfiltration surface (built into the CRUD API),
  no injection needed — arguably cleaner than SUT1's. The "thin admin surface"
  concern is resolved: `max=-1` dumps whole tables.

## Class 5 — SSRF (CWE-918)  [inject, mirroring SUT1; reuse generate_ssrf_traffic.py]
- **The image service is NOT a natural SSRF sink** — `ImageProviderEndpoint`
  takes product IDs + size strings and serves locally-generated images; it
  never fetches a user-supplied URL. Confirmed from source.
- **Same situation as SUT1** (Train-Ticket had no natural sink either).
  **Inject one into the image service**, exactly as avatar was injected on
  SUT1: add a URL-fetch endpoint (e.g. `POST image/fetchFromUrl` taking a
  `src_url`, fetched server-side via the Java HTTP client with NO validation —
  CWE-918). An image provider fetching a remote image by URL is a plausible
  feature, so the cover story is native, like avatar's.
- **Instrumentation:** the OTel agent already traces the image service (it's
  one of the 5 instrumented Java services), and it auto-instruments the Java
  HTTP client — so the injected outbound fetch is captured as a child span,
  just like SUT1's urllib span. No extra instrumentation work.
- **Normal class:** the existing `getProductImages` (legitimate, no outbound).
- **Attack class:** `fetchFromUrl` pointed at internal targets (the DB at
  `db:3306`, the registry, another service, a closed port) — the SUT2
  analogue of SUT1's ssrf_db_reach / internal_svc / closed_port sub-types.
- **Paper value:** the SAME injection method applied to a DIFFERENT system is
  a clean generalization result for the primary attack class.

---

## Injection work required (only SSRF, like SUT1)
Four of five classes need NO code change — they abuse real endpoints
(login, catalog reads, bulk listAll). Only SSRF requires an injected endpoint
in the image service, mirroring SUT1's single-injection approach. Document the
injection in the fork (a `SUT2_SSRF_INJECTION_DESIGN.md`) the same way SUT1's
avatar injection was documented.

## Infra-noise filter (add to corpus_audit.py for SUT2)
SUT2 noise = single-span client GET/PUT to the registry (service-discovery
polling), the analogue of SUT1's NacosWatch. Real request traces are
multi-span rooted at `webui` (or at the directly-hit persistence/image
endpoint for the CRUD-level attacks).

## Collection order (suggested)
1. Credential abuse — easiest, already-confirmed endpoint, validates the SUT2
   pilot flow end to end.
2. Resource exhaustion — same-endpoint burst, simple.
3. Data exfiltration — the natural listAll surface.
4. Injection — characterize honestly (rejected-input likely).
5. SSRF — last, because it needs the injection + rebuild step first.

Each: pilot 15+15, 60s gap, explicit windows, corpus_audit zero-leakage gate,
then scale. Freeze the SUT2 corpus + data statement, run run_detection.py in
trace-only mode, hand cross-system results to the main chat.

## Still to confirm before/at collection
- The WebUI-level string search param for the injection class (grep webui for
  search/query params) — or accept the integer-param rejected-input signal.
- The exact WebUI category/product-list path for resource exhaustion (or hit
  persistence directly).
