# SUT2 (TeaStore) — credential_abuse

> **Status: SCALED TO N=150 logins, CLEAN (2026-09-17).** 302 attack / 302
> normal traces (150 logins/label × ~2 traces each: the login POST + the
> followed redirect). Zero multi-label. Cross-system detection computed (see
> `docs/SUT2_ANALYSIS_DRAFT_20260917.md`). Pilot history retained below.

## Class definition
- CWE-307, credential abuse (no code change — abuse of the login endpoint).
- Shared target: `POST webui/loginAction`.
  - Normal: correct password for a real (discovered) username → 302 to
    `/webui/` (home) + `sessionBlob` cookie + `You_are_logged_in!`.
  - Attack: `cred_bruteforce` (real user, wrong pw) 2 : `cred_userenum`
    (nonexistent user) 1 → 302 to `/webui/login` + `You_used_wrong_credentials!`.
- Real usernames are SHUFFLED vs numeric id (id 507 → "user25") — discovered
  at runtime, not guessed.

## Collection
- Generator: `generate_sut2_traffic.py --class credential_abuse --mode pilot`
- 15 normal + 15 attack logins, 60s gap, separate export windows.
- The traffic generator's `requests.Session()` follows the 302 redirect, so
  each login produces two traces: the `POST loginAction` and the follow-up
  page GET.

## Audit / noise (N=150 scale)
- Raw distinct traces: 1582
- Infra noise: 978 (61.8%) — lower ratio than other classes because the login
  flow generates more real traces per request.
- Real traces retained: 604 (302 normal + 302 attack). Zero multi-label.
- (Pilot: 513 distinct, 87.9% noise, 62 real.)

## Signal (trace-only) — the RQ3 signal-locus finding
- **The login trace is STRUCTURALLY IDENTICAL for success and failure**:
  span_count 5, db_span_count 1 for BOTH labels. TeaStore returns 302 either
  way and (as with injection) spans carry no `http.status_code`.
- The ONLY trace-visible discriminator is the **redirect target of the
  follow-up request**: success → `GET webui/index` (home); failure → `GET
  webui/login` (login page reloaded). This is categorical ROUTING information
  (root_operation / path_signature), NOT trace shape.
- **SUT1 comparison — DIFFERENT SIGNAL LOCUS (headline RQ3 finding).** On SUT1
  (Train-Ticket), a failed login ABORTS EARLY *within* the login trace itself:
  span_count 12→8, DB touches 3→1 — structurally detectable in isolation
  (SUT1 trace-only RF F1 = 1.00). On SUT2 the login trace is identical; the
  signal moved *outside* the login trace to the redirect target. A client that
  ignored redirects would leave NO trace-visible signal at all.
- Detection (trace-only RF F1, 5-fold, N=150, NUMERIC features only): **SUT2
  0.71** vs SUT1 1.00. The gap is not detector failure — it is the signal-locus
  difference: SUT2's discriminator is a categorical route (dropped from the
  numeric feature set), not a structural feature. All top RF feature
  importances on SUT2 are incidental span-duration statistics; the structural
  features (span/db counts) are flat. Full reasoning:
  `docs/SUT2_ANALYSIS_DRAFT_20260917.md` §5a.

## Files
- Raw: `data/raw/jaeger/sut2_credential_abuse_sut2_credential_abuse_{normal,attack}/`
- Parsed: `data/processed/traces/sut2_credential_abuse/{spans,traces}.csv`
- Features: `data/processed/combined/sut2_credential_abuse_features.csv`

## Known limitations
- Detection sets are per-trace (302/302), not per-login (150/150).
- `cred_bruteforce` and `cred_userenum` are indistinguishable at the HTTP level
  (TeaStore returns the same "wrong credentials" for both) — a security-positive
  property (no user enumeration leak), worth a line in the paper.
