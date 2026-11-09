# SUT2 (TeaStore) — credential_abuse — v2 (traces + logs)

> **Status: v2 corpus, N=500 logins/label, CLEAN (2026-10-28).** 1000 attack /
> 1000 normal traces (~2 per login: the login POST + the followed redirect),
> zero multi-label, log join 2000/2000. First SUT2 run with per-request
> application logs. Supersedes v1 `sut2_credential_abuse.md`.

## Class definition
- CWE-307, credential abuse (no code change — abuse of the login endpoint).
- Shared target: `POST webui/loginAction`.
  - Normal: correct password for a real (discovered) username → 302 to
    `/webui/` (home).
  - Attack: `cred_bruteforce` (real user, wrong pw) / `cred_userenum`
    (nonexistent user) → 302 to `/webui/login`.
- Real usernames are shuffled vs numeric id — discovered at runtime.

## Collection
- `collect_sut2_corpus.sh credential_abuse 500 0.5`. The generator's
  `requests.Session()` follows the 302, so each login yields two traces.

## Modalities (v2)
- **Trace:** the login trace is **structurally identical** for success and
  failure (span_count 5, db_span 1 both). TeaStore returns 302 either way and
  carries no `http.status_code`. The only trace-visible discriminator is the
  redirect target of the follow-up GET (home vs login) — categorical routing.
- **Log:** both success and failure emit a request-boundary ENTRY on
  `loginAction`; **the password argument is redacted (`***`)** — 0 plaintext
  credentials in the corpus (verified). Because both outcomes log similarly, the
  count-based log features separate only weakly.

## Detection (RF F1, 5-fold, N=500)
| arm | F1 | note |
|---|---|---|
| trace | **0.78** | discriminator is a categorical route, dropped from numeric features |
| log | 0.55 | success/failure log similarly; counts barely separate |
| combined | 0.77 | neither modality carries the signal structurally |

SUT1 v2 credential_abuse: trace 1.00 / log 1.00 / combined 1.00. **Headline
RQ3 finding — signal locus differs by system:** on SUT1 a failed login aborts
early *within* the trace (span 12→8, DB 3→1) and the failure is logged
distinctly; on SUT2 the login trace is identical and the signal moved to the
redirect route, outside both the numeric trace features and the count log
features. See `docs/CROSS_SYSTEM_ANALYSIS.md` §5a.

## Files
- Features: `data/processed/combined/sut2v2_credential_abuse_features.csv`
- Per-trace logs: `data/processed/logs/sut2v2_credential_abuse/logs_by_trace.csv`
- Traces: `data/processed/traces/sut2v2_credential_abuse/{spans,traces}.csv`
- Traffic: `data/raw/traffic/sut2v2_credential_abuse_{normal,attack}_*.jsonl`
- Transcript: `docs/daily_logs/corpus_sut2v2_credential_abuse_20261028.md`

## Known limitations
- Detection sets are per-trace (1000/1000), not per-login (500/500).
- `cred_bruteforce` and `cred_userenum` are indistinguishable at the HTTP level
  (same "wrong credentials" response) — a security-positive property (no user
  enumeration leak), worth a line in the paper.
- Password redaction is enforced at the instrumentation boundary; the corpus
  contains no plaintext credential, by design.
