#!/usr/bin/env python3
"""
stratification.py — shared entry-point/root_operation logic for SecLogTrace.

Extracted 2026-08-20 per the standing item in PHASE_1_CHECKLIST.md /
PHASE_STATUS.md: this fix had already diverged once (made in
corpus_audit.py, not ported to build_feature_table.py until 2026-08-18 —
see docs/phase_logs/phase_log_20260818.md) and the checklist flagged it as
needing one shared home "before Phase 2, to prevent a third divergence."

Why this exists at all: Spring's catch-all mapping makes the raw span
operationName collapse to "POST /*" / "GET /*" for nearly every request on
this deployment — useless as a stratifier. The real endpoint lives in a
URL-bearing tag, not the operation name.

A THIRD, previously-unflagged divergence was found while extracting this:
parse_jaeger_traces.py's own tag lookup (used to populate spans.csv's
http_url column, which build_feature_table.py then stratifies on) only
checked ("http.url", "http.target"), in that order — the opposite
preference from corpus_audit.py's 5-tag URL_TAGS list below, which checks
http.target FIRST. In practice http.url and http.target carry equivalent
paths on this deployment (verified against experiment_002: root_operation
output is unchanged after unifying the order), so this was latent rather
than symptomatic — but it's exactly the kind of drift this module exists to
prevent, so parse_jaeger_traces.py now imports URL_TAGS from here too
instead of keeping its own narrower, differently-ordered pair.
"""
from typing import Optional

# Preference order for the tag holding the real request path. http.route is
# last on purpose — on this deployment it's the wildcard-only tag
# ("http.route=/*") that made stratification useless in the first place.
URL_TAGS = ("http.target", "url.path", "http.url", "http.path", "http.route")


def tag_value(tags: list, key: str) -> Optional[str]:
    """Look up one tag's value from a raw Jaeger span's `tags` list."""
    for t in tags or []:
        if t.get("key") == key:
            return t.get("value")
    return None


def best_url_tag(tags: list) -> Optional[str]:
    """First present tag from URL_TAGS, as a string, or None."""
    for key in URL_TAGS:
        v = tag_value(tags, key)
        if v:
            return str(v)
    return None


def is_root_span(span: dict, span_ids_in_trace: set) -> bool:
    """A span is the root of its trace if none of its references point to
    another span within the same trace (a reference to a span Jaeger didn't
    return, e.g. cross-service linkage gaps, doesn't disqualify it)."""
    refs = span.get("references") or []
    return not any(r.get("spanID") in span_ids_in_trace for r in refs)


def find_root_span(spans: list) -> Optional[dict]:
    """Root span of a raw Jaeger trace's span list, or None if empty."""
    ids = {s.get("spanID") for s in spans}
    for s in spans:
        if is_root_span(s, ids):
            return s
    return spans[0] if spans else None


def normalize_path(url: str) -> str:
    """Strip query string and scheme/host, collapse numeric (or long
    digit-bearing, e.g. UUID) path segments to '{id}' so /order/12345 and
    /order/67890 group together instead of fragmenting the stratification."""
    path = url.split("?")[0]
    if "://" in path:
        path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
    parts = []
    for seg in path.split("/"):
        if seg and (seg.isdigit() or (len(seg) > 20 and any(c.isdigit() for c in seg))):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts)


def root_operation_from_parts(op_name: Optional[str], url: Optional[str]) -> str:
    """Combine an already-extracted (operationName, url) pair into the
    canonical root_operation label. Used where the raw Jaeger span isn't
    available anymore — e.g. build_feature_table.py, working from
    spans.csv rows rather than raw JSON."""
    if not url:
        return op_name or "?"
    norm_path = normalize_path(str(url))
    return f"{op_name} {norm_path}".strip() if op_name else norm_path


def root_operation_from_spans(spans: list) -> str:
    """Entry-point label for a raw Jaeger trace's span list. Used where the
    raw JSON is still available — e.g. corpus_audit.py, working directly
    from an export file rather than a parsed CSV."""
    root = find_root_span(spans)
    if root is None:
        return "?"
    url = best_url_tag(root.get("tags", []))
    op_name = root.get("operationName", "")
    if not url:
        return op_name or "?"
    return f"{op_name} {normalize_path(url)}".strip()
