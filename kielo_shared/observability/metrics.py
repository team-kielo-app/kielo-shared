"""Prometheus emitters for seam telemetry.

Three record shapes covered:
  * llm_call       — one per LLM provider invocation
  * localization_batch — one per translation batch
  * prewarm_*      — session-localization prewarm lifecycle

Each emitter:
  1. Always logs the record (preserves existing log-based queries).
  2. If `prometheus_client` is importable, increments labelled counters
     and observes labelled histograms — `/metrics` scrape returns them.

Histogram buckets cover the realistic latency range: 50ms baseline up to
~30s for cold LLM calls. Cardinality controls:
  * `task` label is the seam's task tag (~10-20 values, stable).
  * `provider` label is the version-stamped provider id.
  * `cached` is a boolean string for partitioning hit-rate dashboards.
  * `error` is the exception class name OR empty — bounded by raise sites.

Resist the urge to add free-form labels; high-cardinality (e.g. user_id,
item_id) belongs in trace logs, not metrics.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any


logger = logging.getLogger(__name__)

# Per-(service, resolver) lock used to gate the WARN-once log emitted by
# `per_language_search_path_fallback_emit`. Process-local; survives the
# lifetime of the worker. Falling-back background workers stay at DEBUG;
# the WARN is reserved for request-path resolvers (`expected_fallback=False`)
# where a single fallback occurrence already signals a regression.
_PER_LANGUAGE_FALLBACK_WARN_SEEN: set[tuple[str, str]] = set()
_PER_LANGUAGE_FALLBACK_WARN_LOCK = threading.Lock()


try:
    from prometheus_client import REGISTRY, Counter, Histogram, generate_latest
    from prometheus_client import CollectorRegistry  # noqa: F401 — re-exported via REGISTRY

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


# Histogram bucket profile for LLM-style latencies (ms → seconds).
_LATENCY_BUCKETS_S = (
    0.005,  # cache hit
    0.025,
    0.050,
    0.100,
    0.250,
    0.500,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)


# Buckets for char-count distributions (inputs/outputs). LLM payloads
# rarely exceed 8 KiB; provide enough resolution at low end.
_CHAR_BUCKETS = (50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000)


# ─────────────────────────── prometheus metrics ──────────────────────────


if PROMETHEUS_AVAILABLE:
    LLM_CALLS_TOTAL = Counter(
        "kielo_llm_calls_total",
        "LLM call count by provider/task/cache state.",
        labelnames=("provider", "task", "cache_policy", "cached", "error"),
    )
    LLM_LATENCY_S = Histogram(
        "kielo_llm_latency_seconds",
        "LLM call latency in seconds.",
        labelnames=("provider", "task", "cached"),
        buckets=_LATENCY_BUCKETS_S,
    )
    LLM_CHAR_IN = Histogram(
        "kielo_llm_char_count_in",
        "LLM prompt char count distribution.",
        labelnames=("provider", "task"),
        buckets=_CHAR_BUCKETS,
    )
    LLM_CHAR_OUT = Histogram(
        "kielo_llm_char_count_out",
        "LLM response char count distribution.",
        labelnames=("provider", "task"),
        buckets=_CHAR_BUCKETS,
    )

    LOC_BATCHES_TOTAL = Counter(
        "kielo_localization_batches_total",
        "Translation batch count by provider/locale-pair/error.",
        labelnames=("provider", "source_locale", "target_locale", "error"),
    )
    LOC_BATCH_LATENCY_S = Histogram(
        "kielo_localization_batch_latency_seconds",
        "Translation batch wall-clock in seconds.",
        labelnames=("provider", "target_locale"),
        buckets=_LATENCY_BUCKETS_S,
    )
    LOC_BATCH_ITEMS = Histogram(
        "kielo_localization_batch_items",
        "Items per translation batch.",
        labelnames=("provider", "target_locale"),
        buckets=(1, 5, 10, 25, 50, 100, 250),
    )
    LOC_BATCH_CHARS = Histogram(
        "kielo_localization_batch_chars",
        "Total source-text chars per translation batch.",
        labelnames=("provider", "target_locale"),
        buckets=_CHAR_BUCKETS,
    )

    PREWARM_TOTAL = Counter(
        "kielo_session_prewarm_total",
        "Session-localization prewarm outcomes.",
        labelnames=("stage", "result"),
    )

    # TTS seam (`kielo_shared.seam.tts`). Mirrors the Go-side family
    # in `kielo-shared/observe/metrics/tts.go` — same name + label
    # vocabulary so dashboards aggregate Go (kielo-convo) and Python
    # (engine) TTS callers under one metric.
    TTS_CALLS_TOTAL = Counter(
        "kielo_tts_calls_total",
        "TTS provider call count by provider/task/voice/error.",
        labelnames=("provider", "task", "voice", "error"),
    )
    TTS_LATENCY_SECONDS = Histogram(
        "kielo_tts_latency_seconds",
        "TTS provider latency in seconds.",
        labelnames=("provider", "task", "voice"),
        buckets=_LATENCY_BUCKETS_S,
    )

    # Caller-side TTS cache effectiveness signal. Distinct from
    # `kielo_tts_calls_total` because cache HITS short-circuit
    # before the provider call — the provider counter never
    # increments, leaving cache health invisible. This counter
    # closes that gap.
    #
    # Labels:
    #   * caller — pinned per call-site
    #     (`convo_greeting_prime`, `klearn_tts_baseword`, etc.).
    #     Bounded set; same vocabulary as the seam `task` tag.
    #   * outcome — "hit" | "miss". Bounded enum.
    TTS_CACHE_RESULT_TOTAL = Counter(
        "kielo_tts_cache_result_total",
        "TTS caller-side cache lookup outcomes by caller/outcome.",
        labelnames=("caller", "outcome"),
    )

    # STT seam (`kielo_shared.seam.stt`). Phase STT-1 — factory
    # construction-time metrics only; per-transcript runtime
    # metrics are out of scope.
    STT_CALLS_TOTAL = Counter(
        "kielo_stt_calls_total",
        "STT factory construction count by provider/task/language/error.",
        labelnames=("provider", "task", "language", "error"),
    )
    STT_KEYTERMS_COUNT = Histogram(
        "kielo_stt_keyterms_count",
        "Keyterm count per STT factory construction.",
        labelnames=("provider", "task", "language"),
        buckets=(0, 1, 2, 5, 10, 25, 50, 100),
    )

    # Phase I — idempotency layer for engine async / generation
    # workflows. One emit per `run_idempotent(...)` call.
    #
    # Bounded labels:
    #   * namespace — caller-pinned per workflow
    #     (`topic_list_prompt`, `concept_hub_generation`, etc.).
    #     Same vocabulary as the seam `task` label.
    #   * result — bounded enum: "started" (new run), "hit"
    #     (cached succeeded result returned), "in_progress"
    #     (existing run within TTL — caller maps to 202),
    #     "conflict" (incompatible request body for same key),
    #     "failed" (run completed with error stored), "error"
    #     (run raised; transient, caller may retry).
    IDEMPOTENCY_TOTAL = Counter(
        "kielo_idempotency_total",
        "Idempotent-execution outcomes by namespace/result.",
        labelnames=("namespace", "result"),
    )
    IDEMPOTENCY_LATENCY_S = Histogram(
        "kielo_idempotency_latency_seconds",
        "Idempotent-execution wall-clock latency by namespace/result.",
        labelnames=("namespace", "result"),
        buckets=_LATENCY_BUCKETS_S,
    )

    # F-lite generate+validate layer. Emits one record per
    # `generate_with_validation` call (NOT per attempt — the attempts
    # observation pins distribution shape).
    LLM_GENERATE_VALIDATE_TOTAL = Counter(
        "kielo_llm_generate_validate_total",
        "F-lite generate+validate outcomes by task/valid/cached/error_class.",
        labelnames=("task", "valid", "cached", "error_class"),
    )
    LLM_GENERATE_VALIDATE_ATTEMPTS = Histogram(
        "kielo_llm_generate_validate_attempts",
        "Attempt-count distribution per generate+validate call.",
        labelnames=("task", "valid"),
        buckets=(1, 2, 3, 5, 10),
    )

    # Pub/Sub publish + ack telemetry. Mirrors the Go-side family in
    # kielo-shared/observe/metrics/pubsub.go so dashboards and alerts can
    # treat Python and Go publishers uniformly.
    PUBSUB_PUBLISH_TOTAL = Counter(
        "kielo_pubsub_publish_total",
        "Pub/Sub publish attempts by service/topic/outcome (success|error|skipped).",
        labelnames=("service", "topic", "outcome"),
    )
    PUBSUB_PUBLISH_LATENCY_S = Histogram(
        "kielo_pubsub_publish_latency_seconds",
        "Pub/Sub publish wall-clock latency by service/topic.",
        labelnames=("service", "topic"),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    PUBSUB_ACK_TOTAL = Counter(
        "kielo_pubsub_ack_total",
        "Pub/Sub consumer ack outcomes by service/topic/outcome (ack|nack|deadletter|drop).",
        labelnames=("service", "topic", "outcome"),
    )

    # v1-sunset burn-down counters. Mirrors the deleted Go-side family
    # (`kielo_v1_route_hits_total`, `kielo_v3_legacy_alias_hits_total`)
    # so dashboards aggregate Go services + Python (kielolearn-engine)
    # uniformly. Used by `kielo_shared.middleware.legacy_alias.Deprecation`
    # / `LegacyAlias` ASGI middleware (FastAPI/Starlette) and by callers
    # outside the middleware (manual increments are NOT expected — the
    # middleware owns the increment site so labels stay consistent).
    #
    # Cardinality controls:
    #   * `service` — short service name pinned per process
    #     ("kielolearn-engine", "mobile-bff", …). Bounded.
    #   * `method` — HTTP verb. Bounded enum.
    #   * `path` — Starlette route template, NOT the request URL
    #     (so `/users/{id}` instead of `/users/42`). Bounded by the
    #     route table at startup. Callers MUST pass the template.
    #   * `successor` — successor v3 path template. Bounded by config.
    V1_ROUTE_HITS_TOTAL = Counter(
        "kielo_v1_route_hits_total",
        "Hit count for /api/v1 (or /klearn/api/v1) routes still in service. "
        "Drives the v1-sunset burn-down dashboard.",
        labelnames=("service", "method", "path"),
    )
    LEGACY_ALIAS_HITS_TOTAL = Counter(
        "kielo_v3_legacy_alias_hits_total",
        "Hit count for v3 legacy-alias routes that forward to a canonical "
        "v3 successor. Drives the alias sunset burn-down dashboard.",
        labelnames=("service", "path", "successor"),
    )

    # Non-fatal side-effect failure counter. Use from any handler that
    # has a primary path (a write the caller depends on) and a set of
    # auxiliary side effects (achievement award, telemetry write,
    # cache invalidation, downstream RPC) where each side effect
    # failure is logged but NOT propagated to the caller. Pre-2026-
    # 05-23 the codebase had ~30 of these in behavioral_event_service,
    # session_state_service, etc. — each one logged at WARN with no
    # counter, so dashboards couldn't alert when the rate climbed.
    #
    # Labels:
    #   * service  — short service name pinned per process
    #     ("kielolearn-engine", "kielo-cms", ...). Bounded by process count.
    #   * kind     — caller-pinned tag of the specific side effect
    #     ("behavioral_event.achievement", "session_persist.checkpoint",
    #      "cache_invalidate.kielotv_recommendations", ...). Bounded by
    #     the set of call sites; the dot-delimited shape keeps
    #     dashboard regexes simple.
    #
    # Alert recipe:
    #   rate(kielo_side_effect_failed_total{service="kielolearn-engine"}[5m]) > 1
    #   → some side-effect chain is consistently broken; drill in by
    #     the `kind` label to find which one.
    SIDE_EFFECT_FAILED_TOTAL = Counter(
        "kielo_side_effect_failed_total",
        "Non-fatal side-effect failures by service/kind. Counts handler "
        "branches that log + swallow a failure instead of propagating.",
        labelnames=("service", "kind"),
    )

    # Per-language search_path fallback counter. Fires when
    # `kielo_shared.db_utils.make_per_language_search_path` resolves a
    # transaction's search_path with no active language on the context
    # AND a static fallback path is configured. The fallback is the
    # documented contract for background workers operating on shared /
    # legacy schemas; on request-path resolvers (engine sessions, content-
    # service repos) any non-zero rate is a regression in upstream
    # language propagation. Used together with the WARN-once log emitted
    # by `per_language_search_path_fallback_emit` when
    # `expected_fallback=False` to surface unexpected fallbacks.
    #
    # Labels:
    #   * service — short service name pinned per process
    #     ("kielolearn-engine", "kielo-ingest-processor", ...). Bounded.
    #   * resolver — caller-pinned tag of the resolver call site
    #     ("session", "data_hygiene", "deduplicate_concepts", ...). Bounded
    #     by the resolver-construction sites (5 today). The label is
    #     the same vocabulary as the Go-side `callsite` label so
    #     dashboards can join Python + Go uniformly.
    PER_LANGUAGE_SEARCH_PATH_FALLBACK_TOTAL = Counter(
        "kielo_per_language_search_path_fallback_total",
        "search_path resolutions that fell back to a static path because no active language was set on context.",
        labelnames=("service", "resolver"),
    )


# ────────────────────────────── emitters ─────────────────────────────────


def llm_emit(record: dict[str, Any]) -> None:
    """Emit one `llm_call` record. Safe with or without prometheus_client.

    Log level policy (Phase D+3.2 transition cleanup):
      * success path (`error` empty)  → DEBUG; metric is the durable signal.
      * failure path (`error` set)    → INFO; carries diagnostic context.
    """
    if str(record.get("error") or ""):
        logger.info("llm_call %s", record)
    else:
        logger.debug("llm_call %s", record)
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        provider = str(record.get("provider") or "unknown")
        task = str(record.get("task") or "generic")
        cache_policy = str(record.get("cache_policy") or "none")
        cached = "true" if record.get("cached") else "false"
        error = str(record.get("error") or "")
        LLM_CALLS_TOTAL.labels(
            provider=provider,
            task=task,
            cache_policy=cache_policy,
            cached=cached,
            error=error,
        ).inc()
        latency_ms = float(record.get("latency_ms") or 0)
        LLM_LATENCY_S.labels(provider=provider, task=task, cached=cached).observe(
            latency_ms / 1000.0
        )
        LLM_CHAR_IN.labels(provider=provider, task=task).observe(
            float(record.get("char_count_in") or 0)
        )
        LLM_CHAR_OUT.labels(provider=provider, task=task).observe(
            float(record.get("char_count_out") or 0)
        )
    except Exception as exc:
        logger.debug("llm_emit prometheus fanout failed: %s", exc)


def localization_emit(record: dict[str, Any]) -> None:
    """Emit one `localization_batch` record.

    Same log policy as `llm_emit`: success → DEBUG, error → INFO.
    """
    if str(record.get("error") or ""):
        logger.info("localization_batch %s", record)
    else:
        logger.debug("localization_batch %s", record)
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        provider = str(record.get("provider") or "unknown")
        source = str(record.get("source_locale") or "")
        target = str(record.get("target_locale") or "")
        error = str(record.get("error") or "")
        LOC_BATCHES_TOTAL.labels(
            provider=provider,
            source_locale=source,
            target_locale=target,
            error=error,
        ).inc()
        latency_ms = float(record.get("latency_ms") or 0)
        LOC_BATCH_LATENCY_S.labels(provider=provider, target_locale=target).observe(
            latency_ms / 1000.0
        )
        LOC_BATCH_ITEMS.labels(provider=provider, target_locale=target).observe(
            float(record.get("item_count") or 0)
        )
        LOC_BATCH_CHARS.labels(provider=provider, target_locale=target).observe(
            float(record.get("char_count") or 0)
        )
    except Exception as exc:
        logger.debug("localization_emit prometheus fanout failed: %s", exc)


def pubsub_publish_emit(
    *,
    service: str,
    topic: str,
    error: bool = False,
    skipped: bool = False,
    latency_seconds: float = 0.0,
) -> None:
    """Record one Pub/Sub publish attempt.

    `skipped=True` covers short-circuit paths (publisher disabled in dev,
    payload empty, dry_run flag) — distinct from `error=True` so dashboards
    separate "couldn't publish" from "deliberately didn't publish".
    Latency is observed only for actual attempts (skipped paths leave the
    histogram untouched).

    Log policy: error path → INFO (caller is interested), success +
    skipped → DEBUG (high frequency; metric is the durable signal).
    """
    if error:
        logger.info(
            "pubsub_publish service=%s topic=%s error=%s skipped=%s latency_s=%.4f",
            service,
            topic,
            error,
            skipped,
            latency_seconds,
        )
    else:
        logger.debug(
            "pubsub_publish service=%s topic=%s error=%s skipped=%s latency_s=%.4f",
            service,
            topic,
            error,
            skipped,
            latency_seconds,
        )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        if skipped:
            outcome = "skipped"
        elif error:
            outcome = "error"
        else:
            outcome = "success"
        PUBSUB_PUBLISH_TOTAL.labels(service=service, topic=topic, outcome=outcome).inc()
        if not skipped:
            PUBSUB_PUBLISH_LATENCY_S.labels(service=service, topic=topic).observe(
                latency_seconds
            )
    except Exception as exc:
        logger.debug("pubsub_publish_emit fanout failed: %s", exc)


def pubsub_ack_emit(
    *,
    service: str,
    topic: str,
    outcome: str = "ack",
) -> None:
    """Record one Pub/Sub consumer ack outcome.

    `outcome` is one of "ack" | "nack" | "deadletter" | "drop". The "drop"
    outcome covers handlers that 2xx-ack a delivery but discard it
    intentionally (e.g. the engine behavioral-event handler dropping
    missing-language envelopes).

    Log policy: ack → DEBUG (success path); nack/deadletter → INFO
    (degradation signal); drop → DEBUG (intentional discard).
    """
    if outcome in ("nack", "deadletter"):
        logger.info(
            "pubsub_ack service=%s topic=%s outcome=%s",
            service,
            topic,
            outcome,
        )
    else:
        logger.debug(
            "pubsub_ack service=%s topic=%s outcome=%s",
            service,
            topic,
            outcome,
        )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        PUBSUB_ACK_TOTAL.labels(service=service, topic=topic, outcome=outcome).inc()
    except Exception as exc:
        logger.debug("pubsub_ack_emit fanout failed: %s", exc)


# ──────── error_class sanitization for generate_validate emitter ────────


# Strips index-style suffixes (`_0_`, `_12_`) so multi-item errors
# don't blow cardinality (e.g. `example_0_missing_text` and
# `example_5_missing_text` collapse to `example_missing_text`).
_INDEX_IN_NAME_RE = re.compile(r"_\d+_")
# Trailing index (e.g. `step_3`) — same intent.
_TRAILING_INDEX_RE = re.compile(r"_\d+$")
# Conservative max length so a runaway error string never becomes
# a high-cardinality label by itself.
_ERROR_CLASS_MAX_LEN = 64


def _sanitize_error_class(raw: str | None) -> str:
    """Reduce a validator error string to a stable bucket name.

    Keeps the prefix before the first `:` (everything after is
    typically a value: term, count, exception message), strips
    embedded indices, lowercases, length-caps. Never returns
    free-form user/LLM text — only the validator's own error tags
    plus exception class names.
    """
    if not raw:
        return ""
    prefix = raw.split(":", 1)[0]
    cleaned = _INDEX_IN_NAME_RE.sub("_", prefix)
    cleaned = _TRAILING_INDEX_RE.sub("", cleaned)
    cleaned = cleaned.strip().lower()
    if len(cleaned) > _ERROR_CLASS_MAX_LEN:
        cleaned = cleaned[:_ERROR_CLASS_MAX_LEN]
    return cleaned


def llm_generate_validate_emit(
    *,
    task: str,
    prompt_version: str = "",
    valid: bool,
    cached: bool | None = None,
    attempts: int = 1,
    validation_errors: list[str] | None = None,
) -> None:
    """Emit one F-lite generate+validate outcome.

    Always logs the structured line (preserves the existing log
    surface used during the migration). When prometheus_client is
    importable, also increments the labelled counter and observes
    the attempts histogram. Label cardinality is bounded:
      * `task` — caller's seam task tag (~10-20 stable values)
      * `valid` — "true" | "false"
      * `cached` — "true" | "false" | "unknown"
      * `error_class` — sanitized first error tag, "" on success
    """
    error_class = _sanitize_error_class(
        validation_errors[0] if validation_errors else None
    )
    # Log policy: success → DEBUG (metric carries the same labels);
    # failure → INFO (validation errors are diagnostic).
    if valid:
        logger.debug(
            "llm_generate_validate task=%s prompt_version=%s attempts=%d valid=%s "
            "cached=%s error_class=%s error_count=%d",
            task,
            prompt_version,
            attempts,
            valid,
            cached,
            error_class,
            len(validation_errors or []),
        )
    else:
        logger.info(
            "llm_generate_validate task=%s prompt_version=%s attempts=%d valid=%s "
            "cached=%s error_class=%s error_count=%d",
            task,
            prompt_version,
            attempts,
            valid,
            cached,
            error_class,
            len(validation_errors or []),
        )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        cached_label = (
            "true" if cached is True else "false" if cached is False else "unknown"
        )
        valid_label = "true" if valid else "false"
        LLM_GENERATE_VALIDATE_TOTAL.labels(
            task=task,
            valid=valid_label,
            cached=cached_label,
            error_class=error_class,
        ).inc()
        LLM_GENERATE_VALIDATE_ATTEMPTS.labels(task=task, valid=valid_label).observe(
            float(attempts)
        )
    except Exception as exc:
        logger.debug("llm_generate_validate_emit prometheus fanout failed: %s", exc)


def idempotency_emit(
    *,
    namespace: str,
    result: str,
    latency_seconds: float = 0.0,
) -> None:
    """Increment the idempotency outcome counter + observe latency.

    `result` is bounded: "started" | "hit" | "in_progress" |
    "conflict" | "failed" | "error". Other values accepted but
    caller is responsible for keeping the label set bounded.

    Log policy: "started" + "hit" → DEBUG (success-path);
    "conflict" + "failed" + "error" + "in_progress" → INFO
    (caller-actionable signal).
    """
    quiet_results = {"started", "hit"}
    if result in quiet_results:
        logger.debug(
            "idempotency namespace=%s result=%s latency_s=%.4f",
            namespace,
            result,
            latency_seconds,
        )
    else:
        logger.info(
            "idempotency namespace=%s result=%s latency_s=%.4f",
            namespace,
            result,
            latency_seconds,
        )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        IDEMPOTENCY_TOTAL.labels(namespace=namespace, result=result).inc()
        IDEMPOTENCY_LATENCY_S.labels(namespace=namespace, result=result).observe(
            latency_seconds
        )
    except Exception as exc:
        logger.debug("idempotency_emit prometheus fanout failed: %s", exc)


def tts_cache_emit(*, caller: str, outcome: str) -> None:
    """Increment the TTS caller-side cache outcome counter.

    `outcome` is "hit" | "miss" (bounded enum). Other values are
    accepted but recorded as-is — caller is responsible for keeping
    the label set bounded.

    Log policy: high-frequency hot path. DEBUG always — metric is
    the durable signal; cache-cold rate is queryable from
    `kielo_tts_cache_result_total{outcome="miss"}`.
    """
    logger.debug("tts_cache caller=%s outcome=%s", caller, outcome)
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        TTS_CACHE_RESULT_TOTAL.labels(caller=caller, outcome=outcome).inc()
    except Exception as exc:
        logger.debug("tts_cache_emit prometheus fanout failed: %s", exc)


def prewarm_emit(*, stage: str, result: str) -> None:
    """Increment a labelled counter for a prewarm outcome.

    Phase E records emit unstructured text; this helper exists so
    prewarm sites can emit BOTH log + metric in one call. Migration is
    optional — log-only still produces the same `prewarm_*` lines.
    """
    logger.info("prewarm_metric stage=%s result=%s", stage, result)
    if PROMETHEUS_AVAILABLE:
        try:
            PREWARM_TOTAL.labels(stage=stage, result=result).inc()
        except Exception as exc:
            logger.debug("prewarm_emit prometheus fanout failed: %s", exc)


# ────────────────────── v1-sunset burn-down emitters ────────────────────


def v1_route_hit_emit(*, service: str, method: str, path: str) -> None:
    """Increment the v1-route hit counter. Used by the `Deprecation`
    ASGI middleware in `kielo_shared.middleware.legacy_alias`.

    `path` MUST be the route template (e.g. `/klearn/api/v1/sessions/{id}`),
    NOT the request URL — otherwise label cardinality explodes with each
    distinct path-param value. Caller is responsible for resolving the
    template from the Starlette match.

    Log policy: DEBUG. High-frequency hot path; the metric is the durable
    signal.
    """
    logger.debug(
        "v1_route_hit service=%s method=%s path=%s",
        service,
        method,
        path,
    )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        V1_ROUTE_HITS_TOTAL.labels(service=service, method=method, path=path).inc()
    except Exception as exc:
        logger.debug("v1_route_hit_emit prometheus fanout failed: %s", exc)


def side_effect_failed_emit(
    *,
    service: str,
    kind: str,
    exc: BaseException | None = None,
) -> None:
    """Record one non-fatal side-effect failure.

    Always increments :data:`SIDE_EFFECT_FAILED_TOTAL{service, kind}`
    (when prometheus_client is importable). The caller has already
    logged at WARN/ERROR with the exception detail; this helper is
    metric-only so dashboards can alert on the rate even when the
    log line is buried in high-traffic services.

    `exc` is optional and currently unused by the metric (cardinality
    would explode if we added an `error_class` label). It's accepted
    in the signature for future expansion (per-class drill-down via
    log correlation) and so callers don't have to restructure their
    catch blocks.
    """
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        SIDE_EFFECT_FAILED_TOTAL.labels(service=service, kind=kind).inc()
    except Exception as fanout_exc:
        logger.debug(
            "side_effect_failed_emit prometheus fanout failed: %s",
            fanout_exc,
        )
    # exc is consumed for type-narrowing only; the caller is responsible
    # for logging it. This keeps emitter semantics consistent with the
    # other *_emit helpers in this module.
    del exc


def per_language_search_path_fallback_emit(
    *,
    service: str,
    resolver: str,
    expected_fallback: bool = False,
) -> None:
    """Record one search_path fallback event from
    :func:`kielo_shared.db_utils.make_per_language_search_path`.

    Always increments :data:`PER_LANGUAGE_SEARCH_PATH_FALLBACK_TOTAL`
    (when prometheus_client is importable). Log policy:

    * ``expected_fallback=False`` — WARN on the FIRST occurrence per
      ``(service, resolver)`` pair, DEBUG thereafter. Used by request-
      path resolvers (engine session, content-service repos) where a
      fallback occurrence already signals an upstream regression: the
      first WARN catches a human's eye, the metric carries the ongoing
      rate.
    * ``expected_fallback=True`` — DEBUG always. Used by background
      workers (data hygiene, embedding backfills, deduplication) where
      fallback IS the documented contract; the WARN would be noise.

    Either way, the metric is the durable signal — alert off
    ``rate(kielo_per_language_search_path_fallback_total{service="kielolearn-engine"}[5m]) > 0``
    for request-path services, and use the per-resolver split to
    investigate which call site is leaking.
    """
    if expected_fallback:
        logger.debug(
            "per_language_search_path_fallback service=%s resolver=%s expected=true",
            service,
            resolver,
        )
    else:
        key = (service, resolver)
        first_occurrence = False
        with _PER_LANGUAGE_FALLBACK_WARN_LOCK:
            if key not in _PER_LANGUAGE_FALLBACK_WARN_SEEN:
                _PER_LANGUAGE_FALLBACK_WARN_SEEN.add(key)
                first_occurrence = True
        if first_occurrence:
            logger.warning(
                "per_language_search_path_fallback service=%s resolver=%s "
                "(no active language; using static fallback — request-path "
                "resolvers should always have a language scoped by middleware)",
                service,
                resolver,
            )
        else:
            logger.debug(
                "per_language_search_path_fallback service=%s resolver=%s expected=false",
                service,
                resolver,
            )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        PER_LANGUAGE_SEARCH_PATH_FALLBACK_TOTAL.labels(
            service=service, resolver=resolver
        ).inc()
    except Exception as exc:
        logger.debug(
            "per_language_search_path_fallback_emit prometheus fanout failed: %s",
            exc,
        )


def legacy_alias_hit_emit(*, service: str, path: str, successor: str) -> None:
    """Increment the v3 legacy-alias hit counter. Used by the
    `LegacyAlias` ASGI middleware in `kielo_shared.middleware.legacy_alias`.

    `path` is the alias route template; `successor` is the canonical v3
    path template the alias forwards to. Both are bounded by route-table
    configuration at startup.

    Log policy: DEBUG (same rationale as `v1_route_hit_emit`).
    """
    logger.debug(
        "legacy_alias_hit service=%s path=%s successor=%s",
        service,
        path,
        successor,
    )
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        LEGACY_ALIAS_HITS_TOTAL.labels(
            service=service, path=path, successor=successor
        ).inc()
    except Exception as exc:
        logger.debug("legacy_alias_hit_emit prometheus fanout failed: %s", exc)


# ─────────────────────────── /metrics text ───────────────────────────────


def metrics_text() -> bytes:
    """Render the default registry to Prometheus text format. Returns
    empty bytes when prometheus_client isn't available so the `/metrics`
    handler stays trivial."""
    if not PROMETHEUS_AVAILABLE:
        return b""
    return generate_latest(REGISTRY)


__all__ = [
    "PROMETHEUS_AVAILABLE",
    "idempotency_emit",
    "legacy_alias_hit_emit",
    "llm_emit",
    "llm_generate_validate_emit",
    "localization_emit",
    "metrics_text",
    "per_language_search_path_fallback_emit",
    "prewarm_emit",
    "pubsub_ack_emit",
    "pubsub_publish_emit",
    "side_effect_failed_emit",
    "tts_cache_emit",
    "v1_route_hit_emit",
]
