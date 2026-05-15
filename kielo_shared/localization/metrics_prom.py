"""prometheus_client-backed implementation of the Metrics protocol.

Mirror of ``kielo-shared/localization/metricsprom`` (Go). Exposes the
counter family ``kielo_translation_total`` with the same labels so a
single Prometheus query slices across both Go and Python services.

Construction is a one-liner at service startup::

    from prometheus_client import REGISTRY
    from kielo_shared.localization.metrics_prom import PromMetrics

    metrics = PromMetrics()  # registers against the default registry
    seam = Seam(registry, cache=..., overrides=..., metrics=metrics)

Tests can pass an isolated registry to avoid global-state collisions::

    from prometheus_client import CollectorRegistry
    reg = CollectorRegistry()
    metrics = PromMetrics(registry=reg)
"""

from __future__ import annotations

from typing import Optional

from prometheus_client import REGISTRY, Counter, CollectorRegistry
from prometheus_client.registry import CollectorRegistry as _RegistryType


# Documented as module constants so dashboards / alerting rules import
# them instead of re-typing the string.
#
# Note: the Go-side adapter at `kielo-shared/localization/metricsprom`
# uses the bare name `kielo_translation_total` because Go's
# prometheus client doesn't strip a `_total` suffix. The Python
# prometheus_client library DOES strip it: passing
# `kielo_translation_total` as the Counter name results in the family
# being collected as `kielo_translation` with samples
# `kielo_translation_total{...}`. To keep dashboards consistent across
# Go and Python services we pass `kielo_translation` here so the wire
# format ends up identical: a counter family named `kielo_translation`
# with a `_total` sample, regardless of source service.
COUNTER_NAME = "kielo_translation"

# The full sample name exposed via /metrics. Tests and dashboards that
# scrape Prometheus see this name; Counter family name is COUNTER_NAME
# without the suffix.
COUNTER_SAMPLE_NAME = "kielo_translation_total"

LABEL_NAMES = ("namespace", "target_locale", "source")

_COUNTER_HELP = (
    "Localization seam resolution counter. "
    "Labels: namespace (resource type), target_locale (BCP-47 base), "
    "source (english_passthrough|override|cache_hit|cache_swr|"
    "cache_miss_share|provider_call|provider_error)."
)


class PromMetrics:
    """Implements the Metrics Protocol from
    ``kielo_shared.localization.seam`` with prometheus_client.

    The counter family is registered against the supplied registry (or
    the package-global REGISTRY by default). Re-registering the same
    shape on the same registry is harmless — the existing collector is
    reused so two Seam instances in one process share the counter.
    """

    def __init__(self, registry: Optional[_RegistryType] = None) -> None:
        target = registry if registry is not None else REGISTRY
        existing = self._find_existing_counter(target)
        if existing is not None:
            self._counter = existing
        else:
            self._counter = Counter(
                COUNTER_NAME,
                _COUNTER_HELP,
                LABEL_NAMES,
                registry=target,
            )

    def record(self, namespace: str, target_locale: str, source: str) -> None:
        self._counter.labels(
            namespace=namespace,
            target_locale=target_locale,
            source=source,
        ).inc()

    @staticmethod
    def _find_existing_counter(registry: _RegistryType) -> Optional[Counter]:
        """Walk the registry for a previously-registered counter with
        our exact name. prometheus_client doesn't expose a public
        lookup-by-name; iterate _names_to_collectors directly. If a
        future client version renames the attribute, fall through to
        re-registration — the duplicate-name error will surface loudly.
        """
        names = getattr(registry, "_names_to_collectors", None)
        if not isinstance(names, dict):
            return None
        existing = names.get(COUNTER_NAME)
        if isinstance(existing, Counter):
            return existing
        return None
