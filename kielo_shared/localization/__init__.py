"""kielo_shared.localization — provider-agnostic translation seam.

Phase B vertical slice: minimal interfaces + OpenAI provider + env-driven
routing. Lets services (engine, ingest, processor) localize text via a single
abstraction so swapping providers, adding caching, or fanning out to multiple
backends is one config change instead of a cross-service grep+edit.

What's intentionally NOT here yet (lands in later phases):
  - Redis cache decorator (cache_key field is wired through but cache layer
    is a no-op; ready to plug a RedisCacheDecorator later)
  - Circuit breakers / fallback chains
  - Gemini / DeepL / OpusMT / Dictionary providers
  - Go mirror package
  - Cross-service migrations (ingest, processor, studio-toolbox)

The seam is:

    >>> from kielo_shared.localization import (
    ...     get_default_registry, TranslationItem,
    ... )
    >>> registry = get_default_registry()
    >>> provider = registry.resolve(source_locale="en", target_locale="vi")
    >>> results = await provider.translate_batch(
    ...     items, source_locale="en", target_locale="vi",
    ... )

Callers depend only on this package — never on a concrete provider.
"""

from __future__ import annotations

from kielo_shared.localization.cache import (
    RedisAsyncClient,
    RedisCacheDecorator,
)
from kielo_shared.localization.cache_redis import RedisCache
from kielo_shared.localization.decorators import (
    CorrelationDecorator,
    MetricsDecorator,
)
from kielo_shared.localization.fallback import (
    CircuitBreaker,
    FallbackDecorator,
)
from kielo_shared.localization.gemini_provider import GeminiProvider
from kielo_shared.localization.openai_provider import OpenAIProvider
from kielo_shared.localization.provider import LocalizationProvider
from kielo_shared.localization.registry import (
    LocalizationRegistry,
    UnknownProviderError,
    build_registry_from_env,
    get_default_registry,
    reset_default_registry,
)
from kielo_shared.localization.routing import (
    RoutingDecorator,
    TIER_A_LOCALE,
    VietnameseFastPathDecorator,
    VietnameseLookup,
)
from kielo_shared.localization.seam import (
    AlwaysSuspiciousGuard,
    BatchCache,
    BatchOverrideStore,
    Cache,
    CacheEntry,
    CountingMetrics,
    MapOverrideStore,
    MapPersister,
    Metrics,
    NoopCache,
    NoopGuard,
    NoopMetrics,
    NoopOverrideStore,
    NoopPersister,
    OverrideRef,
    OverrideStore,
    Seam,
    SeamConfig,
    SourceRef,
    SuspiciousTranslationGuard,
    TranslationPersister,
    override_batch_key,
    source_version_from_text,
)
from kielo_shared.localization.types import (
    TranslationItem,
    TranslationResult,
    TranslationRole,
)

__all__ = [
    "AlwaysSuspiciousGuard",
    "BatchCache",
    "BatchOverrideStore",
    "Cache",
    "CacheEntry",
    "CircuitBreaker",
    "CorrelationDecorator",
    "CountingMetrics",
    "FallbackDecorator",
    "GeminiProvider",
    "LocalizationProvider",
    "LocalizationRegistry",
    "MapOverrideStore",
    "MapPersister",
    "Metrics",
    "MetricsDecorator",
    "NoopCache",
    "NoopGuard",
    "NoopMetrics",
    "NoopOverrideStore",
    "NoopPersister",
    "OpenAIProvider",
    "OverrideRef",
    "OverrideStore",
    "RedisAsyncClient",
    "RedisCache",
    "RedisCacheDecorator",
    "RoutingDecorator",
    "Seam",
    "SeamConfig",
    "SourceRef",
    "SuspiciousTranslationGuard",
    "TIER_A_LOCALE",
    "TranslationItem",
    "TranslationResult",
    "TranslationRole",
    "TranslationPersister",
    "UnknownProviderError",
    "VietnameseFastPathDecorator",
    "VietnameseLookup",
    "build_registry_from_env",
    "get_default_registry",
    "override_batch_key",
    "reset_default_registry",
    "source_version_from_text",
]
