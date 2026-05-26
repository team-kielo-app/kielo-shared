"""kielo_shared.llm — provider-agnostic LLM seam.

Mirrors the structure of `kielo_shared.localization`. Same registry +
decorator stack pattern; different request/response shape because LLM calls
are heterogenous (free-form text, structured JSON, evaluation traces) where
translation is uniform.

Critical scope correction (Phase D):
    Translation cache is broadly safe — same source string → same target
    string for a given provider/role. General LLM calls are NOT — same
    prompt against personalized session state can return different text
    each call. Therefore the cache is OPT-IN per-request via
    `LLMRequest.cache_policy`, defaulting to "none". Only callers who
    KNOW the request is deterministic (and want cross-call dedup) flip
    it to "read_write".
"""

from __future__ import annotations

from kielo_shared.llm.cache import LLMCacheDecorator
from kielo_shared.llm.decorators import (
    LLMCorrelationDecorator,
    LLMMetricsDecorator,
)
from kielo_shared.llm.generate_validate import (
    ResultValidator,
    generate_and_validate,
)
from kielo_shared.llm.openai_provider import (
    OpenAILLMProvider,
    OpenAITextGenerator,
    OpenAIJsonGenerator,
)
from kielo_shared.llm.provider import LLMProvider
from kielo_shared.llm.registry import (
    LLMRegistry,
    UnknownLLMProviderError,
    build_llm_registry_from_env,
)
from kielo_shared.llm.sync_bridge import (
    call_llm_sync,
    call_llm_text_sync,
    run_sync,
)
from kielo_shared.llm.types import (
    CachePolicy,
    LLMRequest,
    LLMResult,
)


__all__ = [
    "call_llm_sync",
    "call_llm_text_sync",
    "CachePolicy",
    "generate_and_validate",
    "LLMCacheDecorator",
    "LLMCorrelationDecorator",
    "LLMMetricsDecorator",
    "LLMProvider",
    "LLMRegistry",
    "LLMRequest",
    "LLMResult",
    "OpenAIJsonGenerator",
    "OpenAILLMProvider",
    "OpenAITextGenerator",
    "ResultValidator",
    "run_sync",
    "UnknownLLMProviderError",
    "build_llm_registry_from_env",
]
