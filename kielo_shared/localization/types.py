"""Translation request/response value types.

Roles map to the three localizer shapes that today live as
`localize_llm_text(mode="plain")`, `localize_llm_text(mode="html")`, and
`localize_llm_gloss` in `kielolearn-engine`. A provider must honor the role
when picking prompts / output validators (e.g. `html` must preserve tags;
`gloss` must output target-language only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


# Three roles cover today's translator surface. Adding a new role is allowed
# but must be coordinated across providers — keep the alphabet small.
TranslationRole = Literal["plain", "gloss", "html"]


@dataclass(frozen=True)
class TranslationItem:
    """One thing to translate.

    Attributes:
      text: source text (UTF-8). Empty string → provider returns empty.
      role: prompt / validation flavor (plain | gloss | html).
      cache_key: optional content-derived key used by future cache decorators.
        Not required for the OpenAI provider; provided so callers don't have
        to revisit shape when caching lands.
      context: free-form metadata (POS tag, glossary domain, etc.) for
        prompt-shaping. Providers MAY ignore.
    """

    text: str
    role: TranslationRole = "plain"
    cache_key: str | None = None
    context: dict[str, Any] | None = None


@dataclass(frozen=True)
class TranslationResult:
    """One translated item + provenance.

    Attributes:
      text: translated text. On failure the provider MAY return the source
        text unchanged (graceful degrade) — `provider == "passthrough"`
        signals that.
      provider: stable provider id including version (e.g.
        "openai:gpt-4o-mini@2026-04"). Never bare model name.
      cached: True if served from a cache layer. False until cache decorator
        lands.
      latency_ms: per-item latency. For batch calls, the provider divides
        wall-time across items.
      confidence: 0..1 if the provider supports it; None otherwise.
      correlation_id: trace id stamped onto the result for log correlation.
    """

    text: str
    provider: str
    cached: bool = False
    latency_ms: int = 0
    confidence: float | None = None
    correlation_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


__all__ = ["TranslationItem", "TranslationResult", "TranslationRole"]
