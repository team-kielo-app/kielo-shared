"""Translation request/response value types.

Roles map to the three localizer shapes that today live as
`localize_llm_text(mode="plain")`, `localize_llm_text(mode="html")`, and
`localize_llm_gloss` in `kielolearn-engine`. A provider must honor the role
when picking prompts / output validators (e.g. `html` must preserve tags;
`gloss` must output target-language only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal


# Three roles cover today's translator surface. Adding a new role is allowed
# but must be coordinated across providers — keep the alphabet small.
TranslationRole = Literal["plain", "gloss", "html"]

# Why a result's text is what it is. `provider` says WHICH backend answered;
# `status` says whether the answer is a translation:
#   translated   the backend's own answer (default, and what every provider
#                that predates this field implicitly meant)
#   echo         the backend answered with the source text unchanged; a real
#                answer (brand names, taught Finnish words), but for prose it
#                is a soft failure
#   unavailable  no answer (outage, timeout, rate limit, empty or unparsable
#                reply, breaker open, length mismatch); `text` is the source
#   same_locale  source and target are the same language; `text` is the source
#   empty_source the source was blank; nothing to translate
TranslationStatus = Literal[
    "translated", "echo", "unavailable", "same_locale", "empty_source"
]

PASSTHROUGH_PROVIDER = "passthrough"


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
        "gemini:gemini-3.1-flash-lite@phase-f"). Never bare model name.
      cached: True if served from a cache layer. False until cache decorator
        lands.
      latency_ms: per-item latency. For batch calls, the provider divides
        wall-time across items.
      confidence: 0..1 if the provider supports it; None otherwise.
      correlation_id: trace id stamped onto the result for log correlation.
      status: provenance of `text` (see TranslationStatus). Defaults to
        "translated" so providers written before the field existed behave as
        before; `provider == "passthrough"` with that default is read as
        "unavailable" (see `is_passthrough`).
    """

    text: str
    provider: str
    cached: bool = False
    latency_ms: int = 0
    confidence: float | None = None
    correlation_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    status: TranslationStatus = "translated"

    @property
    def is_passthrough(self) -> bool:
        """True when `text` is the source standing in for a backend answer.

        Such a result must not be cached or persisted as a translation: it
        would pin the source language until the entry expires. Covers the
        explicit statuses and, for providers that never set one, the legacy
        `provider == "passthrough"` marker. An "echo" is NOT a passthrough:
        the backend did answer.
        """
        if self.status in ("unavailable", "empty_source", "same_locale"):
            return True
        return self.status == "translated" and self.provider == PASSTHROUGH_PROVIDER


def passthrough_result(
    item: TranslationItem, status: TranslationStatus = "unavailable"
) -> TranslationResult:
    return TranslationResult(
        text=item.text, provider=PASSTHROUGH_PROVIDER, status=status
    )


def _normalized(value: str | None) -> str:
    return " ".join((value or "").split()).casefold()


def is_source_echo(source_text: str | None, translated_text: str | None) -> bool:
    """True when the answer equals the source (whitespace/case-insensitive)."""
    source = _normalized(source_text)
    return bool(source) and _normalized(translated_text) == source


def answered_status(
    source_text: str | None, translated_text: str | None
) -> TranslationStatus:
    return "echo" if is_source_echo(source_text, translated_text) else "translated"


_PLACEHOLDER_RE = re.compile(r"\{\{[^}]*\}\}|%[sdvqtf]|%%")
# Three-plus letters: "-Vn", "XP", "·" and digits are not words.
_WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
PROSE_MIN_WORDS = 5


def is_prose(text: str | None) -> bool:
    """True for text long enough that an identical translation is implausible.

    Measured on prod's curated corpus: 2-5% of translations per locale are
    legitimately identical to the English source (brand names, placeholders,
    the Finnish greetings the app teaches), and none of those has five words.
    """
    return (
        len(_WORD_RE.findall(_PLACEHOLDER_RE.sub(" ", text or ""))) >= PROSE_MIN_WORDS
    )


__all__ = [
    "PASSTHROUGH_PROVIDER",
    "PROSE_MIN_WORDS",
    "TranslationItem",
    "TranslationResult",
    "TranslationRole",
    "TranslationStatus",
    "answered_status",
    "is_prose",
    "is_source_echo",
    "passthrough_result",
]
