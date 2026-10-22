"""Compiled price fallback, USD per 1M tokens (input, output incl. thinking).

The source of truth is localization.llm_models, read through
``kielo_shared.llmroute.model_price``. This table only answers while that table
is unreachable, so it lists the models the platform runs by default (plus the OpenAI ones a route may name); any other
model books at the dearest listed rate, never $0.
"""

from __future__ import annotations

PRICES: dict[str, tuple[float, float]] = {
    "gemini-3.8-flash": (0.75, 3.75),
    "gemini-3.5-flash": (1.50, 9.00),
    "gemini-3.1-flash-lite": (0.25, 1.50),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-pro": (1.25, 10.00),
    # Fallback only, for when llm_models is unreachable: an unlisted OpenAI model
    # must not book at the dearest-rate fallback (16x for the mini). The real
    # price is llm_models'.
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-6-luna": (0.10, 0.50),
}

FALLBACK_PRICE: tuple[float, float] = (2.50, 10.00)


def estimate_usd(
    model: str, tokens_in: int, tokens_out: int, thinking: int = 0
) -> float:
    from kielo_shared import llmroute

    return llmroute.estimate_usd(model, tokens_in, tokens_out, thinking)
