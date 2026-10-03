"""USD per 1M tokens (input, output incl. thinking); mirrors localization.llm_models."""

from __future__ import annotations

PRICES: dict[str, tuple[float, float]] = {
    "gemini-3.8-flash": (0.75, 3.75),
    "gemini-3.5-flash": (1.50, 9.00),
    "gemini-3.1-flash-lite": (0.25, 1.50),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-pro": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
}

# An unlisted model books at the dearest listed rate, never $0.
FALLBACK_PRICE: tuple[float, float] = (
    max(p[0] for p in PRICES.values()),
    max(p[1] for p in PRICES.values()),
)


def estimate_usd(
    model: str, tokens_in: int, tokens_out: int, thinking: int = 0
) -> float:
    price_in, price_out = PRICES.get(model, FALLBACK_PRICE)
    return (tokens_in * price_in + (tokens_out + thinking) * price_out) / 1_000_000
