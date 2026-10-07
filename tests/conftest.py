import os

import pytest

# Tests use fakes only. Opt in to the paid-LLM guard explicitly (the dev .env sets
# LLM_ALLOW_PAID_CALLS=false, so setdefault would not stick), turn the Redis
# counters off, and replace any provider key with a dummy so an unstubbed call
# fails authentication instead of spending.
os.environ["LLM_ALLOW_PAID_CALLS"] = "true"
os.environ["LLM_DAILY_BUDGET_USD"] = "0"
os.environ["LLM_HOURLY_CALL_CAP"] = "0"
for _key in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
    os.environ[_key] = "test-key-not-real"


@pytest.fixture(autouse=True)
def _support_locale_overrides_uncached():
    """Each test reads support-locale rows from its own stubs, not a cache an
    earlier test filled."""
    from kielo_shared.localization.support_locale_overrides import clear_prefetch_cache

    clear_prefetch_cache()
    yield
    clear_prefetch_cache()
