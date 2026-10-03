import os

# Tests use fakes only. Opt in to the paid-LLM guard explicitly (the dev .env sets
# LLM_ALLOW_PAID_CALLS=false, so setdefault would not stick), turn the Redis
# counters off, and replace any provider key with a dummy so an unstubbed call
# fails authentication instead of spending.
os.environ["LLM_ALLOW_PAID_CALLS"] = "true"
os.environ["LLM_DAILY_BUDGET_USD"] = "0"
os.environ["LLM_HOURLY_CALL_CAP"] = "0"
for _key in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
    os.environ[_key] = "test-key-not-real"
