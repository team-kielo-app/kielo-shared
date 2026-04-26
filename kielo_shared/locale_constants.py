"""Shared locale constants for the Kielo platform.

These two constants are the universal answers to two questions every
service has to answer when localizing content:

  * What language do we *teach* by default? Finnish (LEGACY_DEFAULT_LEARNING_LANGUAGE).
  * What language do we *support the learner in* by default? English (TIER_A_SUPPORT_LOCALE).

Pre-rollout publishers may emit messages without a learning_language_code
attribute and pre-rollout DB rows may have NULL learning_language_code.
These constants are the single source of truth for what those legacy
gaps resolve to.

Kept in kielo_shared so every Python service (kielolearn-engine,
kielo-ingest-processor, future Python services) imports the same value
rather than redefining it locally.
"""

# The default learning language for legacy data where learning_language_code
# is NULL or missing. Finnish is the original/default learning language of
# the platform; the schema-per-language migration preserves this.
LEGACY_DEFAULT_LEARNING_LANGUAGE: str = "fi"

# The Tier-A support locale — English is the universal fallback support
# language for hints, glosses, explanations etc. Source content is
# authored in English then localized via ContentLocalizer.localize_batch
# to the learner's chosen support locale.
TIER_A_SUPPORT_LOCALE: str = "en"
