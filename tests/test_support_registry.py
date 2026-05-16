"""Contract tests for kielo_shared.localization.support_registry.

Mirrors the Go contract tests in kielo-shared/locale/supportregistry/
registry_test.go so behaviour stays parallel across the language
boundary. Every Go test has a Python equivalent.
"""
from __future__ import annotations

import pytest

from kielo_shared.localization.support_registry import (
    MapRegistry,
    materialize_by_locale,
)


def _new(*locales: str) -> MapRegistry:
    """Construct a MapRegistry, materialize input list-style."""
    return MapRegistry(supported_locales_in=list(locales))


def test_resolve_exact_match():
    r = _new("en", "vi")
    r.set("morphology.word_class.teonsana", "en", "Verb")
    r.set("morphology.word_class.teonsana", "vi", "động từ")

    assert r.resolve("morphology.word_class.teonsana", "en") == "Verb"
    assert r.resolve("morphology.word_class.teonsana", "vi") == "động từ"


def test_falls_back_to_english():
    r = _new("en", "vi", "ar")
    r.set("ui.greeting", "en", "Hello")
    r.set("ui.greeting", "vi", "Xin chào")
    # "ar" intentionally not set — should fall back to English.

    assert r.resolve("ui.greeting", "ar") == "Hello"


def test_unknown_key_returns_key_itself():
    r = _new("en", "vi")
    got = r.resolve("ui.does_not_exist", "vi")
    # Contract: never returns empty. Returning the key tells the
    # caller "I don't have this", but the UI can still render it.
    assert got == "ui.does_not_exist"


def test_normalizes_locale_case():
    r = _new("en", "vi")
    r.set("ui.greeting", "vi", "Xin chào")
    # Caller passes "VI" or " vi " — registry should still find it.
    assert r.resolve("ui.greeting", "VI") == "Xin chào"
    assert r.resolve("ui.greeting", " vi ") == "Xin chào"


def test_finalize_blocks_writes():
    r = _new("en", "vi")
    r.set("ui.greeting", "en", "Hello")
    r.finalize()

    assert r.set("ui.greeting", "vi", "Should not stick") is False

    # Existing entries still resolve; the late set was a no-op.
    assert r.resolve("ui.greeting", "en") == "Hello"
    # vi was never registered, so it falls back to English.
    assert r.resolve("ui.greeting", "vi") == "Hello"


def test_always_includes_english_in_supported_locales():
    # Even if caller forgets en, the registry adds it. English is the
    # universal fallback per the FALLBACK_LOCALE contract.
    r = _new("fi", "vi")
    locales = r.supported_locales()
    assert "en" in locales
    assert "fi" in locales
    assert "vi" in locales


def test_template_substitution():
    r = _new("en", "vi")
    r.set("ui.welcome", "en", "Hello, {name}!")
    r.set("ui.welcome", "vi", "Xin chào, {name}!")

    out = r.resolve_template("ui.welcome", "vi", name="Khanh")
    assert out == "Xin chào, Khanh!"


def test_template_missing_key_returns_empty_substitution():
    r = _new("en")
    r.set("ui.welcome", "en", "Hello, {name}!")

    # _SafeFormatter substitutes empty string for missing keys rather
    # than raising KeyError. Contract: no crash, recognisable output.
    out = r.resolve_template("ui.welcome", "en")
    assert "Hello," in out


def test_template_parse_failure_falls_through_to_literal():
    r = _new("en")
    r.set("ui.broken", "en", "Hello, {name")  # missing closing brace

    # Malformed template returns literal rather than crashing.
    out = r.resolve_template("ui.broken", "en", name="x")
    assert out == "Hello, {name"


def test_no_template_syntax_skips_templating():
    r = _new("en")
    r.set("ui.plain", "en", "Plain text no substitution")

    # Fast path for strings without { — should not even attempt format.
    out = r.resolve_template("ui.plain", "en", name="ignored")
    assert out == "Plain text no substitution"


def test_coverage_report():
    r = _new("en", "vi", "ar")
    r.set("ui.k1", "en", "K1")
    r.set("ui.k1", "vi", "K1-vi")
    r.set("ui.k2", "en", "K2")
    # ui.k1 has en + vi. ui.k2 only has en.

    report = r.coverage_report()
    assert report["en"].total == 2
    assert report["en"].localized == 2  # every key has en
    assert report["vi"].localized == 1  # only k1 has vi
    assert report["vi"].fallback == 1   # k2 falls back
    assert report["ar"].localized == 0  # no ar entries
    assert report["ar"].fallback == 2   # both fall back


def test_resolve_safe_without_registration():
    r = _new("en", "vi")
    # Don't register anything. resolve must still be safe.
    got = r.resolve("ui.anything", "vi")
    assert got == "ui.anything"


def test_materialize_by_locale_returns_all_supported():
    r = _new("en", "vi", "fi")
    r.set("ui.subject.welcome", "en", "Welcome!")
    r.set("ui.subject.welcome", "vi", "Chào mừng!")
    r.set("ui.subject.welcome", "fi", "Tervetuloa!")

    got = materialize_by_locale(r, "ui.subject.welcome")
    assert got == {
        "en": "Welcome!",
        "vi": "Chào mừng!",
        "fi": "Tervetuloa!",
    }


def test_materialize_by_locale_fills_missing_with_english():
    r = _new("en", "vi", "fi")
    r.set("ui.subject.welcome", "en", "Welcome!")
    r.set("ui.subject.welcome", "vi", "Chào mừng!")
    # fi intentionally not seeded.

    got = materialize_by_locale(r, "ui.subject.welcome")
    assert got["fi"] == "Welcome!"  # missing fi falls back to English
    assert got["vi"] == "Chào mừng!"
    assert got["en"] == "Welcome!"


def test_materialize_by_locale_omits_missing_key():
    r = _new("en", "vi")
    # Don't register the key at all.
    got = materialize_by_locale(r, "ui.subject.does_not_exist")
    # Contract: when even English is missing, the map is empty rather
    # than carrying "ui.subject.does_not_exist" as each locale's text.
    assert got == {}


# ---------------------------------------------------------------------------
# Async surface (ADR-008 Phase 5)
# ---------------------------------------------------------------------------
#
# MapRegistry's aresolve / aresolve_template are thin shims over the sync
# path. They exist so the Protocol surface is uniform across MapRegistry
# and DynamicRegistry (which uses the async path for the DB probe). These
# tests pin the contract that aresolve produces the same output as resolve
# for every input — if a future refactor breaks parity, callers that
# `await registry.aresolve(...)` would silently see different values than
# callers that call `registry.resolve(...)` against the same MapRegistry.


@pytest.mark.asyncio
async def test_aresolve_parity_with_resolve():
    r = _new("en", "vi", "fi")
    r.set("ui.greeting", "en", "Hello")
    r.set("ui.greeting", "vi", "Xin chào")

    assert await r.aresolve("ui.greeting", "vi") == r.resolve("ui.greeting", "vi")
    assert await r.aresolve("ui.greeting", "fi") == r.resolve("ui.greeting", "fi")
    assert await r.aresolve("ui.unknown", "vi") == r.resolve("ui.unknown", "vi")


@pytest.mark.asyncio
async def test_aresolve_template_parity_with_resolve_template():
    r = _new("en", "vi")
    r.set("ui.welcome", "en", "Welcome {name}")
    r.set("ui.welcome", "vi", "Chào {name}")

    sync_text = r.resolve_template("ui.welcome", "vi", name="Khanh")
    async_text = await r.aresolve_template("ui.welcome", "vi", name="Khanh")
    assert sync_text == async_text == "Chào Khanh"
