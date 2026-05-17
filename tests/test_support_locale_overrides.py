"""Tests for kielo_shared.localization.support_locale_overrides.

Pins the per-request prefetch contract used by the engine's `_l10n` and
its siblings. The Go-side equivalent is exercised by the comms-service
DynamicRegistry tests; this module covers the Python sync-localizer
override path.
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Any

import pytest

from kielo_shared.localization.support_locale_overrides import (
    clear_overrides,
    consume_missing,
    get_override,
    prefetch_overrides_for_locale,
    register_missing,
    set_overrides_for_request,
)


def _sv(english: str) -> str:
    """Helper: compute source_version the same way the read-path does."""
    return hashlib.sha256(english.encode("utf-8")).hexdigest()[:16]


@pytest.fixture(autouse=True)
def _reset_overrides_between_tests():
    clear_overrides()
    yield
    clear_overrides()


# ---------------------------------------------------------------------------
# get_override — contextvar read path
# ---------------------------------------------------------------------------


# Key shape used by the engine: registry keys are prefixed strings
# like "ui.engine_string.Learn", while the English source for
# source_version validation is just "Learn". Tests use that shape to
# exercise the realistic call pattern.
def _key(english: str) -> str:
    return f"ui.engine_string.{english}"


def test_get_override_no_overrides_loaded_returns_none():
    assert get_override(_key("Practice"), "Practice", "vi") is None


def test_get_override_returns_text_on_hit():
    set_overrides_for_request("vi", {_key("Learn"): (_sv("Learn"), "Học")})
    assert get_override(_key("Learn"), "Learn", "vi") == "Học"


def test_get_override_falls_through_when_key_absent():
    set_overrides_for_request("vi", {_key("Learn"): (_sv("Learn"), "Học")})
    assert get_override(_key("Reinforce"), "Reinforce", "vi") is None


def test_get_override_falls_through_on_locale_mismatch():
    # Prefetched for vi, caller asks for fi → must not return the vi
    # text. Different locales have separate override maps.
    set_overrides_for_request("vi", {_key("Learn"): (_sv("Learn"), "Học")})
    assert get_override(_key("Learn"), "Learn", "fi") is None


def test_get_override_skips_english_locale():
    # English IS the canonical source; overrides shouldn't exist for
    # it. Defensive guard: even if a row leaked in, the read path
    # ignores it.
    set_overrides_for_request("en", {_key("Learn"): (_sv("Learn"), "leak")})
    assert get_override(_key("Learn"), "Learn", "en") is None


def test_get_override_skips_empty_locale():
    set_overrides_for_request("", {_key("Learn"): (_sv("Learn"), "x")})
    assert get_override(_key("Learn"), "Learn", "") is None


def test_get_override_skips_empty_source():
    set_overrides_for_request("vi", {_key(""): (_sv(""), "blank")})
    assert get_override(_key(""), "", "vi") is None


def test_get_override_skips_empty_key():
    set_overrides_for_request("vi", {"": (_sv("Learn"), "x")})
    assert get_override("", "Learn", "vi") is None


def test_get_override_stale_source_version_skips():
    # The English source the override was authored against was
    # "Learn" (sv = hash("Learn")). Author has since edited it to
    # "Learn more" in code. The stored override's source_version no
    # longer matches the current English, so the override is stale
    # and read-path returns None.
    old_sv = _sv("Learn")
    set_overrides_for_request("vi", {_key("Learn more"): (old_sv, "Học")})
    assert get_override(_key("Learn more"), "Learn more", "vi") is None


def test_get_override_supports_slug_key_with_distinct_english_source():
    # Mirrors the comms-service email-subject shape: registry key is a
    # slug ("ui.email.subject.password_reset"), English source is the
    # human subject text ("Reset Your Password"). source_version is
    # computed against the English source, not the slug key.
    slug_key = "ui.email.subject.password_reset"
    english = "Reset Your Password"
    set_overrides_for_request("vi", {slug_key: (_sv(english), "Đặt lại mật khẩu")})
    assert (
        get_override(slug_key, english, "vi") == "Đặt lại mật khẩu"
    )


def test_clear_overrides_resets_to_empty():
    set_overrides_for_request("vi", {_key("Learn"): (_sv("Learn"), "Học")})
    assert get_override(_key("Learn"), "Learn", "vi") == "Học"
    clear_overrides()
    assert get_override(_key("Learn"), "Learn", "vi") is None


def test_clear_overrides_with_token_restores_previous_state():
    set_overrides_for_request("vi", {_key("Learn"): (_sv("Learn"), "outer")})
    token = set_overrides_for_request(
        "vi", {_key("Learn"): (_sv("Learn"), "inner")}
    )
    assert get_override(_key("Learn"), "Learn", "vi") == "inner"
    clear_overrides(token)
    # Token-reset restores the outer context, not the empty state.
    assert get_override(_key("Learn"), "Learn", "vi") == "outer"


# ---------------------------------------------------------------------------
# prefetch_overrides_for_locale — query path
# ---------------------------------------------------------------------------


class _StubResult:
    """Minimal SQLAlchemy `Result`-like object yielding fake row tuples."""

    class _Row:
        def __init__(self, rid: str, sv: str, txt: str) -> None:
            self.resource_id = rid
            self.source_version = sv
            self.translated_text = txt

    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        self._rows = [self._Row(*r) for r in rows]

    def fetchall(self):
        return self._rows


class _StubSession:
    def __init__(self, rows: list[tuple[str, str, str]], *, raise_on_execute: bool = False) -> None:
        self._rows = rows
        self.raise_on_execute = raise_on_execute
        self.captured_params: dict[str, Any] | None = None

    async def execute(self, statement, params=None):
        if self.raise_on_execute:
            raise RuntimeError("db down")
        self.captured_params = params
        return _StubResult(self._rows)


def _factory_for(session: _StubSession):
    @asynccontextmanager
    async def factory():
        yield session
    return factory


@pytest.mark.asyncio
async def test_prefetch_returns_empty_for_english_locale():
    session = _StubSession(rows=[])
    factory = _factory_for(session)
    got = await prefetch_overrides_for_locale(factory, "en")
    assert got == {}
    # Crucially: no query was fired for English. The session's
    # captured_params stays None.
    assert session.captured_params is None


@pytest.mark.asyncio
async def test_prefetch_returns_empty_for_empty_locale():
    session = _StubSession(rows=[])
    factory = _factory_for(session)
    got = await prefetch_overrides_for_locale(factory, "")
    assert got == {}
    assert session.captured_params is None


@pytest.mark.asyncio
async def test_prefetch_builds_dict_keyed_by_resource_id():
    rows = [
        ("Learn", _sv("Learn"), "Học"),
        ("Reinforce", _sv("Reinforce"), "Củng cố"),
        ("Master", _sv("Master"), "Thành thạo"),
    ]
    session = _StubSession(rows=rows)
    factory = _factory_for(session)

    got = await prefetch_overrides_for_locale(factory, "vi")

    assert got == {
        "Learn": (_sv("Learn"), "Học"),
        "Reinforce": (_sv("Reinforce"), "Củng cố"),
        "Master": (_sv("Master"), "Thành thạo"),
    }
    # Confirm the query was scoped to the right (resource_type, locale).
    assert session.captured_params == {
        "resource_type": "ui.string",
        "language_code": "vi",
    }


@pytest.mark.asyncio
async def test_prefetch_degrades_to_empty_on_db_error():
    session = _StubSession(rows=[], raise_on_execute=True)
    factory = _factory_for(session)
    # MUST NOT raise — degrade to seed values rather than failing
    # the request.
    got = await prefetch_overrides_for_locale(factory, "vi")
    assert got == {}


@pytest.mark.asyncio
async def test_prefetch_accepts_custom_resource_type():
    rows = [("notifications.new_article", _sv("X"), "Bài viết mới")]
    session = _StubSession(rows=rows)
    factory = _factory_for(session)

    got = await prefetch_overrides_for_locale(
        factory, "vi", resource_type="notifications.body"
    )
    assert got == {"notifications.new_article": (_sv("X"), "Bài viết mới")}
    assert session.captured_params == {
        "resource_type": "notifications.body",
        "language_code": "vi",
    }


# ---------------------------------------------------------------------------
# register_missing / consume_missing — auto-translate plumbing
# ---------------------------------------------------------------------------


def test_register_missing_records_triple():
    set_overrides_for_request("vi", {})  # scope a locale for the request
    register_missing(_key("Learn"), "Learn", "vi")
    got = consume_missing()
    assert got == {(_key("Learn"), "Learn", "vi")}


def test_register_missing_dedupes_within_request():
    set_overrides_for_request("vi", {})
    register_missing(_key("Learn"), "Learn", "vi")
    register_missing(_key("Learn"), "Learn", "vi")
    register_missing(_key("Learn"), "Learn", "vi")
    assert consume_missing() == {(_key("Learn"), "Learn", "vi")}


def test_register_missing_collects_multiple_keys():
    set_overrides_for_request("vi", {})
    register_missing(_key("Learn"), "Learn", "vi")
    register_missing(_key("Reinforce"), "Reinforce", "vi")
    register_missing(_key("Master"), "Master", "vi")
    assert consume_missing() == {
        (_key("Learn"), "Learn", "vi"),
        (_key("Reinforce"), "Reinforce", "vi"),
        (_key("Master"), "Master", "vi"),
    }


def test_register_missing_skips_english_locale():
    set_overrides_for_request("en", {})
    register_missing(_key("Learn"), "Learn", "en")
    assert consume_missing() == set()


def test_register_missing_skips_empty_locale():
    set_overrides_for_request("", {})
    register_missing(_key("Learn"), "Learn", "")
    assert consume_missing() == set()


def test_register_missing_skips_empty_english_source():
    set_overrides_for_request("vi", {})
    register_missing(_key("blank"), "", "vi")
    register_missing(_key("blank"), "   ", "vi")
    assert consume_missing() == set()


def test_register_missing_skips_template_strings():
    """LLM-translating template placeholders ({}) without breaking
    semantics is fragile. Skip for first pass — admin manual authoring
    is the right path for the ~6 templated strings."""
    set_overrides_for_request("vi", {})
    register_missing(_key("Practice {}"), "Practice {}", "vi")
    register_missing(_key("Hello {name}"), "Hello {name}", "vi")
    assert consume_missing() == set()


def test_register_missing_skips_when_locale_mismatch():
    """Prefetched for vi, caller asks to register for sv → skipped.
    Auto-translate would fire for sv but the next request likely
    targets the prefetched vi locale, so the auto'd sv row would be
    orphaned until a sv request happens to come."""
    set_overrides_for_request("vi", {})
    register_missing(_key("Learn"), "Learn", "sv")
    assert consume_missing() == set()


def test_register_missing_works_without_prefetched_locale():
    """When no overrides contextvar was set (e.g. a request the
    middleware didn't process), register_missing still records the
    triple because there's no prefetched locale to conflict with."""
    clear_overrides()  # ensure default empty state
    register_missing(_key("Learn"), "Learn", "vi")
    assert consume_missing() == {(_key("Learn"), "Learn", "vi")}


def test_consume_missing_resets_to_empty():
    set_overrides_for_request("vi", {})
    register_missing(_key("Learn"), "Learn", "vi")
    consume_missing()
    # Second consume returns empty — the previous call drained the set.
    assert consume_missing() == set()


def test_consume_missing_returns_mutable_set():
    set_overrides_for_request("vi", {})
    register_missing(_key("Learn"), "Learn", "vi")
    got = consume_missing()
    # Callers can mutate without surprising the next request's state.
    got.add((_key("Other"), "Other", "vi"))
    assert consume_missing() == set()
