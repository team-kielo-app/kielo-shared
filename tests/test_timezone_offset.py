import asyncio

import pytest

from kielo_shared import timezone_offset as tz


def test_parse_matches_go_bounds() -> None:
    assert tz.parse_timezone_offset_minutes("120") == 120
    assert tz.parse_timezone_offset_minutes(" -330 ") == -330
    assert tz.parse_timezone_offset_minutes("0") == 0
    assert tz.parse_timezone_offset_minutes("840") == 840
    assert tz.parse_timezone_offset_minutes("-840") == -840
    for bad in ("", None, "abc", "841", "-841", "1.5", True):
        assert tz.parse_timezone_offset_minutes(bad) is None


def test_stamp_adds_the_key_without_mutating_the_caller() -> None:
    original = {"learning_language_code": "fi"}
    stamped = tz.stamp_timezone_offset(original, 180)
    assert stamped == {"learning_language_code": "fi", "tz_offset_minutes": 180}
    assert original == {"learning_language_code": "fi"}


def test_stamp_stamps_an_explicit_utc() -> None:
    assert tz.stamp_timezone_offset(None, 0) == {"tz_offset_minutes": 0}


def test_stamp_without_an_offset_leaves_the_context_alone() -> None:
    assert tz.stamp_timezone_offset(None) is None
    assert tz.stamp_timezone_offset({}) is None
    assert tz.stamp_timezone_offset({"a": 1}) == {"a": 1}


def test_stamp_never_replaces_a_caller_set_key() -> None:
    assert tz.stamp_timezone_offset({"tz_offset_minutes": -60}, 180) == {
        "tz_offset_minutes": -60
    }


def test_stamp_ignores_an_invalid_explicit_offset() -> None:
    assert tz.stamp_timezone_offset({"a": 1}, 99999) == {"a": 1}


def test_stamp_falls_back_to_the_request_offset_and_explicit_wins() -> None:
    token = tz.set_request_timezone_offset(120)
    try:
        assert tz.stamp_timezone_offset(None) == {"tz_offset_minutes": 120}
        assert tz.stamp_timezone_offset(None, -300) == {"tz_offset_minutes": -300}
    finally:
        tz.reset_request_timezone_offset(token)
    assert tz.get_request_timezone_offset() is None


async def _run_middleware(headers: list[tuple[bytes, bytes]]) -> list[object]:
    seen: list[object] = []

    async def app(scope, receive, send) -> None:
        seen.append(tz.get_request_timezone_offset())

    await tz.TimezoneOffsetMiddleware(app)(
        {"type": "http", "headers": headers}, None, None
    )
    seen.append(tz.get_request_timezone_offset())
    return seen


@pytest.mark.parametrize(
    "headers,expected",
    [
        ([(b"x-timezone-offset-minutes", b"-120")], -120),
        ([(b"x-timezone-offset", b"60")], 60),
        (
            [(b"x-timezone-offset", b"60"), (b"x-timezone-offset-minutes", b"0")],
            0,
        ),
        ([(b"x-timezone-offset-minutes", b"nonsense")], None),
        ([], None),
    ],
)
def test_middleware_binds_the_header_for_the_request_only(headers, expected) -> None:
    assert asyncio.run(_run_middleware(headers)) == [expected, None]


def test_middleware_passes_non_http_scopes_through() -> None:
    calls: list[str] = []

    async def app(scope, receive, send) -> None:
        calls.append(scope["type"])

    asyncio.run(tz.TimezoneOffsetMiddleware(app)({"type": "lifespan"}, None, None))
    assert calls == ["lifespan"]


class _Result:
    def __init__(self, row) -> None:
        self._row = row

    def first(self):
        return self._row


class _Session:
    def __init__(self, row, boom: bool = False) -> None:
        self._row, self._boom = row, boom

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def execute(self, *_a, **_k):
        if self._boom:
            raise RuntimeError("db down")
        return _Result(self._row)


def test_lookup_stored_offset() -> None:
    lookup = tz.lookup_stored_timezone_offset
    assert asyncio.run(lookup(lambda: _Session((180,)), "u1")) == 180
    assert asyncio.run(lookup(lambda: _Session((0,)), "u1")) == 0
    assert asyncio.run(lookup(lambda: _Session((None,)), "u1")) is None
    assert asyncio.run(lookup(lambda: _Session(None), "u1")) is None
    assert asyncio.run(lookup(lambda: _Session((9999,)), "u1")) is None
    assert asyncio.run(lookup(lambda: _Session((60,), boom=True), "u1")) is None
    assert asyncio.run(lookup(None, "u1")) is None
    assert asyncio.run(lookup(lambda: _Session((60,)), "")) is None
