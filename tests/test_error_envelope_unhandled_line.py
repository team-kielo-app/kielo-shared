import logging

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from kielo_shared.error_envelope import install_error_handlers


def _app() -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom():  # type: ignore[no-untyped-def]
        raise ValueError("connection was closed in the middle of operation")

    @app.get("/teapot")
    async def teapot():  # type: ignore[no-untyped-def]
        raise HTTPException(status_code=418)

    return app


def test_unhandled_exception_is_named_in_one_short_record(caplog):
    """The exception's type and message must survive Cloud Logging's
    traceback splitting: one short record carries them, the traceback is a
    separate record."""
    client = TestClient(_app(), raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR):
        response = client.get("/boom")
    assert response.status_code == 500
    short = [
        r for r in caplog.records if r.getMessage().startswith("UNHANDLED_EXCEPTION")
    ]
    assert len(short) == 1
    assert "type=ValueError" in short[0].getMessage()
    assert "route=/boom" in short[0].getMessage()
    assert "connection was closed" in short[0].getMessage()
    assert short[0].exc_info is None
    assert any(
        r.exc_info for r in caplog.records if "Unhandled exception in" in r.getMessage()
    )


def test_http_exceptions_are_not_reported_as_unhandled(caplog):
    client = TestClient(_app(), raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR):
        response = client.get("/teapot")
    assert response.status_code == 418
    assert not [r for r in caplog.records if "UNHANDLED_EXCEPTION" in r.getMessage()]
