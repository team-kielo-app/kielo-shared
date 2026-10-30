"""Connection reuse for kielo_shared.http clients, counted on a real server.

Each test starts a loopback server (plain HTTP/1.1, TLS with ALPN http/1.1, or
TLS with ALPN h2) that counts accepted TCP connections, then makes N calls and
asserts how many connections it took.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
import pytest
import pytest_asyncio

from kielo_shared import http as kielo_http
from kielo_shared.http import (
    aclose_shared_internal_clients,
    close_shared_internal_clients,
    connection_limits,
    http2_enabled,
    internal_client_async,
    internal_client_sync,
    shared_internal_client_async,
    shared_internal_client_sync,
)
from kielo_shared.trace import (
    TraceContext,
    reset_current_trace_context,
    set_current_trace_context,
)

h2_config = pytest.importorskip("h2.config")
h2_connection = pytest.importorskip("h2.connection")
h2_events = pytest.importorskip("h2.events")
x509 = pytest.importorskip("cryptography.x509")


@dataclass
class _Counters:
    connections: int = 0
    requests: int = 0
    protocols: list[str] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)


def _record(counters: _Counters, headers: dict[str, str]) -> None:
    counters.requests += 1
    counters.headers.append(headers)


async def _serve_h2(
    counters: _Counters, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    conn = h2_connection.H2Connection(
        config=h2_config.H2Configuration(client_side=False)
    )
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    while True:
        data = await reader.read(65535)
        if not data:
            return
        for event in conn.receive_data(data):
            if isinstance(event, h2_events.RequestReceived):
                _record(counters, {k.decode(): v.decode() for k, v in event.headers})
                conn.send_headers(
                    event.stream_id, [(":status", "200"), ("content-length", "2")]
                )
                conn.send_data(event.stream_id, b"ok", end_stream=True)
            elif isinstance(event, h2_events.ConnectionTerminated):
                return
        writer.write(conn.data_to_send())
        await writer.drain()


async def _serve_h1(
    counters: _Counters, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    while True:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        _record(
            counters,
            {
                k.strip().lower(): v.strip()
                for k, _, v in (line.partition(":") for line in lines[1:] if line)
            },
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
        )
        await writer.drain()


async def _handle(
    counters: _Counters, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    counters.connections += 1
    ssl_object = writer.get_extra_info("ssl_object")
    selected = ssl_object.selected_alpn_protocol() if ssl_object else None
    counters.protocols.append(selected or "http/1.1")
    try:
        if selected == "h2":
            await _serve_h2(counters, reader, writer)
        else:
            await _serve_h1(counters, reader, writer)
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


class _LoopbackServer:
    def __init__(
        self, *, alpn: Optional[list[str]], ssl_context: Optional[ssl.SSLContext]
    ):
        self.counters = _Counters()
        self._ssl_context = ssl_context
        if ssl_context is not None and alpn:
            ssl_context.set_alpn_protocols(alpn)
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._server: Any = None
        self.port = 0
        self._thread = threading.Thread(target=self._run, daemon=True)

    @property
    def url(self) -> str:
        scheme = "https" if self._ssl_context else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())
        self._ready.set()
        self._loop.run_forever()

    async def _start(self) -> None:
        self._server = await asyncio.start_server(
            lambda r, w: _handle(self.counters, r, w),
            "127.0.0.1",
            0,
            ssl=self._ssl_context,
        )
        self.port = self._server.sockets[0].getsockname()[1]

    def start(self) -> "_LoopbackServer":
        self._thread.start()
        assert self._ready.wait(10)
        return self

    def stop(self) -> None:
        async def shutdown() -> None:
            self._server.close()
            pending = [
                t for t in asyncio.all_tasks() if t is not asyncio.current_task()
            ]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run_coroutine_threadsafe(shutdown(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _server_context(tls_material: tuple[str, str]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*tls_material)
    return context


@pytest.fixture
def h2_server(tls_material, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", tls_material[0])
    server = _LoopbackServer(
        alpn=["h2", "http/1.1"], ssl_context=_server_context(tls_material)
    ).start()
    yield server
    server.stop()


@pytest.fixture
def h1_tls_server(tls_material, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", tls_material[0])
    server = _LoopbackServer(
        alpn=["http/1.1"], ssl_context=_server_context(tls_material)
    ).start()
    yield server
    server.stop()


@pytest.fixture
def plain_server():
    server = _LoopbackServer(alpn=None, ssl_context=None).start()
    yield server
    server.stop()


@pytest_asyncio.fixture(autouse=True)
async def _clean_shared_clients():
    yield
    await aclose_shared_internal_clients()
    close_shared_internal_clients()


CALLS = 12


@pytest.mark.asyncio
async def test_default_limits_hold_connections_for_sixty_seconds():
    limits = connection_limits()
    assert limits.keepalive_expiry == 60.0
    assert limits.max_keepalive_connections == 20
    assert httpx.Limits().keepalive_expiry == 5.0


@pytest.mark.asyncio
async def test_client_per_call_opens_a_connection_per_call(h1_tls_server):
    for _ in range(CALLS):
        async with internal_client_async() as client:
            assert (await client.get(h1_tls_server.url)).status_code == 200
    assert h1_tls_server.counters.connections == CALLS


@pytest.mark.asyncio
async def test_shared_client_reuses_one_connection_across_per_call_usage(h1_tls_server):
    for _ in range(CALLS):
        async with shared_internal_client_async() as client:
            assert (await client.get(h1_tls_server.url)).status_code == 200
    assert h1_tls_server.counters.connections == 1
    assert h1_tls_server.counters.requests == CALLS


@pytest.mark.asyncio
async def test_h2_server_gets_one_multiplexed_connection(h2_server):
    assert http2_enabled()
    client = shared_internal_client_async(api_key="k")
    first = await client.get(h2_server.url)
    assert first.http_version == "HTTP/2"
    for _ in range(CALLS - 1):
        assert (await client.get(h2_server.url)).status_code == 200
    assert h2_server.counters.connections == 1
    assert h2_server.counters.protocols == ["h2"]
    assert h2_server.counters.requests == CALLS


@pytest.mark.asyncio
async def test_h2_concurrent_calls_share_the_connection(h2_server):
    client = shared_internal_client_async()
    responses = await asyncio.gather(*(client.get(h2_server.url) for _ in range(8)))
    assert [r.http_version for r in responses] == ["HTTP/2"] * 8
    assert h2_server.counters.connections == 1


@pytest.mark.asyncio
async def test_server_without_h2_falls_back_to_http1(h1_tls_server):
    client = shared_internal_client_async()
    for _ in range(3):
        response = await client.get(h1_tls_server.url)
        assert response.http_version == "HTTP/1.1"
    assert h1_tls_server.counters.protocols == ["http/1.1"]
    assert h1_tls_server.counters.connections == 1


@pytest.mark.asyncio
async def test_plain_http_url_stays_http1(plain_server):
    client = shared_internal_client_async()
    response = await client.get(plain_server.url)
    assert response.http_version == "HTTP/1.1"
    await client.get(plain_server.url)
    assert plain_server.counters.connections == 1


@pytest.mark.asyncio
async def test_missing_h2_package_disables_http2_and_still_works(
    h1_tls_server, monkeypatch
):
    monkeypatch.setitem(sys.modules, "h2", None)
    assert not http2_enabled()
    client = shared_internal_client_async()
    assert (await client.get(h1_tls_server.url)).http_version == "HTTP/1.1"


@pytest.mark.asyncio
async def test_kill_switch_env_disables_http2(h2_server, monkeypatch):
    monkeypatch.setenv(kielo_http.HTTP2_DISABLED_ENV, "1")
    assert not http2_enabled()
    client = shared_internal_client_async()
    response = await client.get(h2_server.url)
    assert response.http_version == "HTTP/1.1"
    assert h2_server.counters.protocols == ["http/1.1"]


@pytest.mark.asyncio
async def test_idle_gap_longer_than_expiry_reopens_the_connection(
    h1_tls_server, monkeypatch
):
    with monkeypatch.context() as short_expiry:
        short_expiry.setattr(kielo_http, "KEEPALIVE_EXPIRY_SECONDS", 0.1)
        client = internal_client_async()
    await client.get(h1_tls_server.url)
    await asyncio.sleep(0.4)
    await client.get(h1_tls_server.url)
    await client.aclose()
    assert h1_tls_server.counters.connections == 2


@pytest.mark.asyncio
async def test_shared_client_keeps_key_header_and_trace_hook(plain_server):
    tc = TraceContext(trace_id="a" * 32, span_id="b" * 16, request_id="req-keepalive")
    token = set_current_trace_context(tc)
    try:
        client = shared_internal_client_async(
            api_key="s3cret", headers={"X-Extra": "1"}
        )
        await client.get(plain_server.url)
    finally:
        reset_current_trace_context(token)
    sent = plain_server.counters.headers[0]
    assert sent["x-internal-api-key"] == "s3cret"
    assert sent["x-extra"] == "1"
    assert sent["traceparent"].startswith("00-" + "a" * 32)
    assert sent["x-request-id"] == "req-keepalive"


@pytest.mark.asyncio
async def test_shared_client_without_api_key_omits_internal_key_and_language(
    plain_server,
):
    client = shared_internal_client_async()
    await client.get(plain_server.url)
    assert "x-internal-api-key" not in plain_server.counters.headers[0]


@pytest.mark.asyncio
async def test_shared_registry_keys_on_configuration():
    base = shared_internal_client_async(
        base_url="https://a.test", api_key="k", timeout=5.0
    )
    assert (
        shared_internal_client_async(
            base_url="https://a.test", api_key="k", timeout=5.0
        )
        is base
    )
    assert (
        shared_internal_client_async(
            base_url="https://b.test", api_key="k", timeout=5.0
        )
        is not base
    )
    assert (
        shared_internal_client_async(
            base_url="https://a.test", api_key="x", timeout=5.0
        )
        is not base
    )
    assert (
        shared_internal_client_async(
            base_url="https://a.test", api_key="k", timeout=6.0
        )
        is not base
    )
    assert (
        shared_internal_client_async(
            base_url="https://a.test",
            api_key="k",
            timeout=httpx.Timeout(5.0, connect=1.0),
        )
        is not base
    )
    assert (
        shared_internal_client_async(
            base_url="https://a.test", api_key="k", timeout=5.0, headers={"X-A": "1"}
        )
        is not base
    )


@pytest.mark.asyncio
async def test_closing_a_shared_client_does_not_close_the_pool(plain_server):
    client = shared_internal_client_async()
    async with client:
        await client.get(plain_server.url)
    await client.aclose()
    assert not client.is_closed
    async with shared_internal_client_async() as again:
        assert again is client
        await again.get(plain_server.url)
    assert plain_server.counters.connections == 1


@pytest.mark.asyncio
async def test_aclose_shared_internal_clients_closes_and_rebuilds(plain_server):
    client = shared_internal_client_async()
    await client.get(plain_server.url)
    await aclose_shared_internal_clients()
    assert client.is_closed
    fresh = shared_internal_client_async()
    assert fresh is not client
    assert (await fresh.get(plain_server.url)).status_code == 200


def test_each_event_loop_gets_its_own_shared_client():
    seen: list[httpx.AsyncClient] = []

    async def grab() -> None:
        seen.append(shared_internal_client_async(base_url="https://loop.test"))
        seen.append(shared_internal_client_async(base_url="https://loop.test"))
        await aclose_shared_internal_clients()

    asyncio.run(grab())
    asyncio.run(grab())
    assert seen[0] is seen[1]
    assert seen[2] is seen[3]
    assert seen[0] is not seen[2]


def test_without_a_running_loop_the_client_is_private_and_closable():
    client = shared_internal_client_async(base_url="https://noloop.test")
    assert not isinstance(client, kielo_http._SharedAsyncClient)
    assert client is not shared_internal_client_async(base_url="https://noloop.test")

    async def close() -> None:
        await client.aclose()

    asyncio.run(close())
    assert client.is_closed


def test_shared_sync_client_reuses_one_connection(plain_server):
    for _ in range(CALLS):
        with shared_internal_client_sync(api_key="k") as client:
            assert client.get(plain_server.url).status_code == 200
    assert plain_server.counters.connections == 1
    assert shared_internal_client_sync(api_key="k") is client
    assert shared_internal_client_sync(api_key="other") is not client
    client.close()
    assert not client.is_closed
    close_shared_internal_clients()
    assert client.is_closed


def test_sync_client_per_call_opens_a_connection_per_call(plain_server):
    for _ in range(4):
        with internal_client_sync() as client:
            client.get(plain_server.url)
    assert plain_server.counters.connections == 4


@pytest.mark.asyncio
async def test_explicit_transport_still_wins_over_pool_settings():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200)

    async with internal_client_async(
        transport=httpx.MockTransport(handler), base_url="https://svc.test"
    ) as client:
        await client.get("/probe")
    assert seen == ["/probe"]
