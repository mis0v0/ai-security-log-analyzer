"""Exercise legacy upload admission directly through ASGI without sockets."""

import asyncio
import json

import pytest
from starlette import formparsers

import app.api as api


BOUNDARY = b"synthetic-sec5b"
CANARY = b"SEC5B_PRIVATE_CANARY"
BODY_LIMIT = 30 * 1024 * 1024 + 64 * 1024


def file_prefix(role):
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + role.encode()
        + b'_file"; filename="' + CANARY + b'.log"\r\n\r\n'
    )


def upload_body():
    return b"".join(
        file_prefix(role) + CANARY + b"\r\n" for role in ("application", "ssh", "access")
    ) + b"--" + BOUNDARY + b"--\r\n"


def chunk(body, *, more=True):
    return {"type": "http.request", "body": body, "more_body": more}


async def request(app, receive, *, length=None, path="/api/analyze"):
    headers = [
        (b"content-type", b"multipart/form-data; boundary=" + BOUNDARY),
        (b"x-synthetic-private", CANARY),
    ]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    sent = []

    async def send(message):
        sent.append(message)

    await app({
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1", "method": "GET" if path == "/api/health" else "POST",
        "scheme": "http", "path": path, "root_path": "", "query_string": b"",
        "headers": headers, "client": ("127.0.0.1", 10001), "server": ("127.0.0.1", 8000),
    }, receive, send)
    assert sum(message["type"] == "http.response.start" for message in sent) == 1
    return sent[0]["status"], dict(sent[0]["headers"]), b"".join(
        message.get("body", b"") for message in sent[1:]
    )


def assert_private(response, status, content_type, body, *, deprecated=False):
    actual_status, headers, actual_body = response
    assert actual_status == status
    assert headers[b"content-type"] == content_type
    assert headers.get(b"deprecation") == (b"true" if deprecated else None)
    assert int(headers[b"content-length"]) == len(actual_body)
    assert actual_body == body
    assert CANARY not in actual_body
    assert all(CANARY not in name + value for name, value in headers.items())


@pytest.fixture
def spools(monkeypatch):
    original = formparsers.SpooledTemporaryFile
    opened = []

    def track(*args, **kwargs):
        spool = original(*args, **kwargs)
        opened.append(spool)
        return spool

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", track)
    return opened


def assert_all_slots_available(app):
    route = next(route for route in app.routes if isinstance(route, api.LegacyAnalysisRoute))
    acquired = 0
    try:
        for _ in range(2):
            assert route._slots.acquire(blocking=False)
            acquired += 1
        assert not route._slots.acquire(blocking=False)
    finally:
        for _ in range(acquired):
            route._slots.release()


def forbid_analysis(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("rejected or interrupted uploads must not reach staging or analysis")

    monkeypatch.setattr(api, "save_upload_to_temp", forbidden)
    monkeypatch.setattr(api, "analyze", forbidden)


def test_real_cumulative_limit_rejects_one_additional_byte(monkeypatch, spools):
    forbid_analysis(monkeypatch)
    assert api.MAX_LEGACY_BODY_SIZE == BODY_LIMIT
    app = api.create_app()
    block = b"x" * (1024 * 1024)
    prefix = file_prefix("application") + CANARY
    full, tail = divmod(BODY_LIMIT - len(prefix), len(block))
    payloads = iter((prefix, *([block] * full), block[:tail], b"x"))
    delivered = []

    async def receive():
        payload = next(payloads)
        delivered.append(len(payload))
        return chunk(payload, more=len(delivered) < full + 3)

    response = asyncio.run(request(app, receive))
    assert sum(delivered[:-1]) == BODY_LIMIT
    assert delivered[-1] == 1 and len(delivered) > 2
    assert_private(response, 413, b"application/json", b'{"detail":"Content Too Large"}')
    assert len(spools) == 1 and all(spool.closed for spool in spools)
    assert_all_slots_available(app)


def test_declared_limit_is_rejected_before_receiving_body(monkeypatch):
    forbid_analysis(monkeypatch)
    app = api.create_app()

    async def receive():
        pytest.fail("declared oversize body must not be read")

    response = asyncio.run(request(app, receive, length=BODY_LIMIT + 1))
    assert_private(response, 413, b"text/plain; charset=utf-8", b"Content Too Large")
    assert_all_slots_available(app)


@pytest.mark.parametrize("stop", ["disconnect", "cancel"])
def test_interrupted_upload_closes_spool_and_returns_slots(monkeypatch, spools, stop):
    forbid_analysis(monkeypatch)
    app = api.create_app()

    async def exercise():
        waiting = asyncio.Event()

        async def receive():
            if not spools:
                return chunk(file_prefix("application") + CANARY + b"x" * (2 * 1024 * 1024))
            assert spools[0]._rolled and not spools[0].closed
            waiting.set()
            if stop == "disconnect":
                return {"type": "http.disconnect"}
            await asyncio.Event().wait()

        if stop == "disconnect":
            status, _, body = await request(app, receive)
            assert status == 400
            assert CANARY not in body
        else:
            task = asyncio.create_task(request(app, receive))
            try:
                await asyncio.wait_for(waiting.wait(), timeout=5)
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    asyncio.run(exercise())
    assert len(spools) == 1 and spools[0].closed
    assert_all_slots_available(app)


def test_two_admitted_uploads_and_private_overload_response(monkeypatch, spools):
    def analyze(sources):
        assert len(sources) == 3
        return {"results": {}, "global_correlation": {
            "multi_ip_authentication": [], "distributed_authentication_to_success": [],
            "linux_audit_session_lifecycle": [], "linux_audit_login_start_co_observation": [],
        }}

    monkeypatch.setattr(api, "analyze", analyze)
    app = api.create_app()

    async def exercise():
        release = asyncio.Event()
        ready = [asyncio.Event(), asyncio.Event()]

        async def admitted(signal):
            signal.set()
            await release.wait()
            return chunk(upload_body(), more=False)

        async def unread():
            pytest.fail("overloaded request must not read the body")

        tasks = [
            asyncio.create_task(request(app, lambda signal=signal: admitted(signal)))
            for signal in ready
        ]
        try:
            await asyncio.wait_for(asyncio.gather(*(signal.wait() for signal in ready)), timeout=5)
            assert (await request(app, unread, path="/api/health"))[0] == 200
            response = await request(app, unread)
            expected = json.dumps(
                {"detail": "분석 요청이 처리 중입니다. 잠시 후 다시 시도하세요."},
                ensure_ascii=False, separators=(",", ":"),
            ).encode()
            assert_private(response, 429, b"application/json", expected, deprecated=True)
        finally:
            release.set()
            responses = await asyncio.gather(*tasks)
        for status, headers, body in responses:
            assert status == 200 and headers[b"deprecation"] == b"true"
            assert json.loads(body)["summary"]["total_sources"] == 3
            assert CANARY not in body

    asyncio.run(exercise())
    assert len(spools) == 6 and all(spool.closed for spool in spools)
    assert_all_slots_available(app)
