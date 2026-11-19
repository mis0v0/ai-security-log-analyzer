"""Exercise legacy upload admission directly through ASGI without sockets."""

import asyncio
import json
from pathlib import Path
from threading import Event, Lock

import anyio

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
    return sent[0]["status"], tuple(sent[0]["headers"]), b"".join(
        message.get("body", b"") for message in sent[1:]
    )


def header_values(headers, name):
    return [value for key, value in headers if key.lower() == name]


def assert_private(response, status, content_type, body, *, deprecated=False):
    actual_status, headers, actual_body = response
    assert actual_status == status
    assert header_values(headers, b"content-type") == [content_type]
    assert header_values(headers, b"deprecation") == ([b"true"] if deprecated else [])
    assert header_values(headers, b"content-length") == [str(len(actual_body)).encode()]
    assert actual_body == body
    assert CANARY not in actual_body
    assert all(CANARY not in name + value for name, value in headers)


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


@pytest.fixture
def parser_writes(monkeypatch):
    original = formparsers.multipart.MultipartParser.write
    writes = []

    def track(parser, data):
        writes.append(data)
        return original(parser, data)

    monkeypatch.setattr(formparsers.multipart.MultipartParser, "write", track)
    return writes


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


@pytest.mark.parametrize("declared", [None, BODY_LIMIT, BODY_LIMIT - 1])
def test_real_cumulative_limit_rejects_one_additional_byte(monkeypatch, spools, parser_writes, declared):
    forbid_analysis(monkeypatch)
    assert api.MAX_LEGACY_BODY_SIZE == BODY_LIMIT
    app = api.create_app()
    block = b"x" * (1024 * 1024)
    prefix = file_prefix("application") + CANARY
    full, tail = divmod(BODY_LIMIT - len(prefix), len(block))
    payloads = iter((prefix, *([block] * full), block[:tail], b"x"))
    received = []

    async def receive():
        payload = next(payloads)
        received.append(payload)
        return chunk(payload, more=len(received) < full + 3)

    response = asyncio.run(request(app, receive, length=declared))
    assert sum(map(len, received[:-1])) == BODY_LIMIT
    assert received[-1] == b"x" and len(received) > 2
    # Request.stream() can emit an empty terminal sentinel independently of the body.
    assert [data for data in parser_writes if data] == received[:-1]
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
            assert status == 200 and header_values(headers, b"deprecation") == [b"true"]
            assert json.loads(body)["summary"]["total_sources"] == 3
            assert CANARY not in body

    asyncio.run(exercise())
    assert len(spools) == 6 and all(spool.closed for spool in spools)
    assert_all_slots_available(app)



def empty_result():
    return {"results": {}, "global_correlation": {
        "multi_ip_authentication": [], "distributed_authentication_to_success": [],
        "linux_audit_session_lifecycle": [], "linux_audit_login_start_co_observation": [],
    }}


def test_exact_total_and_matching_declared_length_reach_analysis(monkeypatch, spools, parser_writes):
    file_size = 10 * 1024 * 1024
    block = b"x" * (1024 * 1024)
    parts = []
    for role in ("application", "ssh", "access"):
        parts.extend((file_prefix(role), *([block] * 10), b"\r\n"))
    padding_prefix = b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="padding"\r\n\r\n'
    ending = b"\r\n--" + BOUNDARY + b"--\r\n"
    padding = BODY_LIMIT - sum(map(len, parts)) - len(padding_prefix) - len(ending)
    parts.extend((padding_prefix, b"p" * padding, ending))
    assert sum(map(len, parts)) == BODY_LIMIT

    staged = []

    def analyze(sources):
        staged.extend(Path(source["path"]) for source in sources)
        assert len(staged) == 3
        assert all(path.stat().st_size == file_size for path in staged)
        return empty_result()

    monkeypatch.setattr(api, "analyze", analyze)
    app = api.create_app()
    payloads = iter(enumerate(parts))

    async def receive():
        index, payload = next(payloads)
        return chunk(payload, more=index < len(parts) - 1)

    status, headers, body = asyncio.run(request(app, receive, length=BODY_LIMIT))
    assert status == 200
    assert header_values(headers, b"deprecation") == [b"true"]
    assert json.loads(body)["summary"]["total_sources"] == 3
    assert [data for data in parser_writes if data] == parts
    assert len(staged) == 3 and all(not path.exists() for path in staged)
    assert len(spools) == 3 and all(spool.closed for spool in spools)
    assert_all_slots_available(app)


@pytest.mark.parametrize("outcome", ["success", "exception", "cancel_scope", "task_cancel"])
def test_slots_remain_held_inside_analysis(monkeypatch, spools, outcome):
    app = api.create_app()
    releases = [Event(), Event()]
    worker_finished = [Event(), Event()]
    lock = Lock()
    staged = []

    async def exercise():
        loop = asyncio.get_running_loop()
        ready = [asyncio.Event(), asyncio.Event()]
        scopes = [anyio.CancelScope(), anyio.CancelScope()]
        completed = [asyncio.Event(), asyncio.Event()]

        def analyze(sources):
            paths = [Path(source["path"]) for source in sources]
            assert len(paths) == 3 and all(path.read_bytes() == CANARY for path in paths)
            with lock:
                index = len(staged)
                staged.append(paths)
            loop.call_soon_threadsafe(ready[index].set)
            try:
                assert releases[index].wait(timeout=10)
                if outcome == "exception":
                    raise RuntimeError(CANARY.decode())
                return empty_result()
            finally:
                worker_finished[index].set()

        monkeypatch.setattr(api, "analyze", analyze)

        async def submit(index):
            async def receive():
                return chunk(upload_body(), more=False)

            with scopes[index]:
                response = await request(app, receive)
                completed[index].set()
                return response

        async def unread():
            pytest.fail("overloaded request read the body while both analysis workers were active")

        tasks = [asyncio.create_task(submit(index)) for index in range(2)]
        try:
            await asyncio.wait_for(asyncio.gather(*(signal.wait() for signal in ready)), timeout=5)
            if outcome in {"cancel_scope", "task_cancel"}:
                if outcome == "cancel_scope":
                    scopes[0].cancel()
                else:
                    tasks[0].cancel()
                # Let the loop deliver cancellation while both worker barriers remain closed.
                checkpoint = loop.create_future()
                loop.call_soon(checkpoint.set_result, None)
                await checkpoint
            assert not any(done.is_set() for done in worker_finished)
            assert (await request(app, unread, path="/api/health"))[0] == 200
            status, _, _ = await request(app, unread)
            assert status == 429, "both active analysis workers must retain their slots"
            assert all(path.exists() for paths in staged for path in paths)
        finally:
            for release in releases:
                release.set()
            responses = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)
        if outcome == "task_cancel":
            assert isinstance(responses[0], asyncio.CancelledError)
            assert responses[1][0] == 200 and completed[1].is_set()
        elif outcome == "cancel_scope":
            # AnyIO may deliver the response or cancel after the shielded worker returns.
            assert responses[0] is None or responses[0][0] == 200
            assert responses[1][0] == 200 and completed[1].is_set()
        else:
            assert [response[0] for response in responses] == [500 if outcome == "exception" else 200] * 2
            assert all(CANARY not in response[2] for response in responses)

    asyncio.run(exercise())
    assert len(staged) == 2 and all(not path.exists() for paths in staged for path in paths)
    assert len(spools) == 6 and all(spool.closed for spool in spools)
    assert_all_slots_available(app)


def test_privacy_assertion_detects_canary_hidden_by_duplicate_header():
    body = b"Content Too Large"
    headers = (
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode()),
        (b"x-test", CANARY), (b"x-test", b"public"),
    )
    with pytest.raises(AssertionError):
        assert_private((413, headers, body), 413, b"text/plain; charset=utf-8", body)
