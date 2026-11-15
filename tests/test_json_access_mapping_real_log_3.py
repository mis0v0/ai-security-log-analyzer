"""User-confirmed access mapping; independent, non-sensitive JSONL records."""

import json
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
import stat
from threading import Event
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.api import create_app
from app.json_access_mapping import normalize_mapped_access
from app.main import _analyze_normalized_logs, analyze


ENDPOINT = "/api/v1/investigations/json-mapping"
MAPPING = {"timestamp": "when", "source_ip": "peer", "method": "verb", "request_uri": "target", "status": "code"}
ROW = {"when": "2026-03-02T12:34:56+05:30", "peer": "192.0.2.183", "verb": "GET", "target": "/download?file=..%2Fprivate", "code": 200}


def client(**kwargs):
    return TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 49123), **kwargs)


def payload(text=None, mapping=None, **updates):
    return {"schema_version": 1, "confirmed": True, "mapping": MAPPING if mapping is None else mapping,
            "log_text": json.dumps(ROW) if text is None else text, **updates}


def test_non_profile_five_field_jsonl_maps_and_runs_existing_investigation():
    with client() as c:
        response = c.post(ENDPOINT, json=payload())
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"schema_version", "input_scope", "result"}
    assert body["input_scope"] == {"mode": "text", "source": "access", "notice_code": "PARTIAL_SINGLE_SOURCE"}
    result = body["result"]
    assert result["analysis_summary"]["supported_detection_count"] == 1
    assert result["input_quality"]["aggregate"]["recognized_lines"] == 1
    assert result["report_export"]["html"]
    for private in ("192.0.2.183", "/download", "..%2Fprivate", '"when"', '"peer"'):
        assert private not in json.dumps(body)


def test_arbitrary_literal_keys_produce_equivalent_events_without_invented_metadata():
    first = normalize_mapped_access(json.dumps({**ROW, "UNMAPPED_PRIVATE_KEY": "UNMAPPED_VALUE_CANARY"}), MAPPING)
    renamed = {"timestamp": "event.time", "source_ip": "출발지", "method": "__proto__", "request_uri": "request-target", "status": "s"}
    second_row = {renamed[meaning]: ROW[key] for meaning, key in MAPPING.items()}
    second = normalize_mapped_access(json.dumps(second_row), renamed)
    assert first == second
    event = first[0]
    assert event.timestamp.isoformat() == "2026-03-02T07:04:56+00:00"
    assert event.protocol is None and event.http.response_size is None
    assert event.raw == "" and event.user_agent is None and event.user is None
    assert "UNMAPPED" not in repr(event)
    assert event.http.query == "file=..%2Fprivate"


def test_mapping_reaches_same_relevant_detector_observations_as_supported_access(tmp_path):
    targets = ["/download?file=..%2Fprivate", "/catalog?id=8%27%20OR%202%3D2", "/preview?x=%3Cscript%3Echeck()%3C/script%3E", "/health", "/docs/union/select?q=green+tea"]
    rows = [{**ROW, "peer": f"192.0.2.{183 + i}", "target": target} for i, target in enumerate(targets)]
    mapped = _analyze_normalized_logs(normalize_mapped_access("\n".join(map(json.dumps, rows)), MAPPING))
    clf = tmp_path / "access.log"
    clf.write_text("\n".join(f'{r["peer"]} - - [02/Mar/2026:07:04:56 +0000] "GET {r["target"]} HTTP/1.1" 200 42' for r in rows), encoding="utf-8")
    reference = analyze([{"source": "access", "path": clf}])
    expected = ["path_traversal", "sql_injection_like", "xss_like", None, None]
    for row, kind in zip(rows, expected):
        actual = mapped["results"][row["peer"]]
        old = reference["results"][row["peer"]]
        found = {name for name, detection in actual["detections"].items() if detection.is_detected}
        assert found == ({kind} if kind else set())
        assert found == {name for name, detection in old["detections"].items() if detection.is_detected}
        assert actual["risk_level"] == old["risk_level"]
        for name in found:
            facts = lambda detection: [(e.type, e.value) for e in detection.evidence if e.type != "http_response_size"]
            assert facts(actual["detections"][name]) == facts(old["detections"][name])
    traversal = mapped["results"][rows[0]["peer"]]["detections"]["path_traversal"]
    assert any(e.type == "http_status_code" and e.value == 200 for e in traversal.evidence)
    assert not any(e.type in {"exploit_success", "attack_success", "http_response_size"} for e in traversal.evidence)


@pytest.mark.parametrize("timestamp", ["2026-03-02T07:04:56Z", "2026-03-02T12:34:56+05:30", "2026-03-02T03:34:56-03:30"])
def test_mapping_timestamps_are_same_utc_instant(timestamp):
    event, = normalize_mapped_access(json.dumps({**ROW, "when": timestamp}), MAPPING)
    assert event.timestamp.isoformat() == "2026-03-02T07:04:56+00:00"


@pytest.mark.parametrize("uri,path,query", [
    ("//host-looking/a?x=1?y=2", "//host-looking/a", "x=1?y=2"),
    (r"/search?q=%253Cscript%253E&literal=\u003c&x=a+b", "/search", r"q=%253Cscript%253E&literal=\u003c&x=a+b"),
])
def test_mapping_never_decodes_or_reinterprets_the_original_uri(uri, path, query):
    event, = normalize_mapped_access(json.dumps({**ROW, "target": uri}), MAPPING)
    assert (event.http.path, event.http.query) == (path, query)


BAD_ROWS = [
    {**ROW, "when": value} for value in (None, "2026-03-02T12:34:56", "2026-03-02T12:34:56-00:00", "2026-02-30T12:34:56Z", "2026-03-02T12:34:56+00:60")
] + [{**ROW, "peer": value} for value in (None, "host.example.test", "192.0.2.999", "2001:db8::1%eth0")
] + [{**ROW, "code": value} for value in (True, 200.0, "200", None, 99, 600)
] + [{**ROW, "target": value} for value in (None, "*", "http://host.example/a", "/a#fragment", "/bad space", "/bad%GG", ["/a"])
] + [{**ROW, "verb": value} for value in (None, "", "GET POST", "ＧＥＴ")
] + [{**ROW, "extra": value} for value in ({"nested": 1}, [1], "private\ncontrol", float("inf"))]


@pytest.mark.parametrize("row", BAD_ROWS, ids=[f"bad-row-{i}" for i in range(len(BAD_ROWS))])
def test_any_bad_record_is_rejected_before_staging_or_worker(row):
    text = json.dumps(ROW) + "\n" + json.dumps(row)
    with patch("app.local_investigation_api._run_worker") as worker, patch("app.local_investigation_api._stage_text") as staging:
        with client() as c:
            response = c.post(ENDPOINT, json=payload(text))
    assert response.status_code == 400, response.text
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert "result" not in response.json()
    assert "192.0.2.183" not in response.text
    worker.assert_not_called()
    staging.assert_not_called()


@pytest.mark.parametrize("data", [
    payload(confirmed=False), payload(confirmed=1), payload(confirmed="true"),
    {key: value for key, value in payload().items() if key != "confirmed"},
    payload(mapping={}), payload(mapping={**MAPPING, "extra": "x"}),
    payload(mapping={**MAPPING, "status": MAPPING["method"]}),
    payload(mapping={**MAPPING, "status": None}),
    payload(mapping={**MAPPING, "status": {"path": "code"}}),
    payload(schema_version=True), payload(extra="not allowed"),
])
def test_invalid_or_unconfirmed_mapping_is_not_an_analysis_request(data):
    with patch("app.local_investigation_api._run_worker") as worker:
        with client() as c:
            response = c.post(ENDPOINT, json=data)
    assert response.status_code == 422
    assert response.json()["error_code"] == "INVALID_SCHEMA"
    worker.assert_not_called()


@pytest.mark.parametrize("text", [
    '{"when":"a","when":"b"}',
    json.dumps(ROW)[:-1] + ',"code":404}',
    json.dumps(ROW)[:-1] + ',"\\u0063ode":404}',
    json.dumps(ROW) + "\n" + '{"when":',
    json.dumps(ROW) + "\n" + json.dumps({k: v for k, v in ROW.items() if k != "target"}),
    "[]", "null", json.dumps(ROW) + "\n\n",
])
def test_malformed_duplicate_or_mixed_records_have_no_partial_success(text):
    with patch("app.local_investigation_api._run_worker") as worker:
        with client() as c:
            response = c.post(ENDPOINT, json=payload(text))
    assert response.status_code == 400
    assert "result" not in response.json()
    worker.assert_not_called()


@pytest.mark.parametrize("headers,peer", [
    ({}, "192.0.2.200"), ({"Host": "evil.example"}, "127.0.0.1"),
    ({"Origin": "https://evil.example"}, "127.0.0.1"),
    ({"Sec-Fetch-Site": "cross-site"}, "127.0.0.1"),
    *[({name: "127.0.0.1"}, "127.0.0.1") for name in ("Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Via")],
])
def test_mapping_uses_same_local_request_security_before_reading_body(headers, peer):
    with patch("app.local_investigation_api._run_worker") as worker, patch("app.local_investigation_api._bounded_json_body") as body:
        with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=(peer, 49123)) as c:
            response = c.post(ENDPOINT, json=payload(), headers=headers)
    assert response.status_code == 403
    worker.assert_not_called()
    body.assert_not_called()


@pytest.mark.parametrize("text,code", [
    ("", "EMPTY_INPUT"), ("x" * (32 * 1024 + 1), "TEXT_TOO_LARGE"),
    ("x" * 2049, "LINE_TOO_LONG"), ("{}\n" * 513, "LINE_COUNT_EXCEEDED"),
])
def test_mapping_preserves_text_size_and_line_limits(text, code):
    with patch("app.local_investigation_api._run_worker") as worker:
        with client() as c:
            response = c.post(ENDPOINT, json=payload(text))
    assert response.status_code in {400, 413}
    assert response.json()["error_code"] == code
    worker.assert_not_called()


def test_envelope_utf8_json_and_closed_existing_text_contract():
    with patch("app.local_investigation_api._run_worker") as worker:
        with client() as c:
            assert c.post(ENDPOINT, content=b" " * (96 * 1024 + 1), headers={"Content-Type": "application/json"}).status_code == 413
            assert c.post(ENDPOINT, content=b"\xff", headers={"Content-Type": "application/json"}).json()["error_code"] == "INVALID_UTF8"
            assert c.post(ENDPOINT, content='{"confirmed":true,"confirmed":true}', headers={"Content-Type": "application/json"}).json()["error_code"] == "INVALID_JSON"
            assert c.post("/api/v1/investigations/text", json={**payload(), "source": "access"}).status_code == 422
    worker.assert_not_called()


def test_staging_permissions_and_cleanup_with_real_spawned_worker(monkeypatch):
    import app.local_investigation_api as local
    paths = []
    stage = local._stage_text
    def observe(raw, directory):
        path = stage(raw, directory)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        paths.append(path)
        return path
    monkeypatch.setattr(local, "_stage_text", observe)
    with client() as c:
        response = c.post(ENDPOINT, json=payload(json.dumps({**ROW, "unmapped": "UNSELECTED_VALUE_CANARY"})))
    assert response.status_code == 200, response.text
    assert "UNSELECTED_VALUE_CANARY" not in response.text
    assert len(paths) == 1 and not paths[0].exists() and not paths[0].parent.exists()


def test_mapping_and_existing_text_route_share_admission_rate_budget():
    with patch("app.local_investigation_api._run_worker") as worker:
        with client() as c:
            for _ in range(6):
                assert c.post(ENDPOINT, json=payload(confirmed=False)).status_code == 422
            response = c.post("/api/v1/investigations/text", json={"schema_version": 1, "source": "access", "log_text": "not a log"})
    assert response.status_code == 429
    assert response.json()["error_code"] == "RATE_LIMITED"
    worker.assert_not_called()


def test_ipv6_and_json_escaping_are_preserved_as_values_not_code():
    event, = normalize_mapped_access(json.dumps({**ROW, "peer": "2001:db8::123", "target": '/search?q="quoted"&x=a+b&path=%252e%252e%252f'}), MAPPING)
    assert event.src_ip == "2001:db8::123"
    assert event.http.path == "/search"
    assert event.http.query == 'q="quoted"&x=a+b&path=%252e%252e%252f'


def test_syntactic_validation_does_not_claim_to_verify_source_field_meaning():
    # Both are valid IP literals. The adapter must follow the explicit choice,
    # never infer which one is the real client or prefer a familiar key name.
    row = {**ROW, "forwarded_header": "198.51.100.72"}
    chosen = {**MAPPING, "source_ip": "forwarded_header"}
    event, = normalize_mapped_access(json.dumps(row), chosen)
    assert event.src_ip == "198.51.100.72"
    assert event.raw == "" and "192.0.2.183" not in repr(event)


def test_mapping_worker_timeout_cleans_staging_and_releases_shared_slot(monkeypatch):
    import app.local_investigation_api as local
    staged = []
    original = local._stage_text
    def track(raw, directory):
        path = original(raw, directory)
        staged.append(path)
        return path
    monkeypatch.setattr(local, "_stage_text", track)
    monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 0.001)
    with client() as c:
        response = c.post(ENDPOINT, json=payload())
        assert response.status_code == 503
        assert response.json()["error_code"] == "ANALYSIS_TIMEOUT"
        assert staged and all(not path.exists() and not path.parent.exists() for path in staged)
        monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 10.0)
        assert c.post(ENDPOINT, json=payload()).status_code == 200


def test_mapping_holds_same_concurrency_slot_as_existing_text_route(monkeypatch):
    import app.local_investigation_api as local
    entered, release = Event(), Event()
    async def blocking_worker(*args):
        entered.set()
        await asyncio.to_thread(release.wait, 5)
        return local._error("ANALYSIS_FAILED")
    monkeypatch.setattr(local, "_run_worker", blocking_worker)
    with client() as c, ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(c.post, ENDPOINT, json=payload())
        try:
            assert entered.wait(5)
            denied = c.post("/api/v1/investigations/text", json={"schema_version": 1, "source": "access", "log_text": "unused"})
            assert denied.status_code == 429
            assert denied.json()["error_code"] == "CONCURRENCY_LIMIT"
        finally:
            release.set()
        assert pending.result(timeout=10).status_code == 500


def test_openapi_mapping_is_closed_and_reuses_existing_response():
    with client() as c:
        schema = c.get("/openapi.json").json()
    operation = schema["paths"][ENDPOINT]["post"]
    request = operation["requestBody"]["content"]["application/json"]["schema"]
    assert request["additionalProperties"] is False
    assert set(request["required"]) == {"schema_version", "confirmed", "mapping", "log_text"}
    assert request["properties"]["confirmed"]["const"] is True
    fields = request["properties"]["mapping"]
    assert fields["additionalProperties"] is False
    assert set(fields["required"]) == set(MAPPING)
    assert "LocalTextInvestigationResponse" in json.dumps(operation["responses"])
