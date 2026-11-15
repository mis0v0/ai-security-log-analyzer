"""Independent synthetic Nginx JSON profile checks; not a producer capture."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.analyzer.html_report import render_investigation_report_html
from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.report_projection import build_investigation_report_projection
from app.api import build_analysis_response, create_app
from app.input_quality_36_12a import assess_record, evaluate_source_text
from app.live_monitoring import LiveTailRecord, parse_live_records
from app.main import analyze
from app.parser.access_log import parse_access_log


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/nginx_json_access_v1.log"
ROW = {
    "profile": "asla-nginx-access-v1",
    "time_iso8601": "2026-03-08T04:05:06+05:30",
    "remote_addr": "192.0.2.91",
    "request_method": "GET",
    "request_uri": "/catalog?name=green%20tea&literal=a+b",
    "server_protocol": "HTTP/1.1",
    "status": 200,
    "body_bytes_sent": 42,
}


def _line(**updates):
    return json.dumps({**ROW, **updates}, ensure_ascii=True, separators=(",", ":"))


@pytest.mark.parametrize("address", ["192.0.2.91", "2001:db8::91"])
@pytest.mark.parametrize("status", [100, 200, 404, 499, 500, 599])
def test_exact_profile_maps_observed_fields_to_existing_http_context(address, status):
    event = parse_access_log(_line(remote_addr=address, status=status), "America/New_York")
    assert event is not None
    assert event.timestamp == datetime(2026, 3, 7, 22, 35, 6, tzinfo=timezone.utc)
    assert event.timestamp.tzinfo is timezone.utc
    assert (event.event_type, event.source, event.src_ip, event.protocol) == (
        "http_request", "access_log", address, "HTTP/1.1",
    )
    assert (event.user, event.user_agent, event.application, event.dst_ip) == (None, None, None, None)
    assert asdict(event.http) == {
        "method": "GET", "path": "/catalog", "query": "name=green%20tea&literal=a+b",
        "status_code": status, "response_size": 42,
    }


@pytest.mark.parametrize("timestamp", [
    "2026-03-07T22:35:06+00:00", "2026-03-08T04:05:06+05:30", "2026-03-07T19:05:06-03:30",
])
def test_numeric_offsets_are_normalized_without_inferred_timezone(timestamp):
    assert parse_access_log(_line(time_iso8601=timestamp)).timestamp.isoformat() == "2026-03-07T22:35:06+00:00"


@pytest.mark.parametrize("uri,path,query", [
    ("/", "/", None),
    ("/docs?q=%E2%9C%93", "/docs", "q=%E2%9C%93"),
    ("//assets/item?x=1?y=2", "//assets/item", "x=1?y=2"),
    ('/echo?q="quoted"&dir=C:\\temp', "/echo", 'q="quoted"&dir=C:\\temp'),
    (r"/echo?literal=\u003cscript\u003e", "/echo", r"literal=\u003cscript\u003e"),
    ("/문서?q=차", "/문서", "q=차"),
    ("/download?file=..%2F..%2Fprivate-canary", "/download", "file=..%2F..%2Fprivate-canary"),
])
def test_json_unescaping_once_preserves_original_target_without_url_decoding(uri, path, query):
    event = parse_access_log(_line(request_uri=uri))
    assert (event.http.path, event.http.query) == (path, query)


@pytest.mark.parametrize("protocol", ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])
def test_documented_protocol_subset(protocol):
    event = parse_access_log(_line(request_method="POST", server_protocol=protocol, body_bytes_sent=0))
    assert (event.protocol, event.http.method, event.http.response_size) == (protocol, "POST", 0)


@pytest.mark.parametrize("field", sorted(set(ROW) - {"profile"}))
def test_identified_profile_requires_every_field(field):
    row = dict(ROW)
    del row[field]
    with pytest.raises(ValueError):
        parse_access_log(json.dumps(row))


INVALID_FIELDS = [
    ("status", value) for value in (True, None, "200", 200.0, 99, 600)
] + [
    ("body_bytes_sent", value) for value in (False, None, "42", 4.2, -1, 2**63)
] + [
    ("remote_addr", value) for value in (None, "host.example.test", "192.0.2.999", "192.0.2.1:80", "2001:db8::1%eth0")
] + [
    ("time_iso8601", value) for value in (
        None, "2026-02-30T04:05:06+05:30", "2026-03-08T04:05:06", "2026-03-08T04:05:06Z",
        "2026-03-08T04:05:06-00:00", "2026-03-08T04:05:06+24:00", "2026-03-08T04:05:06+01:60",
        "2026-03-08T04:05:06.123+05:30", "0001-01-01T00:00:00+01:00",
    )
] + [
    ("request_uri", value) for value in (None, "", "*", "http://other.example/path", "/path#fragment", "/has space", "/bad\nline", "/bad\u0000", "/bad\ud800", "/" + "x" * 2048)
] + [
    ("request_method", value) for value in (None, "", "GET POST", "GET\r\n", "ＧＥＴ")
] + [("server_protocol", value) for value in (None, "HTTP/9.9", "HTTP/1.1 garbage")]


@pytest.mark.parametrize("field,value", INVALID_FIELDS, ids=[f"invalid-{i}" for i in range(len(INVALID_FIELDS))])
def test_identified_profile_rejects_invalid_types_values_and_ambiguous_targets(field, value):
    with pytest.raises(ValueError) as error:
        parse_access_log(_line(**{field: value}))
    assert "private-canary" not in str(error.value)


def test_extra_fields_rejected_and_key_order_not_used_as_profile_identity():
    with pytest.raises(ValueError):
        parse_access_log(_line(unapproved="RAW-CANARY"))
    reversed_row = dict(reversed(list(ROW.items())))
    assert parse_access_log(json.dumps(reversed_row)).http.path == "/catalog"


@pytest.mark.parametrize("line", [
    '{"remote_addr":"192.0.2.91","request_uri":"/"}',
    _line(profile="other-nginx-schema"), _line(profile=1),
    '{"profile":"asla-nginx-access-v1",',
    _line()[:-1] + ',"status":404}',
    _line()[:-1] + ',"\\u0073tatus":404}',
    _line().replace('"status":200', '"status":NaN'),
])
def test_unidentified_or_ambiguous_json_retains_non_event_disposition(line):
    assert parse_access_log(line) is None
    assert assess_record("access", line)[2] is False


def test_excessive_json_nesting_never_produces_an_event_or_unhandled_error():
    line = '{"profile":"asla-nginx-access-v1","nested":' + '[' * 1100 + '0' + ']' * 1100 + '}'
    # Python/pytest recursion budgets differ. Both a decoder non-event and an
    # identified-profile schema rejection are closed dispositions.
    outcome, reason, compatible = assess_record("access", line)
    assert outcome in {"ignored", "rejected"}
    assert reason in {"ignored_record", "unsupported_format"}
    assert compatible is False


@pytest.mark.parametrize("framing", ["{}", " {} ", "{}\n", "{}\r\n"])
def test_json_record_framing(framing):
    assert parse_access_log(framing.format(_line())).http.path == "/catalog"


def test_fixed_synthetic_input_reaches_existing_detectors_risk_and_safe_projections(tmp_path):
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    events = load_normalized_logs(({"source": "access", "path": FIXTURE},))
    assert len(events) == len(lines) == 8
    live = parse_live_records("access", tuple(
        LiveTailRecord("access", index, line, len(line.encode()))
        for index, line in enumerate(lines, 1)
    ))
    assert live.parsed_count == 8
    assert [outcome.event for outcome in live.outcomes] == events
    result = analyze(({"source": "access", "path": FIXTURE},))
    expected = {"192.0.2.94": "path_traversal", "192.0.2.95": "sql_injection_like", "192.0.2.96": "xss_like"}
    for ip, subject in result["results"].items():
        detected = {name for name, item in subject["detections"].items() if item.is_detected}
        assert detected == ({expected[ip]} if ip in expected else set())
        assert subject["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
    # Equal observations through the existing CLF producer contract must yield
    # the complete same deterministic analysis, not just the same alert labels.
    clf = tmp_path / "equivalent-clf.log"
    reference = []
    for line, event in zip(lines, events):
        row = json.loads(line)
        request = f'{row["request_method"]} {row["request_uri"]} {row["server_protocol"]}'
        request = request.replace("\\", "\\\\").replace('"', '\\"')
        timestamp = event.timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        reference.append(f'{event.src_ip} - - [{timestamp}] "{request}" {row["status"]} {row["body_bytes_sent"]}')
    # CLF's existing urlsplit behavior drops a leading // authority. That
    # legacy behavior is not reused for the new original-URI profile.
    json_subset = tmp_path / "parity-json.log"
    json_subset.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    clf.write_text("\n".join(reference[:-1]) + "\n", encoding="utf-8")
    assert analyze(({"source": "access", "path": json_subset},)) == analyze(({"source": "access", "path": clf},))
    public = build_analysis_response(result, 1).model_dump_json()
    html = render_investigation_report_html(build_investigation_report_projection(result))
    for canary in ("private-canary", "/download", "/catalog", "192.0.2.94", "2001:db8::97", "green%20tea"):
        assert canary not in public + html


@pytest.mark.parametrize("mode", ["text", "file"])
def test_existing_local_api_and_report_accept_profile_without_new_public_fields(mode):
    text = FIXTURE.read_text(encoding="utf-8")
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        if mode == "text":
            response = client.post("/api/v1/investigations/text", json={"schema_version": 1, "source": "access", "log_text": text})
        else:
            response = client.post("/api/v1/investigations", files=[
                ("application_file", ("application.log", (ROOT / "sample_logs/brute_force.log").read_bytes(), "text/plain")),
                ("ssh_file", ("ssh.log", (ROOT / "sample_logs/ssh_auth.log").read_bytes(), "text/plain")),
                ("access_file", ("access.log", text.encode(), "text/plain")),
            ])
    assert response.status_code == 200, response.text
    body = response.json()
    result = body["result"] if mode == "text" else body
    quality = next(row for row in result["input_quality"]["by_source"] if row["source"] == "access")
    assert quality["recognized_lines"] == 8
    assert quality["recognition_status"] == "complete"
    assert result["report_export"]["html"]
    for canary in ("private-canary", "/download", "/catalog", "192.0.2.94", "2001:db8::97", "asla-nginx-access-v1"):
        assert canary not in json.dumps(body)


@pytest.mark.parametrize("line,reason", [
    (_line(time_iso8601="2026-02-30T04:05:06+05:30"), "invalid_timestamp"),
    (_line(remote_addr="not-an-address"), "invalid_address"),
    (_line(status=999), "other_rejected"),
])
def test_input_quality_and_text_api_reject_bad_profile_with_fixed_errors(line, reason):
    quality = evaluate_source_text("access", line)
    assert quality.reason_counts.model_dump()[reason] == 1
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/investigations/text", json={"schema_version": 1, "source": "access", "log_text": line})
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert "192.0.2.91" not in response.text
