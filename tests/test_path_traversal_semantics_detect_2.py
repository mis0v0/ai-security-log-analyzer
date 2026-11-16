"""Independently specified DETECT-2 lexical policy, not DETECT-1 labels.

RFC3986 path segments; OWASP encoding/backslash indicators. None means outside
the bounded encoding profile, never TN. Query matches assert no backend/intent.
The validation inputs are first exercised only after the development correction.
"""
from datetime import datetime, timezone
from dataclasses import asdict

import pytest

from app.detector.web_attack import decode_url, detect_path_traversal
from app.evaluation.detector_accuracy import Confusion


# id, path, query, lexical observation, fixed kind, actual matched token
DEVELOPMENT = (
    ("parent", "/records/../panel", None, True, "PATH_PARENT_SEGMENT", "../"),
    ("terminal", "/records/..", None, True, "PATH_PARENT_SEGMENT", ".."),
    ("named_suffix", "/archive../leaf", None, False, None, None),
    ("named_three_dots", "/draft.../leaf", None, False, None, None),
    ("encoded", "/records/%2e%2e/panel", None, True, "DECODED_PATH_PARENT_REFERENCE", "../"),
    ("double_encoded", "/records/%252e%252e/panel", None, True, "DECODED_PATH_PARENT_REFERENCE", "../"),
    ("query_file", "/download", "file=../doc", True, "QUERY_REFERENCE_STRING", "../"),
    ("query_search", "/search", "q=../doc", True, "QUERY_REFERENCE_STRING", "../"),
    ("backslash", "/records/..%5cpanel", None, True, "BACKSLASH_PARENT_REFERENCE", "..\\"),
    ("bad_escape", "/images/%ZZ/panel", None, None, None, None),
    ("unicode_lookalike", "/records/．．/panel", None, False, None, None),
    ("ordinary", "/assets/ordinary", None, False, None, None),
    ("basename_dots", "/foo/bar..", None, False, None, None),
    ("bad_utf8", "/%ff/x", None, None, None, None),
)
VALIDATION = (
    ("encoded_terminal", "/one/%2E%2E", None, True, "DECODED_PATH_PARENT_REFERENCE", ".."),
    ("literal_backslash", "/root\\..\\leaf", None, True, "BACKSLASH_PARENT_REFERENCE", "..\\"),
    ("internal_dots", "/new..name/file", None, False, None, None),
    ("encoded_named_suffix", "/v4%2e%2e%2e/data", None, False, None, None),
    ("query_percent_data", "/lookup", "note=..%255Cdoc&literal=90%25", True, "QUERY_REFERENCE_STRING", "..\\"),
    ("single_dot", "/a/./b", None, False, None, None),
    ("third_layer", "/one/%25252e%25252e/", None, True, "DECODED_PATH_PARENT_REFERENCE", "../"),
    ("fourth_layer", "/one/%2525252e%2525252e/", None, None, None, None),
)
# Held back after the first validation exposed a mixed-percent-data decoder
# defect. Expected labels below still come from the declared lexical policy.
FINAL_VALIDATION = (
    ("empty_segment_parent", "/store//../piece", None, True, "PATH_PARENT_SEGMENT", "../"),
    ("double_terminal", "/store/%252e%252e", None, True, "DECODED_PATH_PARENT_REFERENCE", ".."),
    ("encoded_basename", "/job%2e%2e/notes", None, False, None, None),
    ("query_plus", "/search", "note=..%2Fref+example", True, "QUERY_REFERENCE_STRING", "../"),
    ("mixed_separator", "/alpha/..\\beta", None, True, "BACKSLASH_PARENT_REFERENCE", "..\\"),
    ("version_suffix", "/release/v.../docs", None, False, None, None),
    ("malformed_utf8", "/%F0%28%8C%28", None, None, None, None),
    ("deep_escape", "/x/%2525252f", None, None, None, None),
)


def measure(cases, detector=detect_path_traversal):
    counts = Confusion()
    excluded = 0
    for _, path, query, expected, _, _ in cases:
        actual = detector(path, query).is_detected
        if expected is None:
            excluded += 1
        else:
            counts = counts.add(expected, actual)
    return asdict(counts), excluded


def check_case(case):
    _, path, query, expected, kind, token = case
    result = detect_path_traversal(path, query, "GET", 200, None, datetime(2026, 11, 16, tzinfo=timezone.utc))
    if expected is None:
        assert decode_url(path) is None
        assert not result.is_detected and result.evidence == []
        return
    assert result.is_detected is expected
    if expected:
        evidence = {item.type: item.value for item in result.evidence}
        assert evidence["path_pattern"] == token
        assert evidence.get("path_observation_kind") == kind
        assert "exploit_success" not in evidence
    else:
        assert result.evidence == []


@pytest.mark.parametrize("case", DEVELOPMENT, ids=[row[0] for row in DEVELOPMENT])
def test_development_policy(case):
    check_case(case)


@pytest.mark.parametrize("case", VALIDATION, ids=[row[0] for row in VALIDATION])
def test_validation_policy(case):
    check_case(case)


@pytest.mark.parametrize("case", FINAL_VALIDATION, ids=[row[0] for row in FINAL_VALIDATION])
def test_final_validation_policy(case):
    check_case(case)


def test_decoder_is_bounded_strict_and_preserves_literal_percent_data():
    for value in ("/x/%00", "/x/%ff", "/x/%GG", "/" + "a" * 8192, "/x/" + chr(0xd800)):
        assert decode_url(value) is None
    assert decode_url("90%25") == "90%"
    assert decode_url("/" + "a" * 8191) == "/" + "a" * 8191
    assert decode_url("a+b") == "a+b"
    assert decode_url("/%25252e%25252e/") == "/../"


def test_pipeline_selection_is_independent_of_input_order():
    import json
    from app.json_access_mapping import normalize_mapped_access
    from app.main import _analyze_normalized_logs
    mapping = {"timestamp": "t", "source_ip": "ip", "method": "m", "request_uri": "u", "status": "s"}
    data = [{"t": "2026-11-16T00:00:00Z", "ip": "192.0.2.203", "m": "GET", "u": "/old/../leaf", "s": 403},
            {"t": "2026-11-16T00:00:10Z", "ip": "192.0.2.203", "m": "GET", "u": "/new/..", "s": 200}]
    events = normalize_mapped_access("\n".join(map(json.dumps, data)), mapping)
    first = _analyze_normalized_logs(events)["results"]["192.0.2.203"]
    second = _analyze_normalized_logs(list(reversed(events)))["results"]["192.0.2.203"]
    assert first["detections"]["path_traversal"] == second["detections"]["path_traversal"]
    assert first["risk_level"] == second["risk_level"]
    assert {e.type: e.value for e in first["detections"]["path_traversal"].evidence}["http_status_code"] == 403


@pytest.mark.parametrize("target,kind", [
    ("/private-marker/..", "PATH_PARENT_SEGMENT"),
    ("/private-marker/%252e%252e/leaf", "DECODED_PATH_PARENT_REFERENCE"),
    ("/lookup?term=..%5Cprivate-marker", "QUERY_REFERENCE_STRING"),
    ("/private-marker/..%5Cleaf", "BACKSLASH_PARENT_REFERENCE"),
    ("/private-marker../leaf", None),
])
def test_four_input_formats_preserve_facts_then_analysis_and_private_projection(tmp_path, target, kind):
    import json
    from app.analyzer.pipeline import load_normalized_logs
    from app.analyzer.report_projection import build_investigation_report_projection
    from app.analyzer.html_report import render_investigation_report_html
    from app.api import build_analysis_response
    from app.json_access_mapping import normalize_mapped_access
    from app.main import analyze, _analyze_normalized_logs
    from test_detect_1_path_reference import _common_facts
    from app.detector.web_attack import PATH_OBSERVATION_LABELS

    mapping = {"timestamp": "t", "source_ip": "ip", "method": "m", "request_uri": "u", "status": "s"}
    row = {"t": "2026-11-16T09:00:00+09:00", "ip": "2001:db8::203", "m": "GET", "u": target, "s": 200,
           "ignored": "UNMAPPED_DETECT2_CANARY"}
    clf = f'2001:db8::203 - - [16/Nov/2026:00:00:00 +0000] "GET {target} HTTP/1.1" 200 17'
    profile = {"profile": "asla-nginx-access-v1", "time_iso8601": row["t"], "remote_addr": row["ip"],
               "request_method": "GET", "request_uri": target, "server_protocol": "HTTP/1.1", "status": 200,
               "body_bytes_sent": 17}
    events = normalize_mapped_access(json.dumps(row), mapping)
    analyses = [_analyze_normalized_logs(events)]
    for number, text in enumerate((clf, clf + ' "-" "-"', json.dumps(profile))):
        path = tmp_path / f"input{number}.log"
        path.write_text(text + "\n", encoding="utf-8")
        sources = [{"source": "access", "path": str(path)}]
        parsed = load_normalized_logs(sources)
        assert len(parsed) == 1  # Parser disposition checked first.
        assert _common_facts(parsed[0]) == _common_facts(events[0])
        analyses.append(analyze(sources))
    first = analyses[0]["results"][row["ip"]]
    for raw in analyses:
        result = raw["results"][row["ip"]]
        detection = result["detections"]["path_traversal"]
        assert detection.is_detected is (kind is not None)
        facts = lambda detection: [(e.type, e.value, e.timestamp) for e in detection.evidence if e.type != "http_response_size"]
        assert facts(detection) == facts(first["detections"]["path_traversal"])
        assert result["correlation"] == first["correlation"]
        assert result["risk_level"] == first["risk_level"]
        assert raw["global_correlation"] == analyses[0]["global_correlation"]
        projection = build_investigation_report_projection(raw)
        html = render_investigation_report_html(projection)
        public = build_analysis_response(raw, total_sources=1).model_dump_json()
        for forbidden in (row["ip"], target, "private-marker", "UNMAPPED_DETECT2_CANARY"):
            assert forbidden not in public and forbidden not in html
        if kind:
            assert PATH_OBSERVATION_LABELS[kind] in html
            assert PATH_OBSERVATION_LABELS[kind] in public
            assert '"response_status":200' in public
            assert "판단할 수 없습니다" in html
            assert not any(e.type in {"exploit_success", "attack_success"} for e in detection.evidence)


@pytest.mark.parametrize("target,count", [("/private-marker/..", 1), ("/private-marker../leaf", 0), ("/lookup?q=../private-marker", 1)])
def test_real_local_worker_and_report_preserve_redaction(target, count):
    import json
    from fastapi.testclient import TestClient
    from app.api import create_app
    mapping = {"timestamp": "t", "source_ip": "ip", "method": "m", "request_uri": "u", "status": "s"}
    row = {"t": "2026-11-16T00:00:00Z", "ip": "192.0.2.203", "m": "GET", "u": target, "s": 200,
           "extra": "UNMAPPED_DETECT2_CANARY"}
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 42113)) as client:
        response = client.post("/api/v1/investigations/json-mapping", json={
            "schema_version": 1, "confirmed": True, "mapping": mapping, "log_text": json.dumps(row),
        })
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["analysis_summary"]["supported_detection_count"] == count
    assert body["input_quality"]["aggregate"]["recognized_lines"] == 1
    for private in (target, row["ip"], "private-marker", "UNMAPPED_DETECT2_CANARY"):
        assert private not in response.text
    assert "report_export" in body


def test_terminal_evidence_requires_v2_category_and_unknown_categories_fail_closed():
    import copy
    from app.main import _analyze_normalized_logs
    from app.json_access_mapping import normalize_mapped_access
    from app.analyzer.report_projection import build_investigation_report_projection, InvestigationReportProjectionError
    from app.models.schemas import Evidence
    from app.detector.web_attack import valid_path_evidence
    import json
    mapping = {"timestamp": "t", "source_ip": "ip", "method": "m", "request_uri": "u", "status": "s"}
    raw = _analyze_normalized_logs(normalize_mapped_access(json.dumps({
        "t": "2026-11-16T00:00:00Z", "ip": "192.0.2.203", "m": "GET", "u": "/a/..", "s": 200}), mapping))
    for bad_kind in (None, "PRIVATE_KIND_CANARY"):
        changed = copy.deepcopy(raw)
        evidence = changed["results"]["192.0.2.203"]["detections"]["path_traversal"].evidence
        evidence[:] = [e for e in evidence if e.type != "path_observation_kind"]
        if bad_kind:
            evidence.append(Evidence("path_observation_kind", bad_kind, "path_traversal_detector"))
        with pytest.raises(InvestigationReportProjectionError):
            build_investigation_report_projection(changed)
    assert valid_path_evidence("../") and not valid_path_evidence("..")
    assert not valid_path_evidence([], "PATH_PARENT_SEGMENT")


def test_historical_detector_replay_is_pinned_and_test_only():
    import hashlib
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    source = (root / "tests/detect1_path_policy_v1.py").read_text()
    tail = source.split("def decode_url", 1)[1].split("\n\ndef analyze_mapped_v1", 1)[0]
    assert hashlib.sha256(("def decode_url" + tail).encode()).hexdigest() == "8473bd6994e5e466b626909b385a023001062ec33661d7aed9f01d55def1a976"
    assert not any("detect1_path_policy_v1" in path.read_text() for path in (root / "app").rglob("*.py"))


def test_source_pin_migration_preserves_payload_and_rejects_previous_pin(monkeypatch):
    import hashlib
    from fastapi.testclient import TestClient
    from app import evaluation_snapshot_delivery as delivery
    from app.api import create_app
    assert len(delivery._SOURCE_VERSION_PINS) == 37
    for directories, name, pin in delivery._SOURCE_VERSION_PINS:
        content = delivery._ROOT.joinpath(*directories, name).read_bytes()
        assert hashlib.sha256(content).hexdigest() == pin
    asset = delivery._ROOT / "frontend/evaluation-snapshot-v1.json"
    assert len(asset.read_bytes()) == 13783
    assert hashlib.sha256(asset.read_bytes()).hexdigest() == "9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195"
    previous = "7c60008e756f0333feb160393b1c85e4b96468457533b9bf7c60e4a61d22ad59"
    with pytest.raises(OSError):
        delivery._read_pinned(("app", "detector"), "web_attack.py", previous)
    app = create_app(enable_evidence_review_viewer=True, evidence_review_port=8000)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 42113)) as client:
        assert client.get("/assets/evaluation-snapshot-v1.json").content == asset.read_bytes()
        monkeypatch.setattr(delivery, "_SOURCE_VERSION_PINS", tuple(
            (directory, name, previous if name == "web_attack.py" else pin)
            for directory, name, pin in delivery._SOURCE_VERSION_PINS))
        assert client.get("/assets/evaluation-snapshot-v1.json").status_code == 404


@pytest.mark.parametrize("pattern,label", [
    ("..", None), ("../", "PRIVATE_KIND_CANARY"), ("PRIVATE_PATH_CANARY", None),
])
def test_html_rejects_forged_pattern_or_category(pattern, label):
    from app.analyzer.html_report import _evidence_lines, InvestigationReportRendererError
    from app.analyzer.report_projection import PathTraversalEvidenceProjection
    with pytest.raises(InvestigationReportRendererError):
        _evidence_lines(PathTraversalEvidenceProjection(pattern, "GET", 200, None, label))
