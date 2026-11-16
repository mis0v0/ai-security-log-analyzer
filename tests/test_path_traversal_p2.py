"""P2: literal observation, supported negative and unassessed are distinct.

Only synthetic inputs. IDs and failure messages disclose no request contents.
"""

import pytest

from app.detector.web_attack import decode_url, detect_path_traversal


CASES = (
    ("literal_bad_octet", "/a/../%FF", None, "literal", False),
    ("literal_bad_escape", "/a/../%GG", None, "literal", False),
    ("literal_supported", "/a/../normal", None, "literal", True),
    ("deep_encoded_only", "/a/%2525252e%2525252e/", None, "unassessed", False),
    ("supported_path_bad_query", "/a/normal", "q=%FF", "unassessed", True),
    ("literal_bad_query", "/a/../normal", "q=%FF", "literal", True),
    ("bad_escape_only", "/a/%GG", None, "unassessed", False),
    ("bad_octet_only", "/a/%FF", None, "unassessed", False),
    ("supported_negative", "/a/normal", None, "negative", True),
)


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_p2_disposition(case):
    _, path, query, expected, decoded = case
    if (decode_url(path) is not None) is not decoded:
        pytest.fail("unexpected decoder disposition", pytrace=False)
    if expected == "unassessed":
        result = detect_path_traversal(path, query)
        if getattr(result, "unassessed_reason", None) != "PATH_REFERENCE_ENCODING":
            pytest.fail("unassessed was collapsed to ordinary negative", pytrace=False)
        if result.is_detected or result.evidence:
            pytest.fail("unassessed produced an attack observation", pytrace=False)
        return
    result = detect_path_traversal(path, query)
    incomplete = not decoded or bool(query and decode_url(query) is None)
    if (result.unassessed_reason is not None) is not incomplete:
        pytest.fail("partial evaluation disposition was lost", pytrace=False)
    if result.is_detected is not (expected == "literal"):
        pytest.fail("literal observation lost or negative fabricated", pytrace=False)
    facts = {e.type: e.value for e in result.evidence}
    if expected == "negative":
        if facts:
            pytest.fail("negative contains fabricated evidence", pytrace=False)
        return
    if facts.get("path_observation_kind") != "PATH_PARENT_SEGMENT":
        pytest.fail("literal observation was reinterpreted", pytrace=False)
    if ("url_decoded_path" in facts) is not decoded:
        pytest.fail("undecoded input was labeled decoded", pytrace=False)
    if ("url_original_path" in facts) is decoded:
        pytest.fail("original evidence disposition is inconsistent", pytrace=False)


MAPPING = {"timestamp": "t", "source_ip": "ip", "method": "m", "request_uri": "u", "status": "s"}


def representation(case, source_format):
    import json
    _, path, query, _, _ = case
    uri = path + ("?" + query if query else "")
    row = {"t": "2026-11-16T00:00:00+00:00", "ip": "192.0.2.207", "m": "GET", "u": uri, "s": 200,
           "unselected": "PRIVATE_P2_UNSELECTED_CANARY"}
    if source_format == "mapping":
        return json.dumps(row), uri
    if source_format == "nginx":
        return json.dumps({"profile": "asla-nginx-access-v1", "time_iso8601": row["t"],
                           "remote_addr": row["ip"], "request_method": "GET", "request_uri": uri,
                           "server_protocol": "HTTP/1.1", "status": 200, "body_bytes_sent": 12}), uri
    return f'192.0.2.207 - - [16/Nov/2026:00:00:00 +0000] "GET {uri} HTTP/1.1" 200 12', uri


@pytest.mark.parametrize("source_format", ("clf", "nginx", "mapping"))
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_parser_pipeline_public_projection_and_real_worker(case, source_format, capsys, monkeypatch):
    import json
    from datetime import datetime, timezone
    from fastapi.testclient import TestClient
    from app.api import create_app, build_analysis_response
    from app.parser.access_log import parse_access_log
    from app.json_access_mapping import normalize_mapped_access, MappingInputError
    from app.main import _analyze_normalized_logs
    from app.analyzer.report import print_detection_result
    from app.analyzer.report_projection import build_investigation_report_projection
    from app.analyzer.html_report import render_investigation_report_html
    from app.detector.web_attack import PATH_UNASSESSED_NOTICE

    _, path, query, expected, decoded = case
    text, uri = representation(case, source_format)
    rejected = source_format == "mapping" and "%GG" in uri
    if rejected:
        with pytest.raises(MappingInputError):
            normalize_mapped_access(text, MAPPING)
        async def forbidden(*args, **kwargs):
            pytest.fail("rejected mapping reached worker", pytrace=False)
        monkeypatch.setattr("app.local_investigation_api._run_worker", forbidden)
    else:
        events = normalize_mapped_access(text, MAPPING) if source_format == "mapping" else [parse_access_log(text)]
        if (len(events) != 1 or events[0] is None or events[0].http.path != path
                or events[0].http.query != query
                or events[0].timestamp != datetime(2026, 11, 16, tzinfo=timezone.utc)):
            pytest.fail("parser disposition or normalized observations differ", pytrace=False)
        raw = _analyze_normalized_logs(events)
        detection = raw["results"]["192.0.2.207"]["detections"]["path_traversal"]
        if detection.is_detected is not (expected == "literal"):
            pytest.fail("pipeline changed confirmed observation", pytrace=False)
        incomplete = not decoded or bool(query and decode_url(query) is None)
        if (detection.unassessed_reason is not None) is not incomplete:
            pytest.fail("pipeline dropped incomplete disposition", pytrace=False)
        projection = build_investigation_report_projection(raw)
        html = render_investigation_report_html(projection)
        legacy = build_analysis_response(raw, total_sources=1).model_dump_json()
        # The existing CLI subject header intentionally prints validated IPs.
        # This check covers the changed evidence/notice renderer, not that header.
        print_detection_result(raw["results"]["192.0.2.207"]["detections"])
        cli = capsys.readouterr().out
        for output in (html, legacy, cli):
            if (PATH_UNASSESSED_NOTICE in output) is not incomplete:
                pytest.fail("consumer lost or invented unassessed notice", pytrace=False)
            if any(secret in output for secret in (uri, "192.0.2.207", "PRIVATE_P2_UNSELECTED_CANARY", "\ufffd")):
                pytest.fail("private input or replacement character leaked", pytrace=False)
        public_detection = json.loads(legacy)["results"][0]["detections"]["path_traversal"]
        if expected == "unassessed" and public_detection["pattern_category"] != "인코딩 관찰 평가 미완료":
            pytest.fail("legacy consumer received ordinary negative", pytrace=False)

    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 42115)) as client:
        payload = {"schema_version": 1, "log_text": text}
        if source_format == "mapping":
            payload.update(confirmed=True, mapping=MAPPING)
            endpoint = "/api/v1/investigations/json-mapping"
        else:
            payload.update(source="access")
            endpoint = "/api/v1/investigations/text"
        response = client.post(endpoint, json=payload)
    if response.status_code != (400 if rejected else 200):
        pytest.fail("unexpected local API disposition", pytrace=False)
    if any(secret in response.text for secret in (uri, "192.0.2.207", "PRIVATE_P2_UNSELECTED_CANARY", "\ufffd")):
        pytest.fail("API disclosed private input", pytrace=False)
    if not rejected:
        body = response.json()["result"]
        if "unassessed_reason" in response.text or "url_original_path" in response.text:
            pytest.fail("internal disposition or evidence entered public schema", pytrace=False)
        incomplete = not decoded or bool(query and decode_url(query) is None)
        if (PATH_UNASSESSED_NOTICE in body["bounded_warnings"]) is not incomplete:
            pytest.fail("local API received ordinary negative", pytrace=False)
        if body["input_quality"]["aggregate"]["recognized_lines"] != 1:
            pytest.fail("analysis disposition was mislabeled parser rejection", pytrace=False)


def test_disposition_merge_and_representative_evidence_are_order_independent():
    import itertools
    from app.parser.access_log import parse_access_log
    from app.main import _analyze_normalized_logs
    # Same timestamp and IP: one supported negative, one unassessed, one literal.
    events = [parse_access_log(representation(CASES[index], "clf")[0]) for index in (2, 3, 8)]
    results = [_analyze_normalized_logs(list(order)) for order in itertools.permutations(events)]
    if any(result != results[0] for result in results[1:]):
        pytest.fail("input order changed evidence or disposition", pytrace=False)
    detection = results[0]["results"]["192.0.2.207"]["detections"]["path_traversal"]
    if not detection.is_detected or detection.unassessed_reason != "PATH_REFERENCE_ENCODING":
        pytest.fail("aggregation lost observation or incomplete state", pytrace=False)


def test_evaluation_does_not_score_unassessed_as_tn_or_change_sql_label():
    from app.evaluation.corpus import SCENARIOS
    from app.evaluation.runner import evaluate
    scenario = next(row for row in SCENARIOS if row.id == "web_sql_malformed_percent")
    result = evaluate((scenario,))
    if result.passed_scenarios != 1:
        pytest.fail("original scenario contract changed", pytrace=False)
    metrics = {metric.detection_type: metric for metric in result.detection_metrics}
    traversal = metrics["path_traversal"]
    if (traversal.tp, traversal.fp, traversal.fn, traversal.tn, traversal.excluded_unassessed) != (0, 0, 0, 0, 1):
        pytest.fail("unassessed entered confusion matrix", pytrace=False)
    if metrics["sql_injection_like"].tn != 1:
        pytest.fail("unrelated detector label changed", pytrace=False)


def test_bool_only_helper_and_accuracy_evaluator_cannot_hide_unassessed(monkeypatch):
    from app.detector.web_attack import is_path_traversal
    from app.evaluation import detector_accuracy as accuracy
    result = detect_path_traversal(CASES[3][1])
    with pytest.raises(ValueError, match="Path-reference encoding was not assessed[.]"):
        is_path_traversal(CASES[3][1])
    monkeypatch.setattr(accuracy, "analyze", lambda sources: {"results": {"subject": {"detections": {"path_traversal": result}}}})
    with pytest.raises(accuracy.DetectorAccuracyError, match="analysis_failed"):
        accuracy._observed({"subject": "subject", "source": "access", "detector": "path_traversal"}, "unused")


def test_live_fails_closed_without_committing_incomplete_results():
    from app.live_monitoring import LiveDetectionAccumulator, LiveTailRecord, parse_live_records
    from app.live_monitoring.detection_accumulator import LiveDetectionError
    accumulator = LiveDetectionAccumulator("access", 8, 10000)
    before = accumulator.snapshot()
    text, _ = representation(CASES[3], "clf")
    record = LiveTailRecord("access", 1, text, len(text.encode()))
    batch = parse_live_records("access", (record,))
    with pytest.raises(LiveDetectionError):
        accumulator.prepare(batch)
    if accumulator.snapshot() != before:
        pytest.fail("live committed incomplete result", pytrace=False)


@pytest.mark.parametrize("query,token,incomplete", [
    ("x=..\\doc&y=..%2Fitem", "../", False),
    ("x=..\\doc&y=%FF", "..\\", True),
])
def test_query_preserves_supported_token_preference_and_independent_raw_observation(query, token, incomplete):
    result = detect_path_traversal("/lookup", query)
    facts = {item.type: item.value for item in result.evidence}
    if (not result.is_detected or facts.get("path_pattern") != token
            or facts.get("path_observation_kind") != "QUERY_REFERENCE_STRING"
            or (result.unassessed_reason is not None) is not incomplete):
        pytest.fail("query observation contract changed", pytrace=False)
