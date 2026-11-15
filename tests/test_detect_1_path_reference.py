"""Frozen, internally authored challenge; measured limitations, not a GO oracle.

Reuse detector_accuracy for labels/parser gating/metrics. These tests deliberately
retain measured mismatches; passing does not mean all challenge labels match.
No production detector or held-out label is changed to improve the score.
"""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil

from fastapi.testclient import TestClient
import pytest

from app.analyzer.pipeline import load_normalized_logs
from app.api import create_app
from app.evaluation import detector_accuracy as accuracy
from app.json_access_mapping import (
    MappingInputError, analyze_mapped_access_file, normalize_mapped_access,
)
from app.main import analyze


ROOT = Path(__file__).resolve().parents[1] / "sample_logs" / "detect_1_path_reference"
FREEZE_SHA256 = "c95f142b87ae8686cbcd2c3277736f3657c73286a3ee40b30a7d5f459e2a659b"
MAPPING = {"timestamp": "occurred_at", "source_ip": "observed_peer", "method": "http_verb",
           "request_uri": "original_target", "status": "response_code"}


@pytest.fixture(scope="module")
def frozen():
    raw = (ROOT / "hashes.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FREEZE_SHA256
    freeze = json.loads(raw)
    assert freeze["human_review_status"] == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert {path.name for path in ROOT.iterdir()} == {*freeze["sha256"], "hashes.json"}
    for name, expected in freeze["sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    rows = accuracy.load_corpus(ROOT / "manifest.json")
    assert len(rows) == 14
    assert set(freeze["subsets"]["development"]).isdisjoint(freeze["subsets"]["validation"])
    assert set(freeze["subsets"]["development"] + freeze["subsets"]["validation"]) == {row["id"] for row in rows}
    return freeze, rows


def _summary(tmp_path, rows):
    # Existing closed evaluator accepts a separate manifest; original 46 remain
    # unchanged. Copy only this subset so its exact-fixture inventory still holds.
    for row in rows:
        shutil.copyfile(ROOT / row["fixture"], tmp_path / row["fixture"])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "data_scope": "synthetic-only",
                                    "scenarios": rows}), encoding="utf-8")
    return accuracy.evaluate(manifest)


@pytest.mark.parametrize("subset,counts,excluded", [
    ("development", (2, 3, 1, 0), (0, 1)),
    ("validation", (1, 1, 2, 1), (2, 0)),
    ("combined", (3, 4, 3, 1), (2, 1)),
])
def test_measured_reference_pattern_mismatches_are_not_hidden(frozen, tmp_path, subset, counts, excluded):
    freeze, rows = frozen
    selected = rows if subset == "combined" else tuple(row for row in rows if row["id"] in freeze["subsets"][subset])
    summary = _summary(tmp_path, selected)
    metric, = (row for row in summary["metrics"] if row["detector"] == "path_traversal")
    assert tuple(metric[key] for key in ("tp", "fp", "fn", "tn")) == counts
    assert tuple(metric[key] for key in ("excluded_undetermined", "excluded_parser")) == excluded
    if subset == "combined":
        assert (metric["precision"], metric["recall"], metric["f1"]) == ("0.428571", "0.500000", "0.461538")
        assert metric["positive_support"] == 6 and metric["negative_support"] == 5
        assert len(summary["operational_false_alert_candidates"]) == 5
        # A known benign documentation query remains a pattern TP, not a FP.
        documentation = next(row for row in summary["scenario_results"] if row["scenario_id"] == "detect1_d06_document_query")
        assert documentation["detected"] and documentation["behavioral_pattern"] == "PATTERN_PRESENT"
        assert not any(row.get("finding") == "DETECTOR_FALSE_POSITIVE" and row["scenario_id"] == documentation["scenario_id"] for row in summary["scenario_results"])
        assert len(summary["parser_contributions"]) == 1
        assert sum(row.get("metric_disposition") == "LABEL_UNDETERMINED" for row in summary["scenario_results"]) == 2
        rendered = json.dumps(summary) + accuracy.render_text(summary)
        for row in rows:
            assert row["subject"] not in rendered
            target = json.loads((ROOT / (row["id"] + ".jsonl")).read_text())["original_target"]
            assert target not in rendered
        assert "SYNTHETIC_UNMAPPED_DETECT1_CANARY" not in rendered
        assert str(ROOT) not in rendered


def _common_facts(event):
    # Protocol/size/raw differ legitimately. Compare all shared event facts
    # before comparing detectors; no URL decoding or oracle from detector output.
    return (event.timestamp, event.event_type, event.source, event.src_ip, event.user,
            event.dst_ip, event.application, event.user_agent, event.authentication,
            event.http.method, event.http.path, event.http.query, event.http.status_code)


SCENARIO_IDS = tuple(row["id"] for row in json.loads((ROOT / "manifest.json").read_text())["scenarios"])


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_ncsa_and_approved_mapping_preserve_the_same_findings(frozen, scenario_id):
    freeze, rows = frozen
    row = next(item for item in rows if item["id"] == scenario_id)
    sources = [{"source": "access", "path": str(ROOT / row["fixture"])}]
    json_path = ROOT / (scenario_id + ".jsonl")
    text = json_path.read_text(encoding="utf-8")
    if freeze["expected_parser_dispositions"][scenario_id] == "PARSER_REJECTED":
        assert accuracy._parse_disposition(row, ROOT / row["fixture"])[0] == "PARSER_REJECTED"
        with pytest.raises(MappingInputError):
            normalize_mapped_access(text, MAPPING)
        return
    original_events = load_normalized_logs(sources)
    mapped_events = normalize_mapped_access(text, MAPPING)
    assert len(original_events) == len(mapped_events) == 1
    assert [_common_facts(event) for event in original_events] == [_common_facts(event) for event in mapped_events]
    assert mapped_events[0].protocol is None and mapped_events[0].http.response_size is None
    assert mapped_events[0].raw == ""
    original = analyze(sources)["results"][row["subject"]]
    mapped = analyze_mapped_access_file([{"source": "access", "path": str(json_path)}], mapping=MAPPING).analysis["results"][row["subject"]]
    before, after = original["detections"]["path_traversal"], mapped["detections"]["path_traversal"]
    assert before.is_detected is after.is_detected
    assert before.detection_type == after.detection_type
    # Only truly absent metadata may be omitted, never invented by the mapping.
    assert [item for item in before.evidence if item.type != "http_response_size"] == after.evidence
    assert original["risk_level"] == mapped["risk_level"]
    assert original["correlation"] == mapped["correlation"]


def test_mapping_metric_uses_the_same_frozen_labels_and_existing_confusion(frozen):
    freeze, rows = frozen
    confusion = accuracy.Confusion()
    rejected = unknown = 0
    for row in rows:
        path = ROOT / (row["id"] + ".jsonl")
        if freeze["expected_parser_dispositions"][row["id"]] == "PARSER_REJECTED":
            with pytest.raises(MappingInputError):
                analyze_mapped_access_file([{"source": "access", "path": str(path)}], mapping=MAPPING)
            rejected += 1
            continue
        result = analyze_mapped_access_file([{"source": "access", "path": str(path)}], mapping=MAPPING)
        actual = result.analysis["results"][row["subject"]]["detections"]["path_traversal"].is_detected
        if row["behavioral_pattern"] == "PATTERN_UNDETERMINED":
            unknown += 1
            continue
        confusion = confusion.add(row["behavioral_pattern"] == "PATTERN_PRESENT", actual)
    assert asdict(confusion) == {"tp": 3, "fp": 4, "fn": 3, "tn": 1}
    assert (unknown, rejected) == (2, 1)
    metric = accuracy._metric("path_traversal", confusion, unknown, rejected)
    assert (metric.precision, metric.recall, metric.f1) == ("0.428571", "0.500000", "0.461538")


@pytest.mark.parametrize("scenario_id,count", [("detect1_d01_named_dot_suffix", 1), ("detect1_v02_encoded_terminal_parent", 0)])
def test_scope_mismatch_reaches_current_investigation_without_privacy_expansion(frozen, scenario_id, count):
    _, rows = frozen
    row = next(item for item in rows if item["id"] == scenario_id)
    text = (ROOT / (scenario_id + ".jsonl")).read_text()
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 49213)) as client:
        response = client.post("/api/v1/investigations/json-mapping", json={
            "schema_version": 1, "confirmed": True, "mapping": MAPPING, "log_text": text,
        })
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["input_quality"]["aggregate"]["recognized_lines"] == 1
    assert result["analysis_summary"]["supported_detection_count"] == count
    assert row["subject"] not in response.text
    assert json.loads(text)["original_target"] not in response.text
    assert "SYNTHETIC_UNMAPPED_DETECT1_CANARY" not in response.text


def test_new_evidence_does_not_relabel_or_replace_original_accuracy_corpus():
    original = accuracy.evaluate()
    assert original["scenario_count"] == 46
    assert all(row["fp"] == row["fn"] == row["excluded_parser"] == 0 for row in original["metrics"])
    assert len(original["operational_false_alert_candidates"]) == 7
