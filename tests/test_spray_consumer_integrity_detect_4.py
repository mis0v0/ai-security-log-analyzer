"""Reuse frozen R4A inputs at actual Production consumer boundaries.

These protect truthful presentation of the existing gated pair selector, not
approval of C1/C2/C3, a completion anchor, malicious intent or exploit success.
"""

from datetime import timedelta
import json

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.report import print_correlation_result, print_risk_result
from app.analyzer.report_projection import build_investigation_report_projection
from app.analyzer.html_report import render_investigation_report_html
from app.evaluation.spray_correlation_semantics import CORPUS_ROOT, load_scenarios
from app.main import analyze_with_source_role_snapshot


OBSERVATION = "Password Spraying-like 탐지 IP에서 같은 계정 문자열의 인증 실패 후 로그인 성공이 관찰됨"
LIMITATION = "이 관계는 성공이 다중 계정 실패 패턴 완성 이후에 발생했음을 보장하지 않음"
DISPLAY = "Password Spraying-like IP: Failed Login → Successful Login"
OLD_CLAIM = "Password Spraying-like 탐지 이후 동일 계정의 로그인 성공이 확인됨"


def configs(ident):
    row = next(row for row in load_scenarios() if row["id"] == ident)
    return [{"source": f["source"], "path": str(CORPUS_ROOT / f["path"])}
            for f in row["fixtures"]]


def subject(bound):
    return next(iter(bound.analysis["results"].values()))


@pytest.mark.parametrize("ident,failure,success", (
    ("same_account_success_before_completion", 0, 12),
    ("success_at_window_end", 0, 15),
    ("same_account_success_after_completion", 15, 25),
))
def test_actual_pair_preserves_endpoints_without_claiming_pattern_then_success(ident, failure, success):
    sources = configs(ident)
    events = load_normalized_logs(sources)
    base = min(event.timestamp for event in events)
    result = subject(analyze_with_source_role_snapshot(sources))
    relation = result["correlation"]["password_spray_to_success"]
    assert result["detections"]["password_spray"].is_detected
    assert not result["detections"]["brute_force"].is_detected
    assert relation["is_correlated"]
    assert relation["failure_timestamp"] == base + timedelta(seconds=failure)
    assert relation["success_timestamp"] == base + timedelta(seconds=success)
    if (OBSERVATION not in relation["rationale"]
            or LIMITATION not in relation["rationale"]
            or any("탐지 이후" in text for text in relation["rationale"])):
        pytest.fail("correlation overstates its observed temporal relationship", pytrace=False)


def test_actual_risk_and_html_preserve_the_pair_evidence_boundary():
    bound = analyze_with_source_role_snapshot(configs("same_account_success_before_completion"))
    result = subject(bound)
    assert result["features"]["failure_count"] == 4
    assert result["features"]["unique_target_count"] == 4
    for dimension in ("likelihood", "confidence"):
        assessment = result["risk_factors"][dimension]
        assert assessment["level"] == "HIGH"  # Existing heuristic, not attack probability.
        text = "\n".join(assessment["rationale"])
        assert OBSERVATION in text
        assert LIMITATION in text
        assert OLD_CLAIM not in assessment["rationale"]
    projection = build_investigation_report_projection(bound.analysis)
    assert all(item.correlation_type != "password_spray_to_successful_login"
               for item in projection.subjects[0].correlations)
    html = render_investigation_report_html(projection)
    assert OBSERVATION in html and LIMITATION in html and OLD_CLAIM not in html


def test_case_keeps_generic_transition_and_spray_no_go_with_truthful_display():
    bound = analyze_with_source_role_snapshot(configs("same_account_success_before_completion"))
    projection = project_investigation_cases_from_analysis(bound)
    assert [case.rule_code for case in projection.cases] == ["CASE-AUTH-TRANSITION-01"]
    assert {item.display_type for item in projection.independent_observations} == {
        "Password Spraying-like", DISPLAY,
    }
    assert any(notice.notice_id == "spray_case_no_go" for notice in projection.notices)


def test_local_text_api_and_downloaded_html_are_bounded_and_private():
    sources = configs("same_account_success_before_completion")
    text = (CORPUS_ROOT / next(row for row in load_scenarios()
                              if row["id"] == "same_account_success_before_completion")["fixture"]).read_text()
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 42017)) as client:
        response = client.post("/api/v1/investigations/text", json={
            "schema_version": 1, "source": "application", "log_text": text,
        })
    if response.status_code != 200:
        pytest.fail("supported actual local analysis failed", pytrace=False)
    result = response.json()["result"]
    public = json.dumps(result, ensure_ascii=False)
    assert DISPLAY in public and OLD_CLAIM not in public
    html = result["report_export"]["html"]
    assert OBSERVATION in html and LIMITATION in html
    private = {event.src_ip for event in load_normalized_logs(sources)} | {
        event.user for event in load_normalized_logs(sources)
    }
    if any(value and value in public for value in private):
        pytest.fail("private source value entered public output", pytrace=False)


def test_cli_explains_legacy_relation_id_without_reprinting_accounts(capsys):
    sources = configs("same_account_success_before_completion")
    bound = analyze_with_source_role_snapshot(sources)
    result = subject(bound)
    print_correlation_result(result["correlation"])
    print_risk_result(result)
    public = capsys.readouterr().out
    assert LIMITATION in public and OLD_CLAIM not in public
    if any(event.user and event.user in public for event in load_normalized_logs(sources)):
        pytest.fail("CLI exposed private account data", pytrace=False)


def test_restricted_report_label_does_not_assert_post_pattern_success():
    from app.restricted_report import _build_report
    events = load_normalized_logs(configs("same_account_success_before_completion"))
    report = _build_report("application", events)
    text = json.dumps(report, ensure_ascii=False)
    assert "여러 계정 인증 실패 탐지 뒤 로그인 성공 관찰" not in text
    assert "여러 계정 실패 탐지 IP의 인증 실패 후 성공 관찰" in text


@pytest.mark.parametrize("ident", ("same_account_success_before_completion", "mixed_source_same_username"))
def test_equivalent_ipv6_mixed_audit_and_input_order_preserve_pair_and_risk(tmp_path, ident):
    original = configs(ident)
    reference = subject(analyze_with_source_role_snapshot(original))
    events = load_normalized_logs(original)
    old_ip = events[0].src_ip
    compact = "2001:db8::47"
    expanded = "2001:0DB8:0000:0000:0000:0000:0000:0047"
    variants = []
    for index, config in enumerate(original):
        path = tmp_path / f"source-{index}.log"
        rows = (CORPUS_ROOT / config["path"].split("/")[-1]).read_text().splitlines()
        path.write_text("\n".join(line.replace(old_ip, (compact, expanded)[i % 2])
                                  for i, line in enumerate(rows)) + "\n")
        variants.append({"source": config["source"], "path": str(path)})
    audit = tmp_path / "audit.log"
    epoch = int(min(e.timestamp for e in events).timestamp())
    audit.write_text(
        f"node=synthetic-node type=USER_AUTH msg=audit({epoch}.000:101): "
        "pid=4101 uid=0 auid=1000 ses=7 msg='op=PAM:authentication "
        'acct="synthetic_audit" exe="/usr/sbin/sshd" '
        f"hostname=synthetic-host addr={expanded} terminal=ssh res=failed'\n"
    )
    variants.append({"source": "linux_audit", "path": str(audit),
                     "source_instance": "synthetic-detect4-audit"})
    for reverse_lines in (False, True):
        if reverse_lines:
            for config in variants:
                from pathlib import Path
                path = Path(config["path"])
                path.write_text("\n".join(reversed(path.read_text().splitlines())) + "\n")
        for ordered in (variants, list(reversed(variants))):
            normalized = load_normalized_logs(ordered)
            if len(normalized) != len(events) + 1 or {e.src_ip for e in normalized} != {compact}:
                pytest.fail("mixed source normalization lost or split observations", pytrace=False)
            bound = analyze_with_source_role_snapshot(ordered)
            current = subject(bound)
            for key in ("features", "detections", "correlation", "risk_factors", "risk_level"):
                if current[key] != reference[key]:
                    pytest.fail("equivalent source identity/order changed consumer facts", pytrace=False)
            cases = project_investigation_cases_from_analysis(bound)
            assert all(c.rule_code != "CASE-SPRAY-SUCCESS-01" for c in cases.cases)
            html = render_investigation_report_html(build_investigation_report_projection(bound.analysis))
            assert LIMITATION in html
            if any(value in html for value in (compact, expanded, "synthetic_audit", "synthetic-detect4-audit")):
                pytest.fail("mixed source private context entered report", pytrace=False)


def test_spray_only_already_has_high_likelihood_without_forcing_a_gate(tmp_path):
    sources = configs("same_account_success_before_completion")
    rows = (CORPUS_ROOT / sources[0]["path"].split("/")[-1]).read_text().splitlines()
    path = tmp_path / "failures-only.log"
    path.write_text("\n".join(row for row in rows if " user_login " not in row) + "\n")
    result = subject(analyze_with_source_role_snapshot([{"source": "application", "path": str(path)}]))
    assert result["detections"]["password_spray"].is_detected
    assert not result["correlation"]["password_spray_to_success"]["is_correlated"]
    assert result["risk_factors"]["likelihood"]["level"] == "HIGH"
    assert result["risk_factors"]["confidence"]["level"] == "MEDIUM"
