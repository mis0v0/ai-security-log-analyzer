"""Post-merge regression: synthetic batch records, no raw values in failures."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
from pathlib import Path

import pytest

from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.report_projection import build_investigation_report_projection
from app.analyzer.html_report import render_investigation_report_html
from app.main import analyze


COMPACT = "2001:db8::47"
EXPANDED = "2001:0DB8:0000:0000:0000:0000:0000:0047"
EPOCH = datetime(2026, 11, 17, tzinfo=timezone.utc)


def audit_line(address, *, record="USER_AUTH", outcome="failed", serial=101, second=0):
    epoch = int(EPOCH.timestamp()) + second
    return (f"node=synthetic-node type={record} msg=audit({epoch}.000:{serial}): "
            f"pid=4101 uid=0 auid=1000 ses=7 msg='op=PAM:authentication "
            f'acct="synthetic_hotfix_a" exe="/usr/sbin/sshd" '
            f"hostname=synthetic-host addr={address} terminal=ssh res={outcome}'")


def sources(tmp_path, *, general_ip=COMPACT, audit_ip=EXPANDED, role="application", reverse=False):
    general = tmp_path / "general.log"
    rows = []
    for i, user in enumerate("abca"):
        stamp = EPOCH + timedelta(hours=9, seconds=i*7)
        if role == "application":
            rows.append(f"{stamp:%Y-%m-%d %H:%M:%S} INFO login_failed user=synthetic_hotfix_{user} ip={general_ip}")
        else:
            rows.append(f"{stamp:%Y-%m-%d %H:%M:%S} sshd: Failed password for synthetic_hotfix_{user} from {general_ip} port 4242 ssh2")
    general.write_text("\n".join(reversed(rows) if reverse else rows)+"\n", encoding="utf-8")
    audit = tmp_path / "audit.log"
    audit.write_text(audit_line(audit_ip)+"\n", encoding="utf-8")
    configs = [{"source":role,"path":str(general)},
               {"source":"linux_audit","path":str(audit),"source_instance":"synthetic-hotfix-source"}]
    return configs


def assert_report_privacy(text):
    if any(value in text for value in (COMPACT, EXPANDED, "synthetic_hotfix_", "synthetic-hotfix-source", "msg=audit(", "op=PAM:")):
        pytest.fail("private input entered public report", pytrace=False)


def test_actual_user_auth_type_is_not_general_login_failure(tmp_path):
    from app.loader.linux_audit_loader import load_linux_audit_events
    from app.parser.linux_audit import parse_linux_audit_events
    config = sources(tmp_path)[1]
    groups = load_linux_audit_events(config["path"], source_instance=config["source_instance"])
    event, = parse_linux_audit_events(groups[0])
    if (event.event_type, event.authentication.outcome, event.linux_audit.record_types) != (
            "authentication_attempt", "failure", ("USER_AUTH",)):
        pytest.fail("USER_AUTH parser semantics differ from expected contract", pytrace=False)


@pytest.mark.parametrize("role", ("application", "ssh"))
def test_mixed_batch_is_one_subject_with_four_general_failures(tmp_path, role):
    configs = sources(tmp_path, role=role)
    events = load_normalized_logs(configs)
    if len(events) != 5 or {event.src_ip for event in events} != {COMPACT}:
        pytest.fail("same numeric address was split or records were lost", pytrace=False)
    audit_events = [e for e in events if e.source == "linux_audit"]
    if len(audit_events) != 1 or audit_events[0].event_type != "authentication_attempt":
        pytest.fail("Linux Audit record was lost or reinterpreted", pytrace=False)
    result = analyze(configs)
    if set(result["results"]) != {COMPACT}:
        pytest.fail("result subjects do not match numeric IP identity", pytrace=False)
    subject = result["results"][COMPACT]
    facts = subject["features"]
    if (facts["failure_count"], facts["unique_target_count"], facts["window_seconds"]) != (4, 3, 21):
        pytest.fail("Audit outcome was promoted into general failure features", pytrace=False)
    if (not subject["detections"]["password_spray"].is_detected
            or subject["detections"]["brute_force"].is_detected):
        pytest.fail("existing 4/3/60 observation changed", pytrace=False)


def test_mixed_html_projection_succeeds_without_private_values(tmp_path):
    projection = build_investigation_report_projection(analyze(sources(tmp_path)))
    html = render_investigation_report_html(projection)
    if projection.summary.analyzed_subject_count != 1:
        pytest.fail("report subject count differs from batch", pytrace=False)
    assert_report_privacy(html)


def test_mixed_cli_creates_html_and_exits_successfully(tmp_path, monkeypatch, capsys):
    main = importlib.import_module("app.main")
    configs = sources(tmp_path)
    monkeypatch.setattr(main, "LOG_SOURCES", configs[:1])
    output = tmp_path / "report.html"
    try:
        main.main(["--linux-audit", configs[1]["path"], "--html-report", str(output)])
    except SystemExit:
        pytest.fail("supported mixed CLI failed report generation", pytrace=False)
    captured = capsys.readouterr()
    if not output.is_file() or captured.err:
        pytest.fail("CLI did not produce a successful report", pytrace=False)
    assert_report_privacy(output.read_text())
    # Existing trusted CLI subject headers display validated IPs; evidence must
    # not add raw records, accounts or source-instance identifiers.
    if any(v in captured.out for v in ("synthetic_hotfix_", "msg=audit(", "op=PAM:")):
        pytest.fail("CLI evidence leaked private records", pytrace=False)


def test_linux_audit_standalone_keeps_records_and_does_not_invent_login_failures(tmp_path):
    configs = sources(tmp_path)[1:]
    path = Path(configs[0]["path"])
    path.write_text(audit_line(COMPACT)+"\n"+audit_line(EXPANDED,serial=102,second=1)+"\n")
    events = load_normalized_logs(configs)
    if len(events) != 2 or {e.src_ip for e in events} != {COMPACT}:
        pytest.fail("Audit-only source did not use common normalization",pytrace=False)
    if len({e.linux_audit.event_id for e in events}) != 2:
        pytest.fail("Audit record identities were lost",pytrace=False)
    result = analyze(configs)
    if set(result["results"]) != {COMPACT} or result["results"][COMPACT]["features"]["failure_count"] != 0:
        pytest.fail("Audit-only outcome was reinterpreted",pytrace=False)
    assert_report_privacy(render_investigation_report_html(build_investigation_report_projection(result)))


@pytest.mark.parametrize("fixture", (
    "linux_audit_session_process_co_observation_contract_synthetic.log",
    "linux_audit_exec_success_rhel_source_derived.log",
))
def test_audit_process_session_and_raw_metadata_are_preserved(fixture):
    from app.loader.linux_audit_loader import load_linux_audit_events
    from app.parser.linux_audit import parse_linux_audit_events
    path = Path(__file__).resolve().parents[1]/"sample_logs"/fixture
    original = [event for group in load_linux_audit_events(path,source_instance="synthetic-hotfix-source")
                for event in parse_linux_audit_events(group)]
    normalized = load_normalized_logs([{"source":"linux_audit","path":str(path),"source_instance":"synthetic-hotfix-source"}])
    if len(original) != len(normalized):
        pytest.fail("typed Audit events were dropped",pytrace=False)
    for before, after in zip(original,normalized):
        # All fields other than the declared normalization values remain equal,
        # including complete ProcessExecutionContext and LinuxAuditContext.
        if replace(after,src_ip=before.src_ip,timestamp=before.timestamp) != before:
            pytest.fail("Audit process/session/raw context changed",pytrace=False)


@pytest.mark.parametrize("general_ip,audit_ip", ((COMPACT,EXPANDED),(EXPANDED,COMPACT),(EXPANDED,EXPANDED)))
def test_input_and_source_order_do_not_change_analysis(tmp_path,general_ip,audit_ip):
    reference = None
    for reverse_lines in (False,True):
        configs = sources(tmp_path,general_ip=general_ip,audit_ip=audit_ip,reverse=reverse_lines)
        for ordered in (configs,list(reversed(configs))):
            result = analyze(ordered)
            if reference is not None and result != reference:
                pytest.fail("input/source order changed analysis",pytrace=False)
            reference = result


@pytest.mark.parametrize("general_ip,audit_ip", (
    (COMPACT,"2001:db8::48"),
    ("192.0.2.247","::ffff:192.0.2.247"),
    (COMPACT+"%zone-a",COMPACT+"%zone-b"),
))
def test_different_addresses_families_and_scopes_are_not_joined(tmp_path,general_ip,audit_ip):
    result = analyze(sources(tmp_path,general_ip=general_ip,audit_ip=audit_ip))
    if len(result["results"]) != 2:
        pytest.fail("unproven address identities were joined",pytrace=False)


@pytest.mark.parametrize("value", (COMPACT,EXPANDED,"192.0.2.247","::ffff:192.0.2.247",COMPACT+"%zone",None,"invalid"))
def test_normalization_is_idempotent(value):
    from app.parser.time_utils import normalize_source_ip
    once = normalize_source_ip(value)
    if normalize_source_ip(once) != once:
        pytest.fail("normalization is not idempotent",pytrace=False)


def test_session_source_namespace_is_not_replaced_by_ip_identity(tmp_path):
    left = tmp_path/"start.log";right = tmp_path/"end.log"
    left.write_text(audit_line(COMPACT,record="USER_START",outcome="success")+"\n")
    right.write_text(audit_line(EXPANDED,record="USER_END",outcome="success",serial=102,second=1)+"\n")
    configs = [{"source":"linux_audit","path":str(left),"source_instance":"synthetic-start-source"},
               {"source":"linux_audit","path":str(right),"source_instance":"synthetic-end-source"}]
    result = analyze(configs)
    if result["global_correlation"]["linux_audit_session_lifecycle"]:
        pytest.fail("same IP bypassed independent Audit source identity",pytrace=False)
    configs[1]["source_instance"] = configs[0]["source_instance"]
    matched = analyze(configs)["global_correlation"]["linux_audit_session_lifecycle"]
    if len(matched) != 1 or "src_ip" not in matched[0]["matched_fields"]:
        pytest.fail("equivalent numeric address lost session corroboration",pytrace=False)
