"""Independent synthetic whole-span proposition, not malicious intent labels.

Labels and rendered-input hashes are frozen before candidate execution. Source
address equality means equal IP literals (RFC 4291/5952), never equal actors.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json

import pytest

from app.evaluation.detector_accuracy import Confusion


V4 = "192.0.2.247"
V6 = "2001:db8::47"
EXPANDED = "2001:0DB8:0000:0000:0000:0000:0000:0047"
EPOCH = datetime(2026, 11, 16, tzinfo=timezone.utc)
# id, (microseconds, observed account label or None, outcome, address) events,
# behavioral label, operational context. No backend credentials are present.
DEVELOPMENT = (
    ("d01_four_three", ((0,"a","failure",V4),(7_000_000,"b","failure",V4),(14_000_000,"c","failure",V4),(21_000_000,"a","failure",V4)), True, "UNKNOWN"),
    ("d02_outside", ((0,"a","failure",V4),(20_000_000,"b","failure",V4),(40_000_000,"c","failure",V4),(61_000_000,"a","failure",V4)), False, "UNKNOWN"),
    ("d03_separate_windows", ((0,"a","failure",V4),(30_000_000,"a","failure",V4),(90_000_000,"b","failure",V4),(120_000_000,"c","failure",V4)), False, "UNKNOWN"),
    ("d04_one_account", tuple((i*1_000_000,"a","failure",V4) for i in range(6)), False, "UNKNOWN"),
    ("d05_two_accounts", tuple((i*1_000_000,"ab"[i%2],"failure",V4) for i in range(8)), False, "UNKNOWN"),
    ("d06_same_time", tuple((0,u,"failure",V4) for u in "abca"), True, "UNKNOWN"),
    ("d07_inclusive_60", tuple((i*20_000_000,u,"failure",V4) for i,u in enumerate("abca")), True, "UNKNOWN"),
    ("d08_missing_fourth", tuple((i*4_000_000,u,"failure",V4) for i,u in enumerate(("a","b","c",None))), True, "UNKNOWN"),
    ("d09_two_known", tuple((i*4_000_000,u,"failure",V4) for i,u in enumerate(("a","b",None,""))), False, "UNKNOWN"),
    ("d10_ipv6_spelling", tuple((i*8_000_000,u,"failure",(V6,EXPANDED)[i%2]) for i,u in enumerate("abca")), True, "UNKNOWN"),
)
FINAL_VALIDATION = (
    ("v01_microsecond_outside", ((0,"a","failure",V4),(1_000_000,"b","failure",V4),(2_000_000,"c","failure",V4),(60_000_001,"a","failure",V4)), False, "UNKNOWN"),
    ("v02_reversed", tuple(reversed(tuple((i*9_000_000,u,"failure",V4) for i,u in enumerate("abca")))), True, "UNKNOWN"),
    ("v03_nat_clients", tuple((i*3_000_000,u,"failure",V4) for i,u in enumerate("abca")), True, "KNOWN_BENIGN_NAT"),
    ("v04_approved_automation", tuple((i*3_000_000,u,"failure",V4) for i,u in enumerate("abca")), True, "KNOWN_BENIGN_AUTOMATION"),
    ("v05_invalid_user_labels", tuple((i*5_000_000,u,"failure",V4) for i,u in enumerate("abca")), True, "ACCOUNT_EXISTENCE_UNVERIFIED"),
    ("v06_outlier_whole_span", tuple((i*5_000_000,u,"failure",V4) for i,u in enumerate("abca"))+((120_000_000,None,"failure",V4),), False, "UNKNOWN"),
    ("v07_ipv6_three_spellings", tuple((i*6_000_000,u,"failure",(EXPANDED,"2001:db8:0:0::47",V6,EXPANDED)[i]) for i,u in enumerate("acba")), True, "UNKNOWN"),
    ("v08_success_interleaving", ((0,"a","failure",V4),(10_000_000,"b","failure",V4),(15_000_000,"b","success",V4),(20_000_000,"c","failure",V4),(30_000_000,"a","failure",V4),(3_600_000_000,"c","success",V4)), True, "UNKNOWN"),
)


def formats(case):
    ident, rows, _, _ = case
    if ident == "v01_microsecond_outside":
        return ("rfc5424",)
    if any(row[1] in (None, "") for row in rows):
        return ("application",)
    if ident == "v05_invalid_user_labels":
        return ("invalid_ssh",)
    return ("application", "ssh", "journal")


def render(case, profile):
    lines = []
    for offset, account, outcome, address in case[1]:
        utc = EPOCH + timedelta(microseconds=offset)
        user = None if account is None else ("" if account == "" else "synthetic_d3_"+account)
        if profile == "application":
            local = utc + timedelta(hours=9)
            line = f"{local:%Y-%m-%d %H:%M:%S} INFO {'login_failed' if outcome == 'failure' else 'user_login'} ip={address}"
            if user is not None:
                line += " user="+user
        else:
            message = f"{'Failed' if outcome == 'failure' else 'Accepted'} password for {'invalid user ' if profile == 'invalid_ssh' else ''}{user} from {address} port 4242 ssh2"
            if profile == "journal":
                line = f"{utc:%Y-%m-%dT%H:%M:%S}+0000 synthetic-host sshd[4242]: {message}"
            elif profile == "rfc5424":
                line = f"<38>1 {utc.isoformat().replace('+00:00','Z')} synthetic-host sshd 4242 - - {message}"
            else:
                local = utc + timedelta(hours=9)
                line = f"{local:%Y-%m-%d %H:%M:%S} sshd: {message}"
        lines.append(line)
    return "\n".join(lines)+"\n"


def frozen_bundle():
    cases = DEVELOPMENT + FINAL_VALIDATION
    return {"proposition": "whole-numeric-source-IP; failures>=4; observed-labels>=3; complete-span<=60; inclusive",
            "labels": cases,
            "fixtures": {case[0]+":"+profile: hashlib.sha256(render(case, profile).encode()).hexdigest()
                         for case in cases for profile in formats(case)}}


FREEZE_SHA256 = "dd8bb93d397477be2fe88b3dfefe9bd468de279c5ec74d095dd8da9a39b23263"


def test_labels_and_fixture_hashes_are_frozen():
    value = json.dumps(frozen_bundle(), sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(value).hexdigest() == FREEZE_SHA256


def run_case(tmp_path, case, profile):
    from app.analyzer.pipeline import load_normalized_logs
    from app.main import analyze
    path = tmp_path / (case[0]+"-"+profile+".log")
    path.write_text(render(case, profile), encoding="utf-8")
    sources = [{"source": "application" if profile == "application" else "ssh", "path": str(path)}]
    events = load_normalized_logs(sources)
    if len(events) != len(case[1]):
        pytest.fail("parser disposition differs from frozen expectation", pytrace=False)
    analysis = analyze(sources)
    return events, analysis


def check_case(tmp_path, case, profile):
    events, analysis = run_case(tmp_path, case, profile)
    subject = str(ipaddress.ip_address(case[1][0][3]))
    result = analysis["results"].get(subject)
    if result is None or len(analysis["results"]) != 1:
        pytest.fail("equivalent source-address spellings fragmented the cohort", pytrace=False)
    failures = [event for event in events if event.event_type == "login_failed"]
    known = {event.user for event in failures if event.user}
    start, end = min(e.timestamp for e in failures), max(e.timestamp for e in failures)
    span = (end-start).total_seconds()
    facts = result["features"]
    if (facts["failure_count"], facts["unique_target_count"], facts["window_seconds"], facts["within_window"]) != (len(failures), len(known), span, span <= 60):
        pytest.fail("feature fields refer to different event subsets", pytrace=False)
    detected = result["detections"]["password_spray"]
    if detected.is_detected is not case[2]:
        pytest.fail("frozen behavioral proposition mismatch", pytrace=False)
    if detected.is_detected:
        ev = {e.type:e for e in detected.evidence}
        if (ev["multiple_login_failures"].value, ev["multiple_target_users"].value,
            ev["failures_within_short_window"].value, ev["multiple_login_failures"].time_range) != (len(failures),len(known),span,(start,end)):
            pytest.fail("positive evidence does not support the proposition", pytrace=False)
    return events, analysis


@pytest.mark.parametrize("case", DEVELOPMENT, ids=[row[0] for row in DEVELOPMENT])
def test_development(case, tmp_path):
    for profile in formats(case):
        check_case(tmp_path, case, profile)


@pytest.mark.parametrize("profile", ("application", "ssh", "journal"))
def test_development_ipv6_api_keeps_one_subject_without_private_output(profile):
    from fastapi.testclient import TestClient
    from app.api import create_app
    case = DEVELOPMENT[-1]
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 42119)) as client:
        response = client.post("/api/v1/investigations/text", json={
            "schema_version": 1, "source": "application" if profile == "application" else "ssh",
            "log_text": render(case, profile),
        })
    if response.status_code != 200:
        pytest.fail("equivalent valid IP spellings failed public projection", pytrace=False)
    result = response.json()["result"]
    if (result["analysis_summary"]["analyzed_subject_count"], result["analysis_summary"]["supported_detection_count"]) != (1, 1):
        pytest.fail("public result fragmented or lost the observation", pytrace=False)
    if any(value in response.text for value in (V6, EXPANDED, "synthetic_d3_")):
        pytest.fail("public output contains private source values", pytrace=False)


@pytest.mark.parametrize("case", FINAL_VALIDATION, ids=[row[0] for row in FINAL_VALIDATION])
def test_final_validation(case, tmp_path):
    for profile in formats(case):
        check_case(tmp_path, case, profile)


def test_development_address_normalization_keeps_batch_live_parity_and_raw(tmp_path):
    from app.live_monitoring import LiveDetectionAccumulator, LiveTailRecord, parse_live_records
    from app.analyzer.pipeline import detect_attacks
    case = DEVELOPMENT[-1]
    for profile in formats(case):
        events, analysis = run_case(tmp_path, case, profile)
        role = "application" if profile == "application" else "ssh"
        text = render(case, profile)
        records = tuple(LiveTailRecord(role, i, line, len(line.encode())) for i,line in enumerate(text.splitlines(),1))
        parsed = parse_live_records(role, records)
        live = tuple(outcome.event for outcome in parsed.outcomes)
        if tuple(events) != live or any(event.src_ip != V6 for event in live):
            pytest.fail("batch/live address normalization differs", pytrace=False)
        if [event.raw for event in events] != text.splitlines():
            pytest.fail("normalization changed raw source records", pytrace=False)
        accumulator = LiveDetectionAccumulator(role, 16, 100000)
        proposal = accumulator.prepare(parsed)
        if proposal._detection != detect_attacks(events):
            pytest.fail("live and batch detection differ", pytrace=False)
        snapshot = accumulator.commit(proposal)
        if dict(snapshot.detected_type_counts)["password_spraying_like"] != 1:
            pytest.fail("live lost the same-address observation", pytrace=False)


def test_development_registered_access_and_mapping_share_address_normalization(tmp_path):
    from app.json_access_mapping import normalize_mapped_access
    from app.analyzer.pipeline import load_normalized_logs
    mapping = {"timestamp":"t", "source_ip":"i", "method":"m", "request_uri":"u", "status":"s"}
    rows = [{"t":EPOCH.isoformat(),"i":ip,"m":"GET","u":"/normal","s":200} for ip in (V6,EXPANDED)]
    mapped = normalize_mapped_access("\n".join(map(json.dumps,rows)),mapping)
    path = tmp_path / "access.log"
    path.write_text("\n".join(f'{row["i"]} - - [16/Nov/2026:00:00:00 +0000] "GET /normal HTTP/1.1" 200 1' for row in rows)+"\n")
    batch = load_normalized_logs([{"source":"access","path":str(path)}])
    if any(event.src_ip != V6 for event in (*mapped,*batch)):
        pytest.fail("shared input roles disagree about the same source address", pytrace=False)
    if any(event.http.path != "/normal" for event in (*mapped,*batch)):
        pytest.fail("address normalization changed unrelated observations", pytrace=False)


def test_development_timezone_views_do_not_change_the_event_cohort(tmp_path):
    from app.analyzer.pipeline import load_normalized_logs
    from app.main import analyze
    rows = DEVELOPMENT[0][1]
    lines=[]
    for (offset,user,_,ip),zone in zip(rows,(0,330,-240,540)):
        stamp=(EPOCH+timedelta(microseconds=offset)).astimezone(timezone(timedelta(minutes=zone)))
        lines.append(f'{stamp:%Y-%m-%dT%H:%M:%S%z} synthetic-host sshd[4242]: Failed password for synthetic_d3_{user} from {ip} port 4242 ssh2')
    path=tmp_path/"timezones.log";path.write_text("\n".join(lines)+"\n")
    sources=[{"source":"ssh","path":str(path)}]
    events=load_normalized_logs(sources)
    if [e.timestamp for e in events] != [EPOCH+timedelta(microseconds=r[0]) for r in rows]:
        pytest.fail("timezone interpretation changed the cohort",pytrace=False)
    result=analyze(sources)["results"][V4]
    if not result["detections"]["password_spray"].is_detected or result["features"]["window_seconds"] != 21:
        pytest.fail("timezone view changed the defined pattern",pytrace=False)


@pytest.mark.parametrize("value,expected", [
    (EXPANDED,V6), (V6,V6), (V4,V4), (None,None),
    ("host.invalid","host.invalid"), ("192.000.2.247","192.000.2.247"),
    ("2001:0DB8::0047%zone","2001:0DB8::0047%zone"),
])
def test_address_normalization_does_not_add_admission_or_identity(value, expected):
    from app.parser.time_utils import normalize_source_ip
    if normalize_source_ip(value) != expected:
        pytest.fail("normalization invented or changed address semantics",pytrace=False)


def test_numeric_address_and_family_isolation_are_preserved():
    from app.parser.time_utils import normalize_source_ip
    if normalize_source_ip(V6) == normalize_source_ip("2001:db8::48"):
        pytest.fail("different numeric addresses were joined",pytrace=False)
    if normalize_source_ip(V4) == normalize_source_ip("::ffff:"+V4):
        pytest.fail("address families were heuristically joined",pytrace=False)


def test_record_order_and_equivalent_source_profiles_do_not_change_the_observation(tmp_path):
    import itertools
    from app.analyzer.pipeline import detect_attacks
    case=DEVELOPMENT[-1]
    first_events,first_analysis=check_case(tmp_path,case,"application")
    first=first_analysis["results"][V6]
    for profile in formats(case):
        events,analysis=check_case(tmp_path,case,profile)
        common=lambda event:(event.timestamp,event.event_type,event.user,event.src_ip)
        if list(map(common,events)) != list(map(common,first_events)):
            pytest.fail("common normalized observations differ",pytrace=False)
        current=analysis["results"][V6]
        if (current["detections"],current["correlation"],current["risk_level"]) != (first["detections"],first["correlation"],first["risk_level"]):
            pytest.fail("equivalent observations changed analysis",pytrace=False)
        for order in itertools.permutations(events):
            if detect_attacks(list(order))[V6]["detections"] != first["detections"]:
                pytest.fail("event order changed detection evidence",pytrace=False)


def test_public_report_and_cli_evidence_do_not_expose_source_values(tmp_path,capsys):
    from app.api import build_analysis_response
    from app.analyzer.report_projection import build_investigation_report_projection
    from app.analyzer.html_report import render_investigation_report_html
    from app.analyzer.report import print_detection_result
    _,analysis=check_case(tmp_path,DEVELOPMENT[-1],"application")
    public=build_analysis_response(analysis,total_sources=1).model_dump_json()
    html=render_investigation_report_html(build_investigation_report_projection(analysis))
    print_detection_result(analysis["results"][V6]["detections"])
    cli=capsys.readouterr().out  # Existing CLI subject-IP header is outside this renderer.
    if any(value in text for text in (public,html,cli) for value in (V6,EXPANDED,"synthetic_d3_")):
        pytest.fail("private source values leaked",pytrace=False)


def test_malformed_authentication_record_is_rejection_not_tn():
    from app.parser.ssh_auth import parse_ssh_auth_log
    line="2026-11-16T00:00:00+0000 synthetic-host sshd[4242]: Failed password for from 192.0.2.247 port 4242 ssh2"
    with pytest.raises(ValueError,match="Malformed SSH authentication message"):
        parse_ssh_auth_log(line)
