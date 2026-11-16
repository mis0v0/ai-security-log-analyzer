"""Narrow user-approved adapter. No field aliases, user transforms or format inference."""

from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import re
import unicodedata

from pydantic import ValidationError

from app.input_quality_36_12a import (
    InputQualityReasonCounts, InputQualitySummary, aggregate_input_quality,
)
from app.models.json_access_mapping import JsonAccessFieldMapping, JsonAccessMappingRequest
from app.models.schemas import HttpContext, NormalizedEvent
from app.parser.time_utils import normalize_source_ip


_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEX = frozenset("0123456789abcdefABCDEF")


class MappingInputError(ValueError):
    def __init__(self, code="PARSER_INCOMPATIBLE"):
        self.code = code
        super().__init__("JSON access mapping input is invalid.")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.") from None
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("Nonfinite JSON constant.") from None


def _json(value):
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant)


def _safe_string(value):
    return type(value) is str and not any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value
    )


def _mapping(mapping):
    try:
        validated = JsonAccessFieldMapping.model_validate(mapping)
    except (ValidationError, ValueError, TypeError):
        raise MappingInputError("INVALID_SCHEMA") from None
    keys = validated.model_dump()
    if len(set(keys.values())) != 5 or any(
        not _safe_string(key) or not key or len(key.encode("utf-8")) > 2048
        for key in keys.values()
    ):
        raise MappingInputError("INVALID_SCHEMA") from None
    return validated


def parse_mapping_request(raw):
    try:
        value = _json(raw.decode("utf-8", "strict"))
    except UnicodeError:
        raise MappingInputError("INVALID_UTF8") from None
    except (ValueError, RecursionError):
        raise MappingInputError("INVALID_JSON") from None
    if (type(value) is not dict
            or set(value) != {"schema_version", "confirmed", "mapping", "log_text"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["confirmed"] is not True):
        raise MappingInputError("INVALID_SCHEMA") from None
    try:
        request = JsonAccessMappingRequest.model_validate(value)
    except ValidationError:
        raise MappingInputError("INVALID_SCHEMA") from None
    _mapping(request.mapping)
    return request


def _timestamp(value):
    if _TIMESTAMP.fullmatch(value) is None or value.endswith("-00:00"):
        raise MappingInputError()
    if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise MappingInputError()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise MappingInputError() from None


def normalize_mapped_access(text, mapping):
    """Validate the entire sample before returning any normalized events."""
    fields = _mapping(mapping).model_dump()
    if type(text) is not str:
        raise MappingInputError("INVALID_SCHEMA")
    try:
        raw = text.encode("utf-8", "strict")
    except UnicodeError:
        raise MappingInputError("INVALID_UTF8") from None
    if len(raw) > 32 * 1024:
        raise MappingInputError("TEXT_TOO_LARGE")
    if not text.strip():
        raise MappingInputError("EMPTY_INPUT")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} and char not in "\r\n\t" for char in text) or "\r" in text.replace("\r\n", ""):
        raise MappingInputError("INVALID_TEXT")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > 512:
        raise MappingInputError("LINE_COUNT_EXCEEDED")
    events = []
    for line in lines:
        if len(line.encode("utf-8")) > 2048:
            raise MappingInputError("LINE_TOO_LONG")
        try:
            row = _json(line.removesuffix("\r"))
        except (ValueError, RecursionError):
            raise MappingInputError() from None
        if type(row) is not dict or any(
            not _safe_string(key)
            or type(value) not in {str, int, float, bool, type(None)}
            or (type(value) is str and not _safe_string(value))
            or (type(value) is float and not math.isfinite(value))
            for key, value in row.items()
        ):
            raise MappingInputError()
        if any(key not in row or row[key] is None for key in fields.values()):
            raise MappingInputError()
        selected = {meaning: row[key] for meaning, key in fields.items()}
        if any(type(selected[name]) is not str for name in ("timestamp", "source_ip", "method", "request_uri")):
            raise MappingInputError()
        timestamp = _timestamp(selected["timestamp"])
        address = selected["source_ip"]
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            raise MappingInputError() from None
        if getattr(parsed_address, "scope_id", None) is not None:
            raise MappingInputError()
        method, target, status = selected["method"], selected["request_uri"], selected["status"]
        if _METHOD.fullmatch(method) is None or type(status) is not int or not 100 <= status <= 599:
            raise MappingInputError()
        if (not target.startswith("/") or len(target) > 2048 or "#" in target
                or any(ord(char) <= 32 or ord(char) == 127 for char in target)
                or any(char == "%" and (index + 2 >= len(target) or target[index + 1] not in _HEX or target[index + 2] not in _HEX)
                       for index, char in enumerate(target))):
            raise MappingInputError()
        path, _, query = target.partition("?")
        events.append(NormalizedEvent(
            timestamp=timestamp, event_type="http_request", source="access_log",
            user=None, src_ip=normalize_source_ip(address), dst_ip=None, application=None, protocol=None,
            user_agent=None, raw="",  # Unmapped fields never enter the event.
            http=HttpContext(method=method, path=path, query=query or None,
                             status_code=status, response_size=None),
        ))
    return events


def validate_mapped_text(text, mapping):
    events = normalize_mapped_access(text, mapping)
    count = len(events)
    summary = InputQualitySummary(
        schema_version="1", source="access", total_lines=count, nonempty_lines=count,
        recognized_lines=count, unrecognized_lines=0, ignored_lines=0,
        recognition_status="complete", reason_counts=InputQualityReasonCounts(
            unsupported_format=0, invalid_timestamp=0, invalid_address=0, invalid_port=0,
            invalid_header=0, incomplete_record=0, blank_line=0, ignored_record=0, other_rejected=0,
        ), limitations=("INPUT_RECORD_RECOGNITION_ONLY", "NOT_COLLECTION_COMPLETENESS_OR_DETECTION_ACCURACY"),
    )
    return text.encode("utf-8"), aggregate_input_quality({"access": summary})


def analyze_mapped_access_file(sources, *, mapping):
    """Worker-only adapter to the same owned analysis and source-role snapshot."""
    from app.main import _analyze_normalized_logs_with_context
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot, AnalysisWithSourceRoleSnapshot

    if (type(sources) is not list or len(sources) != 1 or set(sources[0]) != {"source", "path"}
            or sources[0]["source"] != "access"):
        raise MappingInputError()
    with Path(sources[0]["path"]).open("rb") as staged:
        raw = staged.read(32 * 1024 + 1)
    if len(raw) > 32 * 1024:
        raise MappingInputError("TEXT_TOO_LARGE")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise MappingInputError("INVALID_UTF8") from None
    events = normalize_mapped_access(text, mapping)
    result, contexts, owner = _analyze_normalized_logs_with_context(events)
    roles = AnalysisSourceRoleSnapshot.from_events(result, tuple(events))
    return AnalysisWithSourceRoleSnapshot(result, roles, contexts, owner)
