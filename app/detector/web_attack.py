from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from urllib.parse import unquote
from types import MappingProxyType
import unicodedata

from app.models.schemas import Evidence, DetectionResult


_MAX_TARGET_CHARS = 2048
_MAX_DECODED_CHARS = 2048
_MAX_DECODE_PASSES = 4  # at most three changes and one fixed-point check
_MAX_SUBJECT_REQUESTS = 4096
_SCAN_REQUEST_COUNT = 6
_SCAN_DISTINCT_TARGETS = 6
_SCAN_CLIENT_ERRORS = 3
_SCAN_WINDOW_SECONDS = 60
_PATTERN_ORDER = (
    "SQLI_BOOLEAN_EXPRESSION", "SQLI_UNION_SELECT", "SQLI_COMMENT_SEQUENCE",
    "XSS_SCRIPT_ELEMENT", "XSS_EVENT_HANDLER", "XSS_SCRIPT_SCHEME",
    "SENSITIVE_ENV_FILE", "SENSITIVE_VCS_METADATA", "SENSITIVE_CONFIG_FILE",
    "WEB_SCAN_DISTINCT_TARGETS",
)
_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True, repr=False)
class _WebRequest:
    timestamp: datetime
    method: str
    status: int
    path: str = field(repr=False)
    query: str = field(repr=False)


def _bounded_decode(value: str) -> str | None:
    """One contract for new web rules; legacy traversal retains its old semantics."""
    if type(value) is not str or not 0 < len(value) <= _MAX_TARGET_CHARS:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    decoded = value
    # Three percent-decoding layers at most; the fourth pass must be stable.
    for _ in range(_MAX_DECODE_PASSES):
        for index, char in enumerate(decoded):
            if char == "%" and (
                index + 2 >= len(decoded)
                or decoded[index + 1] not in _HEX
                or decoded[index + 2] not in _HEX
            ):
                return None
        try:
            next_value = unquote(decoded, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
        if len(next_value) > _MAX_DECODED_CHARS or any(
            ord(char) < 32 or ord(char) == 127 for char in next_value
        ):
            return None
        if next_value == decoded:
            return decoded.translate(_ASCII_LOWER)
        decoded = next_value
    return None


def _canonical_request(event) -> _WebRequest | None:
    if event.event_type != "http_request" or event.http is None:
        return None
    http = event.http
    if (
        type(event.timestamp) is not datetime
        or event.timestamp.tzinfo is not timezone.utc
        or type(http.method) is not str
        or re.fullmatch(r"[A-Z]{1,16}", http.method) is None
        or type(http.status_code) is not int
        or not 100 <= http.status_code <= 599
        or type(http.path) is not str
        or type(http.query) not in {str, type(None)}
        or len(http.path) + len(http.query or "") > _MAX_TARGET_CHARS
    ):
        return None
    path = _bounded_decode(http.path)
    query = _bounded_decode(http.query) if http.query else ""
    if path is None or query is None:
        return None
    return _WebRequest(event.timestamp, http.method, http.status_code, path, query)


def _pattern_matches(request: _WebRequest) -> tuple[str, ...]:
    query = request.query
    path = request.path
    found = []
    if re.search(r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+", query):
        found.append("SQLI_BOOLEAN_EXPRESSION")
    if re.search(
        r"\bunion\s+(?:all\s+)?select\s+(?:\d+\b|[a-z_][a-z0-9_]*\s*,)",
        query,
    ):
        found.append("SQLI_UNION_SELECT")
    if re.search(r"(?:'|\")\s*(?:;\s*)?(?:select|or|and)\b[^\n]{0,48}(?:--|/\*)", query):
        found.append("SQLI_COMMENT_SEQUENCE")
    if re.search(r"<script(?:\s|>)", query):
        found.append("XSS_SCRIPT_ELEMENT")
    if re.search(r"<[a-z][^>]{0,80}\s+on(?:error|load|click)\s*=", query):
        found.append("XSS_EVENT_HANDLER")
    if re.search(r"\bjavascript\s*:", query):
        found.append("XSS_SCRIPT_SCHEME")
    if re.search(r"(?:^|/)\.env(?:$|/)", path):
        found.append("SENSITIVE_ENV_FILE")
    if re.search(r"(?:^|/)\.git/(?:config|head)(?:$|/)", path):
        found.append("SENSITIVE_VCS_METADATA")
    if re.search(r"(?:^|/)[^/]{1,80}\.(?:bak|old|orig)(?:$|/)", path):
        found.append("SENSITIVE_CONFIG_FILE")
    return tuple(found)


def _web_detection(kind: str, matches: list[tuple[str, _WebRequest, int]]) -> DetectionResult:
    if not matches:
        return DetectionResult(False, None, [])
    # The current per-subject contract has one slot per type. Report the
    # earliest approved category and the count of matching request events.
    # One event may match several categories of the same type.
    matches.sort(key=lambda pair: (pair[1].timestamp, _PATTERN_ORDER.index(pair[0])))
    pattern = matches[0][0]
    first = matches[0][1].timestamp
    last = max(request.timestamp for _, request, _ in matches)
    source = "web_observation_detector"
    return DetectionResult(True, kind, [
        Evidence("pattern_id", pattern, source, time_range=(first, last)),
        Evidence("request_count", len({index for _, _, index in matches}), source),
    ])


def detect_web_observations(events) -> dict[str, DetectionResult]:
    """Return four independent, privacy-safe, per-subject observations."""
    if type(events) is not list or len(events) > _MAX_SUBJECT_REQUESTS:
        raise ValueError("Web observation input contract failed.") from None
    requests = []
    for event in events:
        request = _canonical_request(event)
        if request is None:
            continue
        # The parser has no ingestion identity: equal lines may be separate requests.
        requests.append(request)
    requests.sort(key=lambda item: (item.timestamp, item.method, item.path, item.query, item.status))
    matches = {
        "sql_injection_like": [], "xss_like": [], "sensitive_resource_probing_like": [],
    }
    for index, request in enumerate(requests):
        for pattern in _pattern_matches(request):
            if pattern.startswith("SQLI_"):
                matches["sql_injection_like"].append((pattern, request, index))
            elif pattern.startswith("XSS_"):
                matches["xss_like"].append((pattern, request, index))
            else:
                matches["sensitive_resource_probing_like"].append((pattern, request, index))
    result = {kind: _web_detection(kind, values) for kind, values in matches.items()}
    result["web_scanning_like"] = DetectionResult(False, None, [])
    for start_index, first in enumerate(requests):
        window = []
        distinct = set()
        errors = 0
        for request in requests[start_index:]:
            delta = (request.timestamp - first.timestamp).total_seconds()
            if delta > _SCAN_WINDOW_SECONDS:
                break
            window.append(request)
            distinct.add((request.path, request.query))
            errors += 400 <= request.status < 500
        if (
            len(window) >= _SCAN_REQUEST_COUNT
            and len(distinct) >= _SCAN_DISTINCT_TARGETS
            and errors >= _SCAN_CLIENT_ERRORS
        ):
            last = window[-1]
            result["web_scanning_like"] = DetectionResult(True, "web_scanning_like", [
                Evidence("pattern_id", "WEB_SCAN_DISTINCT_TARGETS", "web_observation_detector",
                         time_range=(first.timestamp, last.timestamp)),
                Evidence("request_count", len(window), "web_observation_detector"),
                Evidence("distinct_target_count", len(distinct), "web_observation_detector"),
                Evidence("client_error_count", errors, "web_observation_detector"),
                Evidence("time_window_seconds", (last.timestamp - first.timestamp).total_seconds(),
                         "web_observation_detector"),
            ])
            return result
    return result

PATH_POLICY_VERSION = "path_reference_v2"
PATH_OBSERVATION_LABELS = MappingProxyType({
    "PATH_PARENT_SEGMENT": "원문 path의 부모 구성요소",
    "DECODED_PATH_PARENT_REFERENCE": "디코딩 후 path의 부모 참조 형태",
    "BACKSLASH_PARENT_REFERENCE": "역슬래시 부모 참조형 문자열",
    "QUERY_REFERENCE_STRING": "질의 문자열의 부모 참조형 문자열",
})
_PATH_MAX_BYTES = 8192  # Project resource bound, not an HTTP/RFC limit.
_PATH_DECODE_LAYERS = 3  # Investigation heuristic, not RFC normalization.
_PARENT_COMPONENT = re.compile(r"(^|[/\\])(\.\.)([/\\]|$)")


def valid_path_evidence(pattern, kind=None):
    if type(pattern) is not str:
        return False
    if kind is None:  # Historical v1 evidence remains readable.
        return pattern in {"../", "..\\"}
    if type(kind) is not str or kind not in PATH_OBSERVATION_LABELS:
        return False
    if kind == "QUERY_REFERENCE_STRING":
        return pattern in {"../", "..\\"}
    if kind == "BACKSLASH_PARENT_REFERENCE":
        return pattern in {"../", "..\\", ".."}
    return pattern in {"../", ".."}


def _path_text(value):
    if type(value) is not str or not value:
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= _PATH_MAX_BYTES and not any(
            unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value
        )
    except UnicodeError:
        return False


def _valid_escapes(value):
    return all(char != "%" or (index + 2 < len(value)
               and value[index + 1] in _HEX and value[index + 2] in _HEX)
               for index, char in enumerate(value))


def decode_url(value):
    """Bounded traversal search view; None means unassessed, never safe/normal.

    Validate original escapes strictly. A percent produced as data (%25) is
    retained when it is not another complete escape layer. No plus conversion,
    Unicode folding, replacement characters or other web-rule policy changes.
    """
    if not _path_text(value) or not _valid_escapes(value):
        return None
    decoded = value
    for _ in range(_PATH_DECODE_LAYERS):
        if "%" not in decoded:
            return decoded
        try:
            next_decoded = unquote(decoded, encoding="utf-8", errors="strict")
        except UnicodeError:
            return None
        if not _path_text(next_decoded):
            return None
        if next_decoded == decoded:
            return decoded
        decoded = next_decoded
    if re.search(r"%[0-9A-Fa-f]{2}", decoded):
        return None  # More than three transform layers: outside this policy.
    return decoded


def is_path_traversal(path):
    return detect_path_traversal(path).is_detected


def detect_path_traversal(
    path,
    query=None,
    method=None,
    status_code=None,
    response_size=None,
    timestamp=None,
):

    decoded_path = decode_url(path)
    if decoded_path is None:
        return DetectionResult(False, None, [])

    decoded_query = None

    if query:
        decoded_query = decode_url(query)

    match = _PARENT_COMPONENT.search(path)
    kind = "PATH_PARENT_SEGMENT"
    if match is None:
        match = _PARENT_COMPONENT.search(decoded_path)
        kind = "DECODED_PATH_PARENT_REFERENCE"
    if match is not None:
        ending = match.group(3)
        path_pattern = ".." + ending
        if "\\" in (match.group(1), ending):
            kind = "BACKSLASH_PARENT_REFERENCE"
    elif decoded_query and ("../" in decoded_query or "..\\" in decoded_query):
        path_pattern = "../" if "../" in decoded_query else "..\\"
        kind = "QUERY_REFERENCE_STRING"
    else:
        return DetectionResult(False, None, [])

    source = "path_traversal_detector"
    evidence = [
        Evidence("url_decoded_path", decoded_path, source, timestamp=timestamp),
        Evidence("path_pattern", path_pattern, source, timestamp=timestamp),
    ]
    for name, value in (
        ("url_decoded_query", decoded_query or None),
        ("http_method", method or None),
        ("http_status_code", status_code),
        ("http_response_size", response_size),
    ):
        if value is not None:
            evidence.append(Evidence(name, value, source, timestamp=timestamp))
    evidence.append(Evidence("path_observation_kind", kind, source, timestamp=timestamp))
    return DetectionResult(True, "path_traversal", evidence)
