"""Test-only replay of the DETECT-1 v1 detector at b0a5dcb.
Never imported by app/. Only pinned, non-sensitive fixtures use this policy.
The original unbounded decoder is preserved as historical evidence, not enabled
for production. The source tail below is byte-identical to the baseline.
"""
from urllib.parse import unquote
from app.models.schemas import Evidence, DetectionResult

def decode_url(value):
    decoded = value

    while True:
        next_decoded = unquote(decoded)

        if next_decoded == decoded:
            break

        decoded = next_decoded

    return decoded


def is_path_traversal(path):
    decoded_path = decode_url(path)

    return (
        "../" in decoded_path
        or "..\\" in decoded_path
    )


def detect_path_traversal(
    path,
    query=None,
    method=None,
    status_code=None,
    response_size=None,
    timestamp=None,
):

    decoded_path = decode_url(path)

    decoded_query = None

    if query:
        decoded_query = decode_url(query)

    values_to_check = [
        decoded_path
    ]

    if decoded_query:
        values_to_check.append(decoded_query)

    for value in values_to_check:

        if (
            "../" not in value
            and "..\\" not in value
        ):
            continue

        if "../" in value:
            path_pattern = "../"
        else:
            path_pattern = "..\\"

        evidence = [
            Evidence(
                type="url_decoded_path",
                value=decoded_path,
                source="path_traversal_detector",
                timestamp=timestamp,
            ),
            Evidence(
                type="path_pattern",
                value=path_pattern,
                source="path_traversal_detector",
                timestamp=timestamp,
            ),
        ]

        if decoded_query:
            evidence.append(
                Evidence(
                    type="url_decoded_query",
                    value=decoded_query,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if method:
            evidence.append(
                Evidence(
                    type="http_method",
                    value=method,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if status_code is not None:
            evidence.append(
                Evidence(
                    type="http_status_code",
                    value=status_code,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if response_size is not None:
            evidence.append(
                Evidence(
                    type="http_response_size",
                    value=response_size,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        return DetectionResult(
            is_detected=True,
            detection_type="path_traversal",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )


def analyze_mapped_v1(sources, *, mapping):
    from unittest.mock import patch
    from app.json_access_mapping import analyze_mapped_access_file
    with patch("app.analyzer.pipeline.detect_path_traversal", detect_path_traversal):
        return analyze_mapped_access_file(sources, mapping=mapping)
