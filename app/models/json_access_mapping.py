"""Closed, ephemeral request for a manually approved five-field mapping."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


MAPPING_MEANINGS = ("timestamp", "source_ip", "method", "request_uri", "status")


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class JsonAccessFieldMapping(_ClosedModel):
    timestamp: StrictStr = Field(repr=False)
    source_ip: StrictStr = Field(repr=False)
    method: StrictStr = Field(repr=False)
    request_uri: StrictStr = Field(repr=False)
    status: StrictStr = Field(repr=False)


class JsonAccessMappingRequest(_ClosedModel):
    schema_version: Literal[1]
    confirmed: StrictBool
    mapping: JsonAccessFieldMapping = Field(repr=False)
    log_text: StrictStr = Field(repr=False)


JSON_ACCESS_MAPPING_OPENAPI_REQUEST = {
    "required": True,
    "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "confirmed", "mapping", "log_text"],
        "properties": {
            "schema_version": {"type": "integer", "const": 1},
            "confirmed": {"type": "boolean", "const": True},
            "mapping": {"type": "object", "additionalProperties": False,
                        "required": list(MAPPING_MEANINGS),
                        "properties": {name: {"type": "string", "minLength": 1}
                                       for name in MAPPING_MEANINGS}},
            "log_text": {"type": "string", "description": "Bounded UTF-8, flat JSON objects, one per line."},
        },
    }}},
}
