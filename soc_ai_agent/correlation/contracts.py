"""Contratos inmutables para relaciones, independientes de NormalizedEvent."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Literal


CORRELATION_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class MatchedKey:
    field: str
    value: str
    source_path: str
    destination_path: str


@dataclass(frozen=True)
class TimeWindow:
    source_time: str
    destination_time: str
    delta_seconds: float
    policy_name: str
    quality: Literal["sufficient"] = "sufficient"


@dataclass(frozen=True)
class CorrelationEvidence:
    source_event_type: str | None
    destination_event_type: str | None
    source_platform: str
    destination_platform: str
    matched_field_count: int
    temporal_basis: Literal["not_required", "event_time"]


def make_correlation_id(source_event_uid: str, destination_event_uid: str, relation_name: str,
                        matching_keys: tuple[MatchedKey, ...]) -> str:
    material = {
        "namespace": "soc-ai-agent:correlation-edge:v1",
        "source_event_uid": source_event_uid,
        "destination_event_uid": destination_event_uid,
        "relation_name": relation_name,
        "matching_keys": [key.__dict__ for key in matching_keys],
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CorrelationEdge:
    schema_version: str
    correlation_id: str
    source_event_uid: str
    destination_event_uid: str
    relation_type: Literal["direct", "supported", "temporal_only"]
    relation_name: str
    strength: Literal["strong", "moderate", "weak"]
    matching_keys: tuple[MatchedKey, ...]
    time_window: TimeWindow | None
    evidence: CorrelationEvidence
    warnings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationResult:
    edges: tuple[CorrelationEdge, ...]
    diagnostics: tuple[str, ...] = ()
