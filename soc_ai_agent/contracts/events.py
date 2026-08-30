"""Contrato normalizado, sin inferencias analíticas ni modificación de evidencia."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from hashlib import sha256
import json
from typing import Any


SCHEMA_VERSION = "1.0"


def make_event_uid(dataset_name: str, line_number: int, raw_event: str) -> str:
    """ID de ingestión estable; no es una identidad lógica ni un fingerprint."""
    material = {
        "namespace": "soc-ai-agent:event-uid:v1",
        "dataset_name": dataset_name,
        "line_number": line_number,
        "raw_event_sha256": sha256(raw_event.encode("utf-8")).hexdigest(),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def _omit_missing(value: Any) -> Any:
    if is_dataclass(value):
        return _omit_missing(asdict(value))
    if isinstance(value, dict):
        return {key: _omit_missing(item) for key, item in value.items()
                if item is not None and item != "" and _omit_missing(item) not in ({}, [])}
    if isinstance(value, (list, tuple)):
        return [_omit_missing(item) for item in value if item is not None and _omit_missing(item) not in ({}, [])]
    return value


@dataclass(frozen=True)
class DatasetRef:
    name: str
    format: str
    line_number: int


@dataclass(frozen=True)
class SourceInfo:
    platform: str
    provider: str | None = None
    channel: str | None = None
    source: str | None = None
    sourcetype: str | None = None
    collector: str | None = None


@dataclass(frozen=True)
class TimeInfo:
    event_time: str | None = None
    event_time_raw: str | None = None
    observed_time: str | None = None
    observed_time_raw: str | None = None
    timezone_status: str | None = None


@dataclass(frozen=True)
class EventInfo:
    code: str | None = None
    event_type: str | None = None
    task_category: str | None = None
    outcome: str | None = None


@dataclass(frozen=True)
class HostInfo:
    name: str | None = None
    fqdn: str | None = None


@dataclass(frozen=True)
class Identity:
    role: str
    name: str | None = None
    domain: str | None = None
    sid: str | None = None
    uid: str | None = None
    logon_id: str | None = None
    logon_guid: str | None = None
    source_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcessInfo:
    image: str | None = None
    command_line: str | None = None
    process_guid: str | None = None
    process_id: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: str | None = None
    current_directory: str | None = None
    integrity_level: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkInfo:
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    initiated: bool | None = None


@dataclass(frozen=True)
class CorrelationInfo:
    logon_id: str | None = None
    logon_guid: str | None = None
    process_guid: str | None = None
    process_id: str | None = None
    parent_process_guid: str | None = None
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None


@dataclass(frozen=True)
class DataQuality:
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class NormalizedEvent:
    schema_version: str
    event_uid: str
    dataset: DatasetRef
    raw_event: str
    raw_payload: str | None
    source: SourceInfo
    time: TimeInfo
    event: EventInfo
    host: HostInfo | None
    identities: tuple[Identity, ...]
    process: ProcessInfo | None
    network: NetworkInfo | None
    correlation: CorrelationInfo
    data_quality: DataQuality

    def to_dict(self) -> dict[str, Any]:
        """Representación apta para exportación que omite campos ausentes."""
        return _omit_missing(self)
