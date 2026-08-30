from __future__ import annotations

import re

from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, EventInfo,
    HostInfo, Identity, NetworkInfo, NormalizedEvent, ProcessInfo, SCHEMA_VERSION,
    SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.ingestion.jsonl import RawJsonRecord
from .base import Normalizer
from .common import payload_of, scalar, valid_ip


class LinuxAuthNormalizer(Normalizer):
    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        data = payload_of(record.parsed); warnings: list[str] = []
        raw_payload = data.get("_raw") if isinstance(data.get("_raw"), str) else None
        host_name = scalar(data.get("host"), warnings, "host")
        user = scalar(data.get("user"), warnings, "user")
        uid = scalar(data.get("uid"), warnings, "uid")
        if not user and raw_payload:
            match = re.search(r"(?:session (?:opened|closed) for user|user=)([^\s]+)", raw_payload)
            user = match.group(1) if match else None
        identity = Identity(role="authenticated_user", name=user, uid=uid,
                            source_fields=("user", "uid")) if user or uid else None
        rhost = scalar(data.get("rhost"), warnings, "rhost")
        source_ip = valid_ip(rhost, warnings, "rhost") if rhost else None
        command = scalar(data.get("COMMAND"), warnings, "COMMAND")
        process = ProcessInfo(command_line=command) if command else None
        network = NetworkInfo(source_ip=source_ip) if source_ip else None
        return NormalizedEvent(
            schema_version=SCHEMA_VERSION,
            event_uid=make_event_uid(record.dataset.name, record.dataset.line_number, record.raw_event),
            dataset=record.dataset, raw_event=record.raw_event, raw_payload=raw_payload,
            source=SourceInfo(platform="linux", provider="Linux authentication", source=data.get("source"),
                              sourcetype=data.get("sourcetype"), collector=data.get("splunk_server")),
            time=TimeInfo(observed_time=scalar(data.get("_time"), warnings, "_time"),
                          observed_time_raw=scalar(data.get("_time"), warnings, "_time"),
                          timezone_status="ambiguous_source_time"),
            event=EventInfo(event_type="authentication"), host=HostInfo(name=host_name) if host_name else None,
            identities=(identity,) if identity else (), process=process, network=network,
            correlation=CorrelationInfo(host=host_name, user=user, source_ip=source_ip),
            data_quality=DataQuality(tuple(dict.fromkeys(warnings))),
        )
