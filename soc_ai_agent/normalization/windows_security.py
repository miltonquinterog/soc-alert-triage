from __future__ import annotations

import re

from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, DatasetRef,
    EventInfo, HostInfo, Identity, NetworkInfo, NormalizedEvent, ProcessInfo, SCHEMA_VERSION,
    SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.ingestion.jsonl import RawJsonRecord
from .base import Normalizer
from .common import optional_int, payload_of, scalar, valid_ip


def _message_identity(message: str, heading: str, role: str, warnings: list[str]) -> Identity | None:
    section = re.search(rf"{re.escape(heading)}:\s*\r?\n(.*?)(?:\r?\n\r?\n|$)", message, re.S)
    if not section:
        return None
    values = dict(re.findall(r"\t?([^:\r\n]+):\s*\t*([^\r\n]*)", section.group(1)))
    name = scalar(values.get("Account Name"), warnings, f"{heading}.Account Name")
    domain = scalar(values.get("Account Domain"), warnings, f"{heading}.Account Domain")
    sid = scalar(values.get("Security ID"), warnings, f"{heading}.Security ID")
    logon_id = scalar(values.get("Logon ID"), warnings, f"{heading}.Logon ID")
    if not any((name, domain, sid, logon_id)):
        return None
    return Identity(role=role, name=name, domain=domain, sid=sid, logon_id=logon_id,
                    source_fields=("Message",))


class WindowsSecurityNormalizer(Normalizer):
    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        data = payload_of(record.parsed)
        warnings: list[str] = []
        message = data.get("Message") if isinstance(data.get("Message"), str) else ""
        identities = tuple(identity for identity in (
            _message_identity(message, "Subject", "subject", warnings),
            _message_identity(message, "New Logon", "new_logon", warnings),
        ) if identity is not None)
        host_name = scalar(data.get("ComputerName") or data.get("host"), warnings, "ComputerName")
        process_id = scalar(data.get("Process_ID"), warnings, "Process_ID")
        process_name = scalar(data.get("Process_Name"), warnings, "Process_Name")
        process = ProcessInfo(image=process_name, process_id=process_id) if process_name or process_id else None
        source_ip = valid_ip(data.get("Source_Network_Address"), warnings, "Source_Network_Address")
        source_port = optional_int(data.get("Source_Port"), warnings, "Source_Port")
        network = NetworkInfo(source_ip=source_ip, source_port=source_port) if source_ip or source_port is not None else None
        logon_id = next((identity.logon_id for identity in identities if identity.logon_id), None)
        outcome = {"Audit Success": "success", "Audit Failure": "failure"}.get(data.get("Keywords"))
        return NormalizedEvent(
            schema_version=SCHEMA_VERSION,
            event_uid=make_event_uid(record.dataset.name, record.dataset.line_number, record.raw_event),
            dataset=record.dataset, raw_event=record.raw_event,
            raw_payload=data.get("_raw") if isinstance(data.get("_raw"), str) else None,
            source=SourceInfo(platform="windows", provider=data.get("SourceName"), channel=data.get("LogName"),
                              source=data.get("source"), sourcetype=data.get("sourcetype"), collector=data.get("splunk_server")),
            time=TimeInfo(observed_time=scalar(data.get("_time"), warnings, "_time"),
                          observed_time_raw=scalar(data.get("_time"), warnings, "_time"),
                          timezone_status="ambiguous_source_time"),
            event=EventInfo(code=scalar(data.get("EventCode"), warnings, "EventCode"),
                            event_type=scalar(data.get("EventType"), warnings, "EventType"),
                            task_category=scalar(data.get("TaskCategory"), warnings, "TaskCategory"), outcome=outcome),
            host=HostInfo(name=host_name, fqdn=host_name) if host_name else None,
            identities=identities, process=process, network=network,
            correlation=CorrelationInfo(logon_id=logon_id, process_id=process_id, host=host_name, source_ip=source_ip,
                                        user=next((item.name for item in identities if item.name), None)),
            data_quality=DataQuality(tuple(dict.fromkeys(warnings))),
        )
