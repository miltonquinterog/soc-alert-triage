from __future__ import annotations

from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, EventInfo,
    HostInfo, Identity, NetworkInfo, NormalizedEvent, ProcessInfo, SCHEMA_VERSION,
    SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.ingestion.jsonl import RawJsonRecord
from .base import Normalizer
from .common import optional_int, parse_hashes, payload_of, scalar, split_user, utc_time, valid_ip


def _base(record: RawJsonRecord, data: dict, warnings: list[str], event_type: str):
    host_name = scalar(data.get("ComputerName") or data.get("host"), warnings, "ComputerName")
    name, domain = split_user(data.get("User"), warnings, "User")
    identity = Identity(role="process_user", name=name, domain=domain,
                        sid=scalar(data.get("Sid"), warnings, "Sid"),
                        source_fields=("User", "Sid")) if name or domain else None
    utc = utc_time(data.get("UtcTime"), warnings)
    return host_name, identity, utc, NormalizedEvent(
        schema_version=SCHEMA_VERSION,
        event_uid=make_event_uid(record.dataset.name, record.dataset.line_number, record.raw_event),
        dataset=record.dataset, raw_event=record.raw_event,
        raw_payload=data.get("_raw") if isinstance(data.get("_raw"), str) else None,
        source=SourceInfo(platform="windows", provider=data.get("SourceName"), channel=data.get("LogName"),
                          source=data.get("source"), sourcetype=data.get("sourcetype"), collector=data.get("splunk_server")),
        time=TimeInfo(event_time=utc, event_time_raw=utc,
                      observed_time=scalar(data.get("_time"), warnings, "_time"),
                      observed_time_raw=scalar(data.get("_time"), warnings, "_time"),
                      timezone_status="utc" if utc else None),
        event=EventInfo(code=scalar(data.get("EventCode"), warnings, "EventCode"), event_type=event_type,
                        task_category=scalar(data.get("TaskCategory"), warnings, "TaskCategory")),
        host=HostInfo(name=host_name, fqdn=host_name) if host_name else None,
        identities=(identity,) if identity else (), process=None, network=None,
        correlation=CorrelationInfo(host=host_name, user=name), data_quality=DataQuality(),
    )


class SysmonEvent1Normalizer(Normalizer):
    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        data = payload_of(record.parsed); warnings: list[str] = []
        host, identity, _utc, base = _base(record, data, warnings, "process_create")
        process_guid = scalar(data.get("ProcessGuid"), warnings, "ProcessGuid")
        process_id = scalar(data.get("ProcessId"), warnings, "ProcessId")
        logon_id = scalar(data.get("LogonId"), warnings, "LogonId")
        logon_guid = scalar(data.get("LogonGuid"), warnings, "LogonGuid")
        process = ProcessInfo(image=scalar(data.get("Image"), warnings, "Image"),
            command_line=scalar(data.get("CommandLine"), warnings, "CommandLine"), process_guid=process_guid,
            process_id=process_id, parent_image=scalar(data.get("ParentImage"), warnings, "ParentImage"),
            parent_command_line=scalar(data.get("ParentCommandLine"), warnings, "ParentCommandLine"),
            parent_process_guid=scalar(data.get("ParentProcessGuid"), warnings, "ParentProcessGuid"),
            parent_process_id=scalar(data.get("ParentProcessId"), warnings, "ParentProcessId"),
            current_directory=scalar(data.get("CurrentDirectory"), warnings, "CurrentDirectory"),
            integrity_level=scalar(data.get("IntegrityLevel"), warnings, "IntegrityLevel"), hashes=parse_hashes(data.get("Hashes"), warnings))
        return base.__class__(**{**base.__dict__, "process": process,
            "correlation": CorrelationInfo(logon_id=logon_id, logon_guid=logon_guid, process_guid=process_guid,
                process_id=process_id, parent_process_guid=process.parent_process_guid, host=host,
                user=identity.name if identity else None), "data_quality": DataQuality(tuple(dict.fromkeys(warnings)))})


class SysmonEvent3Normalizer(Normalizer):
    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        data = payload_of(record.parsed); warnings: list[str] = []
        host, identity, _utc, base = _base(record, data, warnings, "network_connection")
        process_guid = scalar(data.get("ProcessGuid"), warnings, "ProcessGuid")
        process_id = scalar(data.get("ProcessId"), warnings, "ProcessId")
        source_ip = valid_ip(data.get("SourceIp"), warnings, "SourceIp")
        destination_ip = valid_ip(data.get("DestinationIp"), warnings, "DestinationIp")
        initiated_text = scalar(data.get("Initiated"), warnings, "Initiated")
        initiated = {"true": True, "false": False}.get(initiated_text.lower()) if initiated_text else None
        if initiated_text and initiated is None: warnings.append("invalid_boolean:Initiated")
        network = NetworkInfo(source_ip=source_ip, source_port=optional_int(data.get("SourcePort"), warnings, "SourcePort"),
            destination_ip=destination_ip, destination_port=optional_int(data.get("DestinationPort"), warnings, "DestinationPort"),
            protocol=scalar(data.get("Protocol"), warnings, "Protocol"), initiated=initiated)
        process = ProcessInfo(image=scalar(data.get("Image"), warnings, "Image"), process_guid=process_guid, process_id=process_id)
        return base.__class__(**{**base.__dict__, "process": process, "network": network,
            "correlation": CorrelationInfo(process_guid=process_guid, process_id=process_id, host=host,
                user=identity.name if identity else None, source_ip=source_ip, destination_ip=destination_ip),
            "data_quality": DataQuality(tuple(dict.fromkeys(warnings)))})
