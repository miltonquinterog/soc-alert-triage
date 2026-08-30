"""Muestra mínima, sin secretos, para la integración E2E de autenticación Windows."""

from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, DatasetRef, EventInfo, HostInfo,
    NormalizedEvent, SCHEMA_VERSION, SourceInfo, TimeInfo, make_event_uid)


def build_events():
    records = (("4625", "2022-11-08T00:00:00+00:00"), ("4625", "2022-11-08T00:03:00+00:00"),
               ("4625", "2022-11-08T00:06:00+00:00"), ("4624", "2022-11-08T00:09:00+00:00"))
    events = []
    for number, (code, timestamp) in enumerate(records, start=1):
        raw_event = f'{{"fixture":"windows-auth-sequence","record":{number}}}'
        events.append(NormalizedEvent(SCHEMA_VERSION, make_event_uid("windows_auth_sequence", number, raw_event),
            DatasetRef("windows_auth_sequence", "jsonl", number), raw_event, None,
            SourceInfo(platform="windows", provider="Microsoft-Windows-Security-Auditing", channel="Security"),
            TimeInfo(event_time=timestamp, event_time_raw=timestamp, timezone_status="utc"), EventInfo(code=code),
            HostInfo(name="host-a"), (), None, None,
            CorrelationInfo(host="host-a", user="analyst", source_ip="192.0.2.15"), DataQuality()))
    return tuple(events)
