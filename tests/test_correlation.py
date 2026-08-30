from dataclasses import replace
from pathlib import Path
import unittest

from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, DatasetRef, EventInfo,
    HostInfo, NormalizedEvent, SCHEMA_VERSION, SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.correlation.engine import CorrelationEngine, CorrelationLimits
from soc_ai_agent.ingestion.jsonl import read_jsonl
from soc_ai_agent.normalization.registry import default_registry

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_event(name):
    return default_registry().normalize(read_jsonl(FIXTURES / name).records[0])


def event(uid_label, *, platform="windows", channel="Security", code="4624", event_type=None,
          host="host-a", user="user-a", source_ip="192.0.2.10", process_guid=None,
          process_id=None, logon_id=None, event_time=None, timezone_status=None):
    raw = '{"fixture":"' + uid_label + '"}'
    return NormalizedEvent(
        schema_version=SCHEMA_VERSION,
        event_uid=make_event_uid("correlation-fixture", int(uid_label[-1]) if uid_label[-1].isdigit() else 1, raw),
        dataset=DatasetRef("correlation-fixture", "jsonl", 1), raw_event=raw, raw_payload=None,
        source=SourceInfo(platform=platform, channel=channel),
        time=TimeInfo(event_time=event_time, event_time_raw=event_time, timezone_status=timezone_status),
        event=EventInfo(code=code, event_type=event_type), host=HostInfo(name=host), identities=(),
        process=None, network=None,
        correlation=CorrelationInfo(host=host, user=user, source_ip=source_ip,
            process_guid=process_guid, process_id=process_id, logon_id=logon_id),
        data_quality=DataQuality(),
    )


class CorrelationTests(unittest.TestCase):
    def test_sysmon_process_guid_is_direct_strong_with_paths(self):
        first = fixture_event("sysmon_event1.jsonl")
        second = fixture_event("sysmon_event3.jsonl")
        second = replace(second, correlation=replace(second.correlation,
            process_guid=first.correlation.process_guid))
        result = CorrelationEngine().correlate((first, second))
        edge = next(item for item in result.edges if item.relation_name == "sysmon_process_guid_link_v1")
        self.assertEqual(("direct", "strong"), (edge.relation_type, edge.strength))
        self.assertEqual("correlation.process_guid", edge.matching_keys[0].source_path)
        self.assertEqual("correlation.process_guid", edge.matching_keys[0].destination_path)

    def test_windows_logon_id_is_direct_strong(self):
        first = fixture_event("windows_security.jsonl")
        second = replace(first, event_uid="a" * 64)
        result = CorrelationEngine().correlate((first, second))
        edge = next(item for item in result.edges if item.relation_name == "windows_logon_session_v1")
        self.assertEqual("direct", edge.relation_type)
        self.assertEqual("strong", edge.strength)
        self.assertEqual({"logon_id", "host"}, {key.field for key in edge.matching_keys})

    def test_windows_auth_sequence_is_supported_when_canonical_time_exists(self):
        first = event("event1", event_time="2022-01-01T00:00:00+00:00", timezone_status="utc")
        second = event("event2", event_time="2022-01-01T00:10:00+00:00", timezone_status="utc")
        result = CorrelationEngine().correlate((first, second))
        edge = next(item for item in result.edges if item.relation_name == "windows_auth_sequence_v1")
        self.assertEqual(("supported", "moderate"), (edge.relation_type, edge.strength))
        self.assertEqual(600, edge.time_window.delta_seconds)
        self.assertEqual(3, len(edge.matching_keys))

    def test_linux_auth_sequence_is_supported(self):
        first = event("event1", platform="linux", channel=None, code=None, event_type="authentication",
            event_time="2022-01-01T00:00:00+00:00", timezone_status="utc")
        second = event("event2", platform="linux", channel=None, code=None, event_type="authentication",
            event_time="2022-01-01T00:01:00+00:00", timezone_status="utc")
        result = CorrelationEngine().correlate((first, second))
        self.assertTrue(any(item.relation_name == "linux_auth_sequence_v1" for item in result.edges))

    def test_temporal_only_is_restricted_to_useful_categories(self):
        process = event("event1", channel="Microsoft-Windows-Sysmon/Operational", code="1", event_type="process_create",
            event_time="2022-01-01T00:00:00+00:00", timezone_status="utc")
        network = event("event2", channel="Microsoft-Windows-Sysmon/Operational", code="3", event_type="network_connection",
            event_time="2022-01-01T00:02:00+00:00", timezone_status="utc")
        result = CorrelationEngine().correlate((process, network))
        edge = next(item for item in result.edges if item.relation_name == "temporal_proximity_v1")
        self.assertEqual(("temporal_only", "weak"), (edge.relation_type, edge.strength))
        self.assertIn("temporal_proximity_does_not_establish_causality", edge.limitations)

    def test_ambiguous_timestamp_rejects_supported_sequence(self):
        first = event("event1", timezone_status="ambiguous_source_time")
        second = event("event2", timezone_status="ambiguous_source_time")
        result = CorrelationEngine().correlate((first, second))
        self.assertFalse(any(item.relation_name == "windows_auth_sequence_v1" for item in result.edges))

    def test_pid_alone_is_rejected(self):
        first = event("event1", event_type="process_create", process_id="42", event_time="2022-01-01T00:00:00+00:00", timezone_status="utc")
        second = event("event2", event_type="process_create", process_id="42", event_time="2022-01-01T00:00:10+00:00", timezone_status="utc")
        result = CorrelationEngine().correlate((first, second))
        self.assertEqual((), result.edges)

    def test_group_limit_skips_large_bucket(self):
        first = event("event1", process_guid="{same}", event_type="process_create", code="1", channel="Microsoft-Windows-Sysmon/Operational")
        second = event("event2", process_guid="{same}", event_type="network_connection", code="3", channel="Microsoft-Windows-Sysmon/Operational")
        result = CorrelationEngine(CorrelationLimits(max_group_events=1)).correlate((first, second))
        self.assertFalse(result.edges)
        self.assertTrue(any(item.startswith("group_limit_exceeded") for item in result.diagnostics))
