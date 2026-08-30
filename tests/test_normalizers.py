from pathlib import Path
import json
import unittest

from soc_ai_agent.contracts.events import DatasetRef
from soc_ai_agent.ingestion.jsonl import RawJsonRecord
from soc_ai_agent.ingestion.jsonl import read_jsonl
from soc_ai_agent.normalization.registry import default_registry
from soc_ai_agent.quality import validate_event

FIXTURES = Path(__file__).parent / "fixtures"


def normalize_fixture(name):
    record = read_jsonl(FIXTURES / name).records[0]
    return default_registry().normalize(record)


class NormalizerTests(unittest.TestCase):
    def test_windows_security(self):
        event = normalize_fixture("windows_security.jsonl")
        self.assertEqual("4624", event.event.code)
        self.assertEqual("success", event.event.outcome)
        self.assertEqual(2, len(event.identities))
        self.assertEqual("0x3E7", event.correlation.logon_id)
        self.assertIsNone(event.network)
        self.assertEqual((), validate_event(event))

    def test_sysmon_event_1(self):
        event = normalize_fixture("sysmon_event1.jsonl")
        self.assertEqual("process_create", event.event.event_type)
        self.assertEqual("9048", event.process.process_id)
        self.assertIn("sha256", event.process.hashes)
        self.assertEqual("2022-11-08 22:50:20.974", event.time.event_time)
        self.assertEqual((), validate_event(event))

    def test_sysmon_event_3_omits_placeholder(self):
        event = normalize_fixture("sysmon_event3.jsonl")
        self.assertEqual("network_connection", event.event.event_type)
        self.assertEqual("10.0.0.47", event.network.source_ip)
        self.assertEqual(443, event.network.destination_port)
        self.assertTrue(event.network.initiated)
        self.assertIsNone(event.process.command_line)
        self.assertIn("source_placeholder:User", event.data_quality.warnings)
        self.assertEqual((), validate_event(event))

    def test_linux_auth_only_maps_ip_rhost(self):
        event = normalize_fixture("linux_auth.jsonl")
        self.assertEqual("linux", event.source.platform)
        self.assertEqual("analyst", event.identities[0].name)
        self.assertEqual("192.0.2.15", event.network.source_ip)
        self.assertIsNone(event.time.event_time)
        self.assertEqual((), validate_event(event))

    def test_linux_auth_does_not_coerce_named_rhost_to_ip(self):
        raw = '{"result":{"_raw":"auth","host":"linux","rhost":"host.example","sourcetype":"linux:auth"}}'
        record = RawJsonRecord(DatasetRef("linux.jsonl", "jsonl", 1), raw, json.loads(raw))
        event = default_registry().normalize(record)
        self.assertIsNone(event.network)
        self.assertIsNone(event.correlation.source_ip)
        self.assertIn("invalid_ip:rhost", event.data_quality.warnings)

    def test_serialization_omits_missing_values(self):
        event = normalize_fixture("sysmon_event3.jsonl")
        serialized = event.to_dict()
        self.assertNotIn("command_line", serialized["process"])
        self.assertNotIn("destination_hostname", serialized.get("network", {}))
