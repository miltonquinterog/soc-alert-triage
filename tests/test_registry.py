from pathlib import Path
import json
import unittest

from soc_ai_agent.ingestion.jsonl import RawJsonRecord, read_jsonl
from soc_ai_agent.contracts.events import DatasetRef
from soc_ai_agent.normalization.registry import default_registry

FIXTURES = Path(__file__).parent / "fixtures"


class RegistryTests(unittest.TestCase):
    def test_rejects_unsupported_channel(self):
        raw = '{"result":{"LogName":"Application","EventCode":"1000"}}'
        record = RawJsonRecord(DatasetRef("application.json", "jsonl", 1), raw, json.loads(raw))
        with self.assertRaises(ValueError):
            default_registry().normalize(record)
