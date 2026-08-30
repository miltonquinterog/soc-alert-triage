from pathlib import Path
import unittest

from soc_ai_agent.ingestion.jsonl import read_jsonl
from soc_ai_agent.normalization.registry import default_registry
from soc_ai_agent.quality import validate_event


class QualityTests(unittest.TestCase):
    def test_detects_tampered_event_uid(self):
        fixture = Path(__file__).parent / "fixtures" / "linux_auth.jsonl"
        event = default_registry().normalize(read_jsonl(fixture).records[0])
        tampered = event.__class__(**{**event.__dict__, "event_uid": "not-a-valid-uid"})
        self.assertIn("event_uid_not_reproducible", validate_event(tampered))
