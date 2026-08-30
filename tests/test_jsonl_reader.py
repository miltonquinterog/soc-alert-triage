from pathlib import Path
import unittest

from soc_ai_agent.ingestion.jsonl import read_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


class JsonlReaderTests(unittest.TestCase):
    def test_keeps_evidence_and_quarantines_bad_json(self):
        result = read_jsonl(FIXTURES / "malformed.jsonl")
        self.assertEqual(1, len(result.records))
        self.assertEqual(1, len(result.quarantine))
        self.assertEqual(2, result.quarantine[0].line_number)
        self.assertEqual('{"preview":false,"result":', result.quarantine[0].raw_event)
        self.assertIn("JSONDecodeError", result.quarantine[0].parse_error)

    def test_only_line_delimiter_is_removed(self):
        result = read_jsonl(FIXTURES / "windows_security.jsonl")
        self.assertFalse(result.records[0].raw_event.endswith("\n"))
        self.assertIn('"_raw":"11/08/2022 10:00:00 AM\\n', result.records[0].raw_event)
