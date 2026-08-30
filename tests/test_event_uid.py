import unittest

from soc_ai_agent.contracts.events import make_event_uid


class EventUidTests(unittest.TestCase):
    def test_is_deterministic_and_ingestion_scoped(self):
        first = make_event_uid("a.jsonl", 1, '{"a":1}')
        self.assertEqual(first, make_event_uid("a.jsonl", 1, '{"a":1}'))
        self.assertNotEqual(first, make_event_uid("a.jsonl", 2, '{"a":1}'))
        self.assertNotEqual(first, make_event_uid("b.jsonl", 1, '{"a":1}'))
        self.assertNotEqual(first, make_event_uid("a.jsonl", 1, '{"a":2}'))
