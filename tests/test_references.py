import json
from types import SimpleNamespace
import unittest

from soc_ai_agent.orchestration.validation import OutputValidator
from soc_ai_agent.reasoning.openai_response_parser import parse_openai_response
from soc_ai_agent.reasoning.openai_schema import reasoning_response_schema, validate_response_payload
from soc_ai_agent.reasoning.response_adapter import to_reasoning_draft
from soc_ai_agent.reasoning.errors import BackendResponseSchemaViolation
from soc_ai_agent.reasoning.capabilities import ReasoningCapabilities
from soc_ai_agent.reasoning.request_builder import build_request
from tests.integration.openai_windows_auth_e2e import build_preview


def payload(context, event_ref="e1", path="event.code"):
    finding_ref = context.reference_map.aliases("finding")[0]
    fact = {"statement": "An event code was observed.", "supporting_event_refs": [event_ref],
        "supporting_correlation_refs": [], "supporting_finding_refs": [finding_ref],
        "evidence_paths": [{"event_ref": event_ref, "correlation_ref": None, "finding_ref": None, "path": path}],
        "confidence": "low", "limitations": []}
    return {"facts": [fact], "inferences": [], "hypotheses": [], "conclusions": [],
        "proposed_classification": "Insufficient Evidence", "proposed_priority": "low", "confidence": "low",
        "false_positive_considerations": [],
        "missing_evidence": [], "recommended_actions": []}


class ReferenceMapTests(unittest.TestCase):
    def setUp(self):
        self.preview, _events, _edges, _findings = build_preview()
        # Rebuild through public preview to obtain the selected internal context without modifying it.
        from soc_ai_agent.orchestration.context_builder import ContextBuilder
        from soc_ai_agent.analytics.engine import AnalyticsEngine
        from soc_ai_agent.correlation.engine import CorrelationEngine
        from tests.fixtures.windows_auth_sequence_normalized import build_events
        events = build_events(); edges = CorrelationEngine().correlate(events).edges
        self.context = ContextBuilder().build(events, edges, AnalyticsEngine().analyze(events, edges).findings)

    def test_aliases_are_deterministic_and_resolve_to_original_ids(self):
        aliases = self.context.reference_map
        self.assertEqual(("e1", "e2", "e3", "e4"), aliases.aliases("event"))
        self.assertEqual(self.context.events[0]["event_uid"], aliases.resolve("event", "e1"))
        self.assertEqual(aliases, self.context.reference_map.from_context(self.context.events, self.context.correlations, self.context.findings))

    def test_schema_enums_reject_unknown_alias_and_concatenated_path(self):
        schema = reasoning_response_schema(self.context.reference_map)
        valid = payload(self.context)
        validate_response_payload(valid, schema)
        unknown = payload(self.context, "e99")
        with self.assertRaises(BackendResponseSchemaViolation) as bad_alias:
            validate_response_payload(unknown, schema)
        self.assertEqual("enum", bad_alias.exception.schema_rule)
        concatenated = payload(self.context, path="event.code; time.event_time")
        with self.assertRaises(BackendResponseSchemaViolation) as bad_path:
            validate_response_payload(concatenated, schema)
        self.assertEqual("enum", bad_path.exception.schema_rule)

    def test_round_trip_resolves_aliases_before_validator_uses_real_ids(self):
        provider_response = SimpleNamespace(status="completed", output_text=json.dumps(payload(self.context)), id="response",
            usage=SimpleNamespace(input_tokens=1, output_tokens=1), output=[])
        response = parse_openai_response(provider_response, "request", reference_map=self.context.reference_map)
        statement = response.facts[0]
        self.assertEqual((self.context.events[0]["event_uid"],), statement.supporting_event_uids)
        self.assertEqual(self.context.events[0]["event_uid"], statement.evidence_paths[0].event_uid)
        self.assertEqual((), OutputValidator().validate(to_reasoning_draft(response), self.context))

    def test_disabled_capabilities_prune_properties_and_parser_restores_empty_tuples(self):
        schema = reasoning_response_schema(self.context.reference_map, ReasoningCapabilities(False, False, False))
        self.assertNotIn("mitre_mappings", schema["properties"])
        self.assertNotIn("ioc_assessments", schema["properties"])
        self.assertNotIn("mitre_mappings", schema["required"])
        self.assertNotIn("ioc_assessments", schema["required"])
        value = payload(self.context)
        validate_response_payload(value, schema)
        value["mitre_mappings"] = [{}]
        with self.assertRaises(BackendResponseSchemaViolation) as mitre:
            validate_response_payload(value, schema)
        self.assertEqual("properties", mitre.exception.schema_rule)
        value = payload(self.context); value["ioc_assessments"] = [{}]
        with self.assertRaises(BackendResponseSchemaViolation) as ioc:
            validate_response_payload(value, schema)
        self.assertEqual("properties", ioc.exception.schema_rule)
        provider_response = SimpleNamespace(status="completed", output_text=json.dumps(payload(self.context)), id="response",
            usage=SimpleNamespace(input_tokens=1, output_tokens=1), output=[])
        response = parse_openai_response(provider_response, "request", reference_map=self.context.reference_map,
            capabilities=ReasoningCapabilities(False, False, False))
        self.assertEqual((), response.mitre_mappings)
        self.assertEqual((), response.ioc_assessments)

    def test_enabled_capabilities_allow_valid_mitre_and_ioc_objects(self):
        refs = self.context.reference_map
        event_ref, finding_ref = refs.aliases("event")[0], refs.aliases("finding")[0]
        schema = reasoning_response_schema(refs, ReasoningCapabilities(True, True, False))
        self.assertIn("mitre_mappings", schema["properties"])
        self.assertIn("ioc_assessments", schema["properties"])
        self.assertIn("mitre_mappings", schema["required"])
        self.assertIn("ioc_assessments", schema["required"])
        self.assertFalse(schema["properties"]["mitre_mappings"]["items"]["additionalProperties"])
        self.assertFalse(schema["properties"]["ioc_assessments"]["items"]["additionalProperties"])
        value = payload(self.context)
        support = {"supporting_event_refs": [event_ref], "supporting_correlation_refs": [],
            "supporting_finding_refs": [finding_ref], "limitations": []}
        value["mitre_mappings"] = [{"technique_id": None, "technique_name": None, "confidence": "low", **support}]
        value["ioc_assessments"] = [{"value": "192.0.2.15", "artifact_type": "ip", "classification": "Observed",
            "confidence": "low", **support}]
        validate_response_payload(value, schema)

    def test_each_disabled_capability_is_pruned_independently(self):
        mitre_only = reasoning_response_schema(self.context.reference_map, ReasoningCapabilities(True, False, False))
        self.assertIn("mitre_mappings", mitre_only["properties"])
        self.assertNotIn("ioc_assessments", mitre_only["properties"])
        ioc_only = reasoning_response_schema(self.context.reference_map, ReasoningCapabilities(False, True, False))
        self.assertNotIn("mitre_mappings", ioc_only["properties"])
        self.assertIn("ioc_assessments", ioc_only["properties"])

    def test_skill_router_capabilities_match_schema(self):
        request = build_request(self.context, ("windows-log-analysis", "soc-alert-triage"))
        self.assertEqual({"mitre_mapping": False, "ioc_assessment": False, "incident_reporting": False},
            request.capabilities.as_dict())
        value = payload(self.context); value["mitre_mappings"] = [{}]
        with self.assertRaises(BackendResponseSchemaViolation):
            validate_response_payload(value, reasoning_response_schema(self.context.reference_map, request.capabilities))
