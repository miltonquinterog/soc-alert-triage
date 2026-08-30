import unittest
from types import SimpleNamespace

from tests.integration.openai_windows_auth_e2e import (EXPECTED_FINDINGS, EXPECTED_SKILLS,
    INTEGRATION_MAX_ATTEMPTS, INTEGRATION_MAX_OUTPUT_TOKENS, INTEGRATION_MAX_TOTAL_SECONDS,
    INTEGRATION_TIMEOUT_SECONDS, _result_summary, build_preview)
from soc_ai_agent.reasoning.contracts import BackendMetadata
from soc_ai_agent.reasoning.openai_response_diagnostics import BackendDiagnostic


class OpenAIWindowsAuthenticationPreviewTests(unittest.TestCase):
    def test_preview_is_offline_and_matches_deterministic_pipeline(self):
        preview, events, edges, findings = build_preview()
        self.assertEqual(EXPECTED_FINDINGS, preview.finding_types)
        self.assertEqual((), preview.correlation_ids)
        self.assertEqual(EXPECTED_SKILLS, preview.skills)
        self.assertEqual(4, len(events))
        self.assertFalse(any(edge.relation_type == "direct" for edge in edges))
        self.assertEqual(2, len(findings))
        self.assertEqual(("e1", "e2", "e3", "e4"), tuple(item["alias"] for item in preview.reference_map["events"]))
        self.assertIn("event.code", preview.allowed_evidence_paths)
        self.assertEqual(("1.4", "1.2", "1.1", "1.0"), (preview.output_schema_version,
            preview.prompt_policy_version, preview.context_builder_version, preview.reference_map_version))
        self.assertEqual({"mitre_mapping": False, "ioc_assessment": False, "incident_reporting": False},
            preview.capabilities)
        self.assertNotIn("mitre_mappings", preview.effective_top_level_properties)
        self.assertNotIn("ioc_assessments", preview.effective_top_level_properties)
        self.assertNotIn("mitre_mappings", preview.effective_required)
        self.assertNotIn("ioc_assessments", preview.effective_required)
        self.assertFalse(preview.mitre_mappings_present)
        self.assertFalse(preview.ioc_assessments_present)
        self.assertGreater(preview.token_estimate, 0)
        self.assertEqual(preview.token_estimate, preview.estimated_total_input_tokens)
        self.assertGreater(preview.estimated_schema_tokens, 0)
        self.assertEqual(INTEGRATION_MAX_OUTPUT_TOKENS, preview.max_output_tokens)
        self.assertEqual((INTEGRATION_TIMEOUT_SECONDS, INTEGRATION_MAX_TOTAL_SECONDS, INTEGRATION_MAX_ATTEMPTS),
            (preview.timeout_seconds, preview.max_total_seconds, preview.max_attempts))
        self.assertEqual("Suspicious / Requires Investigation", preview.maximum_allowed_classification)

    def test_preview_is_deterministic(self):
        first, second = build_preview()[0], build_preview()[0]
        self.assertEqual(first.request_id, second.request_id)
        self.assertNotIn("raw_event", str(first.context))

    def test_terra_effort_is_capability_aware(self):
        enabled = build_preview("gpt-5.6-terra", True)[0]
        unavailable = build_preview("gpt-5.6-terra", False)[0]
        other_model = build_preview("other-model", True)[0]
        self.assertEqual("low", enabled.reasoning_effort)
        self.assertIsNone(unavailable.reasoning_effort)
        self.assertIsNone(other_model.reasoning_effort)

    def test_runner_summary_includes_only_sanitized_backend_diagnostic(self):
        diagnostic = BackendDiagnostic("response-1", "completed", None, 1, 2, 1, "model",
            ("message",), True, 12, "b" * 64, "response_schema", "$.facts[0]", "type", "string", "integer")
        metadata = BackendMetadata("openai", "1.1", "model", "local-request", "response-1", 1, 2,
            10, 0, 1, "completed", None, 1, diagnostic)
        annotation = SimpleNamespace(classification="Insufficient Evidence", priority="low", confidence="low",
            facts=(), inferences=(), hypotheses=(), missing_evidence=("backend_failure:backend_response_schema_violation",),
            recommended_actions=(), validation_status="accepted", validation_errors=(),
            reasoning_provenance=SimpleNamespace(execution_order=(), backend_metadata=metadata))
        summary = _result_summary(annotation)
        self.assertEqual("response_schema", summary["backend_diagnostic"]["failure_stage"])
        self.assertNotIn("simulated generated content", str(summary))
        self.assertNotIn("api_key=", str(summary).lower())
