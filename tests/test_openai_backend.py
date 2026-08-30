import json
import os
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from soc_ai_agent.orchestration.context_builder import EvidenceContext
from soc_ai_agent.reasoning.errors import (BackendMalformedResponse, BackendProviderRefusal, BackendRequestSchemaViolation,
    BackendResponseSchemaViolation, BackendSchemaViolation, BackendTimeout, BackendUnavailable)
from soc_ai_agent.reasoning.openai_backend import OpenAIReasoningBackend
from soc_ai_agent.reasoning.openai_config import OpenAIConfig, OpenAIModelCapabilities
from soc_ai_agent.reasoning.openai_prompt_builder import build_openai_payload
from soc_ai_agent.reasoning.openai_response_diagnostics import describe_response
from soc_ai_agent.reasoning.openai_schema import (reasoning_response_schema, validate_openai_structured_output_subset,
    validate_response_payload, validate_strict_schema)
from soc_ai_agent.reasoning.request_builder import build_request
from soc_ai_agent.reasoning.retry_policy import RetryPolicy
from soc_ai_agent.reasoning.token_policy import TokenPolicy


def context():
    return EvidenceContext(({"event_uid": "event-1", "event": {"code": "1"}, "process": {"command_line": "safe"}},), (),
        ({"finding_id": "finding-1", "status": "observed"},), (), (), ())


def output():
    return {"facts": [], "inferences": [], "hypotheses": [], "conclusions": [],
        "proposed_classification": "Insufficient Evidence", "proposed_priority": "low", "confidence": "low",
        "false_positive_considerations": [], "missing_evidence": [], "recommended_actions": []}


class FakeClient:
    def __init__(self, outcome): self.outcome = outcome; self.calls = []
    @property
    def responses(self): return self
    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception): raise self.outcome
        return self.outcome


def completed(payload=None):
    return SimpleNamespace(status="completed", output_text=json.dumps(payload or output()), id="resp-provider-1", _request_id="req-provider-1",
        model="test-model", usage=SimpleNamespace(input_tokens=21, output_tokens=34,
        output_tokens_details=SimpleNamespace(reasoning_tokens=13)), output=[])


class OpenAIBackendTests(unittest.TestCase):
    def setUp(self):
        self.config = OpenAIConfig("test-key", "explicit-model")
        self.request = build_request(context(), ("soc-alert-triage",))

    def test_missing_configuration_fails_explicitly(self):
        with self.assertRaises(BackendUnavailable): OpenAIConfig.from_env({"SOC_OPENAI_MODEL": "x"})
        with self.assertRaises(BackendUnavailable): OpenAIConfig.from_env({"OPENAI_API_KEY": "x"})

    def test_request_is_stateless_structured_and_tool_free(self):
        payload = build_openai_payload(self.request, self.config)
        self.assertFalse(payload["store"]); self.assertEqual("disabled", payload["truncation"])
        self.assertNotIn("tools", payload); self.assertNotIn("previous_response_id", payload)
        self.assertTrue(payload["text"]["format"]["strict"])
        self.assertNotIn("temperature", payload); self.assertNotIn("reasoning", payload)
        self.assertNotIn("raw_event", payload["input"][1]["content"][0]["text"])

    def test_sampling_is_capability_aware(self):
        config = OpenAIConfig("key", "model", temperature=0.2, reasoning_effort="low",
            capabilities=OpenAIModelCapabilities(True, True))
        payload = build_openai_payload(self.request, config)
        self.assertEqual(0.2, payload["temperature"])
        self.assertEqual("low", payload["reasoning"]["effort"])

    def test_openai_subset_rejects_compound_enum_values(self):
        with self.assertRaises(BackendRequestSchemaViolation):
            validate_openai_structured_output_subset({"type": "array", "items": {"type": "string"}, "enum": [[]]})
        with self.assertRaises(BackendRequestSchemaViolation):
            validate_openai_structured_output_subset({"type": "array", "items": {"type": "string"}, "maxItems": 0})
        with self.assertRaises(BackendRequestSchemaViolation):
            validate_openai_structured_output_subset({"type": "array", "items": {"type": "string"}, "const": []})

    def test_structured_output_parses_usage_provider_id_and_status(self):
        backend = OpenAIReasoningBackend(self.config, FakeClient(completed()))
        response = backend.reason(self.request)
        metadata = response.backend_metadata
        self.assertEqual((21, 34, "req-provider-1", "resp-provider-1", "completed"),
            (metadata.input_token_count, metadata.output_token_count, metadata.provider_request_id,
             metadata.provider_response_id, metadata.response_status))

    def test_completed_response_diagnostic_is_structural_and_hashes_output_text(self):
        provider_response = completed()
        diagnostic = describe_response(provider_response)
        self.assertEqual(("resp-provider-1", "completed", "test-model", 21, 34, 13),
            (diagnostic.response_id, diagnostic.status, diagnostic.model, diagnostic.input_tokens,
             diagnostic.output_tokens, diagnostic.reasoning_tokens))
        self.assertTrue(diagnostic.output_text_present)
        self.assertEqual(len(provider_response.output_text), diagnostic.output_text_length)
        self.assertEqual(64, len(diagnostic.output_text_sha256))
        self.assertNotIn(provider_response.output_text, repr(diagnostic))

    def test_completed_response_without_output_text_is_distinguished(self):
        missing = SimpleNamespace(status="completed", id="response-no-text", output=[], usage=None)
        with self.assertRaises(BackendMalformedResponse) as raised:
            OpenAIReasoningBackend(self.config, FakeClient(missing)).reason(self.request)
        self.assertEqual("output_text_missing", raised.exception.failure_stage)
        self.assertFalse(raised.exception.response_diagnostic.output_text_present)

    def test_incomplete_diagnostic_propagates_through_retry_metadata(self):
        incomplete = SimpleNamespace(status="incomplete", incomplete_details=SimpleNamespace(reason="max_output_tokens"),
            id="response-incomplete", model="provider-model", output=[SimpleNamespace(type="reasoning", content=[])],
            output_text=None, usage=SimpleNamespace(input_tokens=55, output_tokens=3000,
            output_tokens_details=SimpleNamespace(reasoning_tokens=2500)))
        backend = OpenAIReasoningBackend(self.config, FakeClient(incomplete))
        response, metadata, error = RetryPolicy().execute(backend, self.request, TokenPolicy())
        self.assertIsNone(response); self.assertIsInstance(error, BackendResponseSchemaViolation)
        diagnostic = error.backend_diagnostic
        self.assertEqual(("response-incomplete", "incomplete", "max_output_tokens", 55, 3000, 2500, "provider-model"),
            (diagnostic.provider_response_id, diagnostic.response_status, diagnostic.incomplete_reason,
             diagnostic.input_tokens, diagnostic.output_tokens, diagnostic.reasoning_tokens, diagnostic.response_model))
        self.assertEqual(("response-incomplete", "incomplete", 55, 3000, 2500, "provider-model"),
            (metadata.provider_response_id, metadata.response_status, metadata.input_token_count,
             metadata.output_token_count, metadata.reasoning_token_count, metadata.model_name))

    def test_malformed_json_and_schema_path_are_distinguished(self):
        malformed = completed(); malformed.output_text = "{not-json"
        with self.assertRaises(BackendMalformedResponse) as bad_json:
            OpenAIReasoningBackend(self.config, FakeClient(malformed)).reason(self.request)
        self.assertEqual("output_text_json", bad_json.exception.failure_stage)
        incorrect = output(); incorrect["missing_evidence"] = [42]
        with self.assertRaises(BackendResponseSchemaViolation) as bad_schema:
            OpenAIReasoningBackend(self.config, FakeClient(completed(incorrect))).reason(self.request)
        self.assertEqual(("response_schema", "$.missing_evidence[0]", "type", "string", "integer"),
            (bad_schema.exception.failure_stage, bad_schema.exception.validation_path, bad_schema.exception.schema_rule,
             bad_schema.exception.expected_type, bad_schema.exception.received_type))
        self.assertTrue(bad_schema.exception.backend_diagnostic.output_text_present)

    def test_adapter_failure_and_absent_diagnostic_are_distinguished(self):
        statement = {"statement": "safe", "supporting_event_refs": [], "supporting_correlation_refs": [],
            "supporting_finding_refs": [], "evidence_paths": [], "confidence": "low", "limitations": []}
        payload = output(); payload["facts"] = [statement]
        with patch("soc_ai_agent.reasoning.openai_response_parser._statement", side_effect=TypeError("conversion")):
            with self.assertRaises(BackendResponseSchemaViolation) as adapter:
                OpenAIReasoningBackend(self.config, FakeClient(completed(payload))).reason(self.request)
        self.assertEqual("response_adapter", adapter.exception.backend_diagnostic.failure_stage)
        unavailable = BackendUnavailable("offline")
        backend = FakeClient(unavailable)
        with self.assertRaises(BackendUnavailable) as raised:
            OpenAIReasoningBackend(self.config, backend).reason(self.request)
        self.assertIsNone(raised.exception.backend_diagnostic)

    def test_multiple_output_items_do_not_replace_output_text(self):
        provider_response = completed()
        provider_response.output = [
            SimpleNamespace(type="reasoning", status="completed", content=[]),
            SimpleNamespace(type="message", status="completed", role="assistant",
                content=[SimpleNamespace(type="output_text")]),
        ]
        response = OpenAIReasoningBackend(self.config, FakeClient(provider_response)).reason(self.request)
        self.assertEqual("Insufficient Evidence", response.proposed_classification)
        diagnostic = describe_response(provider_response)
        self.assertEqual((2, ("reasoning", "message"), ("output_text",)),
            (diagnostic.output_count, diagnostic.output_types, diagnostic.output_items[1].content_types))

    def test_timeout_and_rate_limit_are_mapped(self):
        class APITimeoutError(Exception): pass
        class RateLimitError(Exception): pass
        with self.assertRaises(BackendTimeout): OpenAIReasoningBackend(self.config, FakeClient(APITimeoutError())).reason(self.request)
        with self.assertRaises(BackendUnavailable): OpenAIReasoningBackend(self.config, FakeClient(RateLimitError())).reason(self.request)

    def test_refusal_incomplete_and_schema_invalid_are_rejected(self):
        refusal = completed(); refusal.output = [SimpleNamespace(content=[SimpleNamespace(type="refusal", refusal="no")])]
        with self.assertRaises(BackendProviderRefusal): OpenAIReasoningBackend(self.config, FakeClient(refusal)).reason(self.request)
        incomplete = SimpleNamespace(status="incomplete", incomplete_details=SimpleNamespace(reason="max_output_tokens"), output=[])
        with self.assertRaises(BackendSchemaViolation) as raised:
            OpenAIReasoningBackend(self.config, FakeClient(incomplete)).reason(self.request)
        self.assertEqual("max_output_tokens", raised.exception.incomplete_reason)
        self.assertEqual("response_status", raised.exception.failure_stage)
        with self.assertRaises(BackendSchemaViolation): OpenAIReasoningBackend(self.config, FakeClient(completed({"unexpected": True}))).reason(self.request)

    def test_local_strict_schema_validation_rejects_open_objects_and_optional_properties(self):
        schema = reasoning_response_schema()
        validate_strict_schema(schema)
        open_nested = deepcopy(schema)
        del open_nested["properties"]["facts"]["items"]["additionalProperties"]
        with self.assertRaises(BackendRequestSchemaViolation): validate_strict_schema(open_nested)
        missing_required = deepcopy(schema)
        missing_required["properties"]["facts"]["items"]["required"].pop()
        with self.assertRaises(BackendRequestSchemaViolation): validate_strict_schema(missing_required)

    def test_local_response_validation_distinguishes_invalid_payload(self):
        invalid = output(); invalid["missing_evidence"] = [42]
        with self.assertRaises(BackendResponseSchemaViolation): validate_response_payload(invalid, reasoning_response_schema())

    def test_provider_schema_rejection_preserves_sanitized_diagnostics(self):
        class BadRequestError(Exception):
            status_code = 400
            code = "invalid_json_schema"
            param = "text.format.schema"
            def __str__(self): return "schema rejected; api_key=sk-should-not-appear"
        with self.assertRaises(BackendRequestSchemaViolation) as raised:
            OpenAIReasoningBackend(self.config, FakeClient(BadRequestError())).reason(self.request)
        error = raised.exception
        self.assertEqual(("BadRequestError", 400, "invalid_json_schema", "text.format.schema"),
            (error.provider_error_type, error.http_status, error.provider_error_code, error.provider_error_param))
        self.assertNotIn("sk-should-not-appear", error.technical_message)


@unittest.skipUnless(os.getenv("SOC_RUN_OPENAI_INTEGRATION") == "1" and os.getenv("OPENAI_API_KEY") and os.getenv("SOC_OPENAI_MODEL"),
    "requires explicit SOC_RUN_OPENAI_INTEGRATION=1, OPENAI_API_KEY and SOC_OPENAI_MODEL")
class OpenAIIntegrationTests(unittest.TestCase):
    def test_real_responses_call_is_opt_in(self):
        response = OpenAIReasoningBackend().reason(build_request(context(), ()))
        self.assertEqual("completed", response.backend_metadata.response_status)
