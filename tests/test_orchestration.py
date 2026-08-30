from dataclasses import replace
import unittest

from soc_ai_agent.analytics.contracts import AnalyticFinding
from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, DatasetRef, EventInfo, HostInfo,
    NetworkInfo, NormalizedEvent, ProcessInfo, SCHEMA_VERSION, SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.orchestration.context_builder import ContextBudget, ContextBuilder
from soc_ai_agent.orchestration.contracts import EvidenceReference, IocAssessment, ReasonedStatement, ReasoningDraft, make_annotation_id
from soc_ai_agent.orchestration.orchestrator import ReasoningOrchestrator
from soc_ai_agent.orchestration.provenance import make_provenance
from soc_ai_agent.orchestration.skill_router import SkillRouter
from soc_ai_agent.correlation.contracts import CorrelationEdge, CorrelationEvidence
from soc_ai_agent.correlation.time_policy import usable_event_time
from soc_ai_agent.reasoning.contracts import ReasoningResponse
from soc_ai_agent.reasoning.deterministic_backend import DeterministicTestBackend
from soc_ai_agent.reasoning.errors import BackendUnavailable
from soc_ai_agent.reasoning.errors import BackendResponseSchemaViolation
from soc_ai_agent.reasoning.openai_response_diagnostics import BackendDiagnostic


def event(label="one", event_time="2022-01-01T00:00:00+00:00", timezone_status="utc"):
    raw = '{"orchestration":"' + label + '"}'
    uid = make_event_uid("orchestration", 1, raw)
    return NormalizedEvent(SCHEMA_VERSION, uid, DatasetRef("orchestration", "jsonl", 1), raw, "raw payload",
        SourceInfo(platform="windows", channel="Microsoft-Windows-Sysmon/Operational"),
        TimeInfo(event_time=event_time, timezone_status=timezone_status), EventInfo(code="1", event_type="process_create"),
        HostInfo(name="host-a"), (), ProcessInfo(image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -password=secret-token", process_guid="{guid}"),
        NetworkInfo(destination_ip="192.0.2.9", destination_port=443), CorrelationInfo(host="host-a", process_guid="{guid}"), DataQuality())


def finding(event_value, identifier="finding-a", status="observed"):
    return AnalyticFinding("1.0", identifier, "administrative_process_execution", "Administrative process execution context",
        (event_value.event_uid,), (), (), (), "informational", "high", status, (), (), "rule", "v1")


class FakeBackend:
    backend_name = "fake"; backend_version = "1.0"; model_name = None
    def __init__(self, draft): self.draft = draft
    def reason(self, request):
        return ReasoningResponse(self.draft.facts, self.draft.inferences, self.draft.hypotheses, self.draft.conclusions,
            self.draft.classification, self.draft.priority, self.draft.confidence, self.draft.mitre_mappings,
            self.draft.ioc_assessments, self.draft.false_positive_considerations, self.draft.missing_evidence,
            self.draft.recommended_actions)


class FailedBackend:
    backend_name = "fake"; backend_version = "1.1"; model_name = "configured-model"
    def __init__(self, error): self.error = error
    def reason(self, request): raise self.error


def valid_draft(event_value, classification="Suspicious / Requires Investigation"):
    fact = ReasonedStatement("Process execution was observed.", (event_value.event_uid,), evidence_paths=(
        EvidenceReference(event_uid=event_value.event_uid, path="event.code"),), confidence="high")
    return ReasoningDraft(facts=(fact,), classification=classification, priority="low", confidence="moderate",
        missing_evidence=("authorization_context",), recommended_actions=("Review related telemetry.",))


class OrchestrationTests(unittest.TestCase):
    def test_routing_and_context_redaction(self):
        source = event(); context = ContextBuilder().build((source,), (), (finding(source),))
        skills = SkillRouter().route(context, request_report=True)
        self.assertEqual(("windows-log-analysis", "ioc-analysis", "soc-alert-triage", "incident-reporting"), skills)
        self.assertNotIn("raw_event", context.events[0])
        self.assertIn("<REDACTED>", context.events[0]["process"]["command_line"])
        self.assertEqual("potential_credential_or_token", context.redacted_fields[0].reason)
        self.assertIn("secret-token", source.process.command_line)

    def test_valid_annotation_records_full_provenance(self):
        source = event(); annotation = ReasoningOrchestrator(FakeBackend(valid_draft(source))).annotate((source,), (), (finding(source),))
        self.assertEqual("accepted", annotation.validation_status)
        self.assertEqual("Suspicious / Requires Investigation", annotation.classification)
        self.assertEqual(("windows-log-analysis", "ioc-analysis", "soc-alert-triage"), annotation.reasoning_provenance.execution_order)
        self.assertEqual("1.0", annotation.reasoning_provenance.validation_policy_version)
        self.assertEqual(("1.4", "1.0", "1.2"),
            (annotation.reasoning_provenance.output_schema_version,
             annotation.reasoning_provenance.reasoning_policy_version,
             annotation.reasoning_provenance.prompt_policy_version))
        self.assertTrue(annotation.reasoning_provenance.redacted_fields)

    def test_invented_reference_is_rejected_without_reusing_draft(self):
        source = event(); bad = ReasoningDraft(conclusions=(ReasonedStatement("Unsupported conclusion.", ("missing-event",)),),
            classification="Suspicious / Requires Investigation", priority="low", confidence="low")
        annotation = ReasoningOrchestrator(FakeBackend(bad)).annotate((source,), (), (finding(source),))
        self.assertEqual(("Insufficient Evidence", "rejected"), (annotation.classification, annotation.validation_status))
        self.assertIn("unknown_event_reference:missing-event", annotation.validation_errors)
        self.assertEqual((), annotation.conclusions)

    def test_confirmed_incident_is_blocked(self):
        source = event(); annotation = ReasoningOrchestrator(FakeBackend(valid_draft(source, "Confirmed Security Incident"))).annotate(
            (source,), (), (finding(source),))
        self.assertEqual("rejected", annotation.validation_status)
        self.assertIn("confirmed_security_incident_requires_human_review", annotation.validation_errors)

    def test_budget_excludes_findings_and_events_deterministically(self):
        first, second = event("first"), event("second")
        builder = ContextBuilder(ContextBudget(max_findings=1, max_events=1, max_correlations=1, max_artifacts=1))
        context = builder.build((first, second), (), (finding(first, "a"), finding(second, "b")))
        self.assertEqual(("a",), tuple(item["finding_id"] for item in context.findings))
        self.assertTrue(any(item.identifier == "b" and item.reason == "budget:max_findings" for item in context.excluded_evidence))

    def test_annotation_id_changes_with_validation_policy_version(self):
        source = event(); context = ContextBuilder().build((source,), (), (finding(source),))
        router = SkillRouter(); skills = router.route(context); provenance = make_provenance(context, skills, router)
        base = make_annotation_id((source.event_uid,), (), ("finding-a",), provenance)
        changed = make_annotation_id((source.event_uid,), (), ("finding-a",), replace(provenance, validation_policy_version="2.0"))
        self.assertNotEqual(base, changed)

    def test_context_events_are_chronological_only_for_usable_utc_time(self):
        later = event("later", "2022-01-01T00:02:00+00:00")
        earlier = event("earlier", "2022-01-01T00:01:00+00:00")
        ambiguous = event("ambiguous", "2022-01-01T00:00:00", "ambiguous")
        context = ContextBuilder().build((later, ambiguous, earlier), (),
            (finding(later, "later"), finding(ambiguous, "ambiguous"), finding(earlier, "earlier")))
        self.assertEqual((earlier.event_uid, later.event_uid, ambiguous.event_uid),
            tuple(item["event_uid"] for item in context.events))

    def test_ambiguous_timestamp_is_not_used_as_causal_order(self):
        first = event("ambiguous-first", "2022-01-01T00:00:00", "ambiguous")
        second = event("ambiguous-second", "2022-01-01T00:10:00", "ambiguous")
        context = ContextBuilder().build((second, first), (), (finding(first, "one"), finding(second, "two")))
        self.assertIsNone(usable_event_time(first))
        self.assertIsNone(usable_event_time(second))
        self.assertEqual(tuple(sorted((first.event_uid, second.event_uid))),
            tuple(item["event_uid"] for item in context.events))

    def test_temporal_only_causality_is_rejected(self):
        source = event()
        edge = CorrelationEdge("1.0", "edge-t", source.event_uid, source.event_uid, "temporal_only", "temporal_proximity_v1",
            "weak", (), None, CorrelationEvidence("process_create", "process_create", "windows", "windows", 0, "not_required"))
        scoped_finding = replace(finding(source), correlation_ids=("edge-t",))
        draft = ReasoningDraft(inferences=(ReasonedStatement("Events caused a change.", (source.event_uid,), ("edge-t",)),),
            classification="Suspicious / Requires Investigation", priority="low", confidence="low")
        annotation = ReasoningOrchestrator(FakeBackend(draft)).annotate((source,), (edge,), (scoped_finding,))
        self.assertEqual("rejected", annotation.validation_status)
        self.assertIn("causality_from_temporal_only", annotation.validation_errors)

    def test_ioc_assessment_requires_traceable_support(self):
        source = event()
        draft = ReasoningDraft(ioc_assessments=(IocAssessment("192.0.2.9", "ip", "Observed", "low"),),
            classification="Insufficient Evidence", priority="low", confidence="low")
        annotation = ReasoningOrchestrator(FakeBackend(draft)).annotate((source,), (), (finding(source),))
        self.assertEqual("rejected", annotation.validation_status)
        self.assertIn("ioc_assessment_without_support", annotation.validation_errors)

    def test_backend_failure_degrades_to_insufficient_evidence(self):
        source = event()
        backend = DeterministicTestBackend((BackendUnavailable("offline"), BackendUnavailable("offline")))
        annotation = ReasoningOrchestrator(backend).annotate((source,), (), (finding(source),))
        self.assertEqual(("Insufficient Evidence", "accepted"), (annotation.classification, annotation.validation_status))
        self.assertEqual((), annotation.conclusions)
        self.assertIn("backend_failure:backend_unavailable", annotation.missing_evidence)
        self.assertEqual((2, 1), (annotation.reasoning_provenance.backend_metadata.attempt_count,
                                 annotation.reasoning_provenance.backend_metadata.retry_count))

    def test_failure_diagnostic_reaches_provenance_without_becoming_evidence(self):
        source = event()
        error = BackendResponseSchemaViolation("response invalid", "completed")
        error.failure_stage = "response_schema"; error.validation_path = "$.missing_evidence[0]"
        error.backend_diagnostic = BackendDiagnostic("provider-response", "completed", None, 11, 22, 12,
            "provider-model", ("message",), True, 99, "a" * 64, "response_schema",
            "$.missing_evidence[0]", "type", "string", "integer")
        annotation = ReasoningOrchestrator(FailedBackend(error)).annotate((source,), (), (finding(source),))
        metadata = annotation.reasoning_provenance.backend_metadata
        self.assertEqual("Insufficient Evidence", annotation.classification)
        self.assertEqual(("provider-response", 11, 22, 12, "provider-model"),
            (metadata.provider_response_id, metadata.input_token_count, metadata.output_token_count,
             metadata.reasoning_token_count, metadata.model_name))
        self.assertEqual("response_schema", metadata.backend_diagnostic.failure_stage)
        self.assertFalse(annotation.facts)
