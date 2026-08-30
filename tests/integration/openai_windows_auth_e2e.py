"""E2E controlado: preview offline y ejecución real sólo bajo autorización explícita."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import os
import sys

from soc_ai_agent.analytics.engine import AnalyticsEngine
from soc_ai_agent.correlation.engine import CorrelationEngine
from soc_ai_agent.orchestration.context_builder import ContextBuilder
from soc_ai_agent.orchestration.skill_router import SkillRouter
from soc_ai_agent.reasoning.openai_backend import OpenAIReasoningBackend
from soc_ai_agent.reasoning.openai_config import OpenAIConfig, OpenAIModelCapabilities
from soc_ai_agent.reasoning.openai_prompt_builder import build_openai_payload
from soc_ai_agent.reasoning.openai_schema import reasoning_response_schema
from soc_ai_agent.reasoning.request_builder import build_request
from soc_ai_agent.reasoning.retry_policy import RetryPolicy
from soc_ai_agent.reasoning.token_policy import TokenPolicy
from soc_ai_agent.reasoning.versions import OUTPUT_SCHEMA_VERSION, PROMPT_POLICY_VERSION
from tests.fixtures.windows_auth_sequence_normalized import build_events


EXPECTED_FINDINGS = ("authentication_failure_then_success", "repeated_authentication_failures")
EXPECTED_SKILLS = ("windows-log-analysis", "soc-alert-triage")
ALLOWED_FINAL_CLASSIFICATIONS = {"Suspicious / Requires Investigation", "Insufficient Evidence"}
INTEGRATION_MAX_OUTPUT_TOKENS = 5_000
INTEGRATION_TIMEOUT_SECONDS = 45.0
INTEGRATION_MAX_TOTAL_SECONDS = 100.0
INTEGRATION_MAX_ATTEMPTS = 2
INTEGRATION_REASONING_EFFORT = "low"
FORBIDDEN_CLAIMS = ("brute force confirmado", "brute force confirmed", "cuenta comprometida", "account compromised",
    "credenciales robadas", "stolen credentials", "atacante confirmado", "confirmed attacker", "compromiso confirmado")


@dataclass(frozen=True)
class IntegrationPreview:
    event_uids: tuple[str, ...]
    correlation_ids: tuple[str, ...]
    finding_types: tuple[str, ...]
    skills: tuple[str, ...]
    context: dict
    reference_map: dict
    allowed_evidence_paths: tuple[str, ...]
    output_schema_version: str
    prompt_policy_version: str
    context_builder_version: str
    reference_map_version: str
    capabilities: dict
    effective_top_level_properties: tuple[str, ...]
    effective_required: tuple[str, ...]
    mitre_mappings_present: bool
    ioc_assessments_present: bool
    token_estimate: int
    estimated_evidence_tokens: int
    estimated_instruction_tokens: int
    estimated_skill_tokens: int
    estimated_schema_tokens: int
    estimated_overhead_tokens: int
    estimated_total_input_tokens: int
    max_output_tokens: int
    timeout_seconds: float
    max_total_seconds: float
    max_attempts: int
    reasoning_effort: str | None
    maximum_allowed_classification: str
    request_id: str

    def sanitized_dict(self):
        return asdict(self)


def _integration_reasoning_effort(model_name: str | None, supports_reasoning_effort: bool) -> str | None:
    """Sólo solicita effort bajo cuando la capacidad fue declarada para este modelo."""
    if model_name == "gpt-5.6-terra" and supports_reasoning_effort:
        return INTEGRATION_REASONING_EFFORT
    return None


def build_preview(model_name: str | None = None, supports_reasoning_effort: bool | None = None) -> tuple[IntegrationPreview, tuple, tuple, tuple]:
    events = build_events()
    edges = CorrelationEngine().correlate(events).edges
    findings = AnalyticsEngine().analyze(events, edges).findings
    finding_types = tuple(sorted(item.finding_type for item in findings))
    if finding_types != EXPECTED_FINDINGS:
        raise AssertionError(f"unexpected deterministic findings: {finding_types}")
    if any(edge.relation_type == "direct" for edge in edges):
        raise AssertionError("this controlled scenario must not have direct correlation edges")
    context = ContextBuilder().build(events, edges, findings)
    skills = SkillRouter().route(context)
    if skills != EXPECTED_SKILLS:
        raise AssertionError(f"unexpected selected skills: {skills}")
    model_name = os.getenv("SOC_OPENAI_MODEL") if model_name is None else model_name
    supports_reasoning_effort = (os.getenv("SOC_OPENAI_SUPPORTS_REASONING_EFFORT", "false").lower() == "true"
        if supports_reasoning_effort is None else supports_reasoning_effort)
    reasoning_effort = _integration_reasoning_effort(model_name, supports_reasoning_effort)
    request = build_request(context, skills, max_output_tokens=INTEGRATION_MAX_OUTPUT_TOKENS)
    preview_config = OpenAIConfig("", model_name or "preview-model", timeout_seconds=INTEGRATION_TIMEOUT_SECONDS,
        max_output_tokens=INTEGRATION_MAX_OUTPUT_TOKENS,
        reasoning_effort=reasoning_effort, capabilities=OpenAIModelCapabilities(False, supports_reasoning_effort))
    input_estimate = TokenPolicy().enforce_openai_input(build_openai_payload(request, preview_config))
    refs = context.reference_map
    effective_schema = reasoning_response_schema(refs, request.capabilities)
    # The ContextBuilder selects no edges because the selected findings have no correlation IDs.
    preview = IntegrationPreview(tuple(item.event_uid for item in events), (), finding_types, skills,
        {"events": list(context.events), "correlations": list(context.correlations), "findings": list(context.findings),
         "redacted_fields": [item.__dict__ for item in context.redacted_fields]},
        {"events": [{"alias": alias, "event_uid": identifier} for alias, identifier in refs.event_aliases],
         "findings": [{"alias": alias, "finding_id": identifier} for alias, identifier in refs.finding_aliases],
         "correlations": [{"alias": alias, "correlation_id": identifier} for alias, identifier in refs.correlation_aliases]},
        refs.allowed_paths, OUTPUT_SCHEMA_VERSION, request.prompt_policy_version, context.context_builder_version, refs.version,
        request.capabilities.as_dict(), tuple(effective_schema["properties"]), tuple(effective_schema["required"]),
        "mitre_mappings" in effective_schema["properties"], "ioc_assessments" in effective_schema["properties"],
        input_estimate.estimated_total_input_tokens, input_estimate.estimated_evidence_tokens,
        input_estimate.estimated_instruction_tokens, input_estimate.estimated_skill_tokens,
        input_estimate.estimated_schema_tokens, input_estimate.estimated_overhead_tokens,
        input_estimate.estimated_total_input_tokens,
        INTEGRATION_MAX_OUTPUT_TOKENS, INTEGRATION_TIMEOUT_SECONDS, INTEGRATION_MAX_TOTAL_SECONDS,
        INTEGRATION_MAX_ATTEMPTS, reasoning_effort,
        "Suspicious / Requires Investigation", request.request_id)
    return preview, events, edges, findings


def _approved(preview: IntegrationPreview):
    required = ("SOC_RUN_OPENAI_INTEGRATION", "OPENAI_API_KEY", "SOC_OPENAI_MODEL", "SOC_OPENAI_APPROVED_REQUEST_ID")
    missing = [name for name in required if not os.getenv(name)]
    if os.getenv("SOC_RUN_OPENAI_INTEGRATION") != "1": missing.append("SOC_RUN_OPENAI_INTEGRATION=1")
    if missing: raise RuntimeError("integration is not enabled: " + ", ".join(sorted(set(missing))))
    if os.getenv("SOC_OPENAI_APPROVED_REQUEST_ID") != preview.request_id:
        raise RuntimeError("SOC_OPENAI_APPROVED_REQUEST_ID does not match offline preview request_id")


def _integration_backend() -> OpenAIReasoningBackend:
    config = OpenAIConfig.from_env()
    effort = _integration_reasoning_effort(config.model, config.capabilities.supports_reasoning_effort)
    return OpenAIReasoningBackend(replace(config, timeout_seconds=INTEGRATION_TIMEOUT_SECONDS,
        max_output_tokens=INTEGRATION_MAX_OUTPUT_TOKENS,
        reasoning_effort=effort))


def _assert_annotation(annotation, preview):
    if annotation.validation_status != "accepted": raise AssertionError(f"annotation rejected: {annotation.validation_errors}")
    if annotation.classification not in ALLOWED_FINAL_CLASSIFICATIONS: raise AssertionError("unexpected final classification")
    if annotation.classification == "Confirmed Security Incident": raise AssertionError("confirmed classification is forbidden")
    if annotation.mitre_mappings: raise AssertionError("MITRE mappings are not permitted for this scenario")
    if annotation.reasoning_provenance.execution_order != EXPECTED_SKILLS: raise AssertionError("unexpected Skills provenance")
    if tuple(sorted(annotation.finding_ids)) != tuple(sorted(item["finding_id"] for item in preview.context["findings"])):
        raise AssertionError("annotation references findings outside selected context")
    claims = " ".join(statement.statement for section in (annotation.facts, annotation.inferences, annotation.hypotheses, annotation.conclusions)
                      for statement in section).lower()
    if any(claim in claims for claim in FORBIDDEN_CLAIMS): raise AssertionError("forbidden confirmation claim in model response")


def _backend_diagnostic_dict(metadata):
    diagnostic = metadata.backend_diagnostic
    if diagnostic is None:
        return None
    return {"provider_response_id": diagnostic.provider_response_id,
        "response_status": diagnostic.response_status, "incomplete_reason": diagnostic.incomplete_reason,
        "input_tokens": diagnostic.input_tokens, "output_tokens": diagnostic.output_tokens,
        "reasoning_tokens": diagnostic.reasoning_tokens, "response_model": diagnostic.response_model,
        "output_types": diagnostic.output_types, "output_text_present": diagnostic.output_text_present,
        "output_text_length": diagnostic.output_text_length, "output_text_sha256": diagnostic.output_text_sha256,
        "failure_stage": diagnostic.failure_stage, "validation_path": diagnostic.validation_path,
        "schema_rule": diagnostic.schema_rule, "expected_type": diagnostic.expected_type,
        "received_type": diagnostic.received_type}


def _result_summary(annotation):
    metadata = annotation.reasoning_provenance.backend_metadata
    summary = {"classification": annotation.classification, "priority": annotation.priority, "confidence": annotation.confidence,
        "facts": [item.statement for item in annotation.facts], "inferences": [item.statement for item in annotation.inferences],
        "hypotheses": [item.statement for item in annotation.hypotheses], "missing_evidence": annotation.missing_evidence,
        "recommended_actions": annotation.recommended_actions, "validation_status": annotation.validation_status,
        "validation_errors": annotation.validation_errors, "skills": annotation.reasoning_provenance.execution_order,
        "model": metadata.model_name, "input_tokens": metadata.input_token_count, "output_tokens": metadata.output_token_count,
        "reasoning_tokens": metadata.reasoning_token_count, "latency_ms": metadata.latency_ms,
        "estimated_total_input_tokens": getattr(metadata.input_token_estimate, "estimated_total_input_tokens", None),
        "input_token_estimation_error_percent": metadata.input_token_estimation_error_percent,
        "timeout_seconds": metadata.timeout_seconds, "max_total_seconds": metadata.max_total_seconds,
        "max_attempts": metadata.max_attempts,
        "provider_request_id": metadata.provider_request_id, "provider_response_id": metadata.provider_response_id,
        "request_id": metadata.request_id}
    diagnostic = _backend_diagnostic_dict(metadata)
    if diagnostic is not None:
        summary["backend_diagnostic"] = diagnostic
    return summary


def run_real():
    preview, events, edges, findings = build_preview()
    original_events, original_edges, original_findings = events, edges, findings
    print(json.dumps(preview.sanitized_dict(), ensure_ascii=False, indent=2))
    _approved(preview)
    from soc_ai_agent.orchestration.orchestrator import ReasoningOrchestrator
    annotation = ReasoningOrchestrator(_integration_backend(), max_output_tokens=INTEGRATION_MAX_OUTPUT_TOKENS,
        retry_policy=RetryPolicy(INTEGRATION_MAX_ATTEMPTS, INTEGRATION_TIMEOUT_SECONDS,
            INTEGRATION_MAX_TOTAL_SECONDS)).annotate(events, edges, findings)
    if (events, edges, findings) != (original_events, original_edges, original_findings):
        raise AssertionError("deterministic evidence was modified by reasoning")
    _assert_annotation(annotation, preview)
    print(json.dumps(_result_summary(annotation), ensure_ascii=False, indent=2))
    return annotation


if __name__ == "__main__":
    preview, *_ = build_preview()
    if "--preview" in sys.argv:
        print(json.dumps(preview.sanitized_dict(), ensure_ascii=False, indent=2))
    elif "--execute" in sys.argv:
        run_real()
    else:
        raise SystemExit("use --preview or --execute")
