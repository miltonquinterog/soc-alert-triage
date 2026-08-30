from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from soc_ai_agent.orchestration.contracts import (IocAssessment, MitreAssessment, ReasonedStatement)


@dataclass(frozen=True)
class BackendMetadata:
    backend_name: str
    backend_version: str
    model_name: str | None
    request_id: str
    provider_request_id: str | None
    input_token_count: int | None
    output_token_count: int | None
    latency_ms: int | None
    retry_count: int
    attempt_count: int
    response_status: str | None = None
    incomplete_reason: str | None = None
    reasoning_token_count: int | None = None
    backend_diagnostic: object | None = None
    provider_response_id: str | None = None
    input_token_estimate: object | None = None
    input_token_estimation_error_percent: float | None = None
    timeout_seconds: float | None = None
    max_total_seconds: float | None = None
    max_attempts: int | None = None


@dataclass(frozen=True)
class ReasoningRequest:
    request_id: str
    context: object
    activated_skills: tuple[str, ...]
    allowed_classifications: tuple[str, ...]
    guardrails: tuple[str, ...]
    output_schema_version: str
    reasoning_policy_version: str
    prompt_policy_version: str
    max_output_tokens: int
    untrusted_evidence_json: str
    capabilities: object | None = None


@dataclass(frozen=True)
class ReasoningResponse:
    facts: tuple[ReasonedStatement, ...] = ()
    inferences: tuple[ReasonedStatement, ...] = ()
    hypotheses: tuple[ReasonedStatement, ...] = ()
    conclusions: tuple[ReasonedStatement, ...] = ()
    proposed_classification: str = "Insufficient Evidence"
    proposed_priority: str = "low"
    confidence: str = "low"
    mitre_mappings: tuple[MitreAssessment, ...] = ()
    ioc_assessments: tuple[IocAssessment, ...] = ()
    false_positive_considerations: tuple[ReasonedStatement, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    backend_metadata: BackendMetadata | None = None
