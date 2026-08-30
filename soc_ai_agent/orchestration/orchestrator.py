"""Orquestación con backend inyectable; no integra proveedores externos."""

from __future__ import annotations

from .context_builder import ContextBuilder
from .contracts import (ANNOTATION_SCHEMA_VERSION, AnalyticAnnotation, ReasoningDraft,
    make_annotation_id)
from .provenance import make_provenance
from .skill_router import SkillRouter
from .validation import OutputValidator
from soc_ai_agent.reasoning.contracts import BackendMetadata
from soc_ai_agent.reasoning.errors import ReasoningBackendError
from soc_ai_agent.reasoning.request_builder import build_request
from soc_ai_agent.reasoning.response_adapter import to_reasoning_draft
from soc_ai_agent.reasoning.retry_policy import RetryPolicy
from soc_ai_agent.reasoning.token_policy import TokenPolicy


class ReasoningOrchestrator:
    def __init__(self, backend, context_builder: ContextBuilder | None = None, router: SkillRouter | None = None,
                 validator: OutputValidator | None = None, retry_policy: RetryPolicy = RetryPolicy(),
                 token_policy: TokenPolicy = TokenPolicy(), max_output_tokens: int = 1_200) -> None:
        self.backend = backend; self.context_builder = context_builder or ContextBuilder()
        self.router = router or SkillRouter(); self.validator = validator or OutputValidator()
        self.retry_policy = retry_policy; self.token_policy = token_policy; self.max_output_tokens = max_output_tokens

    def annotate(self, events, correlations, findings, request_report: bool = False) -> AnalyticAnnotation:
        context = self.context_builder.build(events, correlations, findings)
        skills = self.router.route(context, request_report)
        backend_metadata = None; request = None
        try:
            request = build_request(context, skills, max_output_tokens=self.max_output_tokens, token_policy=self.token_policy)
            response, backend_metadata, backend_error = self.retry_policy.execute(self.backend, request, self.token_policy)
            if backend_error:
                draft = ReasoningDraft(classification="Insufficient Evidence", priority="low", confidence="low",
                    missing_evidence=(f"backend_failure:{backend_error.code}",),
                    recommended_actions=("Review backend availability and retry when appropriate.",))
            else:
                draft = to_reasoning_draft(response)
        except ReasoningBackendError as error:
            backend_metadata = BackendMetadata("preflight", "1.0", None, "unavailable", None, None, None, None, 0, 0)
            draft = ReasoningDraft(classification="Insufficient Evidence", priority="low", confidence="low",
                missing_evidence=(f"backend_failure:{error.code}",),
                recommended_actions=("Review reasoning request budget or configuration.",))
        provenance = make_provenance(context, skills, self.router, backend_metadata, request)
        errors = self.validator.validate(draft, context)
        event_uids = tuple(sorted(item["event_uid"] for item in context.events))
        correlation_ids = tuple(sorted(item["correlation_id"] for item in context.correlations))
        finding_ids = tuple(sorted(item["finding_id"] for item in context.findings))
        annotation_id = make_annotation_id(event_uids, correlation_ids, finding_ids, provenance)
        if errors:
            return AnalyticAnnotation(ANNOTATION_SCHEMA_VERSION, annotation_id, event_uids, correlation_ids, finding_ids,
                (), (), (), (), "Insufficient Evidence", "low", "low", (), (), (),
                ("output_rejected_by_validation",), ("review_validation_errors",), provenance, "rejected", errors)
        return AnalyticAnnotation(ANNOTATION_SCHEMA_VERSION, annotation_id, event_uids, correlation_ids, finding_ids,
            draft.facts, draft.inferences, draft.hypotheses, draft.conclusions, draft.classification, draft.priority,
            draft.confidence, draft.mitre_mappings, draft.ioc_assessments, draft.false_positive_considerations,
            draft.missing_evidence, draft.recommended_actions, provenance, "accepted")
