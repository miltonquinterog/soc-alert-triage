from .contracts import ReasoningResponse
from soc_ai_agent.orchestration.contracts import ReasoningDraft


def to_reasoning_draft(response: ReasoningResponse) -> ReasoningDraft:
    return ReasoningDraft(response.facts, response.inferences, response.hypotheses, response.conclusions,
        response.proposed_classification, response.proposed_priority, response.confidence, response.mitre_mappings,
        response.ioc_assessments, response.false_positive_considerations, response.missing_evidence,
        response.recommended_actions)
