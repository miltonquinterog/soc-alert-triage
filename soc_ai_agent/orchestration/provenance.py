from .contracts import ReasoningProvenance
from .policy import ORCHESTRATOR_VERSION, VALIDATION_POLICY_VERSION
from soc_ai_agent.reasoning.versions import (OUTPUT_SCHEMA_VERSION, PROMPT_POLICY_VERSION,
    REASONING_POLICY_VERSION)


def make_provenance(context, skills, router, backend_metadata=None, request=None) -> ReasoningProvenance:
    return ReasoningProvenance(activated_skills=skills, execution_order=skills, skill_versions=router.versions(skills),
        selection_policy_version=context.selection_policy_version, context_builder_version=context.context_builder_version,
        orchestrator_version=ORCHESTRATOR_VERSION, validation_policy_version=VALIDATION_POLICY_VERSION,
        output_schema_version=request.output_schema_version if request else OUTPUT_SCHEMA_VERSION,
        reasoning_policy_version=request.reasoning_policy_version if request else REASONING_POLICY_VERSION,
        prompt_policy_version=request.prompt_policy_version if request else PROMPT_POLICY_VERSION,
        excluded_evidence=context.excluded_evidence, redacted_fields=context.redacted_fields,
        backend_metadata=backend_metadata)
