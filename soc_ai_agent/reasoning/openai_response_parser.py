import json

from .contracts import BackendMetadata, ReasoningResponse
from .errors import BackendMalformedResponse, BackendProviderRefusal, BackendResponseSchemaViolation
from .openai_schema import reasoning_response_schema, validate_response_payload
from .openai_response_diagnostics import make_backend_diagnostic
from soc_ai_agent.orchestration.references import resolve_response_aliases
from .versions import OPENAI_BACKEND_VERSION
from soc_ai_agent.orchestration.contracts import EvidenceReference, IocAssessment, MitreAssessment, ReasonedStatement


def _attach(error, diagnostic, stage):
    error.response_diagnostic = diagnostic
    error.failure_stage = stage if error.failure_stage is None else error.failure_stage
    if diagnostic is not None:
        error.backend_diagnostic = make_backend_diagnostic(diagnostic, error)
    return error


def _statement(item):
    try:
        return ReasonedStatement(item["statement"], tuple(item["supporting_event_uids"]), tuple(item["supporting_correlation_ids"]),
            tuple(item["supporting_finding_ids"]), tuple(EvidenceReference(**path) for path in item["evidence_paths"]),
            item["confidence"], tuple(item["limitations"]))
    except (KeyError, TypeError) as error:
        failure = BackendResponseSchemaViolation("response adapter statement conversion failed")
        failure.failure_stage = "response_adapter"
        raise failure from error


def _refusal(response):
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) == "refusal" or getattr(content, "refusal", None): return True
    return False


def parse_openai_response(response, request_id: str, backend_name="openai", backend_version=OPENAI_BACKEND_VERSION,
                          model_name=None, diagnostic=None, reference_map=None, capabilities=None):
    status = getattr(response, "status", None)
    incomplete = getattr(getattr(response, "incomplete_details", None), "reason", None)
    if _refusal(response):
        raise _attach(BackendProviderRefusal("provider refusal", status, incomplete), diagnostic, "provider_refusal")
    if status != "completed":
        raise _attach(BackendResponseSchemaViolation("response not completed", status, incomplete), diagnostic, "response_status")
    output_text = getattr(response, "output_text", None)
    if output_text is None:
        raise _attach(BackendMalformedResponse("response output_text is absent", status, incomplete), diagnostic, "output_text_missing")
    try:
        payload = json.loads(output_text)
    except (TypeError, json.JSONDecodeError) as error:
        raise _attach(BackendMalformedResponse("response output is not valid JSON", status, incomplete), diagnostic, "output_text_json") from error
    try:
        validate_response_payload(payload, reasoning_response_schema(reference_map, capabilities))
        # Campos fuera del espacio de decisión del modelo: los impone la policy de capabilities.
        if not capabilities or not capabilities.mitre_mapping: payload["mitre_mappings"] = []
        if not capabilities or not capabilities.ioc_assessment: payload["ioc_assessments"] = []
        payload = resolve_response_aliases(payload, reference_map)
        metadata = BackendMetadata(backend_name, backend_version, model_name, request_id,
            getattr(response, "_request_id", None),
            getattr(getattr(response, "usage", None), "input_tokens", None), getattr(getattr(response, "usage", None), "output_tokens", None),
            None, 0, 0, status, incomplete,
            getattr(getattr(getattr(response, "usage", None), "output_tokens_details", None), "reasoning_tokens", None),
            None, getattr(response, "id", None))
        mitre = tuple(MitreAssessment(item["technique_id"], item["technique_name"], item["confidence"],
            tuple(item["supporting_event_uids"]), tuple(item["supporting_correlation_ids"]), tuple(item["supporting_finding_ids"]), tuple(item["limitations"])) for item in payload["mitre_mappings"])
        iocs = tuple(IocAssessment(item["value"], item["artifact_type"], item["classification"], item["confidence"],
            tuple(item["supporting_event_uids"]), tuple(item["supporting_correlation_ids"]), tuple(item["supporting_finding_ids"]), tuple(item["limitations"])) for item in payload["ioc_assessments"])
        return ReasoningResponse(tuple(_statement(item) for item in payload["facts"]), tuple(_statement(item) for item in payload["inferences"]),
            tuple(_statement(item) for item in payload["hypotheses"]), tuple(_statement(item) for item in payload["conclusions"]),
            payload["proposed_classification"], payload["proposed_priority"], payload["confidence"], mitre, iocs,
            tuple(_statement(item) for item in payload["false_positive_considerations"]), tuple(payload["missing_evidence"]),
            tuple(payload["recommended_actions"]), metadata)
    except BackendResponseSchemaViolation as error:
        raise _attach(error, diagnostic, "response_schema") from error
    except (KeyError, TypeError, ValueError) as error:
        raise _attach(BackendResponseSchemaViolation("response adapter conversion failed", status, incomplete), diagnostic,
            "response_adapter") from error
