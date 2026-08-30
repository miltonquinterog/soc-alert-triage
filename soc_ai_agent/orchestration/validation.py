"""Validación determinista de trazabilidad y de límites de clasificación."""

from __future__ import annotations

from .contracts import EvidenceReference, ReasoningDraft


VALID_CLASSIFICATIONS = {"Benign / Expected", "Suspicious / Requires Investigation", "Confirmed Security Incident", "Insufficient Evidence"}
VALID_PRIORITIES = {"low", "medium", "high"}
VALID_CONFIDENCE = {"low", "moderate", "high"}


def _path_exists(value, path: str) -> bool:
    current = value
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False
        current = current[segment]
    return current is not None


class OutputValidator:
    def validate(self, draft: ReasoningDraft, context) -> tuple[str, ...]:
        errors: list[str] = []
        event_ids = {item["event_uid"] for item in context.events}
        edge_ids = {item["correlation_id"] for item in context.correlations}
        finding_ids = {item["finding_id"] for item in context.findings}
        events = {item["event_uid"]: item for item in context.events}
        if draft.classification not in VALID_CLASSIFICATIONS: errors.append("invalid_classification")
        if draft.priority not in VALID_PRIORITIES: errors.append("invalid_priority")
        if draft.confidence not in VALID_CONFIDENCE: errors.append("invalid_confidence")
        if draft.classification == "Confirmed Security Incident":
            errors.append("confirmed_security_incident_requires_human_review")
        def validate_support(event_refs, correlation_refs, finding_refs, label):
            supplied = event_refs + correlation_refs + finding_refs
            if not supplied: errors.append(f"{label}_without_support")
            for identifier in event_refs:
                if identifier not in event_ids: errors.append(f"unknown_event_reference:{identifier}")
            for identifier in correlation_refs:
                if identifier not in edge_ids: errors.append(f"unknown_correlation_reference:{identifier}")
            for identifier in finding_refs:
                if identifier not in finding_ids: errors.append(f"unknown_finding_reference:{identifier}")

        statements = draft.facts + draft.inferences + draft.hypotheses + draft.conclusions + draft.false_positive_considerations
        for position, statement in enumerate(statements):
            validate_support(statement.supporting_event_uids, statement.supporting_correlation_ids,
                             statement.supporting_finding_ids, f"statement:{position}")
            for reference in statement.evidence_paths:
                if reference.event_uid and reference.event_uid not in event_ids:
                    errors.append(f"unknown_evidence_event:{reference.event_uid}")
                elif reference.event_uid and reference.path and not _path_exists(events[reference.event_uid], reference.path):
                    errors.append(f"unknown_evidence_path:{reference.path}")
                if reference.correlation_id and reference.correlation_id not in edge_ids:
                    errors.append(f"unknown_evidence_correlation:{reference.correlation_id}")
                if reference.finding_id and reference.finding_id not in finding_ids:
                    errors.append(f"unknown_evidence_finding:{reference.finding_id}")
            temporal_only = set(statement.supporting_correlation_ids) & {item["correlation_id"] for item in context.correlations if item["relation_type"] == "temporal_only"}
            if temporal_only and "caus" in statement.statement.lower():
                errors.append("causality_from_temporal_only")
        for mapping in draft.mitre_mappings:
            validate_support(mapping.supporting_event_uids, mapping.supporting_correlation_ids,
                             mapping.supporting_finding_ids, "mitre_mapping")
        for assessment in draft.ioc_assessments:
            validate_support(assessment.supporting_event_uids, assessment.supporting_correlation_ids,
                             assessment.supporting_finding_ids, "ioc_assessment")
            if assessment.classification == "Confirmed Malicious": errors.append("ioc_confirmation_not_supported_in_phase4")
        return tuple(dict.fromkeys(errors))
