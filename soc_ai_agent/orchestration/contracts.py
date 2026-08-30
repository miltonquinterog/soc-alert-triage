from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Literal


ANNOTATION_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class EvidenceReference:
    event_uid: str | None = None
    correlation_id: str | None = None
    finding_id: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class ReasonedStatement:
    statement: str
    supporting_event_uids: tuple[str, ...] = ()
    supporting_correlation_ids: tuple[str, ...] = ()
    supporting_finding_ids: tuple[str, ...] = ()
    evidence_paths: tuple[EvidenceReference, ...] = ()
    confidence: Literal["low", "moderate", "high"] = "low"
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class MitreAssessment:
    technique_id: str | None
    technique_name: str | None
    confidence: Literal["low", "moderate", "high"]
    supporting_event_uids: tuple[str, ...] = ()
    supporting_correlation_ids: tuple[str, ...] = ()
    supporting_finding_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class IocAssessment:
    value: str
    artifact_type: str
    classification: Literal["Observed", "Unknown", "Benign/Expected", "Suspicious", "Confirmed Malicious"]
    confidence: Literal["low", "moderate", "high"]
    supporting_event_uids: tuple[str, ...] = ()
    supporting_correlation_ids: tuple[str, ...] = ()
    supporting_finding_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class RedactedField:
    event_uid: str
    path: str
    reason: str


@dataclass(frozen=True)
class ExcludedEvidence:
    evidence_type: Literal["event", "correlation", "finding", "artifact"]
    identifier: str
    reason: str


@dataclass(frozen=True)
class ReasoningProvenance:
    activated_skills: tuple[str, ...]
    execution_order: tuple[str, ...]
    skill_versions: tuple[tuple[str, str], ...]
    selection_policy_version: str
    context_builder_version: str
    orchestrator_version: str
    validation_policy_version: str
    output_schema_version: str
    reasoning_policy_version: str
    prompt_policy_version: str
    excluded_evidence: tuple[ExcludedEvidence, ...]
    redacted_fields: tuple[RedactedField, ...]
    backend_metadata: object | None = None


@dataclass(frozen=True)
class AnalyticAnnotation:
    schema_version: str
    annotation_id: str
    event_uids: tuple[str, ...]
    correlation_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    facts: tuple[ReasonedStatement, ...]
    inferences: tuple[ReasonedStatement, ...]
    hypotheses: tuple[ReasonedStatement, ...]
    conclusions: tuple[ReasonedStatement, ...]
    classification: Literal["Benign / Expected", "Suspicious / Requires Investigation", "Confirmed Security Incident", "Insufficient Evidence"]
    priority: Literal["low", "medium", "high"]
    confidence: Literal["low", "moderate", "high"]
    mitre_mappings: tuple[MitreAssessment, ...]
    ioc_assessments: tuple[IocAssessment, ...]
    false_positive_considerations: tuple[ReasonedStatement, ...]
    missing_evidence: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    reasoning_provenance: ReasoningProvenance
    validation_status: Literal["accepted", "rejected"]
    validation_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReasoningDraft:
    facts: tuple[ReasonedStatement, ...] = ()
    inferences: tuple[ReasonedStatement, ...] = ()
    hypotheses: tuple[ReasonedStatement, ...] = ()
    conclusions: tuple[ReasonedStatement, ...] = ()
    classification: str = "Insufficient Evidence"
    priority: str = "low"
    confidence: str = "low"
    mitre_mappings: tuple[MitreAssessment, ...] = ()
    ioc_assessments: tuple[IocAssessment, ...] = ()
    false_positive_considerations: tuple[ReasonedStatement, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()


def make_annotation_id(event_uids: tuple[str, ...], correlation_ids: tuple[str, ...], finding_ids: tuple[str, ...],
                       provenance: ReasoningProvenance) -> str:
    material = {
        "namespace": "soc-ai-agent:analytic-annotation:v1",
        "event_uids": event_uids, "correlation_ids": correlation_ids, "finding_ids": finding_ids,
        "skills": provenance.execution_order, "skill_versions": provenance.skill_versions,
        "selection_policy_version": provenance.selection_policy_version,
        "context_builder_version": provenance.context_builder_version,
        "orchestrator_version": provenance.orchestrator_version,
        "validation_policy_version": provenance.validation_policy_version,
        "output_schema_version": provenance.output_schema_version,
        "reasoning_policy_version": provenance.reasoning_policy_version,
        "prompt_policy_version": provenance.prompt_policy_version,
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
