"""Contratos deterministas de hallazgos, separados de eventos y relaciones."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Literal


ANALYTICS_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ObservedFact:
    name: str
    value: str
    correlation_id: str | None = None


@dataclass(frozen=True)
class EvidencePath:
    event_uid: str | None
    path: str
    value: str
    correlation_id: str | None = None


def make_finding_id(rule_name: str, rule_version: str, finding_type: str,
                    event_uids: tuple[str, ...], correlation_ids: tuple[str, ...],
                    grouping_key: tuple[str, ...]) -> str:
    material = {
        "namespace": "soc-ai-agent:analytic-finding:v1",
        "rule_name": rule_name,
        "rule_version": rule_version,
        "finding_type": finding_type,
        "event_uids": event_uids,
        "correlation_ids": correlation_ids,
        "grouping_key": grouping_key,
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AnalyticFinding:
    schema_version: str
    finding_id: str
    finding_type: str
    title: str
    event_uids: tuple[str, ...]
    correlation_ids: tuple[str, ...]
    observed_facts: tuple[ObservedFact, ...]
    evidence_paths: tuple[EvidencePath, ...]
    severity_hint: Literal["informational", "low", "medium"]
    confidence: Literal["low", "moderate", "high"]
    status: Literal["observed", "suspicious_context", "requires_investigation", "insufficient_evidence"]
    limitations: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    rule_name: str
    rule_version: str


@dataclass(frozen=True)
class AnalyticsResult:
    findings: tuple[AnalyticFinding, ...]
    diagnostics: tuple[str, ...] = ()
