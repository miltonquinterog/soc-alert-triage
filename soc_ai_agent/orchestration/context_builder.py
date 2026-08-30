"""Construye una proyección limitada; nunca transforma los objetos de evidencia."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re

from soc_ai_agent.analytics.contracts import AnalyticFinding
from soc_ai_agent.contracts.events import NormalizedEvent
from soc_ai_agent.correlation.contracts import CorrelationEdge
from .contracts import ExcludedEvidence, RedactedField
from .policy import CONTEXT_BUILDER_VERSION, SELECTION_POLICY_VERSION
from .references import ReferenceMap


@dataclass(frozen=True)
class ContextBudget:
    max_findings: int = 20
    max_events: int = 30
    max_correlations: int = 40
    max_artifacts: int = 25


@dataclass(frozen=True)
class EvidenceContext:
    events: tuple[dict, ...]
    correlations: tuple[dict, ...]
    findings: tuple[dict, ...]
    artifacts: tuple[dict, ...]
    excluded_evidence: tuple[ExcludedEvidence, ...]
    redacted_fields: tuple[RedactedField, ...]
    selection_policy_version: str = SELECTION_POLICY_VERSION
    context_builder_version: str = CONTEXT_BUILDER_VERSION
    reference_map: ReferenceMap = ReferenceMap()

    def __post_init__(self):
        if not (self.reference_map.event_aliases or self.reference_map.finding_aliases or self.reference_map.correlation_aliases):
            object.__setattr__(self, "reference_map", ReferenceMap.from_context(self.events, self.correlations, self.findings))


_SECRET = re.compile(r"(?i)\b(password|token|api[_-]?key)\s*([=:])\s*(\"[^\"]*\"|'[^']*'|\S+)")


def _redact_command_line(value: str) -> tuple[str, bool]:
    return _SECRET.sub(r"\1\2<REDACTED>", value), bool(_SECRET.search(value))


def _event_projection(event: NormalizedEvent, redacted: list[RedactedField]) -> dict:
    process = None
    if event.process:
        process = {"image": event.process.image, "command_line": event.process.command_line,
                   "process_guid": event.process.process_guid, "process_id": event.process.process_id,
                   "parent_image": event.process.parent_image, "integrity_level": event.process.integrity_level,
                   "hashes": event.process.hashes}
        if process["command_line"]:
            safe, changed = _redact_command_line(process["command_line"])
            if changed:
                process["command_line"] = safe
                redacted.append(RedactedField(event.event_uid, "process.command_line", "potential_credential_or_token"))
    return {"event_uid": event.event_uid, "source": {"platform": event.source.platform, "provider": event.source.provider,
            "channel": event.source.channel}, "time": {"event_time": event.time.event_time,
            "timezone_status": event.time.timezone_status}, "event": {"code": event.event.code,
            "event_type": event.event.event_type, "outcome": event.event.outcome}, "host": event.host.name if event.host else None,
            "identities": [{"role": item.role, "name": item.name, "domain": item.domain} for item in event.identities],
            "process": process, "network": event.network.__dict__ if event.network else None,
            "correlation": event.correlation.__dict__, "data_quality_warnings": event.data_quality.warnings}


def _edge_projection(edge: CorrelationEdge) -> dict:
    return {"correlation_id": edge.correlation_id, "source_event_uid": edge.source_event_uid,
            "destination_event_uid": edge.destination_event_uid, "relation_type": edge.relation_type,
            "relation_name": edge.relation_name, "strength": edge.strength,
            "matching_keys": [key.__dict__ for key in edge.matching_keys], "limitations": edge.limitations}


def _finding_projection(finding: AnalyticFinding) -> dict:
    return {"finding_id": finding.finding_id, "finding_type": finding.finding_type, "title": finding.title,
            "event_uids": finding.event_uids, "correlation_ids": finding.correlation_ids,
            "status": finding.status, "confidence": finding.confidence, "limitations": finding.limitations,
            "missing_evidence": finding.missing_evidence}


def _usable_utc_time(event: NormalizedEvent) -> datetime | None:
    """Sólo ordena presentación; no crea relación ni implica causalidad."""
    if event.time.timezone_status != "utc" or not event.time.event_time:
        return None
    try:
        parsed = datetime.fromisoformat(event.time.event_time.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _presentation_event_key(event: NormalizedEvent):
    timestamp = _usable_utc_time(event)
    # Los eventos sin hora UTC utilizable no se ordenan por una hora ambigua.
    return (0, timestamp, event.event_uid) if timestamp is not None else (1, None, event.event_uid)


class ContextBuilder:
    def __init__(self, budget: ContextBudget = ContextBudget()) -> None:
        self.budget = budget

    def build(self, events, correlations, findings) -> EvidenceContext:
        excluded: list[ExcludedEvidence] = []; redacted: list[RedactedField] = []
        selected_findings = sorted(findings, key=lambda item: item.finding_id)[:self.budget.max_findings]
        for item in sorted(findings, key=lambda item: item.finding_id)[self.budget.max_findings:]:
            excluded.append(ExcludedEvidence("finding", item.finding_id, "budget:max_findings"))
        finding_ids = {item.finding_id for item in selected_findings}
        wanted_edges = {edge_id for item in selected_findings for edge_id in item.correlation_ids}
        ranked_edges = sorted((item for item in correlations if item.correlation_id in wanted_edges),
            key=lambda item: ({"direct": 0, "supported": 1, "temporal_only": 2}[item.relation_type], item.correlation_id))
        selected_edges = ranked_edges[:self.budget.max_correlations]
        for item in ranked_edges[self.budget.max_correlations:]:
            excluded.append(ExcludedEvidence("correlation", item.correlation_id, "budget:max_correlations"))
        wanted_events = {uid for item in selected_findings for uid in item.event_uids}
        wanted_events.update(uid for edge in selected_edges for uid in (edge.source_event_uid, edge.destination_event_uid))
        selected_events = [item for item in sorted(events, key=_presentation_event_key) if item.event_uid in wanted_events]
        for item in selected_events[self.budget.max_events:]:
            excluded.append(ExcludedEvidence("event", item.event_uid, "budget:max_events"))
        selected_events = selected_events[:self.budget.max_events]
        artifacts = []
        for event in selected_events:
            if event.network:
                for value, kind in ((event.network.source_ip, "ip"), (event.network.destination_ip, "ip")):
                    if value: artifacts.append({"event_uid": event.event_uid, "type": kind, "value": value})
            if event.process:
                for value, kind in ((event.process.image, "process"),):
                    if value: artifacts.append({"event_uid": event.event_uid, "type": kind, "value": value})
        unique_artifacts = list({(item["event_uid"], item["type"], item["value"]): item for item in artifacts}.values())
        for item in unique_artifacts[self.budget.max_artifacts:]:
            excluded.append(ExcludedEvidence("artifact", item["value"], "budget:max_artifacts"))
        projections = (tuple(_event_projection(item, redacted) for item in selected_events),
            tuple(_edge_projection(item) for item in selected_edges), tuple(_finding_projection(item) for item in selected_findings))
        return EvidenceContext(*projections, tuple(unique_artifacts[:self.budget.max_artifacts]), tuple(excluded), tuple(redacted),
            reference_map=ReferenceMap.from_context(*projections))
