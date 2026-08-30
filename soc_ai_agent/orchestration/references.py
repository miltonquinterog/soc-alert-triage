"""Aliases deterministas para la frontera LLM; los contratos internos conservan IDs reales."""

from __future__ import annotations

from dataclasses import dataclass

from soc_ai_agent.reasoning.errors import BackendResponseSchemaViolation


def _leaf_paths(value, prefix="") -> set[str]:
    if isinstance(value, dict):
        return {path for key, child in value.items()
                for path in _leaf_paths(child, f"{prefix}.{key}" if prefix else key)}
    if isinstance(value, list):
        return set()
    return {prefix} if value is not None and prefix else set()


@dataclass(frozen=True)
class ReferenceMap:
    event_aliases: tuple[tuple[str, str], ...] = ()
    finding_aliases: tuple[tuple[str, str], ...] = ()
    correlation_aliases: tuple[tuple[str, str], ...] = ()
    allowed_paths: tuple[str, ...] = ()
    version: str = "1.0"

    @classmethod
    def from_context(cls, events, correlations, findings):
        return cls(tuple((f"e{index}", item["event_uid"]) for index, item in enumerate(events, 1)),
            tuple((f"f{index}", item["finding_id"]) for index, item in enumerate(findings, 1)),
            tuple((f"c{index}", item["correlation_id"]) for index, item in enumerate(correlations, 1)),
            tuple(sorted(set().union(*(_leaf_paths(item) for item in (*events, *correlations, *findings))))))

    def aliases(self, kind: str) -> tuple[str, ...]:
        return tuple(alias for alias, _identifier in getattr(self, f"{kind}_aliases"))

    def resolve(self, kind: str, alias: str) -> str:
        mapping = dict(getattr(self, f"{kind}_aliases"))
        if alias not in mapping:
            error = BackendResponseSchemaViolation("unknown compact reference")
            error.failure_stage = "response_schema"; error.validation_path = f"$.{kind}_ref"
            error.schema_rule = "enum"; error.expected_type = f"known {kind} alias"; error.received_type = "string"
            raise error
        return mapping[alias]


def project_context_aliases(context) -> dict:
    """Proyección sin IDs largos: el modelo recibe aliases, no los hashes de correlación."""
    refs = context.reference_map
    event_alias = dict((identifier, alias) for alias, identifier in refs.event_aliases)
    finding_alias = dict((identifier, alias) for alias, identifier in refs.finding_aliases)
    correlation_alias = dict((identifier, alias) for alias, identifier in refs.correlation_aliases)
    events = tuple({**item, "event_uid": event_alias[item["event_uid"]]} for item in context.events)
    correlations = tuple({**item, "correlation_id": correlation_alias[item["correlation_id"]],
        **({"source_event_uid": event_alias[item["source_event_uid"]]} if "source_event_uid" in item else {}),
        **({"destination_event_uid": event_alias[item["destination_event_uid"]]} if "destination_event_uid" in item else {})}
        for item in context.correlations)
    findings = tuple({**item, "finding_id": finding_alias[item["finding_id"]],
        **({"event_uids": tuple(event_alias[value] for value in item["event_uids"])} if "event_uids" in item else {}),
        **({"correlation_ids": tuple(correlation_alias[value] for value in item["correlation_ids"])} if "correlation_ids" in item else {})}
        for item in context.findings)
    artifacts = tuple({**item, "event_uid": event_alias[item["event_uid"]]} for item in context.artifacts)
    return {"events": events, "correlations": correlations, "findings": findings, "artifacts": artifacts,
        "allowed_reference_aliases": {"events": refs.aliases("event"), "findings": refs.aliases("finding"),
            "correlations": refs.aliases("correlation")}, "allowed_evidence_paths": refs.allowed_paths,
        "redacted_fields": tuple({"event_ref": event_alias[item.event_uid], "path": item.path, "reason": item.reason}
            for item in context.redacted_fields)}


def resolve_response_aliases(payload: dict, refs: ReferenceMap) -> dict:
    """Convierte sólo aliases válidos; no aproxima IDs ni descompone rutas concatenadas."""
    def resolve_list(values, kind): return [refs.resolve(kind, value) for value in values]
    def statement(item):
        result = dict(item)
        result["supporting_event_uids"] = resolve_list(item.pop("supporting_event_refs"), "event")
        result["supporting_correlation_ids"] = resolve_list(item.pop("supporting_correlation_refs"), "correlation")
        result["supporting_finding_ids"] = resolve_list(item.pop("supporting_finding_refs"), "finding")
        paths = []
        for path in item.pop("evidence_paths"):
            target = [("event", path["event_ref"]), ("correlation", path["correlation_ref"]), ("finding", path["finding_ref"])]
            present = [(kind, value) for kind, value in target if value is not None]
            if len(present) != 1 or path["path"] is None or path["path"] not in refs.allowed_paths:
                error = BackendResponseSchemaViolation("invalid compact evidence reference")
                error.failure_stage = "response_schema"; error.validation_path = "$.evidence_paths"
                error.schema_rule = "reference_path"; error.expected_type = "one known target and one allowed path"; error.received_type = "object"
                raise error
            kind, alias = present[0]
            paths.append({f"{kind}_uid" if kind == "event" else f"{kind}_id": refs.resolve(kind, alias), "path": path["path"]})
        result["evidence_paths"] = paths
        return result
    result = dict(payload)
    for section in ("facts", "inferences", "hypotheses", "conclusions", "false_positive_considerations"):
        result[section] = [statement(dict(item)) for item in payload[section]]
    for section in ("mitre_mappings", "ioc_assessments"):
        values = []
        for item in payload[section]:
            value = dict(item)
            value["supporting_event_uids"] = resolve_list(value.pop("supporting_event_refs"), "event")
            value["supporting_correlation_ids"] = resolve_list(value.pop("supporting_correlation_refs"), "correlation")
            value["supporting_finding_ids"] = resolve_list(value.pop("supporting_finding_refs"), "finding")
            values.append(value)
        result[section] = values
    return result
