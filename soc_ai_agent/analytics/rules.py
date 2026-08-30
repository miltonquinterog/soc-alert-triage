"""Reglas descriptivas y deterministas para patrones observados."""

from __future__ import annotations

from dataclasses import replace
from pathlib import PureWindowsPath

from soc_ai_agent.contracts.events import NormalizedEvent
from soc_ai_agent.correlation.contracts import CorrelationEdge
from .contracts import (ANALYTICS_SCHEMA_VERSION, AnalyticFinding, EvidencePath, ObservedFact,
    make_finding_id)
from .indexing import authentication_groups
from .time_policy import AUTH_WINDOW_SECONDS, usable_time


def _finding(finding_type, title, events, correlations=(), facts=(), evidence=(), severity="informational",
             confidence="high", status="observed", limitations=(), missing=(), rule_name="", rule_version="v1",
             grouping_key=()):
    event_uids = tuple(sorted(event.event_uid for event in events))
    correlation_ids = tuple(sorted(edge.correlation_id for edge in correlations))
    return AnalyticFinding(ANALYTICS_SCHEMA_VERSION,
        make_finding_id(rule_name, rule_version, finding_type, event_uids, correlation_ids, tuple(grouping_key)),
        finding_type, title, event_uids, correlation_ids, tuple(facts), tuple(evidence), severity, confidence,
        status, tuple(limitations), tuple(missing), rule_name, rule_version)


def _windows_auth(event: NormalizedEvent, code: str) -> bool:
    return event.source.platform == "windows" and event.source.channel == "Security" and event.event.code == code


def _linux_auth(event: NormalizedEvent) -> bool:
    return event.source.platform == "linux" and event.event.event_type == "authentication"


def _time_clusters(events: tuple[NormalizedEvent, ...]):
    """Secuencias máximas cuya extensión total no excede la ventana configurada."""
    valid = [(event, usable_time(event)) for event in events]
    valid = [(event, stamp) for event, stamp in valid if stamp is not None]
    clusters = []
    current = []
    start = None
    for event, stamp in valid:
        if start is None or (stamp - start).total_seconds() <= AUTH_WINDOW_SECONDS:
            current.append(event); start = start or stamp
        else:
            clusters.append(tuple(current)); current = [event]; start = stamp
    if current: clusters.append(tuple(current))
    return clusters


def authentication_failure_success(events: tuple[NormalizedEvent, ...]) -> tuple[list[AnalyticFinding], set[str]]:
    findings, elevated_failures = [], set()
    for key, group in authentication_groups(events, "windows").items():
        failures = [item for item in group if _windows_auth(item, "4625") and usable_time(item)]
        successes = [item for item in group if _windows_auth(item, "4624") and usable_time(item)]
        for success in successes:
            related = [failure for failure in failures if 0 <= (usable_time(success) - usable_time(failure)).total_seconds() <= AUTH_WINDOW_SECONDS]
            if not related: continue
            selected = tuple(related + [success])
            elevated_failures.update(item.event_uid for item in related)
            user, host, source_ip = key
            facts = (ObservedFact("failure_event_count", str(len(related))), ObservedFact("subsequent_success", "true"))
            evidence = (EvidencePath(success.event_uid, "event.code", "4624"),
                EvidencePath(success.event_uid, "correlation.user", user), EvidencePath(success.event_uid, "correlation.host", host),
                EvidencePath(success.event_uid, "correlation.source_ip", source_ip))
            findings.append(_finding("authentication_failure_then_success", "Authentication failures followed by success", selected,
                facts=facts, evidence=evidence, severity="medium", confidence="high", status="requires_investigation",
                limitations=("sequence_describes_observed_events",), missing=("authentication_context",),
                rule_name="authentication_failure_then_success_v1", grouping_key=key + (success.event_uid,)))
    return findings, elevated_failures


def repeated_failures(events: tuple[NormalizedEvent, ...], elevated_failures: set[str]) -> list[AnalyticFinding]:
    findings = []
    for key, group in authentication_groups(events, "windows").items():
        failures = tuple(item for item in group if _windows_auth(item, "4625"))
        for cluster in _time_clusters(failures):
            if len(cluster) < 3: continue
            elevated = any(item.event_uid in elevated_failures for item in cluster)
            user, host, source_ip = key
            facts = [ObservedFact("failure_event_count", str(len(cluster))), ObservedFact("grouping_key", "|".join(key))]
            if elevated: facts.append(ObservedFact("related_subsequent_success", "true"))
            evidence = tuple(EvidencePath(item.event_uid, "event.code", "4625") for item in cluster) + (
                EvidencePath(cluster[0].event_uid, "correlation.user", user), EvidencePath(cluster[0].event_uid, "correlation.host", host),
                EvidencePath(cluster[0].event_uid, "correlation.source_ip", source_ip))
            findings.append(_finding("repeated_authentication_failures", "Repeated authentication failures", cluster,
                facts=facts, evidence=evidence, severity="medium" if elevated else "low", confidence="high",
                status="requires_investigation" if elevated else "observed",
                limitations=("pattern_does_not_establish_cause",), missing=("authentication_context",),
                rule_name="repeated_authentication_failures_v1", grouping_key=key + (cluster[0].event_uid, cluster[-1].event_uid)))
    return findings


def privileged_logon_context(events: tuple[NormalizedEvent, ...], edges: tuple[CorrelationEdge, ...]) -> list[AnalyticFinding]:
    by_uid = {event.event_uid: event for event in events}; findings = []
    for edge in edges:
        if edge.relation_name != "windows_logon_session_v1" or edge.relation_type != "direct": continue
        pair = [by_uid.get(edge.source_event_uid), by_uid.get(edge.destination_event_uid)]
        if None in pair or not any(item.event.code == "4672" for item in pair): continue
        facts = (ObservedFact("shared_logon_id", next(key.value for key in edge.matching_keys if key.field == "logon_id"), edge.correlation_id),)
        evidence = tuple(EvidencePath(item.event_uid, "event.code", item.event.code or "", edge.correlation_id) for item in pair)
        findings.append(_finding("privileged_logon_context", "Privileged logon context", tuple(pair), (edge,), facts, evidence,
            severity="medium", confidence="high", limitations=("describes_session_context",),
            rule_name="privileged_logon_context_v1", grouping_key=(edge.correlation_id,)))
    return findings


def process_network_activity(events: tuple[NormalizedEvent, ...], edges: tuple[CorrelationEdge, ...]) -> list[AnalyticFinding]:
    by_uid = {event.event_uid: event for event in events}; findings = []
    for edge in edges:
        if edge.relation_name != "sysmon_process_guid_link_v1" or edge.relation_type != "direct": continue
        pair = [by_uid.get(edge.source_event_uid), by_uid.get(edge.destination_event_uid)]
        if None in pair or {item.event.code for item in pair} != {"1", "3"}: continue
        facts = (ObservedFact("shared_process_guid", next(key.value for key in edge.matching_keys if key.field == "process_guid"), edge.correlation_id),)
        evidence = tuple(EvidencePath(item.event_uid, "event.code", item.event.code or "", edge.correlation_id) for item in pair)
        findings.append(_finding("process_network_activity", "Process and network activity", tuple(pair), (edge,), facts, evidence,
            confidence="high", limitations=("describes_linked_process_and_network_events",),
            rule_name="process_network_activity_v1", grouping_key=(edge.correlation_id,)))
    return findings


def administrative_process_execution(events: tuple[NormalizedEvent, ...], edges: tuple[CorrelationEdge, ...]) -> list[AnalyticFinding]:
    findings = []
    for event in events:
        if event.event.code != "1" or not event.process or not event.process.image: continue
        name = PureWindowsPath(event.process.image).name.lower()
        if name not in {"powershell.exe", "pwsh.exe", "cmd.exe"}: continue
        related = tuple(edge for edge in edges if event.event_uid in {edge.source_event_uid, edge.destination_event_uid}
                        and edge.relation_name == "sysmon_process_guid_link_v1" and edge.relation_type == "direct")
        # A direct network link documents additional activity but is not sufficient by itself.
        # Elevation requires a second, explicit normalized context signal.
        elevated = bool(related) and event.process.integrity_level in {"High", "System"}
        facts = [ObservedFact("process_image", event.process.image)]
        evidence = [EvidencePath(event.event_uid, "process.image", event.process.image)]
        for edge in related:
            facts.append(ObservedFact("direct_process_network_link", "true", edge.correlation_id))
            evidence.append(EvidencePath(event.event_uid, "correlation.process_guid", event.correlation.process_guid or "", edge.correlation_id))
        missing = () if elevated else (("high_integrity_process_context",) if related else ("related_normalized_context",))
        findings.append(_finding("administrative_process_execution", "Administrative process execution context", (event,), related,
            facts, evidence, severity="low" if elevated else "informational", confidence="moderate" if elevated else "high",
            status="suspicious_context" if elevated else "observed", limitations=("process_name_alone_is_context",),
            missing=missing, rule_name="administrative_process_execution_v1",
            grouping_key=(event.event_uid,)))
    return findings


def group_membership_change(events: tuple[NormalizedEvent, ...]) -> list[AnalyticFinding]:
    codes = {"4728", "4729", "4732", "4733", "4756", "4757"}; findings = []
    for event in events:
        if event.source.platform != "windows" or event.source.channel != "Security" or event.event.code not in codes or not event.host: continue
        member = next((identity for identity in event.identities if identity.role == "member" and identity.name), None)
        group = next((identity for identity in event.identities if identity.role == "group" and identity.name), None)
        if not member or not group: continue
        facts = (ObservedFact("member", member.name), ObservedFact("group", group.name))
        evidence = (EvidencePath(event.event_uid, "identities[role=member].name", member.name),
            EvidencePath(event.event_uid, "identities[role=group].name", group.name))
        findings.append(_finding("group_membership_change", "Group membership change", (event,), facts=facts, evidence=evidence,
            severity="medium", confidence="high", limitations=("describes_recorded_membership_change",),
            rule_name="group_membership_change_v1", grouping_key=(event.event_uid,)))
    return findings


def repeated_linux_authentication(events: tuple[NormalizedEvent, ...]) -> list[AnalyticFinding]:
    findings = []
    for key, group in authentication_groups(events, "linux").items():
        for cluster in _time_clusters(tuple(item for item in group if _linux_auth(item))):
            if len(cluster) < 3: continue
            user, host, source_ip = key
            facts = (ObservedFact("authentication_event_count", str(len(cluster))),)
            evidence = (EvidencePath(cluster[0].event_uid, "correlation.user", user), EvidencePath(cluster[0].event_uid, "correlation.host", host),
                EvidencePath(cluster[0].event_uid, "correlation.source_ip", source_ip))
            findings.append(_finding("repeated_linux_authentication_activity", "Repeated Linux authentication activity", cluster,
                facts=facts, evidence=evidence, confidence="high", limitations=("describes_repeated_activity",),
                rule_name="repeated_linux_authentication_activity_v1", grouping_key=key + (cluster[0].event_uid, cluster[-1].event_uid)))
    return findings
