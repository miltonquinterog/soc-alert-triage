"""Reglas reproducibles; no clasifican actividad ni alteran eventos."""

from __future__ import annotations

from itertools import combinations

from soc_ai_agent.contracts.events import NormalizedEvent
from .contracts import (CORRELATION_SCHEMA_VERSION, CorrelationEdge, CorrelationEvidence,
    MatchedKey, TimeWindow, make_correlation_id)
from .time_policy import AUTH_WINDOW_SECONDS, TEMPORAL_WINDOW_SECONDS, window_between


PLACEHOLDERS = {"", "-", "NOT_TRANSLATED", "0x0"}


def event_category(event: NormalizedEvent) -> str | None:
    if event.event.event_type in {"process_create", "process"}: return "process"
    if event.event.event_type in {"network_connection", "network"}: return "network"
    if event.event.event_type in {"file_create", "file"}: return "file"
    if event.event.event_type == "authentication": return "authentication"
    if event.source.platform == "windows" and event.source.channel == "Security" and event.event.code in {"4624", "4625"}:
        return "authentication"
    return None


def _valid(value: str | None) -> bool:
    return value is not None and value not in PLACEHOLDERS


def _ordered(first: NormalizedEvent, second: NormalizedEvent, time_window: TimeWindow | None = None):
    if time_window and time_window.source_time > time_window.destination_time:
        return second, first, TimeWindow(time_window.destination_time, time_window.source_time,
                                          time_window.delta_seconds, time_window.policy_name)
    if time_window is None and first.event_uid > second.event_uid:
        return second, first, None
    return first, second, time_window


def _edge(source: NormalizedEvent, destination: NormalizedEvent, relation_type: str, relation_name: str,
          strength: str, keys: tuple[MatchedKey, ...], time_window: TimeWindow | None = None,
          limitations: tuple[str, ...] = ()) -> CorrelationEdge:
    source, destination, time_window = _ordered(source, destination, time_window)
    # MatchedKey paths name both endpoints explicitly; values are verified before this call.
    evidence = CorrelationEvidence(source.event.event_type, destination.event.event_type,
        source.source.platform, destination.source.platform, len(keys),
        "event_time" if time_window else "not_required")
    return CorrelationEdge(CORRELATION_SCHEMA_VERSION,
        make_correlation_id(source.event_uid, destination.event_uid, relation_name, keys),
        source.event_uid, destination.event_uid, relation_type, relation_name, strength, keys,
        time_window, evidence, limitations=limitations)


def sysmon_process_guid_edges(events: tuple[NormalizedEvent, ...]) -> list[CorrelationEdge]:
    process = [event for event in events if event.event.code == "1" and event.source.channel == "Microsoft-Windows-Sysmon/Operational"]
    network = [event for event in events if event.event.code == "3" and event.source.channel == "Microsoft-Windows-Sysmon/Operational"]
    edges = []
    for source in process:
        guid = source.correlation.process_guid
        if not _valid(guid): continue
        for destination in network:
            if destination.correlation.process_guid != guid: continue
            if source.correlation.host and destination.correlation.host and source.correlation.host != destination.correlation.host: continue
            keys = [MatchedKey("process_guid", guid, "correlation.process_guid", "correlation.process_guid")]
            if source.correlation.host and destination.correlation.host:
                keys.append(MatchedKey("host", source.correlation.host, "correlation.host", "correlation.host"))
            edges.append(_edge(source, destination, "direct", "sysmon_process_guid_link_v1", "strong", tuple(keys)))
    return edges


def windows_logon_edges(events: tuple[NormalizedEvent, ...]) -> list[CorrelationEdge]:
    security = [event for event in events if event.source.platform == "windows" and event.source.channel == "Security"]
    edges = []
    for first, second in combinations(security, 2):
        logon_id = first.correlation.logon_id
        host = first.correlation.host
        if not _valid(logon_id) or not _valid(host): continue
        if second.correlation.logon_id != logon_id or second.correlation.host != host: continue
        keys = (MatchedKey("logon_id", logon_id, "correlation.logon_id", "correlation.logon_id"),
                MatchedKey("host", host, "correlation.host", "correlation.host"))
        edges.append(_edge(first, second, "direct", "windows_logon_session_v1", "strong", keys))
    return edges


def authentication_edges(events: tuple[NormalizedEvent, ...], platform: str) -> list[CorrelationEdge]:
    candidates = [event for event in events if event.source.platform == platform and event_category(event) == "authentication"]
    name = "windows_auth_sequence_v1" if platform == "windows" else "linux_auth_sequence_v1"
    edges = []
    for first, second in combinations(candidates, 2):
        values = (first.correlation.user, first.correlation.host, first.correlation.source_ip)
        if not all(_valid(value) for value in values): continue
        if values != (second.correlation.user, second.correlation.host, second.correlation.source_ip): continue
        time_window = window_between(first, second, AUTH_WINDOW_SECONDS, "authentication_15m_v1")
        if time_window is None: continue
        keys = (MatchedKey("user", values[0], "correlation.user", "correlation.user"),
                MatchedKey("host", values[1], "correlation.host", "correlation.host"),
                MatchedKey("source_ip", values[2], "correlation.source_ip", "correlation.source_ip"))
        edges.append(_edge(first, second, "supported", name, "moderate", keys, time_window))
    return edges


USEFUL_TEMPORAL_PAIRS = {frozenset(("authentication", "process")), frozenset(("process", "network")), frozenset(("process", "file"))}


def temporal_only_edges(events: tuple[NormalizedEvent, ...]) -> list[CorrelationEdge]:
    edges = []
    for first, second in combinations(events, 2):
        categories = frozenset((event_category(first), event_category(second)))
        if categories not in USEFUL_TEMPORAL_PAIRS: continue
        host = first.correlation.host
        if not _valid(host) or second.correlation.host != host: continue
        time_window = window_between(first, second, TEMPORAL_WINDOW_SECONDS, "temporal_proximity_5m_v1")
        if time_window is None: continue
        keys = (MatchedKey("host", host, "correlation.host", "correlation.host"),)
        edges.append(_edge(first, second, "temporal_only", "temporal_proximity_v1", "weak", keys,
                           time_window, ("temporal_proximity_does_not_establish_causality",)))
    return edges
