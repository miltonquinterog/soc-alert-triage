"""Motor acotado que recibe sólo NormalizedEvent y devuelve CorrelationResult."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from soc_ai_agent.contracts.events import NormalizedEvent
from .contracts import CorrelationResult
from .indexing import grouped
from .rules import authentication_edges, sysmon_process_guid_edges, temporal_only_edges, windows_logon_edges


@dataclass(frozen=True)
class CorrelationLimits:
    max_group_events: int = 500
    max_edges: int = 10_000


class CorrelationEngine:
    def __init__(self, limits: CorrelationLimits = CorrelationLimits()) -> None:
        self.limits = limits

    def correlate(self, events: Iterable[NormalizedEvent]) -> CorrelationResult:
        ordered = tuple(sorted(events, key=lambda event: event.event_uid))
        # Indexes are also an explicit guard against unbounded all-pairs processing.
        process_groups, process_diagnostics = grouped(ordered, lambda event: event.correlation.process_guid, self.limits.max_group_events)
        logon_groups, logon_diagnostics = grouped(ordered, lambda event: (event.correlation.host, event.correlation.logon_id)
            if event.correlation.host and event.correlation.logon_id not in {None, "", "0x0", "-"} else None, self.limits.max_group_events)
        auth_groups, auth_diagnostics = grouped(ordered, lambda event: (event.source.platform, event.correlation.host, event.correlation.user, event.correlation.source_ip)
            if event.correlation.host and event.correlation.user and event.correlation.source_ip else None, self.limits.max_group_events)
        edges = []
        for members in process_groups.values(): edges.extend(sysmon_process_guid_edges(members))
        for members in logon_groups.values(): edges.extend(windows_logon_edges(members))
        for key, members in auth_groups.items():
            edges.extend(authentication_edges(members, key[0]))
        # Temporal pairs are restricted by category and prepartitioned by host.
        host_groups, host_diagnostics = grouped(ordered, lambda event: event.correlation.host, self.limits.max_group_events)
        for members in host_groups.values(): edges.extend(temporal_only_edges(members))
        unique = {edge.correlation_id: edge for edge in edges}
        sorted_edges = tuple(sorted(unique.values(), key=lambda edge: edge.correlation_id))
        diagnostics = process_diagnostics + logon_diagnostics + auth_diagnostics + host_diagnostics
        if len(sorted_edges) > self.limits.max_edges:
            diagnostics += (f"edge_limit_exceeded:{len(sorted_edges)}",)
            sorted_edges = sorted_edges[:self.limits.max_edges]
        return CorrelationResult(sorted_edges, diagnostics)
