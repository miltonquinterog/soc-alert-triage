from dataclasses import dataclass
from typing import Iterable

from soc_ai_agent.contracts.events import NormalizedEvent
from soc_ai_agent.correlation.contracts import CorrelationEdge
from .contracts import AnalyticsResult
from .deduplication import deduplicate
from .rules import (administrative_process_execution, authentication_failure_success, group_membership_change,
    privileged_logon_context, process_network_activity, repeated_failures, repeated_linux_authentication)


@dataclass(frozen=True)
class AnalyticsLimits:
    max_findings: int = 10_000


class AnalyticsEngine:
    def __init__(self, limits: AnalyticsLimits = AnalyticsLimits()) -> None:
        self.limits = limits

    def analyze(self, events: Iterable[NormalizedEvent], edges: Iterable[CorrelationEdge]) -> AnalyticsResult:
        event_list = tuple(events); edge_list = tuple(edges)
        findings, elevated = authentication_failure_success(event_list)
        findings.extend(repeated_failures(event_list, elevated))
        findings.extend(privileged_logon_context(event_list, edge_list))
        findings.extend(process_network_activity(event_list, edge_list))
        findings.extend(administrative_process_execution(event_list, edge_list))
        findings.extend(group_membership_change(event_list))
        findings.extend(repeated_linux_authentication(event_list))
        unique = deduplicate(findings)
        diagnostics = ()
        if len(unique) > self.limits.max_findings:
            diagnostics = (f"finding_limit_exceeded:{len(unique)}",)
            unique = unique[:self.limits.max_findings]
        return AnalyticsResult(unique, diagnostics)
