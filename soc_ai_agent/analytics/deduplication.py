from soc_ai_agent.analytics.contracts import AnalyticFinding


def deduplicate(findings: list[AnalyticFinding]) -> tuple[AnalyticFinding, ...]:
    """Un finding por identidad determinista; no modifica la evidencia asociada."""
    return tuple(sorted({finding.finding_id: finding for finding in findings}.values(),
                        key=lambda finding: finding.finding_id))
