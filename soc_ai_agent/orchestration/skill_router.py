from .policy import SKILL_VERSIONS


class SkillRouter:
    def route(self, context, request_report: bool = False) -> tuple[str, ...]:
        skills = []
        if any(event["source"]["platform"] == "windows" for event in context.events): skills.append("windows-log-analysis")
        if context.artifacts: skills.append("ioc-analysis")
        if context.findings: skills.append("soc-alert-triage")
        # MITRE only after a non-isolated behavioral finding with contextual status.
        if any(item["finding_type"] in {"process_network_activity", "group_membership_change"} and item["status"] == "suspicious_context"
               for item in context.findings): skills.append("mitre-attack-mapping")
        if request_report: skills.append("incident-reporting")
        return tuple(skills)

    def versions(self, skills: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
        return tuple((skill, SKILL_VERSIONS[skill]) for skill in skills)
