"""Capacidades de salida derivadas únicamente de las Skills activadas."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReasoningCapabilities:
    mitre_mapping: bool
    ioc_assessment: bool
    incident_reporting: bool

    @classmethod
    def from_skills(cls, skills: tuple[str, ...]):
        return cls("mitre-attack-mapping" in skills, "ioc-analysis" in skills, "incident-reporting" in skills)

    def as_dict(self):
        return {"mitre_mapping": self.mitre_mapping, "ioc_assessment": self.ioc_assessment,
            "incident_reporting": self.incident_reporting}
