from __future__ import annotations

from soc_ai_agent.contracts.events import NormalizedEvent
from soc_ai_agent.ingestion.jsonl import RawJsonRecord
from .common import payload_of
from .linux_auth import LinuxAuthNormalizer
from .sysmon import SysmonEvent1Normalizer, SysmonEvent3Normalizer
from .windows_security import WindowsSecurityNormalizer


class NormalizerRegistry:
    def __init__(self) -> None:
        self._windows_security = WindowsSecurityNormalizer()
        self._sysmon_1 = SysmonEvent1Normalizer()
        self._sysmon_3 = SysmonEvent3Normalizer()
        self._linux_auth = LinuxAuthNormalizer()

    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        data = payload_of(record.parsed)
        sourcetype = data.get("sourcetype")
        channel = data.get("LogName")
        code = str(data.get("EventCode")) if data.get("EventCode") is not None else None
        if sourcetype == "linux:auth": return self._linux_auth.normalize(record)
        if channel == "Security": return self._windows_security.normalize(record)
        if channel == "Microsoft-Windows-Sysmon/Operational" and code == "1": return self._sysmon_1.normalize(record)
        if channel == "Microsoft-Windows-Sysmon/Operational" and code == "3": return self._sysmon_3.normalize(record)
        raise ValueError("No normalizer registered for this record in phase 1")


def default_registry() -> NormalizerRegistry:
    return NormalizerRegistry()
