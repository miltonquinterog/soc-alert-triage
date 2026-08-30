from dataclasses import replace
import unittest

from soc_ai_agent.analytics.engine import AnalyticsEngine
from soc_ai_agent.contracts.events import (CorrelationInfo, DataQuality, DatasetRef, EventInfo, HostInfo,
    Identity, NormalizedEvent, ProcessInfo, SCHEMA_VERSION, SourceInfo, TimeInfo, make_event_uid)
from soc_ai_agent.correlation.engine import CorrelationEngine


def event(label, *, platform="windows", channel="Security", code="4625", event_type=None, timestamp="2022-01-01T00:00:00+00:00",
          host="host-a", user="user-a", source_ip="192.0.2.10", logon_id=None, process_guid=None, image=None,
          integrity_level=None, identities=()):
    raw = '{"analytics":"' + label + '"}'
    return NormalizedEvent(SCHEMA_VERSION, make_event_uid("analytics", 1, raw), DatasetRef("analytics", "jsonl", 1), raw, None,
        SourceInfo(platform=platform, channel=channel), TimeInfo(event_time=timestamp, event_time_raw=timestamp, timezone_status="utc"),
        EventInfo(code=code, event_type=event_type), HostInfo(name=host), tuple(identities),
        ProcessInfo(image=image, process_guid=process_guid, integrity_level=integrity_level) if image else None, None,
        CorrelationInfo(host=host, user=user, source_ip=source_ip, logon_id=logon_id, process_guid=process_guid), DataQuality())


class AnalyticsTests(unittest.TestCase):
    def test_repeated_failures_remain_observed_without_extra_context(self):
        events = tuple(event(f"f{number}", timestamp=f"2022-01-01T00:0{number}:00+00:00") for number in range(3))
        findings = AnalyticsEngine().analyze(events, ()).findings
        finding = next(item for item in findings if item.finding_type == "repeated_authentication_failures")
        self.assertEqual("observed", finding.status)
        self.assertEqual("low", finding.severity_hint)

    def test_failure_then_success_elevates_repeated_context(self):
        failures = tuple(event(f"f{number}", timestamp=f"2022-01-01T00:0{number}:00+00:00") for number in range(3))
        success = event("success", code="4624", timestamp="2022-01-01T00:04:00+00:00")
        findings = AnalyticsEngine().analyze(failures + (success,), ()).findings
        repeated = next(item for item in findings if item.finding_type == "repeated_authentication_failures")
        sequence = next(item for item in findings if item.finding_type == "authentication_failure_then_success")
        self.assertEqual("requires_investigation", repeated.status)
        self.assertEqual("requires_investigation", sequence.status)

    def test_ambiguous_time_rejects_temporal_findings(self):
        events = tuple(replace(event(f"f{number}"), time=TimeInfo(timezone_status="ambiguous_source_time")) for number in range(3))
        self.assertEqual((), AnalyticsEngine().analyze(events, ()).findings)

    def test_process_network_and_normal_powershell_remain_observed(self):
        process = event("process", channel="Microsoft-Windows-Sysmon/Operational", code="1", event_type="process_create",
            process_guid="{guid}", image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        network = event("network", channel="Microsoft-Windows-Sysmon/Operational", code="3", event_type="network_connection", process_guid="{guid}")
        edges = CorrelationEngine().correlate((process, network)).edges
        findings = AnalyticsEngine().analyze((process, network), edges).findings
        process_network = next(item for item in findings if item.finding_type == "process_network_activity")
        powershell = next(item for item in findings if item.finding_type == "administrative_process_execution")
        self.assertEqual("observed", process_network.status)
        self.assertTrue(any(fact.correlation_id for fact in process_network.observed_facts))
        self.assertEqual("observed", powershell.status)
        self.assertEqual("informational", powershell.severity_hint)
        self.assertIn("high_integrity_process_context", powershell.missing_evidence)

    def test_process_network_with_high_integrity_is_contextualized(self):
        process = event("high-process", channel="Microsoft-Windows-Sysmon/Operational", code="1", event_type="process_create",
            process_guid="{high-guid}", integrity_level="High",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        network = event("high-network", channel="Microsoft-Windows-Sysmon/Operational", code="3", event_type="network_connection",
            process_guid="{high-guid}")
        edges = CorrelationEngine().correlate((process, network)).edges
        finding = next(item for item in AnalyticsEngine().analyze((process, network), edges).findings
                       if item.finding_type == "administrative_process_execution")
        self.assertEqual(("suspicious_context", "low"), (finding.status, finding.severity_hint))

    def test_powershell_alone_is_observed_informational(self):
        process = event("process", channel="Microsoft-Windows-Sysmon/Operational", code="1", event_type="process_create",
            process_guid="{guid}", image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        finding = next(item for item in AnalyticsEngine().analyze((process,), ()).findings
                       if item.finding_type == "administrative_process_execution")
        self.assertEqual(("observed", "informational"), (finding.status, finding.severity_hint))

    def test_privileged_logon_context_uses_direct_edge(self):
        first = event("login", code="4624", logon_id="0x123")
        privilege = event("privilege", code="4672", logon_id="0x123")
        edges = CorrelationEngine().correlate((first, privilege)).edges
        finding = next(item for item in AnalyticsEngine().analyze((first, privilege), edges).findings
                       if item.finding_type == "privileged_logon_context")
        self.assertEqual("observed", finding.status)
        self.assertEqual(1, len(finding.correlation_ids))

    def test_group_membership_requires_structured_roles(self):
        identities = (Identity(role="member", name="analyst"), Identity(role="group", name="Administrators"))
        change = event("group", code="4728", identities=identities)
        finding = next(item for item in AnalyticsEngine().analyze((change,), ()).findings
                       if item.finding_type == "group_membership_change")
        self.assertEqual("observed", finding.status)
        incomplete = replace(change, identities=())
        self.assertFalse(AnalyticsEngine().analyze((incomplete,), ()).findings)

    def test_repeated_linux_authentication(self):
        events = tuple(event(f"l{number}", platform="linux", channel=None, code=None, event_type="authentication",
            timestamp=f"2022-01-01T00:0{number}:00+00:00") for number in range(3))
        finding = next(item for item in AnalyticsEngine().analyze(events, ()).findings
                       if item.finding_type == "repeated_linux_authentication_activity")
        self.assertEqual("observed", finding.status)

    def test_duplicate_input_produces_one_deterministic_finding(self):
        events = tuple(event(f"f{number}", timestamp=f"2022-01-01T00:0{number}:00+00:00") for number in range(3))
        findings = AnalyticsEngine().analyze(events + events, ()).findings
        repeated = [item for item in findings if item.finding_type == "repeated_authentication_failures"]
        self.assertEqual(1, len(repeated))
