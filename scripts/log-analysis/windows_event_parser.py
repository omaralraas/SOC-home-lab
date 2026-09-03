#!/usr/bin/env python3
"""
SOC Home Lab - Windows Event Log Parser
=========================================
Parses Windows Security event log XML exports, detects anomalies,
and generates a timeline of suspicious activity.

Author: Omar Alraas
Usage:  python windows_event_parser.py --file SecurityEvents.xml --output report.json
"""

import xml.etree.ElementTree as ET
import json
import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set


# Windows Security Event ID mappings
EVENT_DESCRIPTIONS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempted",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4740: "Account Locked Out",
    7045: "New Service Installed",
}

# MITRE ATT&CK mappings for events
MITRE_MAPPINGS = {
    4625: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    4648: {"technique": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts"},
    4688: {"technique": "T1059", "tactic": "Execution", "name": "Command Interpreter"},
    4697: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service"},
    4698: {"technique": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task"},
    4720: {"technique": "T1136.001", "tactic": "Persistence", "name": "Create Account"},
    7045: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service"},
}

# Logon type descriptions
LOGON_TYPES = {
    "2": "Interactive (local)",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials (RunAs)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


@dataclass
class WindowsEvent:
    """Represents a parsed Windows Security event."""
    event_id: int
    timestamp: str
    computer: str
    description: str
    logon_type: Optional[str] = None
    logon_type_desc: Optional[str] = None
    target_user: Optional[str] = None
    target_domain: Optional[str] = None
    source_ip: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    logon_id: Optional[str] = None
    service_name: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


@dataclass
class AnomalyAlert:
    """Represents a detected anomaly."""
    alert_type: str
    severity: str
    description: str
    events: List[Dict] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    recommendation: str = ""


@dataclass
class WindowsEventReport:
    """Complete Windows event analysis report."""
    total_events: int = 0
    event_summary: Dict[int, int] = field(default_factory=dict)
    anomalies: List[AnomalyAlert] = field(default_factory=list)
    suspicious_events: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    unique_users: int = 0
    unique_source_ips: int = 0
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class WindowsEventParser:
    """Parses Windows Security Event Log XML exports."""

    def __init__(self):
        self.ns = {
            'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'
        }

    def parse_file(self, filepath: str) -> List[WindowsEvent]:
        """Parse a Windows Event XML export file."""
        events = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for event_elem in root.iter():
                if event_elem.tag.endswith('Event') or event_elem.tag == 'Event':
                    parsed = self._parse_event_element(event_elem)
                    if parsed:
                        events.append(parsed)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        except ET.ParseError as e:
            print(f"[ERROR] XML parse error: {e}", file=sys.stderr)
            sys.exit(1)

        events.sort(key=lambda e: e.timestamp)
        return events

    def _parse_event_element(self, elem) -> Optional[WindowsEvent]:
        """Parse a single Event XML element."""
        try:
            system = elem.find('.//System', self.ns) or elem.find('.//evt:System', self.ns)
            event_data = elem.find('.//EventData', self.ns) or elem.find('.//evt:EventData', self.ns)

            if system is None:
                # Try without namespace
                system = elem.find('System')
                event_data = elem.find('EventData')

            if system is None:
                return None

            event_id_elem = system.find('EventID') or system.find('evt:EventID', self.ns)
            time_elem = system.find('TimeCreated') or system.find('evt:TimeCreated', self.ns)
            computer_elem = system.find('Computer') or system.find('evt:Computer', self.ns)

            if event_id_elem is None:
                return None

            event_id = int(event_id_elem.text)
            timestamp = time_elem.get('SystemTime', '') if time_elem is not None else ''
            computer = computer_elem.text if computer_elem is not None else 'unknown'

            event = WindowsEvent(
                event_id=event_id,
                timestamp=timestamp,
                computer=computer,
                description=EVENT_DESCRIPTIONS.get(event_id, f"Event {event_id}")
            )

            # Parse EventData fields
            if event_data is not None:
                data_fields = {}
                for data in event_data:
                    name = data.get('Name', '')
                    value = data.text or ''
                    data_fields[name] = value

                event.target_user = data_fields.get('TargetUserName', '')
                event.target_domain = data_fields.get('TargetDomainName', '')
                event.source_ip = data_fields.get('IpAddress', '')
                event.logon_type = data_fields.get('LogonType', '')
                event.logon_id = data_fields.get('TargetLogonId', '')
                event.process_name = data_fields.get('NewProcessName', '')
                event.command_line = data_fields.get('CommandLine', '')
                event.service_name = data_fields.get('ServiceName', '')

                if event.logon_type:
                    event.logon_type_desc = LOGON_TYPES.get(event.logon_type, f"Type {event.logon_type}")

            # Add MITRE mapping
            if event_id in MITRE_MAPPINGS:
                event.mitre_technique = MITRE_MAPPINGS[event_id]['technique']
                event.mitre_tactic = MITRE_MAPPINGS[event_id]['tactic']

            return event
        except Exception:
            return None


class AnomalyDetector:
    """Detects anomalies in Windows Security events."""

    def __init__(self, business_hours: tuple = (8, 18)):
        self.business_start = business_hours[0]
        self.business_end = business_hours[1]

    def detect_all(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Run all anomaly detection checks."""
        anomalies = []
        anomalies.extend(self._detect_off_hours_logons(events))
        anomalies.extend(self._detect_failed_logon_spikes(events))
        anomalies.extend(self._detect_privilege_escalation(events))
        anomalies.extend(self._detect_suspicious_services(events))
        anomalies.extend(self._detect_account_manipulation(events))
        return anomalies

    def _detect_off_hours_logons(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Detect interactive/RDP logons outside business hours."""
        alerts = []
        off_hours_logons = []

        for event in events:
            if event.event_id == 4624 and event.logon_type in ('2', '10'):
                try:
                    ts = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                    if ts.hour < self.business_start or ts.hour >= self.business_end:
                        off_hours_logons.append(event)
                except (ValueError, AttributeError):
                    continue

        if off_hours_logons:
            alerts.append(AnomalyAlert(
                alert_type="Off-Hours Interactive Logon",
                severity="medium",
                description=f"{len(off_hours_logons)} interactive/RDP logon(s) detected outside business hours ({self.business_start}:00-{self.business_end}:00)",
                events=[asdict(e) for e in off_hours_logons[:10]],
                mitre_technique="T1078",
                recommendation="Verify these logons with the account owners. Investigate if unexpected."
            ))

        return alerts

    def _detect_failed_logon_spikes(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Detect spikes in failed logon attempts."""
        alerts = []
        failed_by_user: Dict[str, int] = Counter()

        for event in events:
            if event.event_id == 4625 and event.target_user:
                failed_by_user[event.target_user] += 1

        for user, count in failed_by_user.items():
            if count >= 10:
                severity = "critical" if count >= 50 else "high" if count >= 20 else "medium"
                alerts.append(AnomalyAlert(
                    alert_type="Failed Logon Spike",
                    severity=severity,
                    description=f"Account '{user}' has {count} failed logon attempts",
                    mitre_technique="T1110",
                    recommendation="Investigate source IPs, check if account is targeted. Consider temporary lockout."
                ))

        return alerts

    def _detect_privilege_escalation(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Detect potential privilege escalation chains."""
        alerts = []
        priv_events = [e for e in events if e.event_id == 4672]

        if len(priv_events) > 20:
            alerts.append(AnomalyAlert(
                alert_type="Excessive Privilege Assignments",
                severity="high",
                description=f"{len(priv_events)} special privilege assignments detected",
                events=[asdict(e) for e in priv_events[:5]],
                mitre_technique="T1078",
                recommendation="Review accounts receiving special privileges. Investigate any non-admin accounts."
            ))

        return alerts

    def _detect_suspicious_services(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Detect suspicious service installations."""
        alerts = []
        for event in events:
            if event.event_id in (4697, 7045) and event.service_name:
                alerts.append(AnomalyAlert(
                    alert_type="New Service Installation",
                    severity="high",
                    description=f"New service installed: {event.service_name}",
                    events=[asdict(event)],
                    mitre_technique="T1543.003",
                    recommendation="Verify this service is legitimate and expected."
                ))

        return alerts

    def _detect_account_manipulation(self, events: List[WindowsEvent]) -> List[AnomalyAlert]:
        """Detect account creation and group modifications."""
        alerts = []
        for event in events:
            if event.event_id == 4720:
                alerts.append(AnomalyAlert(
                    alert_type="User Account Created",
                    severity="medium",
                    description=f"New user account created: {event.target_user}",
                    events=[asdict(event)],
                    mitre_technique="T1136.001",
                    recommendation="Verify this account creation was authorized."
                ))

        return alerts


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SOC Home Lab - Windows Event Log Parser and Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python windows_event_parser.py --file SecurityEvents.xml
  python windows_event_parser.py --file events.xml --output report.json
  python windows_event_parser.py --file events.xml --business-hours 9 17
        """
    )
    parser.add_argument('--file', '-f', required=True, help='Path to Windows Event XML export')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--business-hours', nargs=2, type=int, default=[8, 18],
                        metavar=('START', 'END'),
                        help='Business hours range for off-hours detection (default: 8 18)')

    args = parser.parse_args()

    # Parse events
    print(f"[*] Parsing Windows Event log: {args.file}")
    evt_parser = WindowsEventParser()
    events = evt_parser.parse_file(args.file)
    print(f"[*] Parsed {len(events)} events")

    # Detect anomalies
    print("[*] Running anomaly detection...")
    detector = AnomalyDetector(business_hours=tuple(args.business_hours))
    anomalies = detector.detect_all(events)
    print(f"[*] Found {len(anomalies)} anomalies")

    # Build report
    event_summary = Counter(e.event_id for e in events)
    unique_users = len(set(e.target_user for e in events if e.target_user))
    unique_ips = len(set(e.source_ip for e in events if e.source_ip and e.source_ip != '-'))

    report = WindowsEventReport(
        total_events=len(events),
        event_summary=dict(event_summary.most_common()),
        anomalies=[asdict(a) for a in anomalies],
        unique_users=unique_users,
        unique_source_ips=unique_ips,
        suspicious_events=[asdict(e) for e in events if e.is_suspicious],
        timeline=[{
            "timestamp": e.timestamp,
            "event_id": e.event_id,
            "description": e.description,
            "user": e.target_user,
            "source_ip": e.source_ip
        } for e in events[:100]]
    )

    # Output
    output = json.dumps(asdict(report), indent=2, default=str)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Report saved to: {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
