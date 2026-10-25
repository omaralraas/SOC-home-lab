#!/usr/bin/env python3
"""
SOC Home Lab - Windows Security Log Triage
==========================================
Parses a Security log exported as XML (wevtutil qe Security /f:xml, or
Event Viewer "Save as XML"), normalises the events and runs triage checks:
password spraying, failed-logon bursts, off-hours interactive logons,
service installs, account creation and audit-log clearing.

Author: Omar Alraas
Usage:  python windows_event_parser.py --file security.xml --output report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parses exported logs from lab hosts
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

EVENT_NAMES = {
    1102: "Audit Log Cleared",
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4732: "Member Added to Local Group",
    4740: "Account Locked Out",
    7045: "New Service Installed",
}

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


@dataclass
class WindowsEvent:
    event_id: int
    timestamp: datetime
    computer: str
    data: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return EVENT_NAMES.get(self.event_id, f"Event {self.event_id}")

    def get(self, key: str) -> str:
        value = self.data.get(key, "")
        return "" if value in ("-", "%%") else value


@dataclass
class Finding:
    title: str
    severity: str
    mitre_technique: str
    description: str
    evidence: list[dict] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _child(elem: ET.Element, tag: str) -> ET.Element | None:
    """Namespaced lookup with a fallback for exports that drop the namespace.

    Note: `a.find(x) or a.find(y)` is wrong here; an Element with no children
    is falsy, so a found leaf element would be discarded.
    """
    found = elem.find(NS + tag)
    return found if found is not None else elem.find(tag)


def parse_event(elem: ET.Element) -> WindowsEvent | None:
    system = _child(elem, "System")
    if system is None:
        return None
    event_id = _child(system, "EventID")
    created = _child(system, "TimeCreated")
    computer = _child(system, "Computer")
    if event_id is None or created is None or not (event_id.text or "").strip().isdigit():
        return None
    timestamp = datetime.fromisoformat(created.get("SystemTime", "").replace("Z", "+00:00"))
    data = {}
    event_data = _child(elem, "EventData")
    if event_data is not None:
        for item in event_data:
            if item.get("Name"):
                data[item.get("Name")] = (item.text or "").strip()
    return WindowsEvent(int(event_id.text), timestamp, computer.text if computer is not None else "", data)


def parse_xml(text: str) -> list[WindowsEvent]:
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        root = ET.fromstring(body)  # noqa: S314 - exported logs from lab hosts, not untrusted input
    except ET.ParseError:
        # `wevtutil qe /f:xml` emits bare <Event> elements with no root element
        root = ET.fromstring(f"<Events>{body}</Events>")  # noqa: S314
    candidates = [root] if root.tag in (NS + "Event", "Event") else list(root)
    events = [e for e in map(parse_event, candidates) if e is not None]
    return sorted(events, key=lambda e: e.timestamp)


# --------------------------------------------------------------------------- #
# Triage checks
# --------------------------------------------------------------------------- #


def summarise(event: WindowsEvent) -> dict:
    keep = ("TargetUserName", "IpAddress", "LogonType", "ServiceName", "ImagePath", "SubjectUserName")
    return {
        "time": event.timestamp.isoformat(),
        "event": f"{event.event_id} {event.name}",
        **{k: event.get(k) for k in keep if event.get(k)},
    }


def detect_password_spraying(events: list[WindowsEvent], min_accounts: int = 5) -> list[Finding]:
    accounts_by_source: dict[str, set[str]] = defaultdict(set)
    evidence: dict[str, list[WindowsEvent]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and e.get("IpAddress"):
            accounts_by_source[e.get("IpAddress")].add(e.get("TargetUserName").lower())
            evidence[e.get("IpAddress")].append(e)
    return [
        Finding(
            "Password spraying",
            "high",
            "T1110.003",
            f"{ip} failed logons for {len(users)} different accounts",
            [summarise(e) for e in evidence[ip][:10]],
        )
        for ip, users in accounts_by_source.items()
        if len(users) >= min_accounts
    ]


def detect_failed_logon_bursts(events: list[WindowsEvent], threshold: int = 10) -> list[Finding]:
    by_user = Counter(e.get("TargetUserName") for e in events if e.event_id == 4625 and e.get("TargetUserName"))
    findings = []
    for user, count in by_user.items():
        if count >= threshold:
            severity = "critical" if count >= 50 else "high" if count >= 20 else "medium"
            findings.append(
                Finding("Failed logon burst", severity, "T1110.001", f"'{user}' failed to log on {count} times")
            )
    return findings


def detect_off_hours_logons(events: list[WindowsEvent], start: int, end: int, utc_offset: int) -> list[Finding]:
    """Interactive / RDP logons outside business hours (hours in local time)."""
    hits = [
        e
        for e in events
        if e.event_id == 4624
        and e.get("LogonType") in ("2", "10")
        and not start <= (e.timestamp.hour + utc_offset) % 24 < end
    ]
    if not hits:
        return []
    return [
        Finding(
            "Off-hours interactive logon",
            "medium",
            "T1078",
            f"{len(hits)} interactive/RDP logon(s) outside {start:02d}:00-{end:02d}:00",
            [summarise(e) for e in hits[:10]],
        )
    ]


def detect_service_installs(events: list[WindowsEvent]) -> list[Finding]:
    return [
        Finding(
            "Service installed",
            "high",
            "T1543.003",
            f"Service '{e.get('ServiceName')}' -> {e.get('ImagePath') or e.get('ServiceFileName')}",
            [summarise(e)],
        )
        for e in events
        if e.event_id in (4697, 7045)
    ]


def detect_account_changes(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_id == 4720:
            findings.append(
                Finding(
                    "Account created",
                    "medium",
                    "T1136.001",
                    f"'{e.get('TargetUserName')}' created by '{e.get('SubjectUserName')}'",
                    [summarise(e)],
                )
            )
        elif e.event_id == 4732 and e.get("TargetSid") == "S-1-5-32-544":
            findings.append(
                Finding(
                    "Added to local Administrators",
                    "high",
                    "T1098",
                    f"{e.get('MemberName') or e.get('MemberSid')} added by '{e.get('SubjectUserName')}'",
                    [summarise(e)],
                )
            )
    return findings


def detect_log_clearing(events: list[WindowsEvent]) -> list[Finding]:
    return [
        Finding(
            "Security log cleared", "critical", "T1685.005", f"cleared by '{e.get('SubjectUserName')}'", [summarise(e)]
        )
        for e in events
        if e.event_id == 1102
    ]


def triage(events: list[WindowsEvent], business_hours=(8, 18), utc_offset: int = 0) -> list[Finding]:
    findings = (
        detect_password_spraying(events)
        + detect_failed_logon_bursts(events)
        + detect_off_hours_logons(events, *business_hours, utc_offset)
        + detect_service_installs(events)
        + detect_account_changes(events)
        + detect_log_clearing(events)
    )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: order[f.severity])


def build_report(events: list[WindowsEvent], findings: list[Finding]) -> dict:
    return {
        "total_events": len(events),
        "event_counts": {
            f"{k} {EVENT_NAMES.get(k, '')}".strip(): v for k, v in Counter(e.event_id for e in events).most_common()
        },
        "time_range": [events[0].timestamp.isoformat(), events[-1].timestamp.isoformat()] if events else [],
        "findings": [asdict(f) for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage a Windows Security log XML export")
    parser.add_argument("--file", "-f", required=True)
    parser.add_argument("--output", "-o")
    parser.add_argument("--business-hours", nargs=2, type=int, default=[8, 18], metavar=("START", "END"))
    parser.add_argument("--utc-offset", type=int, default=0, help="local time offset from UTC in hours")
    args = parser.parse_args(argv)

    try:
        with open(args.file, encoding="utf-8-sig") as fh:
            events = parse_xml(fh.read())
    except (OSError, ET.ParseError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    report = build_report(events, triage(events, tuple(args.business_hours), args.utc_offset))
    text = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
