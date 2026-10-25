#!/usr/bin/env python3
"""
SOC Home Lab - SSH Authentication Log Analyzer
==============================================
Parses Linux auth.log (classic syslog or the RFC 3339 timestamps Ubuntu
24.04+ writes by default), finds SSH brute-force sources using a sliding
time window, and flags sources that logged in successfully after failing.

Author: Omar Alraas
Usage:  python log_analyzer.py --file /var/log/auth.log --threshold 5 --timeframe 10
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

SYSLOG_LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
SSH_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+")
SSH_ACCEPTED = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port \d+")
# sshd logs "Invalid user" *and* "Failed password for invalid user" for one
# attempt; the former is kept for username enumeration, not counted twice.
SSH_INVALID_USER = re.compile(r"Invalid user (\S*) from (\S+)")


@dataclass
class LogEntry:
    timestamp: datetime
    hostname: str
    program: str
    message: str
    source_ip: str | None = None
    username: str | None = None
    event_type: str = "other"  # auth_failure | auth_success | invalid_user | other


@dataclass
class BruteForceAlert:
    source_ip: str
    attempt_count: int
    peak_window_count: int
    target_accounts: list[str]
    first_seen: str
    last_seen: str
    severity: str
    successful_login: bool = False
    compromised_accounts: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    total_entries: int = 0
    total_auth_failures: int = 0
    total_auth_successes: int = 0
    unique_source_ips: int = 0
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    top_targeted_accounts: list[tuple[str, int]] = field(default_factory=list)
    brute_force_alerts: list[BruteForceAlert] = field(default_factory=list)


def parse_timestamp(raw: str, year: int) -> datetime:
    if raw[0].isdigit():
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


class LogParser:
    def __init__(self, year: int | None = None) -> None:
        # classic syslog omits the year
        self.year = year or datetime.now().year

    def parse_line(self, line: str) -> LogEntry | None:
        match = SYSLOG_LINE.match(line.strip())
        if not match:
            return None
        try:
            ts = parse_timestamp(match["ts"], self.year)
        except ValueError:
            return None
        entry = LogEntry(ts, match["host"], match["program"], match["message"])
        if entry.program == "sshd":
            self._classify_ssh(entry)
        return entry

    @staticmethod
    def _classify_ssh(entry: LogEntry) -> None:
        for pattern, event_type in (
            (SSH_FAILED, "auth_failure"),
            (SSH_ACCEPTED, "auth_success"),
            (SSH_INVALID_USER, "invalid_user"),
        ):
            m = pattern.search(entry.message)
            if m:
                entry.username, entry.source_ip, entry.event_type = m[1], m[2], event_type
                return

    def parse_lines(self, lines) -> list[LogEntry]:
        return [e for e in map(self.parse_line, lines) if e is not None]


def peak_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of events inside any window of the given length."""
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def severity_for(peak: int) -> str:
    if peak >= 50:
        return "critical"
    if peak >= 20:
        return "high"
    if peak >= 10:
        return "medium"
    return "low"


class BruteForceDetector:
    def __init__(self, threshold: int = 5, timeframe_minutes: int = 10) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=timeframe_minutes)

    def detect(self, entries: list[LogEntry]) -> list[BruteForceAlert]:
        failures: dict[str, list[LogEntry]] = defaultdict(list)
        successes: dict[str, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if e.source_ip and e.event_type == "auth_failure":
                failures[e.source_ip].append(e)
            elif e.source_ip and e.event_type == "auth_success":
                successes[e.source_ip].append(e)

        alerts = []
        for ip, fails in failures.items():
            fails.sort(key=lambda e: e.timestamp)
            peak = peak_in_window([e.timestamp for e in fails], self.window)
            if peak < self.threshold:
                continue
            # only a success *after* the attack started indicates compromise
            later = [s for s in successes.get(ip, []) if s.timestamp >= fails[0].timestamp]
            alerts.append(
                BruteForceAlert(
                    source_ip=ip,
                    attempt_count=len(fails),
                    peak_window_count=peak,
                    target_accounts=sorted({e.username for e in fails if e.username}),
                    first_seen=fails[0].timestamp.isoformat(),
                    last_seen=fails[-1].timestamp.isoformat(),
                    severity="critical" if later else severity_for(peak),
                    successful_login=bool(later),
                    compromised_accounts=sorted({s.username for s in later if s.username}),
                )
            )
        return sorted(alerts, key=lambda a: (not a.successful_login, -a.peak_window_count))


def analyze(entries: list[LogEntry], threshold: int, timeframe: int) -> AnalysisReport:
    report = AnalysisReport(total_entries=len(entries))
    sources, accounts = Counter(), Counter()
    for e in entries:
        if e.event_type == "auth_failure":
            report.total_auth_failures += 1
            sources[e.source_ip] += 1
            accounts[e.username] += 1
        elif e.event_type == "auth_success":
            report.total_auth_successes += 1
    report.unique_source_ips = len(sources)
    report.top_source_ips = sources.most_common(10)
    report.top_targeted_accounts = accounts.most_common(10)
    report.brute_force_alerts = BruteForceDetector(threshold, timeframe).detect(entries)
    return report


def format_table(report: AnalysisReport) -> str:
    lines = [
        "=" * 70,
        "  SSH AUTHENTICATION ANALYSIS",
        "=" * 70,
        f"  Entries parsed:          {report.total_entries}",
        f"  Authentication failures: {report.total_auth_failures}",
        f"  Authentication successes: {report.total_auth_successes}",
        f"  Unique failing sources:  {report.unique_source_ips}",
    ]
    if report.top_source_ips:
        lines += ["", f"  {'Top failing source':<25}{'Failures':>10}"]
        lines += [f"  {ip:<25}{n:>10}" for ip, n in report.top_source_ips]
    if not report.brute_force_alerts:
        lines += ["", "  No brute-force sources above threshold."]
    for a in report.brute_force_alerts:
        flag = f"  COMPROMISED: {', '.join(a.compromised_accounts)}" if a.successful_login else ""
        lines += [
            "",
            f"  [{a.severity.upper()}] {a.source_ip}{flag}",
            f"    failures: {a.attempt_count} total, {a.peak_window_count} peak in window",
            f"    accounts: {', '.join(a.target_accounts[:8])}",
            f"    seen:     {a.first_seen} -> {a.last_seen}",
        ]
    return "\n".join(lines + ["=" * 70])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect SSH brute force in auth.log")
    parser.add_argument("--file", "-f", required=True, help="auth.log to analyse ('-' for stdin)")
    parser.add_argument("--threshold", "-t", type=int, default=5, help="failures within the window (default 5)")
    parser.add_argument("--timeframe", type=int, default=10, help="sliding window in minutes (default 10)")
    parser.add_argument("--year", type=int, help="year for classic syslog timestamps (default: current)")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--output", "-o", help="write the report to this file")
    args = parser.parse_args(argv)

    log_parser = LogParser(args.year)
    try:
        if args.file == "-":
            entries = log_parser.parse_lines(sys.stdin)
        else:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                entries = log_parser.parse_lines(fh)
    except OSError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    report = analyze(entries, args.threshold, args.timeframe)
    text = json.dumps(asdict(report), indent=2) if args.format == "json" else format_table(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    return 2 if any(a.successful_login for a in report.brute_force_alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
