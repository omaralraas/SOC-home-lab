#!/usr/bin/env python3
"""
SOC Home Lab - Log Analyzer Toolkit
====================================
Comprehensive log analysis tool for parsing auth.log/syslog files,
detecting brute force patterns, and generating investigation reports.

Author: Omar Alraas
Usage:  python log_analyzer.py --file /var/log/auth.log --threshold 5 --format table
"""

import re
import json
import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple


@dataclass
class LogEntry:
    """Represents a single parsed log entry."""
    timestamp: str
    hostname: str
    program: str
    pid: Optional[str]
    message: str
    raw: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None  # 'auth_success', 'auth_failure', 'other'


@dataclass
class BruteForceAlert:
    """Represents a detected brute force attempt."""
    source_ip: str
    target_accounts: List[str]
    attempt_count: int
    first_seen: str
    last_seen: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    successful_login: bool = False


@dataclass
class AnalysisReport:
    """Complete analysis report."""
    total_entries: int = 0
    total_auth_failures: int = 0
    total_auth_successes: int = 0
    unique_source_ips: int = 0
    brute_force_alerts: List[BruteForceAlert] = field(default_factory=list)
    top_source_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_targeted_accounts: List[Tuple[str, int]] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class LogParser:
    """Parses syslog/auth.log format files."""

    SYSLOG_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
        r'(\S+)\s+'                                       # hostname
        r'(\S+?)(?:\[(\d+)\])?:\s+'                       # program[pid]
        r'(.+)$'                                          # message
    )

    SSH_FAILED_PATTERN = re.compile(
        r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)'
    )

    SSH_SUCCESS_PATTERN = re.compile(
        r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)'
    )

    SSH_INVALID_USER_PATTERN = re.compile(
        r'Invalid user (\S+) from (\S+)'
    )

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single syslog line into a LogEntry."""
        line = line.strip()
        if not line:
            return None

        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None

        entry = LogEntry(
            timestamp=match.group(1),
            hostname=match.group(2),
            program=match.group(3),
            pid=match.group(4),
            message=match.group(5),
            raw=line
        )

        # Classify SSH events
        if entry.program in ('sshd', 'ssh'):
            self._classify_ssh_event(entry)

        return entry

    def _classify_ssh_event(self, entry: LogEntry) -> None:
        """Classify SSH log events and extract relevant fields."""
        # Check for failed authentication
        failed_match = self.SSH_FAILED_PATTERN.search(entry.message)
        if failed_match:
            entry.username = failed_match.group(1)
            entry.source_ip = failed_match.group(2)
            entry.event_type = 'auth_failure'
            return

        # Check for successful authentication
        success_match = self.SSH_SUCCESS_PATTERN.search(entry.message)
        if success_match:
            entry.username = success_match.group(1)
            entry.source_ip = success_match.group(2)
            entry.event_type = 'auth_success'
            return

        # Check for invalid user
        invalid_match = self.SSH_INVALID_USER_PATTERN.search(entry.message)
        if invalid_match:
            entry.username = invalid_match.group(1)
            entry.source_ip = invalid_match.group(2)
            entry.event_type = 'auth_failure'
            return

        entry.event_type = 'other'

    def parse_file(self, filepath: str) -> List[LogEntry]:
        """Parse an entire log file."""
        entries = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"[ERROR] Permission denied: {filepath}", file=sys.stderr)
            sys.exit(1)

        return entries


class BruteForceDetector:
    """Detects brute force patterns in log entries."""

    def __init__(self, threshold: int = 5, timeframe_minutes: int = 10):
        self.threshold = threshold
        self.timeframe = timedelta(minutes=timeframe_minutes)

    def detect(self, entries: List[LogEntry]) -> List[BruteForceAlert]:
        """Analyze entries for brute force patterns."""
        # Group failed attempts by source IP
        ip_failures: Dict[str, List[LogEntry]] = defaultdict(list)
        ip_successes: Dict[str, List[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.source_ip:
                if entry.event_type == 'auth_failure':
                    ip_failures[entry.source_ip].append(entry)
                elif entry.event_type == 'auth_success':
                    ip_successes[entry.source_ip].append(entry)

        alerts = []
        for ip, failures in ip_failures.items():
            if len(failures) >= self.threshold:
                target_accounts = list(set(
                    e.username for e in failures if e.username
                ))
                count = len(failures)

                # Determine severity
                if count >= 50:
                    severity = 'critical'
                elif count >= 20:
                    severity = 'high'
                elif count >= 10:
                    severity = 'medium'
                else:
                    severity = 'low'

                # Check if there was a successful login after failures
                has_success = ip in ip_successes

                alert = BruteForceAlert(
                    source_ip=ip,
                    target_accounts=target_accounts,
                    attempt_count=count,
                    first_seen=failures[0].timestamp,
                    last_seen=failures[-1].timestamp,
                    severity=severity,
                    successful_login=has_success
                )
                alerts.append(alert)

        # Sort by attempt count descending
        alerts.sort(key=lambda a: a.attempt_count, reverse=True)
        return alerts


class LogAnalyzer:
    """Main analysis engine that coordinates parsing and detection."""

    def __init__(self, threshold: int = 5, timeframe: int = 10):
        self.parser = LogParser()
        self.detector = BruteForceDetector(threshold=threshold, timeframe_minutes=timeframe)

    def analyze(self, filepath: str) -> AnalysisReport:
        """Run complete analysis on a log file."""
        print(f"[*] Parsing log file: {filepath}")
        entries = self.parser.parse_file(filepath)
        print(f"[*] Parsed {len(entries)} log entries")

        report = AnalysisReport(total_entries=len(entries))

        # Count auth events
        source_ips = Counter()
        target_accounts = Counter()

        for entry in entries:
            if entry.event_type == 'auth_failure':
                report.total_auth_failures += 1
                if entry.source_ip:
                    source_ips[entry.source_ip] += 1
                if entry.username:
                    target_accounts[entry.username] += 1
            elif entry.event_type == 'auth_success':
                report.total_auth_successes += 1

        report.unique_source_ips = len(source_ips)
        report.top_source_ips = source_ips.most_common(10)
        report.top_targeted_accounts = target_accounts.most_common(10)

        # Run brute force detection
        print("[*] Running brute force detection...")
        report.brute_force_alerts = self.detector.detect(entries)
        print(f"[*] Detected {len(report.brute_force_alerts)} brute force alerts")

        return report


def format_table(report: AnalysisReport) -> str:
    """Format the analysis report as a readable table."""
    lines = []
    lines.append("=" * 70)
    lines.append("  SOC HOME LAB - LOG ANALYSIS REPORT")
    lines.append(f"  Generated: {report.analysis_timestamp}")
    lines.append("=" * 70)

    # Summary
    lines.append(f"\n  Total Entries Analyzed:    {report.total_entries}")
    lines.append(f"  Authentication Failures:  {report.total_auth_failures}")
    lines.append(f"  Authentication Successes: {report.total_auth_successes}")
    lines.append(f"  Unique Source IPs:        {report.unique_source_ips}")

    # Top Source IPs
    if report.top_source_ips:
        lines.append(f"\n  {'TOP SOURCE IPs':^50}")
        lines.append(f"  {'IP Address':<25} {'Attempts':>10}")
        lines.append("  " + "-" * 35)
        for ip, count in report.top_source_ips:
            lines.append(f"  {ip:<25} {count:>10}")

    # Top Targeted Accounts
    if report.top_targeted_accounts:
        lines.append(f"\n  {'TOP TARGETED ACCOUNTS':^50}")
        lines.append(f"  {'Account':<25} {'Attempts':>10}")
        lines.append("  " + "-" * 35)
        for account, count in report.top_targeted_accounts:
            lines.append(f"  {account:<25} {count:>10}")

    # Brute Force Alerts
    if report.brute_force_alerts:
        lines.append(f"\n  {'BRUTE FORCE ALERTS':^50}")
        lines.append("  " + "-" * 65)
        for alert in report.brute_force_alerts:
            marker = " [COMPROMISED!]" if alert.successful_login else ""
            lines.append(f"\n  [{alert.severity.upper()}]{marker}")
            lines.append(f"    Source IP:  {alert.source_ip}")
            lines.append(f"    Attempts:  {alert.attempt_count}")
            lines.append(f"    Targets:   {', '.join(alert.target_accounts[:5])}")
            lines.append(f"    First:     {alert.first_seen}")
            lines.append(f"    Last:      {alert.last_seen}")
    else:
        lines.append("\n  No brute force alerts detected.")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def format_json(report: AnalysisReport) -> str:
    """Format the analysis report as JSON."""
    data = asdict(report)
    return json.dumps(data, indent=2, default=str)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SOC Home Lab - Log Analyzer: Detect brute force attacks in auth logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py --file /var/log/auth.log
  python log_analyzer.py --file /var/log/auth.log --threshold 10 --format json
  python log_analyzer.py --file auth.log --threshold 3 --output report.json --format json
        """
    )
    parser.add_argument('--file', '-f', required=True, help='Path to log file to analyze')
    parser.add_argument('--threshold', '-t', type=int, default=5,
                        help='Minimum failed attempts to trigger brute force alert (default: 5)')
    parser.add_argument('--timeframe', type=int, default=10,
                        help='Timeframe in minutes for brute force detection (default: 10)')
    parser.add_argument('--format', choices=['table', 'json'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--output', '-o', help='Output file path (default: stdout)')

    args = parser.parse_args()

    # Run analysis
    analyzer = LogAnalyzer(threshold=args.threshold, timeframe=args.timeframe)
    report = analyzer.analyze(args.file)

    # Format output
    if args.format == 'json':
        output = format_json(report)
    else:
        output = format_table(report)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Report saved to: {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
