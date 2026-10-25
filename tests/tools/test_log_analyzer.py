import json
from datetime import datetime, timedelta

from log_analyzer import LogParser, analyze, main, peak_in_window

FAILED = "Oct 25 10:{m:02d}:{s:02d} ubuntu-srv sshd[2201]: Failed password for {user} from {ip} port 51022 ssh2"
INVALID = "Oct 25 10:{m:02d}:{s:02d} ubuntu-srv sshd[2201]: Invalid user {user} from {ip} port 51022"
ACCEPTED = "Oct 25 10:{m:02d}:{s:02d} ubuntu-srv sshd[2210]: Accepted password for {user} from {ip} port 51030 ssh2"


def parse(lines):
    return LogParser(year=2026).parse_lines(lines)


def test_parses_classic_and_rfc3339_timestamps():
    classic, iso = parse(
        [
            FAILED.format(m=0, s=1, user="root", ip="10.0.2.100"),
            "2026-10-25T10:00:01.123456+00:00 ubuntu-srv sshd[2201]: "
            "Failed password for root from 10.0.2.100 port 1 ssh2",
        ]
    )
    assert classic.timestamp == datetime(2026, 10, 25, 10, 0, 1)
    assert iso.timestamp == datetime(2026, 10, 25, 10, 0, 1, 123456)
    assert classic.event_type == iso.event_type == "auth_failure"


def test_invalid_user_attempt_is_not_double_counted():
    # sshd logs both lines for a single attempt against a non-existent user
    entries = parse(
        [
            INVALID.format(m=0, s=1, user="oracle", ip="10.0.2.100"),
            FAILED.format(m=0, s=1, user="invalid user oracle", ip="10.0.2.100"),
        ]
    )
    report = analyze(entries, threshold=1, timeframe=10)
    assert report.total_auth_failures == 1
    assert report.brute_force_alerts[0].target_accounts == ["oracle"]


def test_sliding_window_ignores_slow_failures():
    slow = [FAILED.format(m=i * 6, s=0, user="root", ip="10.0.2.100") for i in range(6)]  # one every 6 minutes
    assert analyze(parse(slow), threshold=5, timeframe=10).brute_force_alerts == []
    fast = [FAILED.format(m=0, s=i * 5, user="root", ip="10.0.2.100") for i in range(5)]
    [alert] = analyze(parse(fast), threshold=5, timeframe=10).brute_force_alerts
    assert alert.peak_window_count == 5 and not alert.successful_login


def test_success_after_attack_marks_compromise():
    lines = [FAILED.format(m=1, s=i, user="jdoe", ip="10.0.2.100") for i in range(8)]
    lines.append(ACCEPTED.format(m=1, s=30, user="jdoe", ip="10.0.2.100"))
    [alert] = analyze(parse(lines), threshold=5, timeframe=10).brute_force_alerts
    assert alert.successful_login and alert.compromised_accounts == ["jdoe"] and alert.severity == "critical"


def test_success_before_attack_is_not_compromise():
    lines = [ACCEPTED.format(m=0, s=0, user="omar", ip="10.0.2.100")]
    lines += [FAILED.format(m=5, s=i, user="root", ip="10.0.2.100") for i in range(8)]
    [alert] = analyze(parse(lines), threshold=5, timeframe=10).brute_force_alerts
    assert not alert.successful_login


def test_peak_in_window():
    t = [datetime(2026, 1, 1, 0, m) for m in (0, 1, 2, 20, 21)]
    assert peak_in_window(t, window=timedelta(minutes=5)) == 3


def test_cli_json_output_and_exit_code(tmp_path, capsys):
    log = tmp_path / "auth.log"
    lines = [FAILED.format(m=0, s=i, user="admin", ip="203.0.113.9") for i in range(6)]
    lines.append(ACCEPTED.format(m=0, s=50, user="admin", ip="203.0.113.9"))
    log.write_text("\n".join(lines))
    assert main(["--file", str(log), "--format", "json", "--year", "2026"]) == 2  # compromise found
    report = json.loads(capsys.readouterr().out)
    assert report["brute_force_alerts"][0]["source_ip"] == "203.0.113.9"
