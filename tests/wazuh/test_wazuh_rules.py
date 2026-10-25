"""Unit tests for the custom Wazuh ruleset, run against a real wazuh-analysisd.

A wazuh-manager container is started with the repo's ossec.conf, rules and
agent.conf mounted exactly as wazuh/docker-compose.yml mounts them. Every case
in cases/*.yml is replayed through the logtest socket and the rule that fires
on the case's final event is compared with the expectation.

Case format (see cases/*.yml):
  - name: human-readable description
    events: [...]            # replayed in order inside one logtest session
    expect: "100100"         # rule id that must fire on the last event
    expect_not: "100100"     # ...or a rule id that must NOT fire on it

Event shorthands:
  "raw log line"                          syslog line (case log_format/location)
  {repeat: N, event: <event>}             the same event N times
  {sysmon: 1, image: ..., ...}            Sysmon event, keys are eventdata fields
  {security: 4625, ...} / {system: 7045}  Windows Security / System channel event
  {json: {...}}                           JSON line (Suricata EVE, SOAR audit log)
"""

import json
import re

import pytest
import yaml

from tests.wazuh.harness import HERE, RULES_DIR, docker, parse_rules

pytestmark = pytest.mark.docker

CASES_DIR = HERE / "cases"
CUSTOM_RULE_RANGE = range(100000, 110000)

CHANNELS = {
    "sysmon": {
        "providerName": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "severityValue": "INFORMATION",
    },
    "security": {
        "providerName": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "severityValue": "AUDIT_SUCCESS",
    },
    "system": {
        "providerName": "Service Control Manager",
        "channel": "System",
        "severityValue": "INFORMATION",
    },
}
AUDIT_FAILURE_EVENTS = {"4625", "4771", "4776"}


# --------------------------------------------------------------------------- #
# Case loading
# --------------------------------------------------------------------------- #


def _expand(event, defaults):
    """Turn one YAML event item into (raw_event, log_format, location) tuples."""
    if isinstance(event, str):
        return [(event, defaults["log_format"], defaults["location"])]
    if "repeat" in event:
        return _expand(event["event"], defaults) * int(event["repeat"])
    if "json" in event:
        return [(json.dumps(event["json"]), "json", defaults.get("json_location", "/var/log/soc/events.json"))]
    for channel, system_defaults in CHANNELS.items():
        if channel in event:
            eventdata = {k: str(v) for k, v in event.items() if k not in (channel, "_system")}
            event_id = str(event[channel])
            if channel == "sysmon" and event_id == "1" and "image" in eventdata:
                # Real Sysmon always reports OriginalFileName, and stock rules
                # (e.g. 92028) key on it, so omitting it would test an event
                # shape that never occurs. Default to the image's file name.
                eventdata.setdefault("originalFileName", re.split(r"[\\/]", eventdata["image"])[-1])
            # The production EventChannel decoder keeps backslashes JSON-escaped,
            # so field values hold "C:\\Windows" (see Wazuh's own
            # ruleset/testing/tests/sysmon_eid_*.ini). Reproduce that here.
            eventdata = {k: v.replace("\\", "\\\\") for k, v in eventdata.items()}
            system = {**system_defaults, "eventID": event_id, "computer": "WIN10-LAB"}
            if channel == "security" and event_id in AUDIT_FAILURE_EVENTS:
                system["severityValue"] = "AUDIT_FAILURE"
            system.update(event.get("_system", {}))
            win = json.dumps({"win": {"system": system, "eventdata": eventdata}})
            return [(win, "json", "EventChannel")]
    raise ValueError(f"Unrecognised event shorthand: {event!r}")


def load_cases():
    cases = []
    for path in sorted(CASES_DIR.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = {"log_format": "syslog", "location": "/var/log/auth.log", **doc.get("defaults", {})}
        for case in doc["cases"]:
            case_defaults = {**defaults, **{k: case[k] for k in ("log_format", "location") if k in case}}
            expanded = [e for item in case["events"] for e in _expand(item, case_defaults)]
            formats = {(fmt, loc) for _, fmt, loc in expanded}
            assert len(formats) == 1, f"{path.name}: '{case['name']}' mixes log formats {formats}"
            ((log_format, location),) = formats
            cases.append(
                {
                    "id": f"{path.stem}: {case['name']}",
                    "expect": str(case["expect"]) if "expect" in case else None,
                    "expect_not": str(case["expect_not"]) if "expect_not" in case else None,
                    "scenario": {
                        "events": [raw for raw, _, _ in expanded],
                        "log_format": log_format,
                        "location": location,
                    },
                }
            )
    return cases


CASES = load_cases()


def custom_rule_ids():
    return {str(rule.id) for path in RULES_DIR.glob("*.xml") for rule in parse_rules(path)}


@pytest.fixture(scope="session")
def results(wazuh_manager):
    """Replay every case once; tests look up their result by case id."""
    proc = docker(
        "exec",
        "-i",
        wazuh_manager,
        "/var/ossec/framework/python/bin/python3",
        "/opt/soclab/logtest_client.py",
        input=json.dumps([c["scenario"] for c in CASES]),
    )
    assert proc.returncode == 0, proc.stderr
    return {case["id"]: res for case, res in zip(CASES, json.loads(proc.stdout), strict=True)}


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_ruleset_loads_cleanly(wazuh_manager):
    """analysisd only *warns* about a bad if_sid or regex and drops the rule,
    so a broken rule would otherwise go unnoticed."""
    log = docker("exec", wazuh_manager, "cat", "/var/ossec/logs/ossec.log").stdout
    problems = [
        line for line in log.splitlines() if "wazuh-analysisd" in line and re.search(r"(WARNING|ERROR|CRITICAL)", line)
    ]
    assert not problems, "\n".join(problems)


def test_config_passes_analysisd_check(wazuh_manager):
    check = docker("exec", wazuh_manager, "/var/ossec/bin/wazuh-analysisd", "-t")
    assert check.returncode == 0, check.stdout + check.stderr


def test_agent_conf_is_valid(wazuh_manager):
    check = docker("exec", wazuh_manager, "/var/ossec/bin/verify-agent-conf")
    assert check.returncode == 0 and "ERROR" not in check.stdout + check.stderr, check.stdout + check.stderr


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case, results):
    fired = results[case["id"]][-1]
    fired_id = fired["id"] if fired else None
    detail = f"last event matched {fired_id} ({fired and fired['description']})"
    if case["expect"]:
        assert fired_id == case["expect"], detail
    if case["expect_not"]:
        assert fired_id != case["expect_not"], detail


def test_every_custom_rule_has_a_positive_case():
    untested = yaml.safe_load((HERE / "untested.yml").read_text(encoding="utf-8")) or {}
    expected = {c["expect"] for c in CASES if c["expect"]}
    missing = custom_rule_ids() - expected - {str(k) for k in untested}
    assert not missing, f"custom rules without a positive test case: {sorted(missing)}"


def test_custom_rule_ids_stay_in_range():
    assert all(int(i) in CUSTOM_RULE_RANGE for i in custom_rule_ids())
