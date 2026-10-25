"""Sigma detection tests: every rule must match its true positives and stay
silent on its benign look-alikes (tests/sigma/cases/*.yml)."""

from pathlib import Path

import pytest
import yaml

from tools.sigma_engine import load_rule, matches

REPO_ROOT = Path(__file__).resolve().parents[2]
RULE_PATHS = sorted((REPO_ROOT / "detection-rules" / "sigma").rglob("*.yml"))
RULES = {str(rule.id): rule for rule in map(load_rule, RULE_PATHS)}

CASES = {}
for case_file in sorted((Path(__file__).parent / "cases").glob("*.yml")):
    CASES.update(yaml.safe_load(case_file.read_text(encoding="utf-8")))

PARAMS = [
    pytest.param(rule_id, case, id=f"{RULES[rule_id].title} :: {case['name']}" if rule_id in RULES else rule_id)
    for rule_id, cases in CASES.items()
    for case in cases
]


@pytest.mark.parametrize(("rule_id", "case"), PARAMS)
def test_rule_against_event(rule_id, case):
    assert rule_id in RULES, f"test cases reference unknown rule id {rule_id}"
    assert matches(RULES[rule_id], case["event"]) is case["match"]


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_has_positive_and_negative_cases(rule_id):
    outcomes = {case["match"] for case in CASES.get(rule_id, [])}
    assert outcomes == {True, False}, f"{RULES[rule_id].title} needs at least one matching and one non-matching event"


@pytest.mark.parametrize("path", RULE_PATHS, ids=lambda p: p.name)
def test_rule_metadata(path):
    rule = load_rule(path)
    assert rule.id and rule.author and rule.date and rule.falsepositives, "id, author, date, falsepositives required"
    assert rule.level is not None and rule.status is not None
    techniques = [t for t in rule.tags if t.namespace == "attack" and t.name.startswith("t")]
    assert techniques, "every rule must map to at least one ATT&CK technique"


def test_rule_ids_are_unique():
    assert len(RULES) == len(RULE_PATHS)
