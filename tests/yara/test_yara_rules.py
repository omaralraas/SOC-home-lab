"""YARA rule tests: compile cleanly and match exactly the expected samples."""

import warnings
from pathlib import Path

import pytest
import yaml
import yara
from sigma.data.mitre_attack import mitre_attack_techniques

REPO_ROOT = Path(__file__).resolve().parents[2]
RULE_FILES = sorted((REPO_ROOT / "detection-rules" / "yara").glob("*.yar"))
SAMPLES = yaml.safe_load((Path(__file__).parent / "samples.yml").read_text(encoding="utf-8"))
REQUIRED_META = {"description", "author", "date", "severity", "mitre_attack"}


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepaths={p.stem: str(p) for p in RULE_FILES}, error_on_warning=True)


def build(sample) -> bytes:
    text = "".join(sample["parts"])
    data = text.encode(sample.get("encoding", "utf-8"))
    if sample.get("pe"):
        data = b"MZ" + b"\x00" * 62 + data
    return data


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_compiles_without_warnings(path):
    """error_on_warning turns unreferenced strings and slow regexes into failures."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        yara.compile(filepath=str(path), error_on_warning=True)


@pytest.mark.parametrize("sample", SAMPLES, ids=[s["name"] for s in SAMPLES])
def test_sample(rules, sample):
    matched = {m.rule for m in rules.match(data=build(sample))}
    assert matched == set(sample["expect"])


def test_every_rule_has_a_positive_sample(rules):
    names = {r.identifier for r in rules}
    covered = {name for s in SAMPLES for name in s["expect"]}
    assert names - covered == set(), f"rules without a positive sample: {sorted(names - covered)}"


def test_rule_metadata(rules):
    problems = []
    for rule in rules:
        missing = REQUIRED_META - rule.meta.keys()
        if missing:
            problems.append(f"{rule.identifier}: missing meta {sorted(missing)}")
        technique = rule.meta.get("mitre_attack")
        if technique and technique not in mitre_attack_techniques:
            problems.append(f"{rule.identifier}: {technique} is not an ATT&CK v20 technique")
    assert not problems, "\n".join(problems)
