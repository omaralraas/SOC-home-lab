"""Unit tests for tools/sigma_engine.py itself, so a bug in the evaluator cannot
make the rule tests pass vacuously."""

import textwrap

import pytest
from sigma.rule import SigmaRule

from tools.sigma_engine import matches


def rule(detection: str) -> SigmaRule:
    body = textwrap.dedent(
        """
        title: engine test
        logsource: {category: test}
        detection:
        """
    ) + textwrap.indent(textwrap.dedent(detection), "  ")
    return SigmaRule.from_yaml(body)


@pytest.mark.parametrize(
    ("detection", "event", "expected"),
    [
        # plain strings: whole-value, case-insensitive
        ("sel: {Image: 'C:\\Windows\\cmd.exe'}\ncondition: sel", {"Image": "c:\\windows\\CMD.EXE"}, True),
        ("sel: {Image: 'cmd.exe'}\ncondition: sel", {"Image": "C:\\Windows\\cmd.exe"}, False),
        # modifiers
        ("sel: {Image|endswith: '\\cmd.exe'}\ncondition: sel", {"Image": "C:\\Windows\\cmd.exe"}, True),
        ("sel: {Image|startswith: 'C:\\Temp'}\ncondition: sel", {"Image": "C:\\Windows\\cmd.exe"}, False),
        ("sel: {CommandLine|contains|all: [a, b]}\ncondition: sel", {"CommandLine": "x a y"}, False),
        ("sel: {CommandLine|contains|all: [a, b]}\ncondition: sel", {"CommandLine": "b x a"}, True),
        ("sel: {CommandLine|cased: Foo}\ncondition: sel", {"CommandLine": "foo"}, False),
        # wildcards inside plain values; the dot is literal
        ("sel: {Image: '*\\cm?.exe'}\ncondition: sel", {"Image": "C:\\x\\cmd.exe"}, True),
        ("sel: {Image: '*cmd.exe'}\ncondition: sel", {"Image": "C:\\x\\cmdXexe"}, False),
        # regex: unanchored search, case-sensitive unless flagged
        ("sel: {q|re: 'ab+c'}\ncondition: sel", {"q": "xxabbbcxx"}, True),
        ("sel: {q|re: 'ABC'}\ncondition: sel", {"q": "abc"}, False),
        ("sel: {q|re|i: 'ABC'}\ncondition: sel", {"q": "abc"}, True),
        # numbers compare numerically, also against numeric strings
        ("sel: {EventID: 4698}\ncondition: sel", {"EventID": "4698"}, True),
        ("sel: {EventID: 4698}\ncondition: sel", {"EventID": 4699}, False),
        ("sel: {Size|gte: 100}\ncondition: sel", {"Size": 150}, True),
        # cidr
        ("sel: {ip|cidr: 10.0.2.0/24}\ncondition: sel", {"ip": "10.0.2.100"}, True),
        ("sel: {ip|cidr: 10.0.2.0/24}\ncondition: sel", {"ip": "10.0.1.5"}, False),
        # missing fields never match, null matches missing
        ("sel: {Image: x}\ncondition: sel", {}, False),
        ("sel: {Image: null}\ncondition: sel", {}, True),
        # conditions
        ("a: {x: 1}\nb: {y: 2}\ncondition: a and not b", {"x": 1, "y": 2}, False),
        ("a: {x: 1}\nb: {y: 2}\ncondition: a and not b", {"x": 1, "y": 3}, True),
        ("selection_a: {x: 1}\nselection_b: {y: 2}\ncondition: 1 of selection_*", {"y": 2}, True),
        ("selection_a: {x: 1}\nselection_b: {y: 2}\ncondition: all of selection_*", {"y": 2}, False),
        # list of maps is OR, map keys are AND
        ("sel:\n  - {x: 1, y: 2}\n  - {z: 3}\ncondition: sel", {"x": 1, "y": 0}, False),
        ("sel:\n  - {x: 1, y: 2}\n  - {z: 3}\ncondition: sel", {"z": 3}, True),
        # keywords are substring searches over every value
        ("kw: ['NOT in sudoers']\ncondition: kw", {"message": "sudo: bob : user NOT in sudoers ; TTY=pts/0"}, True),
        ("kw: ['NOT in sudoers']\ncondition: kw", {"message": "session opened"}, False),
        # list-valued and nested event fields
        ("sel: {tags: b}\ncondition: sel", {"tags": ["a", "b"]}, True),
        ("sel: {process.name: cmd.exe}\ncondition: sel", {"process": {"name": "cmd.exe"}}, True),
    ],
)
def test_semantics(detection, event, expected):
    assert matches(rule(detection), event) is expected
