"""Evaluate Sigma rules against JSON events, without a SIEM.

pySigma does the hard part: it parses the rule, applies value modifiers
(contains, endswith, windash, re, cidr, ...) and resolves the condition
(including `1 of selection_*` and `all of them`) into a tree of AND/OR/NOT
nodes over field/value comparisons. This module walks that tree against a
flat or nested event dict, following Sigma matching semantics:

  * string comparisons are case-insensitive unless the `cased` modifier is used
  * wildcards (* ?) are honoured; plain strings must match the whole value
  * `re` values are searched (unanchored), with the rule's regex flags
  * a list-valued event field matches if any element matches
  * keyword detections (no field) search every string value of the event

It exists so each rule in detection-rules/sigma can ship with positive and
negative test events that run in CI (tests/sigma).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

_MISSING = object()


def load_rule(path: str | Path) -> SigmaRule:
    return SigmaRule.from_yaml(Path(path).read_text(encoding="utf-8"))


def matches(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """True if any of the rule's conditions matches the event."""
    return any(_eval(condition.parsed, event) for condition in rule.detection.parsed_condition)


# --------------------------------------------------------------------------- #
# Condition tree
# --------------------------------------------------------------------------- #


def _eval(node: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_matches(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        # Keywords are full-text searches: substring match against any value.
        if isinstance(node.value, SigmaString):
            pattern = _compile_string(node.value)
            return any(pattern.search(v) for v in _all_strings(event))
        return any(_value_matches(v, node.value) for v in _all_strings(event))
    raise NotImplementedError(f"unsupported condition node: {type(node).__name__}")


def _lookup(event: Mapping[str, Any], field: str) -> Any:
    """Exact key first, then dotted-path traversal (ECS-style nested events)."""
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _all_strings(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for v in value.values():
            yield from _all_strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _all_strings(v)
    elif isinstance(value, str):
        yield value


def _field_matches(event: Mapping[str, Any], field: str, expected: Any) -> bool:
    actual = _lookup(event, field)
    if isinstance(expected, SigmaExists):
        return (actual is not _MISSING) == expected.exists
    if isinstance(expected, SigmaNull):
        return actual is _MISSING or actual is None
    if actual is _MISSING or actual is None:
        return False
    candidates = actual if isinstance(actual, list | tuple) else [actual]
    return any(_value_matches(c, expected) for c in candidates)


# --------------------------------------------------------------------------- #
# Values
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=4096)
def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _compile_string(value: SigmaString) -> re.Pattern[str]:
    flags = re.DOTALL
    if not isinstance(value, SigmaCasedString):
        flags |= re.IGNORECASE
    return _compile(str(value.to_regex().regexp), flags)


def _compile_regex(value: SigmaRegularExpression) -> re.Pattern[str]:
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    return _compile(str(value.regexp), flags)


def _as_number(value: Any) -> float | None:
    """Event fields often hold numbers as strings ("4698", "0x1010")."""
    try:
        return float(int(str(value).strip(), 0))
    except ValueError:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, SigmaExpansion):  # windash, base64offset, ...
        return any(_value_matches(actual, v) for v in expected.values)
    if isinstance(expected, SigmaString):
        return _compile_string(expected).fullmatch(str(actual)) is not None
    if isinstance(expected, SigmaRegularExpression):
        return _compile_regex(expected).search(str(actual)) is not None
    if isinstance(expected, SigmaBool):
        return str(actual).lower() == str(expected.boolean).lower()
    if isinstance(expected, SigmaNumber):
        number = _as_number(actual)
        return number is not None and number == float(expected.number)
    if isinstance(expected, SigmaCompareExpression):
        number = _as_number(actual)
        if number is None:
            return False
        op, ref = expected.op, float(expected.number.number)
        ops = SigmaCompareExpression.CompareOperators
        return {
            ops.LT: number < ref,
            ops.LTE: number <= ref,
            ops.GT: number > ref,
            ops.GTE: number >= ref,
        }[op]
    if isinstance(expected, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in expected.network
        except ValueError:
            return False
    raise NotImplementedError(f"unsupported Sigma value type: {type(expected).__name__}")
