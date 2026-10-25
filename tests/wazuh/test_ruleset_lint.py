"""Static checks that custom rules do not silently break stock correlation.

analysisd files every event in exactly one place after matching (rules.c /
analysisd.c, "Copy the structure to the state memory of if_matched_sid"):

  * the sid list of its final rule, if any rule uses if_matched_sid on it;
  * otherwise the group lists of if_matched_group rules that marked it.

Two ways a custom rule can therefore disable stock detections without any
error or warning:

  A. if_matched_sid on a stock rule that previously had no sid consumers moves
     all of that rule's events out of the group lists that stock
     if_matched_group rules (e.g. 60204, 40111) count on.
  B. a custom child rule that matches becomes the event's final rule, so the
     event is filed under the custom rule and the stock rules correlating on
     the parent never see it.

This test rebuilds the load order and the sid/group marking from the stock
ruleset shipped in the image, then flags both patterns.
"""

from collections import defaultdict

import pytest

from tests.wazuh.harness import RULES_DIR, parse_rules

pytestmark = pytest.mark.docker

STOCK_EXCLUDED = {"0215-policy_rules.xml"}  # rule_exclude in wazuh/ossec.conf

# (custom rule, stock parent) pairs reviewed and accepted, with the reason.
ACCEPTED_PARENT_OVERLAPS: dict[tuple[int, int], str] = {}


def _words(expr: str) -> list[str]:
    return [w.strip() for w in expr.split("|") if w.strip()]


def _load(stock_dir):
    stock = [r for p in sorted(stock_dir.glob("*.xml")) if p.name not in STOCK_EXCLUDED for r in parse_rules(p)]
    custom = [r for p in sorted(RULES_DIR.glob("*.xml")) for r in parse_rules(p)]
    return stock, custom


def _consumers(rules_in_load_order):
    """Replay OS_MarkID / OS_MarkGroup in load order."""
    sid_consumers, group_consumers = defaultdict(set), defaultdict(set)
    loaded = []
    for rule in rules_in_load_order:
        if rule.overwrite:
            continue
        if rule.if_matched_sid is not None:
            sid_consumers[rule.if_matched_sid].add(rule.id)
        elif rule.if_matched_group:
            for q in loaded:
                if any(w in q.groups for w in _words(rule.if_matched_group)):
                    group_consumers[q.id].add(rule.id)
        loaded.append(rule)
    return sid_consumers, group_consumers


def _parents(rule, loaded_before):
    if rule.if_sid:
        return set(rule.if_sid)
    if rule.if_group:
        return {q.id for q in loaded_before if any(w in q.groups for w in _words(rule.if_group))}
    if rule.if_matched_sid is not None:
        return {rule.if_matched_sid}
    return set()


def test_no_custom_rule_starves_stock_correlation(stock_rules_dir):
    stock, custom = _load(stock_rules_dir)
    stock_ids = {r.id for r in stock}
    sid_consumers, group_consumers = _consumers(stock + custom)

    def stock_consumers(rule_id):
        sids = {c for c in sid_consumers[rule_id] if c in stock_ids}
        groups = {c for c in group_consumers[rule_id] if c in stock_ids}
        return sids, groups

    problems = []
    for rule in custom:
        # A: if_matched_sid re-routes a stock rule's events away from group lists
        target = rule.if_matched_sid
        if target in stock_ids:
            sids, groups = stock_consumers(target)
            if groups and not sids:
                problems.append(
                    f"{rule.id}: if_matched_sid {target} moves {target}'s events out of the group "
                    f"lists used by stock rules {sorted(groups)}; correlate via if_matched_group instead"
                )
        # B: a (non-correlation) child steals events its stock parent is counted on
        if rule.is_correlation:
            continue
        for parent in sorted(_parents(rule, stock) & stock_ids):
            sids, groups = stock_consumers(parent)
            if (sids or groups) and (rule.id, parent) not in ACCEPTED_PARENT_OVERLAPS:
                problems.append(
                    f"{rule.id}: child of stock rule {parent}, whose events feed stock correlation "
                    f"rules {sorted(sids | groups)}; events {rule.id} matches are hidden from them"
                )
    assert not problems, "\n".join(problems)


def test_custom_rules_reference_existing_parents(stock_rules_dir):
    stock, custom = _load(stock_rules_dir)
    known = {r.id for r in stock + custom}
    missing = [
        f"{rule.id} -> {ref}"
        for rule in custom
        for ref in [*rule.if_sid, rule.if_matched_sid]
        if ref is not None and ref not in known
    ]
    assert not missing, f"references to rules that do not exist: {missing}"
