"""Shared helpers for the Wazuh test suite: container control and rule parsing."""

import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

IMAGE = "wazuh/wazuh-manager:4.14.8"
HERE = Path(__file__).parent
REPO_ROOT = HERE.parents[1]
RULES_DIR = REPO_ROOT / "wazuh" / "rules"

MOUNTS = {
    REPO_ROOT / "wazuh" / "ossec.conf": "/wazuh-config-mount/etc/ossec.conf",
    RULES_DIR: "/wazuh-config-mount/etc/rules",
    REPO_ROOT / "wazuh" / "shared" / "agent.conf": "/wazuh-config-mount/etc/shared/default/agent.conf",
    HERE / "shim" / "0005-windows-eventchannel-shim.xml": (
        "/wazuh-config-mount/ruleset/decoders/0005-windows-eventchannel-shim.xml"
    ),
    HERE / "logtest_client.py": "/opt/soclab/logtest_client.py",
}


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], capture_output=True, text=True, **kwargs)


@dataclass
class Rule:
    id: int
    level: int
    groups: list[str]
    source: str
    if_sid: list[int] = field(default_factory=list)
    if_group: str | None = None
    if_matched_sid: int | None = None
    if_matched_group: str | None = None
    overwrite: bool = False

    @property
    def is_correlation(self) -> bool:
        return self.if_matched_sid is not None or self.if_matched_group is not None


def _text(el: ET.Element, tag: str) -> str | None:
    return (el.findtext(tag) or "").strip() or None


def parse_rules(path: Path) -> list[Rule]:
    """Parse a Wazuh rule file (an XML fragment with several top-level groups).

    Wazuh's own XML reader tolerates bare '<' and '&' inside regex text, which
    some stock files rely on, so those are escaped before strict parsing.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"&(?!(amp|lt|gt|quot|apos|#\d+);)", "&amp;", text)
    text = re.sub(r"<(?![A-Za-z/!?])", "&lt;", text)
    root = ET.fromstring(f"<root>{text}</root>")  # noqa: S314 - repo and vendor rule files, not untrusted input
    rules = []
    for group in root.iter("group"):
        if group.get("name") is None:
            continue
        file_groups = [g for g in group.get("name").split(",") if g]
        for el in group.findall("rule"):
            groups = file_groups + [g for t in el.findall("group") for g in (t.text or "").split(",") if g.strip()]
            if_sid = _text(el, "if_sid")
            matched_sid = _text(el, "if_matched_sid")
            rules.append(
                Rule(
                    id=int(el.get("id")),
                    level=int(el.get("level", 0)),
                    groups=[g.strip() for g in groups],
                    source=path.name,
                    if_sid=[int(s) for s in if_sid.replace(",", " ").split()] if if_sid else [],
                    if_group=_text(el, "if_group"),
                    if_matched_sid=int(matched_sid) if matched_sid else None,
                    if_matched_group=_text(el, "if_matched_group"),
                    overwrite=el.get("overwrite") == "yes",
                )
            )
    return rules
