"""Suricata rule tests: replay generated PCAPs through Suricata 8 running the
lab overlay (suricata/soc-lab.yaml + threshold.config) and compare the lab
SIDs that alert with each scenario's expectation."""

import json
import re
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.suricata.pcaps import Pcap
from tests.suricata.scenarios import SCENARIOS

pytestmark = pytest.mark.docker

IMAGE = "jasonish/suricata:8.0.7"
REPO_ROOT = Path(__file__).resolve().parents[2]
SURICATA_DIR = REPO_ROOT / "suricata"
LAB_SIDS = range(1000000, 1000100)
OVERLAY = ["-c", "/etc/suricata/suricata.yaml", "--include", "/etc/suricata/soc-lab.yaml"]


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def sensor(tmp_path_factory):
    """A Suricata container with the lab config; PCAPs are written to a shared dir."""
    pcap_dir = tmp_path_factory.mktemp("pcaps")
    name = f"soclab-suricata-test-{uuid.uuid4().hex[:8]}"
    mounts = {
        SURICATA_DIR / "rules": "/etc/suricata/rules",
        SURICATA_DIR / "soc-lab.yaml": "/etc/suricata/soc-lab.yaml",
        SURICATA_DIR / "threshold.config": "/etc/suricata/threshold.config",
        pcap_dir: "/pcaps",
    }
    volumes = [a for src, dst in mounts.items() for a in ("-v", f"{src}:{dst}")]
    started = docker("run", "-d", "--rm", "--name", name, "--entrypoint", "sleep", *volumes, IMAGE, "infinity")
    assert started.returncode == 0, started.stderr
    # ET Open is not part of the test run: only the lab's own signatures load.
    docker("exec", name, "sh", "-c", "mkdir -p /var/lib/suricata/rules && touch /var/lib/suricata/rules/suricata.rules")
    try:
        yield name, pcap_dir
    finally:
        docker("rm", "-f", name)


def replay(sensor, scenario_name, build) -> set[int]:
    name, pcap_dir = sensor
    pcap = Pcap()
    build(pcap)
    pcap.write(pcap_dir / f"{scenario_name}.pcap")
    out = f"/var/log/suricata/runs/{scenario_name}"
    run = docker(
        "exec",
        name,
        "sh",
        "-c",
        f"mkdir -p {out} && suricata {' '.join(OVERLAY)} -r /pcaps/{scenario_name}.pcap -l {out} -k none "
        f"--runmode single >/dev/null 2>{out}/stderr; cat {out}/eve.json",
    )
    assert run.returncode == 0, run.stderr
    sids = {
        event["alert"]["signature_id"]
        for event in map(json.loads, filter(None, run.stdout.splitlines()))
        if event.get("event_type") == "alert"
    }
    return {sid for sid in sids if sid in LAB_SIDS}


def test_config_and_rules_load(sensor):
    name, _ = sensor
    check = docker("exec", name, "suricata", "-T", *OVERLAY, "-l", "/var/log/suricata")
    assert check.returncode == 0, check.stdout + check.stderr


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_scenario(sensor, scenario_name):
    build, expected = SCENARIOS[scenario_name]
    assert replay(sensor, scenario_name, build) == expected


def test_every_lab_sid_has_a_positive_scenario():
    rule_text = "\n".join(p.read_text(encoding="utf-8") for p in (SURICATA_DIR / "rules").glob("*.rules"))
    defined = {int(s) for s in re.findall(r"^alert .*?\bsid:(\d+);", rule_text, flags=re.MULTILINE)}
    covered = set().union(*(expected for _, expected in SCENARIOS.values()))
    assert defined - covered == set(), f"SIDs without a positive scenario: {sorted(defined - covered)}"
