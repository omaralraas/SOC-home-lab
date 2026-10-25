"""Run every ES|QL hunt in scripts/threat-hunting/esql against Elasticsearch.

A disposable single-node Elasticsearch (same version as elastic/) is seeded
with events shaped like the Logstash pipelines' output. Each query must run
without a parsing or verification error (so field names and syntax are real),
and selected hunts must surface the malicious event planted for them.
"""

import json
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

from tests.elastic.seed import STREAMS

pytestmark = pytest.mark.docker

REPO_ROOT = Path(__file__).resolve().parents[2]
HUNT_DIR = REPO_ROOT / "scripts" / "threat-hunting" / "esql"
STACK_VERSION = re.search(r"STACK_VERSION=(\S+)", (REPO_ROOT / "elastic" / ".env.example").read_text()).group(1)


def load_hunts():
    hunts = []
    for path in sorted(HUNT_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for section in re.split(r"^## ", text, flags=re.MULTILINE)[1:]:
            title = re.sub(r"^\d+\.\s*", "", section.splitlines()[0].strip())
            for query in re.findall(r"```esql\n(.*?)```", section, flags=re.DOTALL):
                hunts.append(pytest.param(query.strip(), id=f"{path.stem}: {title}"))
    return hunts


HUNTS = load_hunts()

# hunt title prefix -> (column, value) the planted event must produce
EXPECTED_HITS = {
    "Scheduled tasks created on few hosts": ("winlog.event_data.TaskName", "\\OneDriveSync"),
    "Run-key values pointing at unusual binaries": ("registry.data.strings", "C:\\Users\\Public\\upd.exe"),
    "New services, suspicious image paths first": ("winlog.event_data.ServiceName", "BTOBTO"),
    "WMI event subscriptions": ("winlog.event_data.Destination", "powershell -enc SQBFAFgA"),
    "Files dropped into Startup folders": ("file.name", "run.vbs"),
    "Admin share access followed by a service install": ("host.name", "WIN10-LAB"),
    "Processes spawned by the WMI provider host": ("process.executable", "C:\\Windows\\System32\\cmd.exe"),
    "Commands run inside WinRM sessions": ("process.executable", "C:\\Windows\\System32\\whoami.exe"),
    "NewCredentials logons via seclogo": ("winlog.event_data.TargetOutboundUserName", "administrator"),
    "RDP fan-out and fan-in": ("winlog.event_data.TargetUserName", "admin"),
    "Hosts sending far more than they receive": ("destination.ip", "198.51.100.9"),
    "DNS tunnelling": ("parent", "attacker.example"),
    "Persistent periodic connections": ("destination.ip", "203.0.113.50"),
    "Self-signed or default TLS certificates": ("suricata.eve.tls.sni", "update-cdn.example"),
    "Archives staged in temporary folders": ("file.path", "C:\\Users\\Public\\q3.zip"),
    "SSH sources that failed and then succeeded": ("source.ip", "10.0.2.100"),
    "Password spraying against Windows accounts": ("source.ip", "10.0.2.100"),
    "Processes opening LSASS": ("winlog.event_data.SourceImage", "C:\\Users\\Public\\m.exe"),
}


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def es():
    name = f"soclab-es-test-{uuid.uuid4().hex[:8]}"
    started = docker(
        "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::9200",
        "-e", "discovery.type=single-node", "-e", "xpack.security.enabled=false",
        "-e", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
        f"docker.elastic.co/elasticsearch/elasticsearch:{STACK_VERSION}",
    )  # fmt: skip
    assert started.returncode == 0, started.stderr
    try:
        port = docker("port", name, "9200/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if requests.get(f"{url}/_cluster/health", timeout=2).ok:
                    break
            except requests.RequestException:
                pass
            time.sleep(2)
        else:
            pytest.fail("Elasticsearch did not start")
        for stream, build in STREAMS.items():
            body = "".join(json.dumps({"create": {}}) + "\n" + json.dumps(doc) + "\n" for doc in build())
            resp = requests.post(
                f"{url}/{stream}/_bulk?refresh=true",
                data=body,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=30,
            )
            assert resp.ok and not resp.json()["errors"], resp.text[:2000]
        yield url
    finally:
        docker("rm", "-f", name)


def run(es, query):
    resp = requests.post(f"{es}/_query?format=json", json={"query": query}, timeout=30)
    assert resp.ok, f"{resp.status_code}: {resp.json().get('error', {}).get('reason', resp.text)[:1500]}"
    body = resp.json()
    names = [c["name"] for c in body["columns"]]
    return [dict(zip(names, row, strict=True)) for row in body["values"]]


@pytest.mark.parametrize("query", HUNTS)
def test_hunt_runs_and_finds_planted_activity(es, query, request):
    rows = run(es, query)
    title = request.node.callspec.id.split(": ", 1)[1]
    for prefix, (column, value) in EXPECTED_HITS.items():
        if title.startswith(prefix):
            values = [row.get(column) for row in rows]
            flat = {v for item in values for v in (item if isinstance(item, list) else [item])}
            assert value in flat, f"expected {column}={value!r} in results, got {values}"


def test_every_hunt_has_an_expectation():
    titles = [p.id.split(": ", 1)[1] for p in HUNTS]
    missing = [t for t in titles if not any(t.startswith(prefix) for prefix in EXPECTED_HITS)]
    assert not missing, f"hunts without a planted-event expectation: {missing}"
