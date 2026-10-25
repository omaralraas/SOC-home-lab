"""End-to-end test of the Elastic tier exactly as elastic/docker-compose.yml deploys it.

Brings the whole stack up (setup job, Elasticsearch, Logstash, Kibana), then
feeds it the way the lab does: syslog over UDP, and Filebeat containers using
the repo's beats configs to ship an auth.log and a Suricata eve.json that
Suricata itself produced from a generated PCAP. Asserts the pipelines' ECS
output, the least-privilege Logstash user and Kibana health.

Heavy (about 3 GB RAM, a few minutes), so it only runs with `-m e2e`.
"""

import json
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

from tests.suricata.pcaps import Pcap
from tests.suricata.scenarios import SCENARIOS

pytestmark = [pytest.mark.docker, pytest.mark.e2e]

REPO_ROOT = Path(__file__).resolve().parents[2]
ELASTIC_DIR = REPO_ROOT / "elastic"
ENV = dict(re.findall(r"^(\w+)=(.*)$", (ELASTIC_DIR / ".env.example").read_text(), flags=re.MULTILINE))
ES = "http://127.0.0.1:9201"
ADMIN = ("elastic", ENV["ELASTIC_PASSWORD"])
PREFIX = "2026-10-25T10:00:0{i}.000000+00:00 ubuntu-srv sshd[22{i}0]: "
AUTH_LOG = [PREFIX.format(i=i) + f"Failed password for root from 203.0.113.77 port 5102{i} ssh2" for i in range(6)] + [
    PREFIX.format(i=9) + "Accepted password for root from 203.0.113.77 port 51030 ssh2"
]


def sh(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def wait_for(predicate, timeout=300, every=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except requests.RequestException:
            pass
        time.sleep(every)
    return False


def count(stream, query=None):
    body = {"query": query} if query else None
    resp = requests.post(f"{ES}/{stream}/_count", json=body, auth=ADMIN, timeout=10)
    return resp.json().get("count", 0) if resp.ok else 0


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    project = f"soclab-e2e-{uuid.uuid4().hex[:6]}"
    compose = ["docker", "compose", "-p", project, "--env-file", ".env.example"]
    up = sh(*compose, "up", "-d", "--wait", cwd=ELASTIC_DIR, timeout=900)
    try:
        assert up.returncode == 0, up.stdout[-3000:] + up.stderr[-3000:]
        work = tmp_path_factory.mktemp("e2e")
        yield project, work
    finally:
        sh(*compose, "down", "-v", cwd=ELASTIC_DIR, timeout=300)


def run_filebeat(project, work, config, log_dir, target_path, port):
    """Run Filebeat with a repo config, pointed at the compose network's Logstash."""
    sh(
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        f"{project}-fb-{port}",
        "--network",
        f"{project}_default",
        "-v",
        f"{config}:/usr/share/filebeat/filebeat.yml:ro",
        "-v",
        f"{log_dir}:{target_path}:ro",
        "docker.elastic.co/beats/filebeat:" + ENV["STACK_VERSION"],
        "-e",
        "--strict.perms=false",
        "-E",
        f'output.logstash.hosts=["logstash:{port}"]',
    )


def test_setup_created_least_privilege_logstash_user(stack):
    writer = ("logstash_internal", ENV["LOGSTASH_PASSWORD"])
    assert requests.get(f"{ES}/_security/_authenticate", auth=writer, timeout=10).ok
    # the writer may create docs in logs-soc.* but not read them or touch other indices
    assert requests.post(f"{ES}/logs-soc.*/_search", auth=writer, timeout=10).status_code == 403
    assert requests.put(f"{ES}/not-allowed/_doc/1", json={"a": 1}, auth=writer, timeout=10).status_code == 403


def test_syslog_ssh_events_are_normalised(stack):
    project, _ = stack
    # Sent from inside the compose network, as pfSense would from the SOC VLAN
    # (Docker Desktop does not reliably forward UDP published ports from the host).
    # The UDP listener binds just after Logstash reports the pipeline running,
    # and datagrams sent into that gap are dropped, so resend until they land.
    lines = "; ".join(
        f'echo "<38>Oct 25 10:00:0{i} pfsense-fw sshd[2201]: Failed password for admin from 198.51.100.23 '
        f'port 4000{i} ssh2" > /dev/udp/logstash/5514'
        for i in range(3)
    )
    image = "docker.elastic.co/logstash/logstash:" + ENV["STACK_VERSION"]
    q = {"term": {"source.ip": "198.51.100.23"}}
    for _ in range(6):
        sent = sh(
            "docker", "run", "--rm", "--network", f"{project}_default", "--entrypoint", "bash", image, "-c", lines
        )
        assert sent.returncode == 0, sent.stderr
        if wait_for(lambda: count("logs-soc.syslog-lab", q) >= 3, timeout=30):
            break
    else:
        pytest.fail("syslog events never reached logs-soc.syslog-lab")

    docs = requests.post(f"{ES}/logs-soc.syslog-lab/_search", auth=ADMIN, timeout=10,
                         json={"query": q, "size": 20}).json()["hits"]["hits"]  # fmt: skip
    for doc in (d["_source"] for d in docs):
        assert doc["user"]["name"] == "admin"
        assert doc["event"]["category"] == "authentication" and doc["event"]["outcome"] == "failure"
        assert doc["host"]["hostname"] == "pfsense-fw" and doc["process"]["name"] == "sshd"


def test_filebeat_auth_log_feeds_the_ssh_hunt(stack):
    project, work = stack
    log_dir = work / "auth"
    log_dir.mkdir()
    (log_dir / "auth.log").write_text("\n".join(AUTH_LOG) + "\n")
    run_filebeat(project, work, ELASTIC_DIR / "beats" / "filebeat-linux.yml", log_dir, "/var/log", 5044)
    try:
        q = {"term": {"source.ip": "203.0.113.77"}}
        assert wait_for(lambda: count("logs-soc.syslog-lab", q) == 7, timeout=180), "auth.log not shipped"
        hunt = (REPO_ROOT / "scripts/threat-hunting/esql/credential_access_hunting.md").read_text()
        query = re.search(r"```esql\n(.*?)```", hunt, flags=re.DOTALL).group(1)
        resp = requests.post(f"{ES}/_query?format=json", json={"query": query}, auth=ADMIN, timeout=30)
        assert resp.ok, resp.text
        rows = [dict(zip([c["name"] for c in resp.json()["columns"]], r, strict=True)) for r in resp.json()["values"]]
        assert any(r["source.ip"] == "203.0.113.77" and r["successes"] == 1 for r in rows), rows
    finally:
        sh("docker", "rm", "-f", f"{project}-fb-5044")


def test_suricata_eve_from_a_real_sensor_run_is_mapped_to_ecs(stack, tmp_path):
    project, work = stack
    # produce a genuine eve.json: replay a generated PCAP through Suricata with the lab overlay
    pcap = Pcap()
    SCENARIOS["tls_openssl_default_certificate"][0](pcap)
    SCENARIOS["sql_injection_union_select"][0](pcap)
    eve_dir = work / "suricata"
    eve_dir.mkdir()
    pcap.write(eve_dir / "lab.pcap")
    suricata = REPO_ROOT / "suricata"
    run = sh(
        "docker",
        "run",
        "--rm",
        "-v",
        f"{eve_dir}:/data",
        "-v",
        f"{suricata / 'rules'}:/etc/suricata/rules:ro",
        "-v",
        f"{suricata / 'soc-lab.yaml'}:/etc/suricata/soc-lab.yaml:ro",
        "-v",
        f"{suricata / 'threshold.config'}:/etc/suricata/threshold.config:ro",
        "--entrypoint",
        "sh",
        "jasonish/suricata:8.0.7",
        "-c",
        "mkdir -p /var/lib/suricata/rules && touch /var/lib/suricata/rules/suricata.rules && "
        "suricata -c /etc/suricata/suricata.yaml --include /etc/suricata/soc-lab.yaml -r /data/lab.pcap "
        "-l /data -k none --runmode single",
        timeout=300,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    shutil.move(eve_dir / "eve.json", eve_dir / "eve.json.done")  # filebeat reads a complete file
    (eve_dir / "eve.json").write_text((eve_dir / "eve.json.done").read_text())

    run_filebeat(project, work, ELASTIC_DIR / "beats" / "filebeat-suricata.yml", eve_dir, "/var/log/suricata", 5046)
    try:
        alert_q = {"bool": {"filter": [{"term": {"event.kind": "alert"}}, {"term": {"rule.id": 1000012}}]}}
        assert wait_for(lambda: count("logs-soc.suricata-lab", alert_q) >= 1, timeout=180), "Suricata alert not mapped"
        hits = requests.post(
            f"{ES}/logs-soc.suricata-lab/_search", auth=ADMIN, timeout=10, json={"query": alert_q, "size": 1}
        ).json()["hits"]["hits"]
        doc = hits[0]["_source"]
        assert doc["source"]["ip"] == "10.0.2.100" and doc["destination"]["ip"] == "10.0.0.51"
        assert doc["threat"]["technique"]["id"] == ["T1190"] or doc["threat"]["technique"]["id"] == "T1190"
        assert doc["network"]["transport"] == "tcp" and int(doc["event"]["severity"]) > 0
        tls_q = {"term": {"suricata.eve.event_type": "tls"}}
        assert count("logs-soc.suricata-lab", tls_q) >= 1
    finally:
        sh("docker", "rm", "-f", f"{project}-fb-5046")


def test_data_streams_use_the_soc_retention_policy(stack):
    """setup.sh attaches soc-logs (weekly rollover, 30-day delete) via logs@custom."""
    q = {"term": {"source.ip": "198.51.100.23"}}
    assert wait_for(lambda: count("logs-soc.syslog-lab", q) > 0, timeout=60)  # stream exists
    explain = requests.get(f"{ES}/logs-soc.syslog-lab/_ilm/explain", auth=ADMIN, timeout=10).json()["indices"]
    assert explain and all(index["policy"] == "soc-logs" and index["managed"] for index in explain.values()), explain


def test_kibana_is_available(stack):
    def ready():
        resp = requests.get("http://127.0.0.1:5601/api/status", auth=ADMIN, timeout=10)
        return resp.ok and resp.json()["status"]["overall"]["level"] == "available"

    assert wait_for(ready, timeout=300), "Kibana did not report available"


def test_logstash_pipelines_are_running(stack):
    project, _ = stack
    out = sh(
        "docker",
        "compose",
        "-p",
        project,
        "--env-file",
        ".env.example",
        "exec",
        "-T",
        "logstash",
        "curl",
        "-s",
        "localhost:9600/_node/pipelines",
        cwd=ELASTIC_DIR,
    )
    assert set(json.loads(out.stdout)["pipelines"]) == {"syslog", "windows", "suricata"}
