import importlib.util
import json
from pathlib import Path

import pytest
import soar_engine as soar

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = "test-secret"
NOW = 1_800_000_000.0

CONFIG = {
    "response": {
        "block_ip_min_level": 10,
        "block_min_reputation": 50,
        "always_block_rules": [5763],
        "block_ttl_seconds": 3600,
        "never_block": ["10.0.0.0/24", "10.0.1.0/24"],
        "notify_min_level": 12,
        "recommend_disable_account_rules": [100102],
    },
    "dedup_seconds": 600,
}


class FakeReputation:
    def __init__(self, scores=None):
        self.scores = scores or {}

    def score(self, ip):
        return self.scores.get(ip, 0)


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    sent = []
    playbook = soar.Playbook(
        CONFIG,
        FakeReputation({"198.51.100.66": 97}),
        soar.Blocklist(tmp_path / "blocklist.json", clock),
        soar.AuditLog(tmp_path / "actions.json"),
        notifier=lambda text: sent.append(text) or True,
        clock=clock,
    )
    client = soar.create_app(playbook, SECRET, max_skew=300, clock=clock).test_client()
    return client, playbook, clock, tmp_path, sent


def wazuh_alert(rule_id, level, srcip=None, alert_id="1761390000.1234", **data):
    alert = {
        "id": alert_id,
        "rule": {"id": str(rule_id), "level": level, "description": "test"},
        "agent": {"name": "ubuntu-srv"},
        "data": data,
    }
    if srcip:
        alert["data"]["srcip"] = srcip
    return alert


def post(client, alert, secret=SECRET, timestamp=NOW):
    body = json.dumps(alert).encode()
    ts = str(int(timestamp))
    headers = {soar.TIMESTAMP_HEADER: ts, soar.SIGNATURE_HEADER: soar.sign(secret, ts, body)}
    return client.post("/webhook/wazuh", data=body, headers=headers, content_type="application/json")


# ------------------------------------------------------------- authentication
def test_rejects_unsigned_requests(env):
    client, *_ = env
    assert client.post("/webhook/wazuh", json=wazuh_alert(5763, 10, "10.0.2.100")).status_code == 401


def test_rejects_wrong_secret_and_replayed_requests(env):
    client, *_ = env
    assert post(client, wazuh_alert(5763, 10, "10.0.2.100"), secret="wrong").status_code == 401
    assert post(client, wazuh_alert(5763, 10, "10.0.2.100"), timestamp=NOW - 3600).status_code == 401


def test_wazuh_integration_signature_is_accepted_by_the_engine():
    """The integration script and the webhook must agree on the signature scheme."""
    path = REPO_ROOT / "wazuh" / "integrations" / "custom-soar.py"
    spec = importlib.util.spec_from_file_location("custom_soar", path)
    integration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(integration)
    req = integration.build_request({"rule": {"id": "5763"}}, SECRET, "http://soar:5000/webhook/wazuh")
    ts = req.get_header(soar.TIMESTAMP_HEADER.capitalize())
    sig = req.get_header(soar.SIGNATURE_HEADER.capitalize())
    assert soar.verify(SECRET, ts, sig, req.data, now=float(ts), max_skew=300)
    with pytest.raises(ValueError):
        integration.build_request({}, SECRET, "file:///etc/passwd")


# ------------------------------------------------------------- playbook
def test_brute_force_from_attacker_vlan_is_blocked_and_served_to_pfsense(env):
    client, _, _, tmp_path, _ = env
    resp = post(client, wazuh_alert(5763, 10, "10.0.2.100"))
    [action] = resp.get_json()["actions"]
    assert (action["action"], action["status"]) == ("block_ip", "executed")
    assert client.get("/blocklist.txt").get_data(as_text=True).split() == ["10.0.2.100"]


def test_internal_hosts_are_never_blocked(env):
    client, *_ = env
    [action] = post(client, wazuh_alert(5763, 10, "10.0.1.10")).get_json()["actions"]
    assert action["status"] == "skipped" and "never-block" in action["detail"]


def test_public_ip_needs_bad_reputation(env):
    client, *_ = env
    [clean] = post(client, wazuh_alert(100109, 10, "203.0.113.5", alert_id="a1")).get_json()["actions"]
    [bad] = post(client, wazuh_alert(100109, 10, "198.51.100.66", alert_id="a2")).get_json()["actions"]
    assert clean["status"] == "skipped" and bad["status"] == "executed"


def test_duplicate_alerts_are_ignored(env):
    client, *_ = env
    alert = wazuh_alert(5763, 10, "10.0.2.100")
    assert post(client, alert).get_json()["actions"]
    assert post(client, alert).get_json()["actions"] == []


def test_blocks_expire(env):
    client, _, clock, _, _ = env
    post(client, wazuh_alert(5763, 10, "10.0.2.100"))
    clock.now += 3601
    assert client.get("/blocklist.txt").get_data(as_text=True).strip() == ""


def test_compromise_alert_recommends_disabling_account_and_notifies(env):
    client, _, _, _, sent = env
    alert = wazuh_alert(
        100102, 13, alert_id="c1", win={"eventdata": {"ipAddress": "10.0.2.100", "targetUserName": "administrator"}}
    )
    actions = {a["action"]: a for a in post(client, alert).get_json()["actions"]}
    assert actions["recommend_disable_account"]["target"] == "administrator"
    assert actions["block_ip"]["target"] == "10.0.2.100"  # Windows source IP extracted from eventdata
    assert actions["notify"]["status"] == "executed" and sent


def test_audit_log_lines_match_the_wazuh_soar_rules(env):
    client, _, _, tmp_path, _ = env
    post(client, wazuh_alert(5763, 10, "10.0.2.100"))
    [line] = (tmp_path / "actions.json").read_text().splitlines()
    record = json.loads(line)["soar"]
    # wazuh/rules/custom-soar.xml keys on soar.action / soar.status / soar.target / soar.rule_id
    assert {"action", "status", "target", "rule_id"} <= record.keys()
    assert record["rule_id"] == "5763"
