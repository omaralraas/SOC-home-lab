"""Replay test events through wazuh-analysisd via the logtest socket.

Runs *inside* the wazuh-manager container (stdlib only, Wazuh's bundled
Python). Reads a JSON list of scenarios on stdin and prints a JSON list of
results: for every event, the rule that fired (id, level, groups) or null.

Each scenario gets its own logtest session token, so frequency/timeframe
rules (brute-force counters, correlation) are evaluated with the state built
up by the earlier events of that scenario only.
"""

import json
import socket
import struct
import sys

SOCKET_PATH = "/var/ossec/queue/sockets/logtest"


def _request(payload):
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET_PATH)
        sock.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", _recv_exact(sock, 4))[0]
        return json.loads(_recv_exact(sock, size))


def _recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("logtest socket closed mid-response")
        buf += chunk
    return buf


def run_scenario(scenario):
    token = None
    results = []
    for event in scenario["events"]:
        params = {
            "event": event,
            "log_format": scenario.get("log_format", "syslog"),
            "location": scenario.get("location", "/var/log/auth.log"),
        }
        if token:
            params["token"] = token
        reply = _request(
            {
                "version": 1,
                "origin": {"name": "soclab-tests", "module": "wazuh-logtest"},
                "command": "log_processing",
                "parameters": params,
            }
        )
        if reply.get("error"):
            raise RuntimeError(f"logtest error: {reply}")
        data = reply["data"]
        token = data.get("token", token)
        rule = data.get("output", {}).get("rule")
        results.append(
            {
                "id": rule["id"],
                "level": rule["level"],
                "description": rule.get("description", ""),
                "groups": rule.get("groups", []),
                "mitre": rule.get("mitre", {}).get("id", []),
                "decoder": data["output"].get("decoder", {}).get("name"),
            }
            if rule
            else None
        )
    if token:
        _request(
            {
                "version": 1,
                "origin": {"name": "soclab-tests", "module": "wazuh-logtest"},
                "command": "remove_session",
                "parameters": {"token": token},
            }
        )
    return results


def main():
    scenarios = json.load(sys.stdin)
    json.dump([run_scenario(s) for s in scenarios], sys.stdout)


if __name__ == "__main__":
    main()
