import json
import random
from datetime import UTC, datetime, timedelta

from beacon_hunter import Flow, hunt, main, parse_eve

START = datetime(2026, 10, 25, 8, 0, tzinfo=UTC)


def beacon(n=120, interval=60, jitter=0.05, size=512, dest="203.0.113.50", seed=1):
    rng = random.Random(seed)
    t, flows = START, []
    for _ in range(n):
        t += timedelta(seconds=interval * (1 + rng.uniform(-jitter, jitter)))
        flows.append(Flow(t, "10.0.0.50", dest, 443, "TCP", size + rng.randint(-8, 8)))
    return flows


def browsing(n=120, dest="198.51.100.20", seed=2):
    rng = random.Random(seed)
    t, flows = START, []
    for _ in range(n):
        t += timedelta(seconds=rng.expovariate(1 / 90))  # bursty, Poisson-like human activity
        flows.append(Flow(t, "10.0.0.50", dest, 443, "TCP", rng.randint(300, 40000)))
    return flows


def test_regular_beacon_scores_high_and_browsing_scores_low():
    # 2 hours of activity earns a third of the persistence weight, so even a
    # perfect beacon lands just above 0.8 here
    results = {c.dest_ip: c for c in hunt(beacon() + browsing())}
    assert results["203.0.113.50"].score > 0.8
    assert results["198.51.100.20"].score < 0.4


def test_jittered_beacon_still_ranks_first():
    # 30% jitter (common C2 profile setting) lowers but does not hide the beacon
    [top, *_] = hunt(beacon(jitter=0.3) + browsing())
    assert top.dest_ip == "203.0.113.50"


def test_missed_check_ins_do_not_break_regularity():
    flows = beacon()
    del flows[40:43]  # host asleep for a few minutes
    [candidate] = hunt(flows)
    assert candidate.jitter < 0.05


def test_minimum_connections_and_ignore_list():
    assert hunt(beacon(n=5)) == []
    assert hunt(beacon(), ignore=["203.0.113.0/24"]) == []


def test_parses_suricata_eve_flow_records(tmp_path, capsys):
    # field layout and +HHMM offset as written by Suricata 8
    lines = []
    for f in beacon(n=30):
        lines.append(
            json.dumps(
                {
                    "timestamp": f.start.strftime("%Y-%m-%dT%H:%M:%S.%f+0400"),
                    "event_type": "flow",
                    "src_ip": f.src_ip,
                    "src_port": 49152,
                    "dest_ip": f.dest_ip,
                    "dest_port": f.dest_port,
                    "proto": f.proto,
                    "flow": {
                        "pkts_toserver": 6,
                        "bytes_toserver": f.bytes_toserver,
                        "start": f.start.strftime("%Y-%m-%dT%H:%M:%S.%f+0400"),
                    },
                }
            )
        )
    lines.append('{"event_type": "alert"}')
    lines.append("not json")
    assert len(parse_eve(lines)) == 30

    eve = tmp_path / "eve.json"
    eve.write_text("\n".join(lines))
    assert main(["--eve", str(eve), "--format", "json", "--min-score", "0.5"]) == 0
    [result] = json.loads(capsys.readouterr().out)
    assert result["dest_ip"] == "203.0.113.50" and result["connections"] == 30
