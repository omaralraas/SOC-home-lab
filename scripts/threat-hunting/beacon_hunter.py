#!/usr/bin/env python3
"""
SOC Home Lab - C2 Beacon Hunter
===============================
Scores connection pairs in Suricata EVE flow logs for beaconing: implants
check in on a timer, so their connections arrive at regular intervals with
consistent request sizes, for hours. Human and application traffic does not.

For each (source, destination, port, protocol) pair with enough connections:

  interval regularity  1 - (MAD of inter-arrival times / median interval),
                       scaled so 50% jitter or more scores 0. Median and MAD
                       are robust to a missed check-in or a burst of retries.
  size regularity      1 - coefficient of variation of bytes sent to server
  persistence          how much of a 6-hour window the pair was active

score = 0.5 * interval + 0.3 * size + 0.2 * persistence  (0..1)

Author: Omar Alraas
Usage:  python beacon_hunter.py --eve /var/log/suricata/eve.json --min-score 0.7
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import statistics
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime

JITTER_CEILING = 0.5  # MAD/median at or above this scores 0 for regularity
PERSISTENCE_HOURS = 6.0


@dataclass(frozen=True)
class Flow:
    start: datetime
    src_ip: str
    dest_ip: str
    dest_port: int
    proto: str
    bytes_toserver: int


@dataclass
class BeaconCandidate:
    src_ip: str
    dest_ip: str
    dest_port: int
    proto: str
    connections: int
    median_interval_s: float
    jitter: float
    size_cv: float
    active_hours: float
    score: float


def parse_eve(lines: Iterable[str]) -> list[Flow]:
    flows = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "flow" or "flow" not in event:
            continue
        flows.append(
            Flow(
                # Suricata writes local offsets as +HHMM; normalise to +HH:MM
                start=datetime.fromisoformat(re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", event["flow"]["start"])),
                src_ip=event["src_ip"],
                dest_ip=event["dest_ip"],
                dest_port=int(event.get("dest_port", 0)),
                proto=event.get("proto", ""),
                bytes_toserver=int(event["flow"].get("bytes_toserver", 0)),
            )
        )
    return flows


def score_pair(flows: list[Flow]) -> BeaconCandidate:
    flows = sorted(flows, key=lambda f: f.start)
    starts = [f.start.timestamp() for f in flows]
    intervals = [b - a for a, b in zip(starts, starts[1:], strict=False)]
    median = statistics.median(intervals)
    mad = statistics.median(abs(i - median) for i in intervals)
    jitter = mad / median if median > 0 else 1.0
    sizes = [f.bytes_toserver for f in flows]
    mean_size = statistics.fmean(sizes)
    size_cv = statistics.pstdev(sizes) / mean_size if mean_size > 0 else 1.0
    active_hours = (starts[-1] - starts[0]) / 3600

    interval_score = max(0.0, 1 - jitter / JITTER_CEILING)
    size_score = max(0.0, 1 - size_cv)
    persistence = min(1.0, active_hours / PERSISTENCE_HOURS)
    first = flows[0]
    return BeaconCandidate(
        src_ip=first.src_ip,
        dest_ip=first.dest_ip,
        dest_port=first.dest_port,
        proto=first.proto,
        connections=len(flows),
        median_interval_s=round(median, 1),
        jitter=round(jitter, 3),
        size_cv=round(size_cv, 3),
        active_hours=round(active_hours, 2),
        score=round(0.5 * interval_score + 0.3 * size_score + 0.2 * persistence, 3),
    )


def hunt(
    flows: Iterable[Flow], min_connections: int = 10, min_score: float = 0.0, ignore: Iterable[str] = ()
) -> list[BeaconCandidate]:
    ignored = [ipaddress.ip_network(n) for n in ignore]
    pairs: dict[tuple, list[Flow]] = defaultdict(list)
    for f in flows:
        if any(ipaddress.ip_address(f.dest_ip) in net for net in ignored):
            continue
        pairs[(f.src_ip, f.dest_ip, f.dest_port, f.proto)].append(f)
    candidates = [score_pair(group) for group in pairs.values() if len(group) >= min_connections]
    return sorted((c for c in candidates if c.score >= min_score), key=lambda c: c.score, reverse=True)


def format_table(candidates: list[BeaconCandidate]) -> str:
    header = (
        f"{'score':>5}  {'source':<15} {'destination':<21} {'conns':>5} "
        f"{'interval':>9} {'jitter':>6} {'size_cv':>7} {'hours':>5}"
    )
    rows = [
        f"{c.score:>5.2f}  {c.src_ip:<15} {c.dest_ip + ':' + str(c.dest_port):<21} {c.connections:>5} "
        f"{c.median_interval_s:>8.0f}s {c.jitter:>6.2f} {c.size_cv:>7.2f} {c.active_hours:>5.1f}"
        for c in candidates
    ]
    return "\n".join([header, "-" * len(header), *rows]) if rows else "No beacon candidates above the score threshold."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score Suricata flow logs for C2 beaconing")
    parser.add_argument("--eve", required=True, help="Suricata eve.json ('-' for stdin)")
    parser.add_argument("--min-connections", type=int, default=10)
    parser.add_argument("--min-score", type=float, default=0.7)
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="CIDR",
        help="destination network to skip (NTP, update servers); repeatable",
    )
    parser.add_argument("--format", choices=["table", "json"], default="table")
    args = parser.parse_args(argv)

    try:
        if args.eve == "-":
            flows = parse_eve(sys.stdin)
        else:
            with open(args.eve, encoding="utf-8") as fh:
                flows = parse_eve(fh)
    except OSError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    candidates = hunt(flows, args.min_connections, args.min_score, args.ignore)
    print(json.dumps([asdict(c) for c in candidates], indent=2) if args.format == "json" else format_table(candidates))
    return 0


if __name__ == "__main__":
    sys.exit(main())
