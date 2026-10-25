#!/usr/bin/env python3
"""
SOC Home Lab - Lightweight SOAR Engine
======================================
Receives Wazuh alerts from the custom-soar integration, enriches the source
IP, and runs the response playbook:

  * block_ip  - adds the source to an expiring blocklist that pfSense pulls
                as a URL-table alias (GET /blocklist.txt), so containment
                needs no firewall credentials on this host
  * notify    - Slack message for high-severity alerts
  * recommend_disable_account - surfaced for an analyst, never automatic

Safety rails: requests must carry a valid HMAC signature from the Wazuh
integration (with a replay window), internal and allow-listed networks are
never blocked, duplicate alerts are ignored, and every action is written as
a JSON audit line that Wazuh ingests (wazuh/rules/custom-soar.xml).

Author: Omar Alraas
Usage:  SOAR_SHARED_SECRET=... python soar_engine.py --config config/soar_config.yml
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml
from flask import Flask, Response, jsonify, request

log = logging.getLogger("soar")

SIGNATURE_HEADER = "X-SOAR-Signature"
TIMESTAMP_HEADER = "X-SOAR-Timestamp"


# --------------------------------------------------------------------------- #
# Request authentication
# --------------------------------------------------------------------------- #


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """Same construction as wazuh/integrations/custom-soar.py."""
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str | None, signature: str | None, body: bytes, now: float, max_skew: int) -> bool:
    if not (secret and timestamp and signature):
        return False
    try:
        if abs(now - int(timestamp)) > max_skew:
            return False  # stale or replayed request
    except ValueError:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


# --------------------------------------------------------------------------- #
# Alert model
# --------------------------------------------------------------------------- #


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    level: int
    description: str
    agent: str
    source_ip: str | None
    user: str | None
    mitre: list[str]

    @classmethod
    def from_wazuh(cls, raw: dict[str, Any]) -> Alert:
        rule, data = raw.get("rule", {}), raw.get("data", {})
        eventdata = data.get("win", {}).get("eventdata", {})
        source_ip = data.get("srcip") or eventdata.get("ipAddress")
        user = data.get("dstuser") or data.get("srcuser") or eventdata.get("targetUserName")
        alert_id = str(raw.get("id") or hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:16])
        return cls(
            alert_id=alert_id,
            rule_id=str(rule.get("id", "")),
            level=int(rule.get("level", 0)),
            description=rule.get("description", ""),
            agent=raw.get("agent", {}).get("name", ""),
            source_ip=source_ip if source_ip not in ("-", "::1", "127.0.0.1") else None,
            user=user or None,
            mitre=rule.get("mitre", {}).get("id", []),
        )


@dataclass
class Action:
    action: str
    target: str
    status: str  # executed | skipped | failed | recommended
    detail: str = ""
    alert_id: str = ""
    rule_id: str = ""
    timestamp: float = field(default_factory=time.time)


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #


class Reputation:
    """AbuseIPDB lookup with a TTL cache; private and unknown IPs score 0."""

    def __init__(
        self,
        api_key: str | None,
        ttl: int = 86400,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.api_key, self.ttl, self.clock = api_key, ttl, clock
        self.session = session or requests.Session()
        self._cache: dict[str, tuple[float, int]] = {}

    def score(self, ip: str) -> int:
        if not self.api_key or not ipaddress.ip_address(ip).is_global:
            return 0
        cached = self._cache.get(ip)
        if cached and self.clock() - cached[0] < self.ttl:
            return cached[1]
        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            resp.raise_for_status()
            value = int(resp.json()["data"]["abuseConfidenceScore"])
        except (requests.RequestException, KeyError, ValueError) as exc:
            log.warning("reputation lookup failed for %s: %s", ip, exc)
            return 0
        self._cache[ip] = (self.clock(), value)
        return value


# --------------------------------------------------------------------------- #
# Containment and audit
# --------------------------------------------------------------------------- #


class Blocklist:
    """Expiring IP blocklist persisted to JSON and served to pfSense."""

    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self.path, self.clock = path, clock
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        if path.exists():
            self._entries = json.loads(path.read_text(encoding="utf-8"))

    def add(self, ip: str, ttl: int, reason: str) -> bool:
        with self._lock:
            self._expire()
            new = ip not in self._entries
            self._entries[ip] = {"expires": self.clock() + ttl, "reason": reason}
            self._save()
            return new

    def active(self) -> list[str]:
        with self._lock:
            self._expire()
            return sorted(self._entries)

    def _expire(self) -> None:
        now = self.clock()
        self._entries = {ip: e for ip, e in self._entries.items() if e["expires"] > now}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._entries, indent=2), encoding="utf-8")


class AuditLog:
    """One JSON object per line under a "soar" key, decoded by Wazuh's JSON decoder."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, action: Action) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"soar": asdict(action)}) + "\n")


# --------------------------------------------------------------------------- #
# Playbook
# --------------------------------------------------------------------------- #


class Playbook:
    def __init__(
        self,
        config: dict[str, Any],
        reputation: Reputation,
        blocklist: Blocklist,
        audit: AuditLog,
        notifier: Callable[[str], bool] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        rules = config.get("response", {})
        self.block_min_level = int(rules.get("block_ip_min_level", 10))
        self.block_min_reputation = int(rules.get("block_min_reputation", 50))
        self.always_block_rules = {str(r) for r in rules.get("always_block_rules", [])}
        self.block_ttl = int(rules.get("block_ttl_seconds", 3600))
        self.notify_min_level = int(rules.get("notify_min_level", 12))
        self.disable_account_rules = {str(r) for r in rules.get("recommend_disable_account_rules", [])}
        self.never_block = [ipaddress.ip_network(n) for n in rules.get("never_block", [])]
        self.reputation, self.blocklist, self.audit = reputation, blocklist, audit
        self.notifier, self.clock = notifier, clock
        self.dedup_window = int(config.get("dedup_seconds", 600))
        self._seen: dict[str, float] = {}

    def handle(self, alert: Alert) -> list[Action]:
        now = self.clock()
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.dedup_window}
        if alert.alert_id in self._seen:
            return []
        self._seen[alert.alert_id] = now

        actions = []
        if alert.source_ip:
            actions.append(self._maybe_block(alert))
        if alert.user and alert.rule_id in self.disable_account_rules:
            actions.append(
                self._action(
                    alert,
                    "recommend_disable_account",
                    alert.user,
                    "recommended",
                    "possible credential compromise; confirm with the user before disabling",
                )
            )
        if alert.level >= self.notify_min_level and self.notifier:
            sent = self.notifier(f"[L{alert.level}] {alert.description} | agent={alert.agent} src={alert.source_ip}")
            actions.append(self._action(alert, "notify", "slack", "executed" if sent else "failed"))
        for action in actions:
            self.audit.write(action)
        return actions

    def _maybe_block(self, alert: Alert) -> Action:
        ip = alert.source_ip
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return self._action(alert, "block_ip", ip, "skipped", "not an IP address")
        if any(addr in net for net in self.never_block):
            return self._action(alert, "block_ip", ip, "skipped", "address is on the never-block list")
        if alert.level < self.block_min_level and alert.rule_id not in self.always_block_rules:
            return self._action(alert, "block_ip", ip, "skipped", f"level {alert.level} below {self.block_min_level}")
        score = self.reputation.score(ip)
        if alert.rule_id not in self.always_block_rules and score < self.block_min_reputation:
            return self._action(
                alert, "block_ip", ip, "skipped", f"reputation {score} below {self.block_min_reputation}"
            )
        new = self.blocklist.add(ip, self.block_ttl, f"rule {alert.rule_id}: {alert.description}")
        return self._action(
            alert,
            "block_ip",
            ip,
            "executed",
            f"{'added to' if new else 'refreshed in'} blocklist for {self.block_ttl}s (reputation {score})",
        )

    def _action(self, alert: Alert, name: str, target: str, status: str, detail: str = "") -> Action:
        return Action(name, target, status, detail, alert.alert_id, alert.rule_id, self.clock())


def slack_notifier(webhook_url: str) -> Callable[[str], bool]:
    def send(text: str) -> bool:
        try:
            return requests.post(webhook_url, json={"text": text}, timeout=10).ok
        except requests.RequestException as exc:
            log.warning("slack notification failed: %s", exc)
            return False

    return send


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #


def create_app(playbook: Playbook, secret: str, max_skew: int = 300, clock: Callable[[], float] = time.time) -> Flask:
    app = Flask(__name__)
    stats = {"received": 0, "rejected": 0, "actions": 0}

    @app.post("/webhook/wazuh")
    def wazuh_webhook():
        body = request.get_data()
        if not verify(
            secret,
            request.headers.get(TIMESTAMP_HEADER),
            request.headers.get(SIGNATURE_HEADER),
            body,
            clock(),
            max_skew,
        ):
            stats["rejected"] += 1
            return jsonify(error="invalid or missing signature"), 401
        try:
            alert = Alert.from_wazuh(json.loads(body))
        except (ValueError, TypeError) as exc:
            return jsonify(error=f"malformed alert: {exc}"), 400
        stats["received"] += 1
        actions = playbook.handle(alert)
        stats["actions"] += len(actions)
        return jsonify(alert_id=alert.alert_id, actions=[asdict(a) for a in actions])

    @app.get("/blocklist.txt")
    def blocklist():
        # pfSense: Firewall > Aliases > URL Table (IPs) pointing here
        return Response("\n".join(playbook.blocklist.active()) + "\n", mimetype="text/plain")

    @app.get("/health")
    def health():
        return jsonify(status="ok", **stats, blocked=len(playbook.blocklist.active()))

    return app


def build_from_config(config: dict[str, Any]) -> tuple[Playbook, str]:
    secret = os.environ.get("SOAR_SHARED_SECRET", "")
    if not secret:
        raise SystemExit("SOAR_SHARED_SECRET is not set; refusing to accept unsigned webhooks")
    paths = config.get("paths", {})
    slack = os.environ.get("SLACK_WEBHOOK_URL")
    playbook = Playbook(
        config,
        Reputation(os.environ.get("ABUSEIPDB_API_KEY"), int(config.get("reputation_cache_seconds", 86400))),
        Blocklist(Path(paths.get("blocklist", "data/blocklist.json"))),
        AuditLog(Path(paths.get("audit_log", "/var/log/soar/actions.json"))),
        slack_notifier(slack) if slack else None,
    )
    return playbook, secret


def wsgi() -> Flask:
    """Entry point for gunicorn: `gunicorn 'soar_engine:wsgi()'` (config path from SOAR_CONFIG)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    with open(os.environ.get("SOAR_CONFIG", "config/soar_config.yml"), encoding="utf-8") as fh:
        config = yaml.safe_load(fh)
    playbook, secret = build_from_config(config)
    return create_app(playbook, secret, int(config.get("max_clock_skew_seconds", 300)))


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Home Lab SOAR engine")
    parser.add_argument("--config", "-c", default="config/soar_config.yml")
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - runs inside the SOC VLAN / container
    parser.add_argument("--port", "-p", type=int, default=5000)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    with open(args.config, encoding="utf-8") as fh:
        config = yaml.safe_load(fh)
    playbook, secret = build_from_config(config)
    create_app(playbook, secret, int(config.get("max_clock_skew_seconds", 300))).run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
