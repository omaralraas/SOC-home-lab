#!/usr/bin/env python3
"""
SOC Home Lab - Lightweight SOAR Engine
========================================
Security Orchestration, Automation, and Response engine that processes
Wazuh alerts via webhook, enriches them with threat intelligence, and
executes automated response actions.

Author: Omar Alraas
Usage:  python soar_engine.py --config config/soar_config.yml --port 5000
"""

import json
import logging
import hashlib
import argparse
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from pathlib import Path

try:
    import yaml
    import requests
    from flask import Flask, request, jsonify
except ImportError:
    print("[!] Missing dependencies. Install with: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('soar_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SOAR')


# ==============================================================================
# Data Models
# ==============================================================================

@dataclass
class ThreatIntel:
    """Threat intelligence enrichment result."""
    ip: str
    is_malicious: bool
    confidence_score: float  # 0.0 - 1.0
    abuse_reports: int = 0
    country: str = ""
    isp: str = ""
    categories: List[str] = field(default_factory=list)
    source: str = "local"
    last_checked: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ResponseAction:
    """Automated response action record."""
    action_type: str  # 'block_ip', 'disable_account', 'quarantine', 'notify'
    target: str
    status: str = "pending"  # 'pending', 'executed', 'failed'
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: str = ""
    error: Optional[str] = None


@dataclass
class EnrichedAlert:
    """Alert enriched with threat intelligence and response actions."""
    alert_id: str
    original_alert: Dict[str, Any] = field(default_factory=dict)
    rule_id: int = 0
    rule_level: int = 0
    rule_description: str = ""
    source_ip: Optional[str] = None
    agent_name: Optional[str] = None
    timestamp: str = ""
    threat_intel: Optional[Dict] = None
    response_actions: List[Dict] = field(default_factory=list)
    enrichment_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ==============================================================================
# Threat Intelligence Enrichment
# ==============================================================================

class IPReputationChecker:
    """Checks IP reputation against threat intelligence sources."""

    def __init__(self, config: Dict):
        self.config = config
        self.cache: Dict[str, ThreatIntel] = {}
        self.cache_ttl = timedelta(hours=config.get('cache_ttl_hours', 24))
        self.local_blocklist = self._load_local_blocklist(
            config.get('local_blocklist_path', '')
        )

    def _load_local_blocklist(self, path: str) -> set:
        """Load local IP blocklist from file."""
        blocklist = set()
        if path and Path(path).exists():
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blocklist.add(line)
            logger.info(f"Loaded {len(blocklist)} IPs from local blocklist")
        return blocklist

    def check(self, ip: str) -> ThreatIntel:
        """Check IP reputation with caching."""
        # Check cache first
        if ip in self.cache:
            cached = self.cache[ip]
            cache_age = datetime.now() - datetime.fromisoformat(cached.last_checked)
            if cache_age < self.cache_ttl:
                logger.debug(f"Cache hit for {ip}")
                return cached

        # Check local blocklist
        if ip in self.local_blocklist:
            result = ThreatIntel(
                ip=ip,
                is_malicious=True,
                confidence_score=0.95,
                categories=["local_blocklist"],
                source="local"
            )
            self.cache[ip] = result
            return result

        # Check AbuseIPDB API (if configured)
        api_key = self.config.get('abuseipdb_api_key', '')
        if api_key and api_key != 'YOUR_API_KEY_HERE':
            result = self._check_abuseipdb(ip, api_key)
        else:
            # Default: not in any blocklist
            result = ThreatIntel(
                ip=ip,
                is_malicious=False,
                confidence_score=0.0,
                source="default"
            )

        self.cache[ip] = result
        return result

    def _check_abuseipdb(self, ip: str, api_key: str) -> ThreatIntel:
        """Query AbuseIPDB for IP reputation."""
        try:
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                return ThreatIntel(
                    ip=ip,
                    is_malicious=score > 50,
                    confidence_score=score / 100.0,
                    abuse_reports=data.get('totalReports', 0),
                    country=data.get('countryCode', ''),
                    isp=data.get('isp', ''),
                    source="abuseipdb"
                )
        except requests.RequestException as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

        return ThreatIntel(ip=ip, is_malicious=False, confidence_score=0.0, source="error")


# ==============================================================================
# Response Engine
# ==============================================================================

class ResponseEngine:
    """Executes automated response actions."""

    def __init__(self, config: Dict):
        self.config = config
        self.dry_run = config.get('dry_run', True)
        self.blocked_ips_path = config.get('blocked_ips_path', 'blocked_ips.txt')

    def block_ip(self, ip: str, reason: str) -> ResponseAction:
        """Generate firewall block command for malicious IP."""
        action = ResponseAction(action_type='block_ip', target=ip)

        if self.dry_run:
            action.status = 'simulated'
            action.details = f"[DRY RUN] Would block IP {ip}: {reason}"
            logger.info(f"[DRY RUN] Would block IP: {ip} - {reason}")
        else:
            try:
                # Append to blocked IPs file
                with open(self.blocked_ips_path, 'a') as f:
                    f.write(f"{ip} # {reason} - {datetime.now().isoformat()}\n")

                # Generate iptables command (logged for manual execution)
                cmd = f"iptables -I INPUT -s {ip} -j DROP"
                action.status = 'executed'
                action.details = f"IP blocked. Command: {cmd}"
                logger.info(f"Blocked IP: {ip} - {reason}")
            except Exception as e:
                action.status = 'failed'
                action.error = str(e)
                logger.error(f"Failed to block IP {ip}: {e}")

        return action

    def disable_account(self, username: str, reason: str) -> ResponseAction:
        """Generate command to disable compromised account."""
        action = ResponseAction(action_type='disable_account', target=username)

        if self.dry_run:
            action.status = 'simulated'
            action.details = f"[DRY RUN] Would disable account: {username}"
            logger.info(f"[DRY RUN] Would disable account: {username} - {reason}")
        else:
            action.status = 'pending_manual'
            action.details = f"Manual action required: Disable account {username}. Reason: {reason}"
            logger.warning(f"Manual action required: Disable account {username}")

        return action

    def send_notification(self, channel: str, message: str) -> ResponseAction:
        """Send alert notification to configured channel."""
        action = ResponseAction(action_type='notify', target=channel)

        slack_webhook = self.config.get('slack_webhook_url', '')
        if channel == 'slack' and slack_webhook and slack_webhook != 'YOUR_WEBHOOK_URL':
            try:
                payload = {
                    "text": f":rotating_light: *SOC Alert*\n{message}",
                    "username": "SOC-SOAR-Bot"
                }
                response = requests.post(slack_webhook, json=payload, timeout=10)
                if response.status_code == 200:
                    action.status = 'executed'
                    action.details = "Slack notification sent"
                else:
                    action.status = 'failed'
                    action.error = f"Slack API returned {response.status_code}"
            except requests.RequestException as e:
                action.status = 'failed'
                action.error = str(e)
        else:
            action.status = 'simulated'
            action.details = f"[DRY RUN] Notification: {message}"
            logger.info(f"Notification ({channel}): {message}")

        return action


# ==============================================================================
# Alert Processor
# ==============================================================================

class AlertProcessor:
    """Processes incoming Wazuh alerts and coordinates enrichment and response."""

    def __init__(self, config: Dict):
        self.config = config
        self.ip_checker = IPReputationChecker(config.get('threat_intel', {}))
        self.response_engine = ResponseEngine(config.get('response', {}))
        self.alert_history: List[EnrichedAlert] = []

        # Auto-response thresholds
        self.auto_block_level = config.get('auto_response', {}).get('block_ip_min_level', 10)
        self.auto_disable_level = config.get('auto_response', {}).get('disable_account_min_level', 12)

    def process(self, raw_alert: Dict) -> EnrichedAlert:
        """Process a single alert through the enrichment and response pipeline."""
        # Generate alert ID
        alert_id = hashlib.sha256(
            json.dumps(raw_alert, sort_keys=True).encode()
        ).hexdigest()[:16]

        # Extract key fields from Wazuh alert format
        rule = raw_alert.get('rule', {})
        agent = raw_alert.get('agent', {})
        data = raw_alert.get('data', {})

        enriched = EnrichedAlert(
            alert_id=alert_id,
            original_alert=raw_alert,
            rule_id=rule.get('id', 0),
            rule_level=rule.get('level', 0),
            rule_description=rule.get('description', ''),
            source_ip=data.get('srcip', raw_alert.get('srcip')),
            agent_name=agent.get('name', ''),
            timestamp=raw_alert.get('timestamp', datetime.now().isoformat())
        )

        logger.info(
            f"Processing alert {alert_id}: "
            f"Rule {enriched.rule_id} (Level {enriched.rule_level}) - "
            f"{enriched.rule_description}"
        )

        # Step 1: Threat Intelligence Enrichment
        if enriched.source_ip:
            intel = self.ip_checker.check(enriched.source_ip)
            enriched.threat_intel = asdict(intel)
            logger.info(
                f"  IP {enriched.source_ip}: malicious={intel.is_malicious}, "
                f"score={intel.confidence_score:.2f}"
            )

        # Step 2: Automated Response Actions
        actions = self._determine_actions(enriched)
        for action in actions:
            enriched.response_actions.append(asdict(action))

        # Step 3: Notifications
        if enriched.rule_level >= 10:
            notification = self.response_engine.send_notification(
                'slack',
                f"Level {enriched.rule_level} alert from {enriched.agent_name}: "
                f"{enriched.rule_description} (Source: {enriched.source_ip or 'N/A'})"
            )
            enriched.response_actions.append(asdict(notification))

        # Store in history
        self.alert_history.append(enriched)

        return enriched

    def _determine_actions(self, alert: EnrichedAlert) -> List[ResponseAction]:
        """Determine which automated response actions to take."""
        actions = []

        # Auto-block IP if alert level is high and IP is malicious
        if (alert.source_ip and
                alert.rule_level >= self.auto_block_level and
                alert.threat_intel and
                alert.threat_intel.get('is_malicious', False)):
            action = self.response_engine.block_ip(
                alert.source_ip,
                f"Auto-block: Rule {alert.rule_id} level {alert.rule_level}"
            )
            actions.append(action)

        # Auto-disable account for critical alerts
        if alert.rule_level >= self.auto_disable_level:
            target_user = alert.original_alert.get('data', {}).get('dstuser', '')
            if target_user:
                action = self.response_engine.disable_account(
                    target_user,
                    f"Auto-disable: Rule {alert.rule_id} level {alert.rule_level}"
                )
                actions.append(action)

        return actions


# ==============================================================================
# Flask Webhook Server
# ==============================================================================

def create_app(config: Dict) -> Flask:
    """Create and configure the Flask webhook application."""
    app = Flask(__name__)
    processor = AlertProcessor(config)

    @app.route('/webhook/wazuh', methods=['POST'])
    def wazuh_webhook():
        """Receive and process Wazuh alert webhooks."""
        try:
            alert_data = request.get_json(force=True)
            if not alert_data:
                return jsonify({'error': 'No JSON data received'}), 400

            enriched = processor.process(alert_data)
            return jsonify({
                'status': 'processed',
                'alert_id': enriched.alert_id,
                'actions_taken': len(enriched.response_actions)
            }), 200

        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'alerts_processed': len(processor.alert_history),
            'uptime': datetime.now().isoformat()
        }), 200

    @app.route('/stats', methods=['GET'])
    def stats():
        """Return processing statistics."""
        return jsonify({
            'total_alerts': len(processor.alert_history),
            'blocked_ips': len(processor.ip_checker.cache),
            'cache_size': len(processor.ip_checker.cache)
        }), 200

    return app


# ==============================================================================
# Main
# ==============================================================================

def load_config(path: str) -> Dict:
    """Load SOAR configuration from YAML file."""
    try:
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"YAML parse error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SOC Home Lab - Lightweight SOAR Engine"
    )
    parser.add_argument('--config', '-c', default='config/soar_config.yml',
                        help='Path to SOAR configuration file')
    parser.add_argument('--port', '-p', type=int, default=5000,
                        help='Webhook listener port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Webhook listener host (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Create and run Flask app
    app = create_app(config)
    logger.info(f"SOAR Engine starting on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
