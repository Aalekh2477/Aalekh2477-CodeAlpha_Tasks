#!/usr/bin/env python3
"""
NIDS Alert Manager
==================
Central alert processing, deduplication, notification, and automated response.
"""

import json
import yaml
import time
import threading
import logging
import smtplib
import requests
import subprocess
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from queue import Queue, Empty
import signal
import sys

# Configuration
CONFIG_FILE = Path("/app/config.yaml")
WHITELIST_FILE = Path("/app/whitelist.yaml")
THRESHOLDS_FILE = Path("/app/thresholds.yaml")
EVE_LOG_FILE = Path("/var/log/suricata/eve.json")
SNORT_LOG_FILE = Path("/var/log/snort/alert")
ALERT_LOG_FILE = Path("/var/log/nids/alerts.log")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nids/alert_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('alert-manager')


@dataclass
class Alert:
    """Standardized alert structure"""
    timestamp: str
    source: str  # suricata, snort
    rule_id: int
    rule_msg: str
    severity: str  # critical, high, medium, low
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    payload: Optional[str] = None
    metadata: Optional[Dict] = None
    alert_hash: str = ""

    def __post_init__(self):
        # Create unique hash for deduplication
        hash_input = f"{self.rule_id}_{self.src_ip}_{self.dst_ip}_{self.timestamp[:16]}"
        self.alert_hash = hashlib.md5(hash_input.encode()).hexdigest()[:16]


class Deduplicator:
    """Deduplicate alerts within time window"""

    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self.seen: Dict[str, float] = {}
        self.lock = threading.Lock()

    def is_duplicate(self, alert_hash: str) -> bool:
        now = time.time()
        with self.lock:
            # Clean old entries
            self.seen = {k: v for k, v in self.seen.items() if now - v < self.window}
            if alert_hash in self.seen:
                return True
            self.seen[alert_hash] = now
            return False


class Whitelist:
    """IP/Domain/Rule whitelist manager"""

    def __init__(self, whitelist_file: Path):
        self.file = whitelist_file
        self.data = {"ips": [], "networks": [], "domains": [], "rules": []}
        self.load()

    def load(self):
        if self.file.exists():
            with open(self.file) as f:
                self.data = yaml.safe_load(f) or self.data

    def is_whitelisted(self, alert: Alert) -> bool:
        # Check rule ID
        if str(alert.rule_id) in self.data.get("rules", []):
            return True

        # Check source IP
        for ip in self.data.get("ips", []):
            if alert.src_ip == ip:
                return True

        # Check networks (CIDR)
        for network in self.data.get("networks", []):
            # Simple check - in production use ipaddress module
            if "/" in network:
                # Basic CIDR check would go here
                pass

        return False


class AlertProcessor:
    """Process incoming alerts from various sources"""

    def __init__(self, config: Dict):
        self.config = config
        self.dedup = Deduplicator(config.get("dedup_window", 300))
        self.whitelist = Whitelist(WHITELIST_FILE)
        self.thresholds = self.load_thresholds()
        self.alert_queue = Queue()
        self.stats = defaultdict(int)
        self.running = True

    def load_thresholds(self) -> Dict:
        if THRESHOLDS_FILE.exists():
            with open(THRESHOLDS_FILE) as f:
                return yaml.safe_load(f) or {}
        return {}

    def process_suricata_line(self, line: str) -> Optional[Alert]:
        """Parse Suricata EVE JSON line"""
        try:
            event = json.loads(line)
            if event.get("event_type") != "alert":
                return None

            alert_data = event.get("alert", {})
            return Alert(
                timestamp=event.get("timestamp", datetime.utcnow().isoformat()),
                source="suricata",
                rule_id=alert_data.get("signature_id", 0),
                rule_msg=alert_data.get("signature", "Unknown"),
                severity=alert_data.get("severity", 3),
                src_ip=event.get("src_ip", ""),
                src_port=event.get("src_port", 0),
                dst_ip=event.get("dest_ip", ""),
                dst_port=event.get("dest_port", 0),
                protocol=event.get("proto", ""),
                payload=event.get("payload", ""),
                metadata={
                    "category": alert_data.get("category", ""),
                    "flow_id": event.get("flow_id", 0),
                }
            )
        except json.JSONDecodeError:
            return None

    def process_snort_line(self, line: str) -> Optional[Alert]:
        """Parse Snort unified2/fast alert line"""
        # Simplified parser for fast alert format
        # Format: [**] [1:1000001:2] WEB-APP SQL Injection [**] [Priority: 1] {TCP} 192.168.1.50:54321 -> 10.0.0.1:80
        try:
            if "[**]" not in line:
                return None

            parts = line.split("[**]")
            if len(parts) < 3:
                return None

            # Parse rule info
            rule_part = parts[1].strip()
            rule_info = rule_part.split(":")
            rule_id = int(rule_info[1]) if len(rule_info) > 1 else 0

            msg_part = parts[2].strip()
            rule_msg = msg_part.split("[**]")[0].strip()

            # Parse IPs
            ip_part = line.split("{")[-1].split("}")[0]
            src_part, dst_part = ip_part.split("->")
            src_ip, src_port = src_part.strip().rsplit(":", 1)
            dst_ip, dst_port = dst_part.strip().rsplit(":", 1)

            return Alert(
                timestamp=datetime.utcnow().isoformat(),
                source="snort",
                rule_id=rule_id,
                rule_msg=rule_msg,
                severity=2,  # Default high
                src_ip=src_ip.strip(),
                src_port=int(src_port),
                dst_ip=dst_ip.strip(),
                dst_port=int(dst_port),
                protocol="TCP",
            )
        except Exception as e:
            logger.debug(f"Failed to parse Snort line: {e}")
            return None

    def assess_severity(self, alert: Alert) -> str:
        """Determine severity based on rule and thresholds"""
        rule_id = str(alert.rule_id)

        # Check rule-specific threshold
        if rule_id in self.thresholds.get("rules", {}):
            return self.thresholds["rules"][rule_id].get("severity", "medium")

        # Check category-based thresholds
        category = alert.metadata.get("category", "").lower()
        for cat, config in self.thresholds.get("categories", {}).items():
            if cat.lower() in category:
                return config.get("severity", "medium")

        # Default based on Suricata severity (1=high, 2=medium, 3=low)
        severity_map = {1: "critical", 2: "high", 3: "medium"}
        return severity_map.get(alert.severity, "medium")

    def should_alert(self, alert: Alert) -> bool:
        """Determine if alert should be processed"""
        # Whitelist check
        if self.whitelist.is_whitelisted(alert):
            logger.debug(f"Whitelisted: {alert.alert_hash}")
            return False

        # Deduplication
        if self.dedup.is_duplicate(alert.alert_hash):
            logger.debug(f"Duplicate: {alert.alert_hash}")
            return False

        # Rate limiting per source IP
        # (implement rate limiter here)

        return True

    def process_alert(self, alert: Alert):
        """Process a validated alert"""
        alert.severity = self.assess_severity(alert)

        if not self.should_alert(alert):
            return

        self.stats["total"] += 1
        self.stats[f"severity_{alert.severity}"] += 1
        self.stats[f"source_{alert.source}"] += 1

        # Log alert
        self.log_alert(alert)

        # Send notifications
        self.notify(alert)

        # Trigger automated responses
        self.trigger_response(alert)

    def log_alert(self, alert: Alert):
        """Log alert to file"""
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(json.dumps(asdict(alert)) + "\n")

    def notify(self, alert: Alert):
        """Send notifications via configured channels"""
        notifications = self.config.get("notifications", {})

        # Slack
        if notifications.get("slack", {}).get("enabled", False):
            self.notify_slack(alert, notifications["slack"])

        # Email
        if notifications.get("email", {}).get("enabled", False):
            self.notify_email(alert, notifications["email"])

        # Webhook
        if notifications.get("webhook", {}).get("enabled", False):
            self.notify_webhook(alert, notifications["webhook"])

    def notify_slack(self, alert: Alert, config: Dict):
        """Send Slack notification"""
        try:
            color_map = {
                "critical": "danger",
                "high": "warning",
                "medium": "#ff9900",
                "low": "good"
            }

            payload = {
                "channel": config.get("channel", "#security"),
                "username": "NIDS Alert",
                "icon_emoji": ":warning:",
                "attachments": [{
                    "color": color_map.get(alert.severity, "warning"),
                    "title": f"[{alert.severity.upper()}] {alert.rule_msg}",
                    "fields": [
                        {"title": "Rule ID", "value": str(alert.rule_id), "short": True},
                        {"title": "Severity", "value": alert.severity.upper(), "short": True},
                        {"title": "Source IP", "value": alert.src_ip, "short": True},
                        {"title": "Dest IP", "value": alert.dst_ip, "short": True},
                        {"title": "Protocol", "value": alert.protocol, "short": True},
                        {"title": "Source", "value": alert.source, "short": True},
                    ],
                    "footer": "NIDS",
                    "ts": int(time.time())
                }]
            }

            if alert.payload:
                payload["attachments"][0]["fields"].append({
                    "title": "Payload",
                    "value": alert.payload[:500],
                    "short": False
                })

            requests.post(config["webhook_url"], json=payload, timeout=10)
            logger.info(f"Slack notification sent for {alert.alert_hash}")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    def notify_email(self, alert: Alert, config: Dict):
        """Send email notification"""
        try:
            msg = MIMEMultipart()
            msg["From"] = config["username"]
            msg["To"] = ", ".join(config["recipients"])
            msg["Subject"] = f"[NIDS {alert.severity.upper()}] {alert.rule_msg}"

            body = f"""
NIDS Alert - {alert.severity.upper()}

Rule: {alert.rule_msg} (SID: {alert.rule_id})
Time: {alert.timestamp}
Source: {alert.source}
Severity: {alert.severity.upper()}

Source: {alert.src_ip}:{alert.src_port}
Destination: {alert.dst_ip}:{alert.dst_port}
Protocol: {alert.protocol}

Payload: {alert.payload[:500] if alert.payload else 'N/A'}

---
NIDS Alert Manager
            """

            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
                server.starttls()
                server.login(config["username"], config["password"])
                server.send_message(msg)

            logger.info(f"Email notification sent for {alert.alert_hash}")
        except Exception as e:
            logger.error(f"Email notification failed: {e}")

    def notify_webhook(self, alert: Alert, config: Dict):
        """Send generic webhook notification"""
        try:
            payload = asdict(alert)
            headers = config.get("headers", {})
            headers["Content-Type"] = "application/json"

            requests.post(config["url"], json=payload, headers=headers, timeout=10)
            logger.info(f"Webhook notification sent for {alert.alert_hash}")
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")

    def trigger_response(self, alert: Alert):
        """Trigger automated responses"""
        responses = self.config.get("responses", {})

        # Auto-block
        if responses.get("auto_block", {}).get("enabled", False):
            for trigger in responses["auto_block"].get("triggers", []):
                if trigger.get("rule_id") == alert.rule_id:
                    action = trigger.get("action")
                    duration = trigger.get("duration", 3600)
                    self.execute_response(action, alert, duration)

        # Rate limiting
        if responses.get("rate_limit", {}).get("enabled", False):
            threshold = responses["rate_limit"].get("threshold", 100)
            # Implement rate limiting logic
            pass

    def execute_response(self, action: str, alert: Alert, duration: int):
        """Execute automated response action"""
        try:
            if action == "block_ip":
                subprocess.run([
                    "python3", "/app/responders/block_ip.py",
                    "--ip", alert.src_ip,
                    "--duration", str(duration),
                    "--reason", f"Rule {alert.rule_id}: {alert.rule_msg}"
                ], check=True)
                logger.info(f"Auto-blocked {alert.src_ip} for {duration}s")

            elif action == "quarantine_host":
                subprocess.run([
                    "python3", "/app/responders/quarantine_host.py",
                    "--ip", alert.src_ip,
                    "--duration", str(duration),
                    "--reason", f"Rule {alert.rule_id}: {alert.rule_msg}"
                ], check=True)
                logger.info(f"Quarantined {alert.src_ip} for {duration}s")

        except subprocess.CalledProcessError as e:
            logger.error(f"Response execution failed: {e}")


class LogTailer:
    """Tail log files and process new lines"""

    def __init__(self, filepath: Path, processor: AlertProcessor, source: str):
        self.filepath = filepath
        self.processor = processor
        self.source = source
        self.running = True

    def run(self):
        """Tail file and process new lines"""
        # Wait for file to exist
        while not self.filepath.exists() and self.running:
            time.sleep(1)

        with open(self.filepath, "r") as f:
            # Seek to end
            f.seek(0, 2)

            while self.running:
                line = f.readline()
                if line:
                    if self.source == "suricata":
                        alert = self.processor.process_suricata_line(line)
                    elif self.source == "snort":
                        alert = self.processor.process_snort_line(line)
                    else:
                        continue

                    if alert:
                        self.processor.process_alert(alert)
                else:
                    time.sleep(0.1)


def load_config(config_file: Path) -> Dict:
    """Load configuration from YAML file"""
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def main():
    """Main entry point"""
    logger.info("Starting NIDS Alert Manager")

    # Load configuration
    config = load_config(CONFIG_FILE)

    # Initialize processor
    processor = AlertProcessor(config)

    # Create log tailers
    tailers = []

    if EVE_LOG_FILE.parent.exists():
        tailers.append(LogTailer(EVE_LOG_FILE, processor, "suricata"))

    if SNORT_LOG_FILE.parent.exists():
        tailers.append(LogTailer(SNORT_LOG_FILE, processor, "snort"))

    # Start tailers
    threads = []
    for tailer in tailers:
        t = threading.Thread(target=tailer.run, daemon=True)
        t.start()
        threads.append(t)

    # Signal handling
    def signal_handler(signum, frame):
        logger.info("Shutdown signal received")
        for tailer in tailers:
            tailer.running = False
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Stats reporting loop
    try:
        while True:
            time.sleep(60)
            logger.info(f"Stats: {dict(processor.stats)}")
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
        for tailer in tailers:
            tailer.running = False


if __name__ == "__main__":
    main()