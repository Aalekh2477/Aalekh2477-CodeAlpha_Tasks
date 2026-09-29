#!/usr/bin/env python3
"""
NIDS Alert Monitor
==================
Monitors Suricata EVE JSON logs and triggers response actions.
"""

import json
import time
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, Set

# Configuration
EVE_LOG_FILE = Path("./suricata/logs/eve.json")
ALERT_LOG_FILE = Path("./alerts/alerts.log")
BLOCKED_IPS_FILE = Path("./alerts/blocked_ips.txt")

# Alert thresholds
THRESHOLDS = {
    "critical": ["1000001", "1000002", "1000003", "1000004", "1000401", "1000402", "1000403", "1000404", "1000405"],
    "high": ["1000005", "1000006", "1000007", "1000008", "1000009", "1000010", "1000101", "1000102", "1000103", "1000201", "1000202", "1000203"],
    "medium": ["1000301", "1000302", "1000303", "1000304", "1000305", "1000306"],
    "low": ["1000501", "1000502", "1000503", "1000601", "1000602", "1000603", "1000604", "1000701", "1000702", "1000703"]
}

# Auto-block critical alerts
AUTO_BLOCK = True

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('./alerts/monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('nids-monitor')

# Track alert counts per IP for rate limiting
alert_counts = defaultdict(int)
blocked_ips: Set[str] = set()

def load_blocked_ips():
    global blocked_ips
    if BLOCKED_IPS_FILE.exists():
        with open(BLOCKED_IPS_FILE, 'r') as f:
            blocked_ips = set(line.strip() for line in f if line.strip())

def save_blocked_ips():
    BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(BLOCKED_IPS_FILE, 'w') as f:
        for ip in blocked_ips:
            f.write(f"{ip}\n")

def get_severity(signature_id: str) -> str:
    for severity, sids in THRESHOLDS.items():
        if signature_id in sids:
            return severity
    return "info"

def block_ip(ip: str, reason: str):
    if ip in blocked_ips:
        return
    
    logger.warning(f"BLOCKING IP {ip}: {reason}")
    
    # On Windows, use netsh (requires admin)
    # On Linux, use iptables
    try:
        if sys.platform == "win32":
            # Windows Firewall rule
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=NIDS_BLOCK_{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ], check=False, capture_output=True)
        else:
            # Linux iptables
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ], check=False, capture_output=True)
        
        blocked_ips.add(ip)
        save_blocked_ips()
        
        # Log the block
        with open(ALERT_LOG_FILE, 'a') as f:
            f.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "blocked",
                "ip": ip,
                "reason": reason
            }) + "\n")
            
    except Exception as e:
        logger.error(f"Failed to block IP {ip}: {e}")

def log_alert(alert_data: dict):
    """Log alert to file"""
    ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_LOG_FILE, 'a') as f:
        f.write(json.dumps(alert_data) + "\n")

def process_alert(alert: dict):
    """Process a single alert from Suricata"""
    src_ip = alert.get("src_ip", "")
    dest_ip = alert.get("dest_ip", "")
    signature_id = str(alert.get("alert", {}).get("signature_id", ""))
    signature = alert.get("alert", {}).get("signature", "")
    severity = alert.get("alert", {}).get("severity", 3)
    
    severity_label = get_severity(signature_id)
    
    alert_record = {
        "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": alert.get("src_port", 0),
        "dest_port": alert.get("dest_port", 0),
        "protocol": alert.get("proto", ""),
        "signature_id": signature_id,
        "signature": signature,
        "severity": severity_label,
        "category": alert.get("alert", {}).get("category", "")
    }
    
    # Log alert
    log_alert(alert_record)
    
    # Update counters
    alert_counts[src_ip] += 1
    
    # Auto-block critical alerts
    if AUTO_BLOCK and severity_label == "critical" and src_ip:
        block_ip(src_ip, f"Critical alert: {signature} (SID: {signature_id})")
    
    # Rate-based blocking for high volume
    if alert_counts[src_ip] > 100 and src_ip not in blocked_ips:
        block_ip(src_ip, f"High alert volume: {alert_counts[src_ip]} alerts")
    
    # Console output
    color_map = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",      # Yellow
        "medium": "\033[94m",    # Blue
        "low": "\033[92m",       # Green
        "info": "\033[0m"        # Reset
    }
    color = color_map.get(severity_label, "\033[0m")
    reset = "\033[0m"
    
    print(f"{color}[{severity_label.upper()}]{reset} {src_ip}:{alert.get('src_port',0)} -> {dest_ip}:{alert.get('dest_port',0)} | {signature} (SID:{signature_id})")

def tail_file(filepath: Path):
    """Generator to tail a file like tail -f"""
    with open(filepath, 'r') as f:
        f.seek(0, 2)  # Seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def main():
    logger.info("Starting NIDS Alert Monitor")
    
    load_blocked_ips()
    ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    if not EVE_LOG_FILE.exists():
        logger.error(f"EVE log file not found: {EVE_LOG_FILE}")
        logger.info("Make sure Suricata is running and generating eve.json")
        return
    
    logger.info(f"Monitoring {EVE_LOG_FILE}")
    
    try:
        for line in tail_file(EVE_LOG_FILE):
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    process_alert(event)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
    except Exception as e:
        logger.error(f"Monitor error: {e}")

if __name__ == "__main__":
    main()