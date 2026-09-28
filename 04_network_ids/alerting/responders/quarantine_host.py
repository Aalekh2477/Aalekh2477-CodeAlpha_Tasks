#!/usr/bin/env python3
"""
Host Quarantine Responder
=========================
Isolate compromised hosts from network using VLAN isolation,
port shutdown, or NAC integration.
"""

import argparse
import json
import logging
import subprocess
import sqlite3
import requests
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Configuration
DB_FILE = Path("/var/log/nids/quarantine.db")
LOG_FILE = Path("/var/log/nids/quarantine.log")

# NAC Integration (example configurations)
NAC_CONFIGS = {
    "aruba": {
        "api_url": "https://aruba-controller/api",
        "username": "${ARUBA_USER}",
        "password": "${ARUBA_PASS}",
        "verify_ssl": False
    },
    "cisco_ise": {
        "api_url": "https://ise-server:9060/ers",
        "username": "${ISE_USER}",
        "password": "${ISE_PASS}",
        "verify_ssl": False
    },
    "forescout": {
        "api_url": "https://forescout/api",
        "token": "${FORESCOUT_TOKEN}",
        "verify_ssl": False
    }
}

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('quarantine-host')


class QuarantineDatabase:
    """Track quarantined hosts"""

    def __init__(self, db_file: Path):
        self.db_file = Path(db_file)
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    reason TEXT,
                    method TEXT,
                    quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    released_at TIMESTAMP,
                    release_reason TEXT,
                    nac_policy_id TEXT,
                    switch_port TEXT,
                    vlan_id INTEGER,
                    active BOOLEAN DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_active ON quarantine(ip, active)")

    def add_quarantine(self, ip: str, reason: str, duration: int,
                       mac: str = None, hostname: str = None,
                       method: str = "vlan", nac_policy_id: str = None,
                       switch_port: str = None, vlan_id: int = None) -> int:
        expires = datetime.utcnow() + timedelta(seconds=duration)
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                """INSERT INTO quarantine
                   (ip, mac, hostname, reason, method, expires_at, nac_policy_id, switch_port, vlan_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ip, mac, hostname, reason, method,
                 datetime.utcnow() + timedelta(seconds=duration),
                 nac_policy_id, switch_port, vlan_id)
            )
            return cursor.lastrowid

    def release(self, ip: str, reason: str = "Manual release") -> bool:
        with sqlite3.connect(self.db_file) as conn:
            cursor = self.db.execute(
                "UPDATE quarantine SET active=0, released_at=CURRENT_TIMESTAMP, release_reason=? WHERE ip=? AND active=1",
                (reason, ip)
            )
            return cursor.rowcount > 0

    def is_quarantined(self, ip: str) -> bool:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM quarantine WHERE ip=? AND active=1 AND expires_at > CURRENT_TIMESTAMP",
                (ip,)
            )
            return cursor.fetchone() is not None

    def get_active(self) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM quarantine WHERE active=1 AND expires_at > CURRENT_TIMESTAMP"
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_all(self) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
            return [dict(row) for row in cursor.fetchall()]


class QuarantineMethod:
    """Base class for quarantine methods"""

    def quarantine(self, ip: str, mac: str = None, hostname: str = None,
                   switch_port: str = None, vlan_id: int = None,
                   duration: int = 3600) -> bool:
        raise NotImplementedError

    def release(self, ip: str, mac: str = None, hostname: str = None) -> bool:
        raise NotImplementedError


class VLANQuarantine(QuarantineMethod):
    """Quarantine by moving to isolated VLAN"""

    def __init__(self, quarantine_vlan: int = 999, management_vlan: int = 1):
        self.quarantine_vlan = quarantine_vlan
        self.management_vlan = management_vlan
        self.original_ports = {}  # Track original VLANs

    def quarantine(self, ip: str, mac: str = None, hostname: str = None,
                   switch_port: str = None, vlan_id: int = None,
                   duration: int = 3600) -> bool:
        """Move host to quarantine VLAN"""
        logger.info(f"Quarantining {ip} via VLAN isolation")

        # In production, integrate with switch API (Cisco, Arista, Juniper, etc.)
        # Example for Cisco:
        # self._set_port_vlan(switch_port, self.quarantine_vlan)

        # For demo, just log
        logger.info(f"Would move {ip} (MAC: {mac}) on port {switch_port} to VLAN {self.quarantine_vlan}")

        # Store original VLAN for restoration
        if switch_port:
            self.original_ports[switch_port] = vlan_id or self.management_vlan

        return True

    def release(self, ip: str, mac: str = None, hostname: str = None) -> bool:
        """Restore original VLAN"""
        logger.info(f"Releasing {ip} from VLAN quarantine")

        # In production, restore original VLAN
        # for port, vlan in self.original_ports.items():
        #     self._set_port_vlan(port, vlan)

        return True


class NACQuarantine(QuarantineMethod):
    """Quarantine via NAC integration (Aruba, Cisco ISE, Forescout)"""

    def __init__(self, nac_type: str = "cisco_ise"):
        self.nac_type = nac_type
        self.config = NAC_CONFIGS.get(nac_type, {})
        self.session = requests.Session()
        self.session.verify = self.config.get("verify_ssl", False)

    def _authenticate(self) -> bool:
        """Authenticate with NAC"""
        try:
            if self.nac_type == "cisco_ise":
                auth = (self.config["username"], self.config["password"])
                response = self.session.post(
                    f"{self.config['api_url']}/auth/token",
                    auth=auth,
                    timeout=10
                )
                if response.status_code == 200:
                    token = response.json().get("access_token")
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    return True

            elif self.nac_type == "forescout":
                self.session.headers["Authorization"] = f"Bearer {self.config['token']}"
                return True

        except Exception as e:
            logger.error(f"NAC authentication failed: {e}")
        return False

    def quarantine(self, ip: str, mac: str = None, hostname: str = None,
                   switch_port: str = None, vlan_id: int = None,
                   duration: int = 3600) -> bool:
        logger.info(f"Quarantining {ip} via NAC ({self.nac_type})")

        if not self._authenticate():
            return False

        try:
            if self.nac_type == "cisco_ise":
                return self._ise_quarantine(ip, mac, duration)
            elif self.nac_type == "forescout":
                return self._forescout_quarantine(ip, mac, duration)
            elif self.nac_type == "aruba":
                return self._aruba_quarantine(ip, mac, duration)
        except Exception as e:
            logger.error(f"NAC quarantine failed: {e}")

        return False

    def _ise_quarantine(self, ip: str, mac: str, duration: int) -> bool:
        """Quarantine via Cisco ISE"""
        try:
            # Create endpoint group for quarantine
            group_data = {
                "EndPointGroup": {
                    "name": f"NIDS_Quarantine_{ip.replace('.', '_')}",
                    "description": f"Auto-quarantined by NIDS at {datetime.utcnow().isoformat()}"
                }
            }
            response = self.session.post(
                f"{self.config['api_url']}/endpointgroup",
                json=group_data,
                timeout=10
            )
            if response.status_code not in (200, 201):
                return False

            group_id = response.json()["EndPointGroup"]["id"]

            # Add endpoint to group
            endpoint_data = {
                "ERSEndPoint": {
                    "mac": mac.replace(":", "").lower() if mac else "",
                    "ip": ip,
                    "groupId": group_id,
                    "profileId": "Quarantine"
                }
            }
            response = self.session.post(
                f"{self.config['api_url']}/endpoint",
                json=endpoint_data,
                timeout=10
            )
            return response.status_code in (200, 201)
        except Exception as e:
            logger.error(f"ISE quarantine failed: {e}")
            return False

    def _forescout_quarantine(self, ip: str, mac: str, duration: int) -> bool:
        """Quarantine via Forescout"""
        try:
            # Apply quarantine policy
            policy_data = {
                "ip": ip,
                "mac": mac,
                "policy": "Quarantine",
                "duration": duration
            }
            response = self.session.post(
                f"{self.config['api_url']}/host/quarantine",
                json=policy_data,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Forescout quarantine failed: {e}")
            return False

    def _aruba_quarantine(self, ip: str, mac: str, duration: int) -> bool:
        """Quarantine via Aruba ClearPass"""
        try:
            # Use ClearPass API to apply quarantine
            endpoint_data = {
                "mac_address": mac.replace(":", "").lower() if mac else "",
                "ip_address": ip,
                "attributes": {
                    "Quarantine": "True",
                    "Quarantine_Reason": "NIDS Auto-Quarantine",
                    "Quarantine_Duration": str(duration)
                }
            }
            response = self.session.post(
                f"{self.config['api_url']}/endpoint",
                json=endpoint_data,
                timeout=10
            )
            return response.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Aruba quarantine failed: {e}")
            return False

    def release(self, ip: str, mac: str = None, hostname: str = None) -> bool:
        """Release from NAC quarantine"""
        logger.info(f"Releasing {ip} from NAC quarantine")

        if not self._authenticate():
            return False

        try:
            if self.nac_type == "cisco_ise":
                # Remove from quarantine group
                response = self.session.delete(
                    f"{self.config['api_url']}/endpoint/mac/{mac.replace(':', '').lower()}",
                    timeout=10
                )
                return response.status_code in (200, 204)
        except Exception as e:
            logger.error(f"NAC release failed: {e}")

        return False


class SwitchPortShutdown(QuarantineMethod):
    """Quarantine by shutting down switch port"""

    def __init__(self):
        self.shutdown_ports = {}

    def quarantine(self, ip: str, mac: str = None, hostname: str = None,
                   switch_port: str = None, vlan_id: int = None,
                   duration: int = 3600) -> bool:
        if not switch_port:
            logger.error(f"No switch port provided for {ip}")
            return False

        logger.info(f"Shutting down port {switch_port} for {ip}")

        # In production, use SNMP/NETCONF/RESTCONF to shutdown port
        # Example for Cisco:
        # self._shutdown_cisco_port(switch_port)

        self.shutdown_ports[switch_port] = {
            "ip": ip,
            "mac": mac,
            "shutdown_at": datetime.utcnow()
        }
        return True

    def release(self, ip: str, mac: str = None, hostname: str = None) -> bool:
        # Find and re-enable port
        for port, info in self.shutdown_ports.items():
            if info["ip"] == ip:
                logger.info(f"Re-enabling port {port}")
                # self._enable_cisco_port(port)
                del self.shutdown_ports[port]
                return True
        return False


class HostQuarantineManager:
    """High-level quarantine manager"""

    def __init__(self, method: str = "vlan"):
        self.db = QuarantineDatabase(DB_FILE)
        self.method = self._get_method(method)

    def _get_method(self, method: str) -> QuarantineMethod:
        methods = {
            "vlan": VLANQuarantine(),
            "nac": NACQuarantine(),
            "cisco_ise": NACQuarantine("cisco_ise"),
            "forescout": NACQuarantine("forescout"),
            "aruba": NACQuarantine("aruba"),
            "port_shutdown": SwitchPortShutdown()
        }
        return methods.get(method, VLANQuarantine())

    def quarantine(self, ip: str, reason: str, duration: int = 3600,
                   mac: str = None, hostname: str = None,
                   switch_port: str = None, vlan_id: int = None) -> bool:
        """Quarantine a host"""
        logger.info(f"Quarantining {ip} for {duration}s: {reason}")

        if self.db.is_quarantined(ip):
            logger.warning(f"Host {ip} already quarantined")
            return False

        success = self.method.quarantine(ip, mac, hostname, switch_port, vlan_id, duration)

        if success:
            self.db.add_quarantine(ip, reason, duration, mac, hostname)
            logger.info(f"Successfully quarantined {ip}")

        return success

    def release(self, ip: str, reason: str = "Manual release") -> bool:
        """Release host from quarantine"""
        logger.info(f"Releasing {ip} from quarantine: {reason}")

        if not self.db.is_quarantined(ip):
            logger.warning(f"Host {ip} not currently quarantined")
            return False

        success = self.method.release(ip)
        if success:
            self.db.release(ip, reason)
            logger.info(f"Successfully released {ip}")

        return success

    def list_quarantines(self, all_history: bool = False) -> List[Dict]:
        return self.db.get_all() if all_history else self.db.get_active()


def main():
    parser = argparse.ArgumentParser(description="NIDS Host Quarantine Responder")
    parser.add_argument("--ip", help="IP address to quarantine/release")
    parser.add_argument("--mac", help="MAC address")
    parser.add_argument("--hostname", help="Hostname")
    parser.add_argument("--duration", type=int, default=3600, help="Quarantine duration in seconds")
    parser.add_argument("--reason", default="NIDS automated quarantine", help="Reason for quarantine")
    parser.add_argument("--method", choices=["vlan", "nac", "cisco_ise", "forescout", "aruba", "port_shutdown"],
                        default="vlan", help="Quarantine method")
    parser.add_argument("--switch-port", help="Switch port (e.g., Gi1/0/1)")
    parser.add_argument("--vlan-id", type=int, help="Original VLAN ID")
    parser.add_argument("--release", action="store_true", help="Release from quarantine")
    parser.add_argument("--list", action="store_true", help="List active quarantines")
    parser.add_argument("--list-all", action="store_true", help="List all quarantines (including history)")

    args = parser.parse_args()

    manager = HostQuarantineManager(args.method)

    if args.list or args.list_all:
        quarantines = manager.list_quarantines(all_history=args.list_all)
        if not quarantines:
            print("No quarantines found")
            return

        print(f"{'IP':<18} {'MAC':<18} {'Reason':<40} {'Method':<12} {'Quarantined':<20} {'Expires':<20} {'Status'}")
        print("-" * 160)
        for q in quarantines:
            expires = q.get('expires_at', 'Permanent')
            if expires and expires != 'Permanent':
                try:
                    expires = expires.split('.')[0]
                except:
                    pass
            status = "Active" if q.get('active') else "Released"
            print(f"{q['ip']:<18} {q.get('mac', 'N/A'):<18} {q['reason'][:39]:<40} {q['method']:<12} {q['quarantined_at'][:19]:<20} {str(expires)[:19]:<20} {status}")
        return

    if not args.ip:
        parser.error("--ip is required for quarantine/release operations")

    if args.release:
        success = manager.release(args.ip, args.reason)
        print(f"Release {'successful' if success else 'failed'}: {args.ip}")
    else:
        success = manager.quarantine(
            args.ip, args.reason, args.duration,
            args.mac, args.hostname,
            args.switch_port, args.vlan_id
        )
        print(f"Quarantine {'successful' if success else 'failed'}: {args.ip}")


if __name__ == "__main__":
    main()