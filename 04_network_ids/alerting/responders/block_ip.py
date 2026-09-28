#!/usr/bin/env python3
"""
IP Blocking Responder
=====================
Automated IP blocking using iptables/nftables.
Supports temporary and permanent blocks with audit logging.
"""

import argparse
import subprocess
import json
import time
import logging
import sqlite3
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict

# Configuration
DB_FILE = Path("/var/log/nids/blocks.db")
BLOCK_CHAIN = "NIDS_BLOCK"
LOG_FILE = Path("/var/log/nids/block_ip.log")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('block-ip')


class BlockDatabase:
    """SQLite database for tracking blocked IPs"""

    def __init__(self, db_file: Path):
        self.db_file = db_file
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    reason TEXT,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    permanent BOOLEAN DEFAULT 0,
                    active BOOLEAN DEFAULT 1,
                    unblocked_at TIMESTAMP,
                    unblock_reason TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_active ON blocks(ip, active)")

    def add_block(self, ip: str, reason: str, duration: int, permanent: bool = False) -> int:
        expires = None if permanent else datetime.utcnow() + timedelta(seconds=duration)
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "INSERT INTO blocks (ip, reason, expires_at, permanent) VALUES (?, ?, ?, ?)",
                (ip, reason, expires.isoformat() if expires else None, permanent)
            )
            return cursor.lastrowid

    def remove_block(self, ip: str, reason: str = "Manual unblock") -> bool:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "UPDATE blocks SET active=0, unblocked_at=CURRENT_TIMESTAMP, unblock_reason=? WHERE ip=? AND active=1",
                (reason, ip)
            )
            return cursor.rowcount > 0

    def is_blocked(self, ip: str) -> bool:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM blocks WHERE ip=? AND active=1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
                (ip,)
            )
            return cursor.fetchone() is not None

    def get_active_blocks(self) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM blocks WHERE active=1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_all_blocks(self) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM blocks ORDER BY blocked_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def cleanup_expired(self) -> int:
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute(
                "UPDATE blocks SET active=0, unblocked_at=CURRENT_TIMESTAMP, unblock_reason='Expired' "
                "WHERE active=1 AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP"
            )
            return cursor.rowcount


class FirewallManager:
    """Manage firewall rules for IP blocking"""

    def __init__(self, chain_name: str = "NIDS_BLOCK"):
        self.chain_name = chain_name
        self.backend = self._detect_backend()
        self.ensure_chain()

    def _detect_backend(self) -> str:
        """Detect available firewall backend"""
        try:
            subprocess.run(["nft", "--version"], capture_output=True, check=True)
            return "nftables"
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        try:
            subprocess.run(["iptables", "--version"], capture_output=True, check=True)
            return "iptables"
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        return "none"

    def ensure_chain(self):
        """Create custom chain for NIDS blocks"""
        if self.backend == "nftables":
            self._run_nft(f"add table inet filter")
            self._run_nft(f"add chain inet filter {self.chain_name} {{ type filter hook input priority 0 ; }}")
            self._run_nft(f"add chain inet filter {self.chain_name}_v6 {{ type filter hook input priority 0 ; }}")
        elif self.backend == "iptables":
            self._run_iptables(["-N", self.chain_name])
            self._run_iptables(["-I", "INPUT", "-j", self.chain_name])
            # IPv6
            try:
                subprocess.run(["ip6tables", "-N", self.chain_name], capture_output=True)
                subprocess.run(["ip6tables", "-I", "INPUT", "-j", self.chain_name], capture_output=True)
            except Exception:
                pass

    def _run_nft(self, command: str) -> bool:
        try:
            subprocess.run(["nft"] + command.split(), capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"nft command failed: {e}")
            return False

    def _run_iptables(self, args: list) -> bool:
        try:
            subprocess.run(["iptables"] + args, capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables command failed: {e}")
            return False

    def block_ip(self, ip: str, comment: str = "") -> bool:
        """Block an IP address"""
        comment_str = f"comment \"NIDS: {comment}\"" if comment else ""

        if ":" in ip:  # IPv6
            if self.backend == "nftables":
                return self._run_nft(f"add rule inet filter {self.chain_name}_v6 ip6 saddr {ip} drop {comment_str}")
            else:
                return self._run_iptables(["-A", self.chain_name, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"NIDS: {comment}"])
        else:  # IPv4
            if self.backend == "nftables":
                return self._run_nft(f"add rule inet filter {self.chain_name} ip saddr {ip} drop {comment_str}")
            else:
                return self._run_iptables(["-A", self.chain_name, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"NIDS: {comment}"])

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        if ":" in ip:  # IPv6
            if self.backend == "nftables":
                # nftables requires handle - need to list rules first
                self._list_and_delete_nft(ip, "ip6")
            else:
                # Delete all matching rules
                while True:
                    result = subprocess.run(
                        ["ip6tables", "-D", self.chain_name, "-s", ip, "-j", "DROP"],
                        capture_output=True
                    )
                    if result.returncode != 0:
                        break
        else:  # IPv4
            if self.backend == "nftables":
                self._list_and_delete_nft(ip, "ip")
            else:
                while True:
                    result = subprocess.run(
                        ["iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"],
                        capture_output=True
                    )
                    if result.returncode != 0:
                        break
        return True

    def _list_and_delete_nft(self, ip: str, family: str):
        """List nft rules and delete matching ones"""
        try:
            result = subprocess.run(
                ["nft", "-a", "list", "chain", "inet", "filter", f"{self.chain_name}_{family if family == 'ip6' else ''}"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.split('\n'):
                if ip in line and "drop" in line:
                    # Extract handle
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "handle":
                            handle = parts[i+1]
                            self._run_nft(f"delete rule inet filter {self.chain_name}_{family if family == 'ip6' else ''} handle {handle}")
                            break
        except Exception as e:
            logger.error(f"Failed to delete nft rule: {e}")

    def list_blocks(self) -> List[Dict]:
        """List currently blocked IPs"""
        blocks = []

        if self.backend == "nftables":
            try:
                result = subprocess.run(
                    ["nft", "list", "chain", "inet", "filter", self.chain_name],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.split('\n'):
                    if 'drop' in line and 'ip saddr' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'ip' and parts[i+1] == 'saddr':
                                blocks.append({"ip": parts[i+2], "family": "ipv4"})
                            elif part == 'ip6' and parts[i+1] == 'saddr':
                                blocks.append({"ip": parts[i+2], "family": "ipv6"})
            except Exception as e:
                logger.error(f"Failed to list nft blocks: {e}")
        else:
            try:
                result = subprocess.run(
                    ["iptables", "-L", "NIDS_BLOCK", "-n", "--line-numbers"],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.split('\n'):
                    if 'DROP' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            blocks.append({"ip": parts[3], "family": "ipv4"})
            except Exception as e:
                logger.error(f"Failed to list iptables blocks: {e}")

        return blocks

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        blocks = self.list_blocks()
        return any(b["ip"] == ip for b in blocks)


class BlockManager:
    """High-level block management"""

    def __init__(self):
        self.db = BlockDatabase(DB_FILE)
        self.firewall = FirewallManager()

    def block(self, ip: str, reason: str, duration: int = 3600, permanent: bool = False) -> bool:
        """Block an IP address"""
        logger.info(f"Blocking {ip} for {duration}s: {reason}")

        # Check if already blocked
        if self.db.is_blocked(ip):
            logger.warning(f"IP {ip} already blocked")
            return False

        # Add to firewall
        if not self.firewall.block_ip(ip, f"{reason} (duration: {duration}s)"):
            logger.error(f"Failed to add firewall rule for {ip}")
            return False

        # Add to database
        self.db.add_block(ip, reason, duration, permanent)
        logger.info(f"Successfully blocked {ip}")
        return True

    def unblock(self, ip: str, reason: str = "Manual unblock") -> bool:
        """Unblock an IP address"""
        logger.info(f"Unblocking {ip}: {reason}")

        if not self.db.is_blocked(ip):
            logger.warning(f"IP {ip} not currently blocked")
            return False

        if not self.firewall.unblock_ip(ip):
            logger.error(f"Failed to remove firewall rule for {ip}")
            return False

        self.db.remove_block(ip, reason)
        logger.info(f"Successfully unblocked {ip}")
        return True

    def list_blocks(self, all_history: bool = False) -> List[Dict]:
        """List blocked IPs"""
        if all_history:
            return self.db.get_all_blocks()
        return self.db.get_active_blocks()

    def cleanup(self) -> int:
        """Clean up expired blocks"""
        count = self.db.cleanup_expired()
        if count > 0:
            logger.info(f"Cleaned up {count} expired blocks")
            # Reload firewall rules
            self.reload_firewall()
        return count

    def reload_firewall(self):
        """Reload all active blocks into firewall"""
        logger.info("Reloading firewall rules")
        # Flush and recreate chain
        self.firewall = FirewallManager(self.firewall.chain_name)

        # Re-add all active blocks
        for block in self.db.get_active_blocks():
            self.firewall.block_ip(block['ip'], block['reason'] or 'Auto-reload')


def main():
    parser = argparse.ArgumentParser(description="NIDS IP Blocking Responder")
    parser.add_argument("--ip", help="IP address to block/unblock")
    parser.add_argument("--duration", type=int, default=3600, help="Block duration in seconds")
    parser.add_argument("--reason", default="NIDS automated block", help="Reason for block")
    parser.add_argument("--permanent", action="store_true", help="Permanent block")
    parser.add_argument("--unblock", action="store_true", help="Unblock IP")
    parser.add_argument("--list", action="store_true", help="List active blocks")
    parser.add_argument("--list-all", action="store_true", help="List all blocks (including history)")
    parser.add_argument("--cleanup", action="store_true", help="Clean up expired blocks")
    parser.add_argument("--reload", action="store_true", help="Reload firewall from database")

    args = parser.parse_args()

    manager = BlockManager()

    if args.cleanup:
        count = manager.cleanup()
        print(f"Cleaned up {count} expired blocks")
        return

    if args.reload:
        manager.reload_firewall()
        print("Firewall reloaded from database")
        return

    if args.list or args.list_all:
        blocks = manager.list_blocks(all_history=args.list_all)
        if not blocks:
            print("No blocks found")
            return

        print(f"{'IP':<40} {'Reason':<50} {'Blocked':<20} {'Expires':<20} {'Status':<10}")
        print("-" * 150)
        for block in blocks:
            expires = block.get('expires_at', 'Permanent')
            if expires and expires != 'Permanent':
                try:
                    expires = expires.split('.')[0]  # Remove microseconds
                except:
                    pass
            status = "Active" if block.get('active') else "Expired/Removed"
            print(f"{block['ip']:<40} {block['reason'][:49]:<50} {block['blocked_at'][:19]:<20} {str(expires)[:19]:<20} {status:<10}")
        return

    if not args.ip:
        parser.error("--ip is required for block/unblock operations")

    if args.unblock:
        success = manager.unblock(args.ip, args.reason)
        print(f"Unblock {'successful' if success else 'failed'}: {args.ip}")
    else:
        success = manager.block(args.ip, args.reason, args.duration, args.permanent)
        print(f"Block {'successful' if success else 'failed'}: {args.ip}")


if __name__ == "__main__":
    main()