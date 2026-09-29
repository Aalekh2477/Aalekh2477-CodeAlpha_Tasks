#!/usr/bin/env python3
"""
Network Packet Capture and Analysis Tool
=========================================
A comprehensive tool for capturing and analyzing network traffic packets.
Supports live capture, packet filtering, and detailed protocol analysis.

Requirements:
    pip install scapy
    
Note: Requires root/admin privileges for packet capture
"""

import sys
import os
import argparse
import signal
import time
from datetime import datetime
from collections import defaultdict
from typing import Optional, List, Dict, Any

try:
    from scapy.all import (
        sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, 
        Raw, wrpcap, rdpcap, conf, get_if_list, get_if_addr
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.all import TLS
    from scapy.layers.dns import DNSQR, DNSRR
    
    # ICMPv6 may not be available in all versions
    try:
        from scapy.all import ICMPv6
    except ImportError:
        ICMPv6 = None
        
    # TCPflags may not be available
    try:
        from scapy.layers.inet import TCPflags
    except ImportError:
        TCPflags = None
except ImportError as e:
    print(f"Error importing scapy: {e}")
    print("Please install scapy: pip install scapy")
    sys.exit(1)


class PacketAnalyzer:
    """Main class for packet capture and analysis."""
    
    def __init__(self, interface: Optional[str] = None, filter_str: str = "", 
                 count: int = 0, timeout: int = 0, output_file: Optional[str] = None):
        self.interface = interface
        self.filter_str = filter_str
        self.count = count
        self.timeout = timeout
        self.output_file = output_file
        self.packets = []
        self.stats = defaultdict(int)
        self.running = False
        
        # Protocol mappings
        self.ip_protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 
            50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"
        }
        
        self.tcp_flags = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
            'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
        }
        
        # Common port mappings
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT",
            69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
            143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
            443: "HTTPS", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP-SUB",
            636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            1521: "ORACLE", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES",
            5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            27017: "MONGODB"
        }
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        print("\n\n[!] Capture interrupted by user")
        self.running = False
        self.display_summary()
        if self.output_file and self.packets:
            self.save_packets()
        sys.exit(0)
    
    def get_interface_info(self) -> str:
        """Get information about the capture interface."""
        if self.interface:
            try:
                ip = get_if_addr(self.interface)
                return f"{self.interface} (IP: {ip})"
            except:
                return self.interface
        return "Default interface"
    
    def protocol_name(self, proto_num: int) -> str:
        """Convert protocol number to name."""
        return self.ip_protocols.get(proto_num, f"PROTO-{proto_num}")
    
    def port_name(self, port: int) -> str:
        """Convert port number to service name."""
        return self.common_ports.get(port, str(port))
    
    def tcp_flags_str(self, flags: int) -> str:
        """Convert TCP flags to readable string."""
        flag_str = []
        # TCP flags bit values
        flag_bits = {
            'F': 0x01,  # FIN
            'S': 0x02,  # SYN
            'R': 0x04,  # RST
            'P': 0x08,  # PSH
            'A': 0x10,  # ACK
            'U': 0x20,  # URG
            'E': 0x40,  # ECE
            'C': 0x80,  # CWR
        }
        for bit, name in self.tcp_flags.items():
            if flags & flag_bits.get(bit, 0):
                flag_str.append(name)
        return "|".join(flag_str) if flag_str else "NONE"
    
    def format_mac(self, mac: str) -> str:
        """Format MAC address."""
        return mac.upper() if mac else "Unknown"
    
    def format_timestamp(self, timestamp) -> str:
        """Format timestamp to readable string."""
        try:
            ts = float(timestamp)
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except:
            return str(timestamp)
    
    def analyze_ethernet(self, packet) -> Dict[str, Any]:
        """Analyze Ethernet layer."""
        eth = packet[Ether]
        return {
            "src_mac": self.format_mac(eth.src),
            "dst_mac": self.format_mac(eth.dst),
            "type": f"0x{eth.type:04x}",
            "type_name": self.ether_type_name(eth.type)
        }
    
    def ether_type_name(self, eth_type: int) -> str:
        """Get Ethernet type name."""
        types = {
            0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
            0x8847: "MPLS", 0x8848: "MPLS-MCAST", 0x88CC: "LLDP"
        }
        return types.get(eth_type, f"Unknown(0x{eth_type:04x})")
    
    def analyze_ip(self, packet) -> Dict[str, Any]:
        """Analyze IP layer (IPv4 or IPv6)."""
        result = {}
        
        if IP in packet:
            ip = packet[IP]
            result.update({
                "version": 4,
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": self.protocol_name(ip.proto),
                "proto_num": ip.proto,
                "ttl": ip.ttl,
                "length": ip.len,
                "id": ip.id,
                "flags": str(ip.flags),
                "frag_offset": ip.frag,
                "tos": ip.tos,
                "checksum": f"0x{ip.chksum:04x}"
            })
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            result.update({
                "version": 6,
                "src_ip": ipv6.src,
                "dst_ip": ipv6.dst,
                "protocol": self.protocol_name(ipv6.nh),
                "proto_num": ipv6.nh,
                "hop_limit": ipv6.hlim,
                "length": ipv6.plen,
                "flow_label": ipv6.fl,
                "traffic_class": ipv6.tc
            })
        
        return result
    
    def analyze_tcp(self, packet) -> Dict[str, Any]:
        """Analyze TCP layer."""
        tcp = packet[TCP]
        return {
            "src_port": tcp.sport,
            "src_port_name": self.port_name(tcp.sport),
            "dst_port": tcp.dport,
            "dst_port_name": self.port_name(tcp.dport),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": self.tcp_flags_str(tcp.flags),
            "window": tcp.window,
            "checksum": f"0x{tcp.chksum:04x}",
            "urg_ptr": tcp.urgptr,
            "options": len(tcp.options) if tcp.options else 0
        }
    
    def analyze_udp(self, packet) -> Dict[str, Any]:
        """Analyze UDP layer."""
        udp = packet[UDP]
        return {
            "src_port": udp.sport,
            "src_port_name": self.port_name(udp.sport),
            "dst_port": udp.dport,
            "dst_port_name": self.port_name(udp.dport),
            "length": udp.len,
            "checksum": f"0x{udp.chksum:04x}"
        }
    
    def analyze_icmp(self, packet) -> Dict[str, Any]:
        """Analyze ICMP layer."""
        icmp = packet[ICMP]
        type_names = {
            0: "Echo Reply", 3: "Destination Unreachable", 
            4: "Source Quench", 5: "Redirect", 8: "Echo Request",
            11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp",
            14: "Timestamp Reply", 15: "Info Request", 16: "Info Reply"
        }
        return {
            "type": icmp.type,
            "type_name": type_names.get(icmp.type, f"Type-{icmp.type}"),
            "code": icmp.code,
            "checksum": f"0x{icmp.chksum:04x}",
            "id": getattr(icmp, 'id', 0),
            "seq": getattr(icmp, 'seq', 0)
        }
    
    def analyze_dns(self, packet) -> Dict[str, Any]:
        """Analyze DNS layer."""
        dns = packet[DNS]
        queries = []
        answers = []
        
        if dns.qd:
            for q in dns.qd:
                queries.append({
                    "name": q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                    "type": q.qtype,
                    "class": q.qclass
                })
        
        if dns.an:
            for a in dns.an:
                answers.append({
                    "name": a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname),
                    "type": a.type,
                    "class": a.rclass,
                    "ttl": a.ttl,
                    "data": str(a.rdata)
                })
        
        return {
            "id": dns.id,
            "qr": "Response" if dns.qr else "Query",
            "opcode": dns.opcode,
            "rcode": dns.rcode,
            "questions": len(dns.qd) if dns.qd else 0,
            "answers": len(dns.an) if dns.an else 0,
            "authority": len(dns.ns) if dns.ns else 0,
            "additional": len(dns.ar) if dns.ar else 0,
            "queries": queries,
            "answers": answers
        }
    
    def analyze_http(self, packet) -> Dict[str, Any]:
        """Analyze HTTP layer."""
        result = {}
        if HTTPRequest in packet:
            http = packet[HTTPRequest]
            result["type"] = "Request"
            result["method"] = http.Method.decode() if isinstance(http.Method, bytes) else str(http.Method)
            result["host"] = http.Host.decode() if http.Host and isinstance(http.Host, bytes) else str(http.Host) if http.Host else ""
            result["path"] = http.Path.decode() if http.Path and isinstance(http.Path, bytes) else str(http.Path) if http.Path else ""
            result["version"] = http.Http_Version.decode() if isinstance(http.Http_Version, bytes) else str(http.Http_Version)
        elif HTTPResponse in packet:
            http = packet[HTTPResponse]
            result["type"] = "Response"
            result["status_code"] = http.Status_Code.decode() if isinstance(http.Status_Code, bytes) else str(http.Status_Code)
            result["version"] = http.Http_Version.decode() if isinstance(http.Http_Version, bytes) else str(http.Http_Version)
        return result
    
    def analyze_arp(self, packet) -> Dict[str, Any]:
        """Analyze ARP layer."""
        arp = packet[ARP]
        op_names = {1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply"}
        return {
            "operation": op_names.get(arp.op, f"Op-{arp.op}"),
            "sender_mac": self.format_mac(arp.hwsrc),
            "sender_ip": arp.psrc,
            "target_mac": self.format_mac(arp.hwdst),
            "target_ip": arp.pdst
        }
    
    def extract_payload(self, packet, max_len: int = 100) -> Dict[str, Any]:
        """Extract and format packet payload."""
        if Raw in packet:
            raw = packet[Raw].load
            return {
                "length": len(raw),
                "hex": raw[:max_len].hex() if len(raw) > 0 else "",
                "ascii": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw[:max_len]),
                "truncated": len(raw) > max_len
            }
        return {"length": 0, "hex": "", "ascii": "", "truncated": False}
    
    def process_packet(self, packet) -> Dict[str, Any]:
        """Process a single packet and extract all relevant information."""
        timestamp = packet.time if hasattr(packet, 'time') else time.time()
        
        info = {
            "timestamp": self.format_timestamp(timestamp),
            "timestamp_raw": timestamp,
            "length": len(packet),
            "layers": []
        }
        
        # Ethernet layer
        if Ether in packet:
            eth_info = self.analyze_ethernet(packet)
            info["ethernet"] = eth_info
            info["layers"].append("Ethernet")
        
        # IP layer
        if IP in packet or IPv6 in packet:
            ip_info = self.analyze_ip(packet)
            info["ip"] = ip_info
            info["layers"].append(f"IPv{ip_info['version']}")
        
        # Transport layer
        if TCP in packet:
            tcp_info = self.analyze_tcp(packet)
            info["tcp"] = tcp_info
            info["layers"].append("TCP")
        elif UDP in packet:
            udp_info = self.analyze_udp(packet)
            info["udp"] = udp_info
            info["layers"].append("UDP")
        elif ICMP in packet:
            icmp_info = self.analyze_icmp(packet)
            info["icmp"] = icmp_info
            info["layers"].append("ICMP")
        elif ICMPv6 is not None and ICMPv6 in packet:
            info["layers"].append("ICMPv6")
        
        # Application layer
        if DNS in packet:
            dns_info = self.analyze_dns(packet)
            info["dns"] = dns_info
            info["layers"].append("DNS")
        
        if HTTPRequest in packet or HTTPResponse in packet:
            http_info = self.analyze_http(packet)
            info["http"] = http_info
            info["layers"].append("HTTP")
        
        if ARP in packet:
            arp_info = self.analyze_arp(packet)
            info["arp"] = arp_info
            info["layers"].append("ARP")
        
        # Payload
        payload_info = self.extract_payload(packet)
        info["payload"] = payload_info
        
        # Update statistics
        self.update_stats(info)
        
        return info
    
    def update_stats(self, info: Dict[str, Any]):
        """Update packet statistics."""
        self.stats["total"] += 1
        self.stats["bytes"] += info["length"]
        
        if "ip" in info:
            proto = info["ip"]["protocol"]
            self.stats[f"proto_{proto}"] += 1
            self.stats[f"src_{info['ip']['src_ip']}"] += 1
            self.stats[f"dst_{info['ip']['dst_ip']}"] += 1
        
        if "tcp" in info:
            self.stats["tcp"] += 1
            self.stats[f"tcp_port_{info['tcp']['dst_port']}"] += 1
        elif "udp" in info:
            self.stats["udp"] += 1
            self.stats[f"udp_port_{info['udp']['dst_port']}"] += 1
        elif "icmp" in info:
            self.stats["icmp"] += 1
        
        if "dns" in info:
            self.stats["dns"] += 1
        if "http" in info:
            self.stats["http"] += 1
        if "arp" in info:
            self.stats["arp"] += 1
    
    def display_packet(self, info: Dict[str, Any], verbose: bool = False):
        """Display packet information in a formatted way."""
        print(f"\n{'='*80}")
        print(f"Packet #{self.stats['total']} | {info['timestamp']} | Length: {info['length']} bytes")
        print(f"{'='*80}")
        
        # Ethernet
        if "ethernet" in info:
            eth = info["ethernet"]
            print(f"  [Ethernet] {eth['src_mac']} -> {eth['dst_mac']} | Type: {eth['type_name']} ({eth['type']})")
        
        # IP
        if "ip" in info:
            ip = info["ip"]
            print(f"  [IPv{ip['version']}] {ip['src_ip']} -> {ip['dst_ip']} | "
                  f"Proto: {ip['protocol']} | TTL/HL: {ip.get('ttl', ip.get('hop_limit', 'N/A'))} | "
                  f"Len: {ip['length']}")
        
        # Transport
        if "tcp" in info:
            tcp = info["tcp"]
            print(f"  [TCP] {tcp['src_port_name']}({tcp['src_port']}) -> {tcp['dst_port_name']}({tcp['dst_port']}) | "
                  f"Seq: {tcp['seq']} | Ack: {tcp['ack']} | Flags: [{tcp['flags']}] | Win: {tcp['window']}")
        elif "udp" in info:
            udp = info["udp"]
            print(f"  [UDP] {udp['src_port_name']}({udp['src_port']}) -> {udp['dst_port_name']}({udp['dst_port']}) | "
                  f"Len: {udp['length']} | Checksum: {udp['checksum']}")
        elif "icmp" in info:
            icmp = info["icmp"]
            print(f"  [ICMP] Type: {icmp['type_name']}({icmp['type']}) | Code: {icmp['code']} | "
                  f"ID: {icmp['id']} | Seq: {icmp['seq']}")
        
        # Application
        if "dns" in info:
            dns = info["dns"]
            print(f"  [DNS] ID: {dns['id']} | {dns['qr']} | Questions: {dns['questions']} | Answers: {dns['answers']}")
            if verbose and dns['queries']:
                for q in dns['queries']:
                    print(f"    Query: {q['name']} (Type: {q['type']})")
            if verbose and dns['answers']:
                for a in dns['answers']:
                    print(f"    Answer: {a['name']} -> {a['data']}")
        
        if "http" in info:
            http = info["http"]
            if http.get("type") == "Request":
                print(f"  [HTTP] {http['method']} {http['path']} {http['version']} | Host: {http['host']}")
            else:
                print(f"  [HTTP] {http['version']} {http['status_code']}")
        
        if "arp" in info:
            arp = info["arp"]
            print(f"  [ARP] {arp['operation']} | {arp['sender_ip']}({arp['sender_mac']}) -> "
                  f"{arp['target_ip']}({arp['target_mac']})")
        
        # Payload
        if info["payload"]["length"] > 0:
            p = info["payload"]
            print(f"  [Payload] {p['length']} bytes")
            if verbose:
                print(f"    Hex: {p['hex']}")
                print(f"    ASCII: {p['ascii']}")
                if p['truncated']:
                    print(f"    ... (truncated, showing first 100 bytes)")
            else:
                # Show first 50 chars of payload
                preview = p['ascii'][:50]
                if p['truncated']:
                    preview += "..."
                print(f"    Preview: {preview}")
        
        if verbose:
            print(f"  Layers: {' -> '.join(info['layers'])}")
    
    def display_summary(self):
        """Display capture summary statistics."""
        print(f"\n{'='*80}")
        print("CAPTURE SUMMARY")
        print(f"{'='*80}")
        print(f"Total Packets: {self.stats['total']}")
        print(f"Total Bytes: {self.stats['bytes']:,}")
        
        if self.stats['total'] > 0:
            print(f"Average Packet Size: {self.stats['bytes'] / self.stats['total']:.1f} bytes")
        
        print(f"\nProtocol Distribution:")
        for key in sorted(self.stats.keys()):
            if key.startswith("proto_"):
                proto = key[6:]
                count = self.stats[key]
                pct = (count / self.stats['total']) * 100
                print(f"  {proto}: {count} ({pct:.1f}%)")
        
        print(f"\nTop Source IPs:")
        src_ips = [(k[4:], v) for k, v in self.stats.items() if k.startswith("src_")]
        for ip, count in sorted(src_ips, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")
        
        print(f"\nTop Destination IPs:")
        dst_ips = [(k[4:], v) for k, v in self.stats.items() if k.startswith("dst_")]
        for ip, count in sorted(dst_ips, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")
        
        print(f"\nTop TCP Ports:")
        tcp_ports = [(k[10:], v) for k, v in self.stats.items() if k.startswith("tcp_port_")]
        for port, count in sorted(tcp_ports, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  Port {port}: {count}")
        
        print(f"\nTop UDP Ports:")
        udp_ports = [(k[10:], v) for k, v in self.stats.items() if k.startswith("udp_port_")]
        for port, count in sorted(udp_ports, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  Port {port}: {count}")
    
    def save_packets(self):
        """Save captured packets to a PCAP file."""
        if self.packets:
            try:
                wrpcap(self.output_file, self.packets)
                print(f"\n[+] Saved {len(self.packets)} packets to {self.output_file}")
            except Exception as e:
                print(f"\n[!] Error saving packets: {e}")
    
    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        self.packets.append(packet)
        info = self.process_packet(packet)
        self.display_packet(info, verbose=False)
    
    def start_capture(self, verbose: bool = False):
        """Start packet capture."""
        self.running = True
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"\n[*] Starting packet capture on {self.get_interface_info()}")
        if self.filter_str:
            print(f"[*] Filter: {self.filter_str}")
        if self.count > 0:
            print(f"[*] Packet count limit: {self.count}")
        if self.timeout > 0:
            print(f"[*] Timeout: {self.timeout} seconds")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.packet_callback,
                count=self.count if self.count > 0 else 0,
                timeout=self.timeout if self.timeout > 0 else None,
                store=False
            )
        except PermissionError:
            print("[!] Error: Permission denied. Run as root/administrator.")
            return
        except Exception as e:
            print(f"[!] Error during capture: {e}")
            return
        
        self.display_summary()
        if self.output_file and self.packets:
            self.save_packets()
    
    def analyze_pcap(self, pcap_file: str, verbose: bool = False):
        """Analyze packets from a PCAP file."""
        print(f"[*] Reading packets from {pcap_file}")
        try:
            packets = rdpcap(pcap_file)
            print(f"[*] Loaded {len(packets)} packets\n")
            
            for packet in packets:
                info = self.process_packet(packet)
                self.display_packet(info, verbose=verbose)
            
            self.display_summary()
        except Exception as e:
            print(f"[!] Error reading PCAP file: {e}")
    
    @staticmethod
    def list_interfaces():
        """List available network interfaces."""
        print("\nAvailable Network Interfaces:")
        print("-" * 60)
        interfaces = get_if_list()
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                print(f"  {iface} (IP: {ip})")
            except:
                print(f"  {iface} (IP: Unknown)")


def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Capture and Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture on default interface
  sudo python packet_analyzer.py
  
  # Capture on specific interface with filter
  sudo python packet_analyzer.py -i eth0 -f "tcp port 80"
  
  # Capture 100 packets and save to file
  sudo python packet_analyzer.py -c 100 -o capture.pcap
  
  # Analyze existing PCAP file
  python packet_analyzer.py -r capture.pcap -v
  
  # List available interfaces
  python packet_analyzer.py --list-interfaces
        """
    )
    
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=0, help="Capture timeout in seconds (0 = unlimited)")
    parser.add_argument("-o", "--output", help="Output PCAP file to save captured packets")
    parser.add_argument("-r", "--read", help="Read and analyze packets from PCAP file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output with payload details")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer(
        interface=args.interface,
        filter_str=args.filter,
        count=args.count,
        timeout=args.timeout,
        output_file=args.output
    )
    
    if args.list_interfaces:
        analyzer.list_interfaces()
        return
    
    if args.read:
        analyzer.analyze_pcap(args.read, verbose=args.verbose)
    else:
        analyzer.start_capture(verbose=args.verbose)


if __name__ == "__main__":
    main()