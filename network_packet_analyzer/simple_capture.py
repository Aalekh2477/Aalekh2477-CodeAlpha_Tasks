#!/usr/bin/env python3
"""
Simple Socket-based Packet Capture (No Root Required on Some Systems)
======================================================================
A basic packet capture example using raw sockets.
Note: On Linux, still requires root. On Windows, may work with admin privileges.
"""

import socket
import struct
import sys
import os
from datetime import datetime

# Check platform
IS_WINDOWS = os.name == 'nt'

def parse_ethernet_header(data):
    """Parse Ethernet header (14 bytes)."""
    dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:14])
    return {
        'dest_mac': ':'.join(f'{b:02x}' for b in dest_mac).upper(),
        'src_mac': ':'.join(f'{b:02x}' for b in src_mac).upper(),
        'eth_type': eth_type,
        'eth_type_name': get_eth_type_name(eth_type)
    }, data[14:]

def get_eth_type_name(eth_type):
    """Get Ethernet type name."""
    types = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x86DD: 'IPv6',
        0x8847: 'MPLS',
        0x88CC: 'LLDP'
    }
    return types.get(eth_type, f'Unknown(0x{eth_type:04x})')

def parse_ipv4_header(data):
    """Parse IPv4 header (minimum 20 bytes)."""
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_len = ihl * 4
    
    ttl, proto, checksum = struct.unpack('!BBH', data[8:12])
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    
    proto_name = get_ip_proto_name(proto)
    
    return {
        'version': version,
        'header_len': header_len,
        'ttl': ttl,
        'protocol': proto_name,
        'proto_num': proto,
        'checksum': f'0x{checksum:04x}',
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }, data[header_len:]

def get_ip_proto_name(proto):
    """Get IP protocol name."""
    protos = {
        1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6',
        47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6'
    }
    return protos.get(proto, f'PROTO-{proto}')

def parse_tcp_header(data):
    """Parse TCP header (minimum 20 bytes)."""
    src_port, dst_port, seq, ack, offset_flags = struct.unpack('!HHIIH', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF
    
    flag_names = []
    flag_map = {
        0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
        0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR', 0x100: 'NS'
    }
    for bit, name in flag_map.items():
        if flags & bit:
            flag_names.append(name)
    
    window, checksum, urg_ptr = struct.unpack('!HHH', data[14:20])
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'flags': '|'.join(flag_names) if flag_names else 'NONE',
        'window': window,
        'checksum': f'0x{checksum:04x}',
        'header_len': offset
    }, data[offset:]

def parse_udp_header(data):
    """Parse UDP header (8 bytes)."""
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'checksum': f'0x{checksum:04x}'
    }, data[8:]

def parse_icmp_header(data):
    """Parse ICMP header."""
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    type_names = {
        0: 'Echo Reply', 3: 'Dest Unreachable', 4: 'Source Quench',
        5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded',
        12: 'Param Problem', 13: 'Timestamp', 14: 'Timestamp Reply'
    }
    return {
        'type': icmp_type,
        'type_name': type_names.get(icmp_type, f'Type-{icmp_type}'),
        'code': code,
        'checksum': f'0x{checksum:04x}'
    }, data[4:]

def format_payload(data, max_len=64):
    """Format payload for display."""
    if not data:
        return "Empty"
    hex_str = ' '.join(f'{b:02x}' for b in data[:max_len])
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:max_len])
    truncated = "..." if len(data) > max_len else ""
    return f"Hex: {hex_str}{truncated}\nASCII: {ascii_str}{truncated}"

def main():
    print("=" * 70)
    print("Simple Socket-based Packet Capture")
    print("=" * 70)
    
    # Create raw socket
    try:
        if IS_WINDOWS:
            # Windows: Use SIO_RCVALL for promiscuous mode
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux: Capture all Ethernet frames
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("\n[!] Permission denied. Run as root/administrator.")
        print("    Linux: sudo python simple_capture.py")
        print("    Windows: Run as Administrator")
        return
    except Exception as e:
        print(f"\n[!] Error creating socket: {e}")
        return
    
    print(f"\n[*] Listening for packets... Press Ctrl+C to stop\n")
    
    packet_count = 0
    
    try:
        while True:
            # Receive packet
            raw_data, addr = sock.recvfrom(65535)
            packet_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            
            print(f"\n{'='*70}")
            print(f"Packet #{packet_count} | {timestamp} | Length: {len(raw_data)} bytes")
            print(f"{'='*70}")
            
            # Parse Ethernet (Linux) or IP directly (Windows)
            if IS_WINDOWS:
                # On Windows with IPPROTO_IP, we get IP header directly
                ip_info, payload = parse_ipv4_header(raw_data)
                print(f"  [IPv4] {ip_info['src_ip']} -> {ip_info['dst_ip']} | "
                      f"Proto: {ip_info['protocol']} | TTL: {ip_info['ttl']}")
            else:
                # Linux: Parse Ethernet first
                eth_info, payload = parse_ethernet_header(raw_data)
                print(f"  [Ethernet] {eth_info['src_mac']} -> {eth_info['dest_mac']} | "
                      f"Type: {eth_info['eth_type_name']}")
                
                if eth_info['eth_type'] == 0x0800:  # IPv4
                    ip_info, payload = parse_ipv4_header(payload)
                    print(f"  [IPv4] {ip_info['src_ip']} -> {ip_info['dst_ip']} | "
                          f"Proto: {ip_info['protocol']} | TTL: {ip_info['ttl']}")
                elif eth_info['eth_type'] == 0x0806:  # ARP
                    print(f"  [ARP] Packet captured")
                    continue
                elif eth_info['eth_type'] == 0x86DD:  # IPv6
                    print(f"  [IPv6] Packet captured")
                    continue
                else:
                    continue
            
            # Parse transport layer
            proto = ip_info['proto_num']
            
            if proto == 6:  # TCP
                tcp_info, tcp_payload = parse_tcp_header(payload)
                print(f"  [TCP] {tcp_info['src_port']} -> {tcp_info['dst_port']} | "
                      f"Seq: {tcp_info['seq']} | Ack: {tcp_info['ack']} | "
                      f"Flags: [{tcp_info['flags']}] | Win: {tcp_info['window']}")
                print(f"  [Payload] {len(tcp_payload)} bytes")
                if tcp_payload:
                    print(f"    {format_payload(tcp_payload)}")
                    
            elif proto == 17:  # UDP
                udp_info, udp_payload = parse_udp_header(payload)
                print(f"  [UDP] {udp_info['src_port']} -> {udp_info['dst_port']} | "
                      f"Len: {udp_info['length']}")
                print(f"  [Payload] {len(udp_payload)} bytes")
                if udp_payload:
                    print(f"    {format_payload(udp_payload)}")
                    
            elif proto == 1:  # ICMP
                icmp_info, icmp_payload = parse_icmp_header(payload)
                print(f"  [ICMP] Type: {icmp_info['type_name']} | Code: {icmp_info['code']}")
                print(f"  [Payload] {len(icmp_payload)} bytes")
                if icmp_payload:
                    print(f"    {format_payload(icmp_payload)}")
            else:
                print(f"  [Protocol {proto}] Payload: {len(payload)} bytes")
                
    except KeyboardInterrupt:
        print(f"\n\n[*] Capture stopped. Total packets: {packet_count}")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        if IS_WINDOWS:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
        sock.close()

if __name__ == "__main__":
    main()