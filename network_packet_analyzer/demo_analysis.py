#!/usr/bin/env python3
"""
Demo Packet Analysis - Offline Packet Structure Learning
=========================================================
This script demonstrates packet structure analysis without requiring
live capture or root privileges. It creates sample packets and shows
how to analyze them.
"""

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
    Raw, wrpcap, rdpcap
)
# HTTP layers might not be available in all scapy versions
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    HTTPRequest = None
    HTTPResponse = None

import os

def create_sample_packets():
    """Create various sample packets for demonstration."""
    packets = []
    
    # 1. Simple TCP SYN packet (start of 3-way handshake)
    print("Creating TCP SYN packet...")
    syn = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
          IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) / \
          TCP(sport=54321, dport=80, flags="S", seq=1000, window=64240) / \
          Raw(b"")
    packets.append(syn)
    
    # 2. TCP SYN-ACK response
    print("Creating TCP SYN-ACK packet...")
    synack = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
             IP(src="8.8.8.8", dst="192.168.1.100", ttl=52) / \
             TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001, window=65535) / \
             Raw(b"")
    packets.append(synack)
    
    # 3. TCP ACK (connection established)
    print("Creating TCP ACK packet...")
    ack = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
          IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) / \
          TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001, window=64240) / \
          Raw(b"")
    packets.append(ack)
    
    # 4. HTTP GET request (using Raw payload since HTTP layer may not be available)
    print("Creating HTTP GET request...")
    http_get = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
               IP(src="192.168.1.100", dst="93.184.216.34", ttl=64) / \
               TCP(sport=54322, dport=80, flags="PA", seq=1001, ack=2001) / \
               Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Demo/1.0\r\nAccept: */*\r\n\r\n")
    packets.append(http_get)
    
    # 5. HTTP Response
    print("Creating HTTP Response...")
    http_resp = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
                IP(src="93.184.216.34", dst="192.168.1.100", ttl=52) / \
                TCP(sport=80, dport=54322, flags="PA", seq=2001, ack=1150) / \
                Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1256\r\n\r\n<!DOCTYPE html><html><head><title>Example</title></head><body><h1>Example Domain</h1></body></html>")
    packets.append(http_resp)
    
    # 6. DNS Query
    print("Creating DNS Query...")
    dns_query = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
                IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
                UDP(sport=12345, dport=53) / \
                DNS(id=0x1234, qr=0, qdcount=1, qd=DNSQR(qname="google.com", qtype="A"))
    packets.append(dns_query)
    
    # 7. DNS Response
    print("Creating DNS Response...")
    dns_resp = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
               IP(src="192.168.1.1", dst="192.168.1.100", ttl=64) / \
               UDP(sport=53, dport=12345) / \
               DNS(id=0x1234, qr=1, qdcount=1, ancount=1, 
                   qd=DNSQR(qname="google.com", qtype="A"),
                   an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46", ttl=300))
    packets.append(dns_resp)
    
    # 8. ICMP Echo Request (Ping)
    print("Creating ICMP Echo Request...")
    ping_req = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
               IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) / \
               ICMP(type=8, code=0, id=0x1234, seq=1) / \
               Raw(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    packets.append(ping_req)
    
    # 9. ICMP Echo Reply
    print("Creating ICMP Echo Reply...")
    ping_rep = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
               IP(src="8.8.8.8", dst="192.168.1.100", ttl=52) / \
               ICMP(type=0, code=0, id=0x1234, seq=1) / \
               Raw(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    packets.append(ping_rep)
    
    # 10. ARP Request
    print("Creating ARP Request...")
    arp_req = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100",
                  hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    packets.append(arp_req)
    
    # 11. ARP Reply
    print("Creating ARP Reply...")
    arp_rep = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
              ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",
                  hwdst="00:11:22:33:44:55", pdst="192.168.1.100")
    packets.append(arp_rep)
    
    # 12. UDP Packet (e.g., NTP)
    print("Creating UDP Packet (NTP-like)...")
    udp_pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src="192.168.1.100", dst="192.168.1.1", ttl=64) / \
              UDP(sport=123, dport=123) / \
              Raw(b"\x1b" + b"\x00" * 47)
    packets.append(udp_pkt)
    
    return packets

def analyze_packet_structure(packet, num):
    """Analyze and display packet structure in detail."""
    print(f"\n{'='*70}")
    print(f"PACKET #{num}: {packet.summary()}")
    print(f"{'='*70}")
    
    # Show raw bytes
    raw_bytes = bytes(packet)
    print(f"\nTotal Length: {len(raw_bytes)} bytes")
    print(f"Raw Bytes (first 64): {' '.join(f'{b:02x}' for b in raw_bytes[:64])}")
    
    # Layer-by-layer analysis
    print("\n--- LAYER BREAKDOWN ---")
    
    # Ethernet
    if Ether in packet:
        eth = packet[Ether]
        print(f"\n[Ethernet Layer] (14 bytes)")
        print(f"  Destination MAC: {eth.dst}")
        print(f"  Source MAC:      {eth.src}")
        print(f"  EtherType:       0x{eth.type:04x} ({get_eth_type_name(eth.type)})")
    
    # IP
    if IP in packet:
        ip = packet[IP]
        ihl = ip.ihl if ip.ihl else 5
        total_len = ip.len if ip.len else len(bytes(ip))
        identification = ip.id if ip.id else 0
        flags = str(ip.flags) if ip.flags else "None"
        frag_offset = ip.frag if ip.frag else 0
        ttl = ip.ttl if ip.ttl else 0
        proto = ip.proto if ip.proto else 0
        chksum = ip.chksum if ip.chksum else 0
        
        print(f"\n[IPv4 Layer] ({ihl * 4} bytes)")
        print(f"  Version:         {ip.version}")
        print(f"  Header Length:   {ihl * 4} bytes")
        print(f"  TOS/DSCP:        0x{ip.tos:02x}")
        print(f"  Total Length:    {total_len} bytes")
        print(f"  Identification:  0x{identification:04x}")
        print(f"  Flags:           {flags}")
        print(f"  Fragment Offset: {frag_offset}")
        print(f"  TTL:             {ttl}")
        print(f"  Protocol:        {proto} ({get_ip_proto_name(proto)})")
        print(f"  Checksum:        0x{chksum:04x}")
        print(f"  Source IP:       {ip.src}")
        print(f"  Dest IP:         {ip.dst}")
        
        if ip.options:
            print(f"  Options:         {len(ip.options)} option(s)")
    
    if IPv6 in packet:
        ipv6 = packet[IPv6]
        print(f"\n[IPv6 Layer] (40 bytes fixed)")
        print(f"  Version:         {ipv6.version}")
        print(f"  Traffic Class:   0x{ipv6.tc:02x}")
        print(f"  Flow Label:      0x{ipv6.fl:05x}")
        print(f"  Payload Length:  {ipv6.plen}")
        print(f"  Next Header:     {ipv6.nh} ({get_ip_proto_name(ipv6.nh)})")
        print(f"  Hop Limit:       {ipv6.hlim}")
        print(f"  Source IP:       {ipv6.src}")
        print(f"  Dest IP:         {ipv6.dst}")
    
    # Transport
    if TCP in packet:
        tcp = packet[TCP]
        flags = []
        # TCP flags are stored as bitmasks
        flag_map = {
            0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
            0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'
        }
        for bit, name in flag_map.items():
            if tcp.flags & bit:
                flags.append(name)
        
        dataofs = tcp.dataofs if tcp.dataofs else 5
        seq = tcp.seq if tcp.seq else 0
        ack = tcp.ack if tcp.ack else 0
        window = tcp.window if tcp.window else 0
        chksum = tcp.chksum if tcp.chksum else 0
        urgptr = tcp.urgptr if tcp.urgptr else 0
        
        print(f"\n[TCP Layer] ({dataofs * 4} bytes)")
        print(f"  Source Port:     {tcp.sport}")
        print(f"  Dest Port:       {tcp.dport}")
        print(f"  Sequence:        {seq}")
        print(f"  Acknowledgment:  {ack}")
        print(f"  Data Offset:     {dataofs * 4} bytes")
        print(f"  Flags:           [{'|'.join(flags) if flags else 'NONE'}]")
        print(f"  Window:          {window}")
        print(f"  Checksum:        0x{chksum:04x}")
        print(f"  Urgent Pointer:  {urgptr}")
        if tcp.options:
            print(f"  Options:         {len(tcp.options)} option(s)")
    
    if UDP in packet:
        udp = packet[UDP]
        sport = udp.sport if udp.sport else 0
        dport = udp.dport if udp.dport else 0
        length = udp.len if udp.len else 0
        chksum = udp.chksum if udp.chksum else 0
        
        print(f"\n[UDP Layer] (8 bytes)")
        print(f"  Source Port:     {sport}")
        print(f"  Dest Port:       {dport}")
        print(f"  Length:          {length} bytes")
        print(f"  Checksum:        0x{chksum:04x}")
    
    if ICMP in packet:
        icmp = packet[ICMP]
        type_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 
                      11: 'Time Exceeded'}
        icmp_type = icmp.type if icmp.type else 0
        icmp_code = icmp.code if icmp.code else 0
        icmp_chksum = icmp.chksum if icmp.chksum else 0
        icmp_id = getattr(icmp, 'id', None)
        icmp_seq = getattr(icmp, 'seq', None)
        
        print(f"\n[ICMP Layer]")
        print(f"  Type:            {icmp_type} ({type_names.get(icmp_type, 'Unknown')})")
        print(f"  Code:            {icmp_code}")
        print(f"  Checksum:        0x{icmp_chksum:04x}")
        print(f"  ID:              {icmp_id if icmp_id is not None else 'N/A'}")
        print(f"  Sequence:        {icmp_seq if icmp_seq is not None else 'N/A'}")
    
    # Application
    if HTTPRequest and HTTPRequest in packet:
        http = packet[HTTPRequest]
        print(f"\n[HTTP Request Layer]")
        print(f"  Method:          {http.Method.decode() if hasattr(http, 'Method') else 'N/A'}")
        print(f"  Path:            {http.Path.decode() if hasattr(http, 'Path') else 'N/A'}")
        print(f"  Version:         {http.Http_Version.decode() if hasattr(http, 'Http_Version') else 'N/A'}")
    
    if HTTPResponse and HTTPResponse in packet:
        http = packet[HTTPResponse]
        print(f"\n[HTTP Response Layer]")
        print(f"  Status Code:     {http.Status_Code.decode() if hasattr(http, 'Status_Code') else 'N/A'}")
        print(f"  Version:         {http.Http_Version.decode() if hasattr(http, 'Http_Version') else 'N/A'}")
    
    if DNS in packet:
        dns = packet[DNS]
        dns_id = dns.id if dns.id else 0
        dns_qr = dns.qr if dns.qr is not None else 0
        dns_opcode = dns.opcode if dns.opcode is not None else 0
        dns_aa = dns.aa if dns.aa is not None else 0
        dns_tc = dns.tc if dns.tc is not None else 0
        dns_rd = dns.rd if dns.rd is not None else 0
        dns_ra = dns.ra if dns.ra is not None else 0
        dns_rcode = dns.rcode if dns.rcode is not None else 0
        dns_qdcount = dns.qdcount if dns.qdcount else 0
        dns_ancount = dns.ancount if dns.ancount else 0
        dns_nscount = dns.nscount if dns.nscount else 0
        dns_arcount = dns.arcount if dns.arcount else 0
        
        print(f"\n[DNS Layer]")
        print(f"  Transaction ID:  0x{dns_id:04x}")
        print(f"  Flags:           QR={dns_qr} Opcode={dns_opcode} AA={dns_aa} TC={dns_tc} RD={dns_rd} RA={dns_ra} RCODE={dns_rcode}")
        print(f"  Questions:       {dns_qdcount}")
        print(f"  Answers:         {dns_ancount}")
        print(f"  Authority:       {dns_nscount}")
        print(f"  Additional:      {dns_arcount}")
        
        if dns.qd:
            for i, q in enumerate(dns.qd):
                qname = q.qname.decode() if hasattr(q.qname, 'decode') else str(q.qname)
                qtype = q.qtype if q.qtype else 0
                print(f"  Query {i+1}:       {qname} Type={qtype}")
        
        if dns.an:
            for i, a in enumerate(dns.an):
                rrname = a.rrname.decode() if hasattr(a.rrname, 'decode') else str(a.rrname)
                rdata = str(a.rdata)
                print(f"  Answer {i+1}:      {rrname} -> {rdata}")
    
    if ARP in packet:
        arp = packet[ARP]
        op_names = {1: 'Request', 2: 'Reply'}
        arp_op = arp.op if arp.op else 0
        print(f"\n[ARP Layer]")
        print(f"  Operation:       {arp_op} ({op_names.get(arp_op, 'Unknown')})")
        print(f"  Sender MAC:      {arp.hwsrc}")
        print(f"  Sender IP:       {arp.psrc}")
        print(f"  Target MAC:      {arp.hwdst}")
        print(f"  Target IP:       {arp.pdst}")
    
    # Payload
    if Raw in packet:
        raw = packet[Raw].load
        print(f"\n[Payload] ({len(raw)} bytes)")
        if len(raw) > 0:
            # Try to decode as text
            try:
                text = raw.decode('utf-8', errors='replace')
                if len(text) <= 200:
                    print(f"  Text: {text}")
                else:
                    print(f"  Text: {text[:200]}... (truncated)")
            except:
                print(f"  Hex:  {' '.join(f'{b:02x}' for b in raw[:32])}...")

def get_eth_type_name(eth_type):
    types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8847: 'MPLS'}
    return types.get(eth_type, f'Unknown(0x{eth_type:04x})')

def get_ip_proto_name(proto):
    protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 58: 'ICMPv6'}
    return protos.get(proto, f'PROTO-{proto}')

def explain_protocol_flow():
    """Explain how data flows through network layers."""
    print("\n" + "="*70)
    print("NETWORK PROTOCOL STACK - DATA FLOW EXPLANATION")
    print("="*70)
    
    explanation = """
When an application sends data, it flows DOWN through the layers (encapsulation):
When data is received, it flows UP through the layers (decapsulation):

+---------------------------------------------------------------+
|  APPLICATION LAYER (Layer 7)                                  |
|  HTTP, DNS, SMTP, FTP, SSH, etc.                              |
|  Data: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"          |
+---------------------------------------------------------------+
                            | Add HTTP headers
                            V
+---------------------------------------------------------------+
|  TRANSPORT LAYER (Layer 4)                                    |
|  TCP: Adds src/dst ports, sequence, ACK, flags, window,       |
|       checksum                                                |
|  UDP: Adds src/dst ports, length, checksum                    |
|  Segment: [TCP Header][HTTP Data]                             |
+---------------------------------------------------------------+
                            | Add IP header
                            V
+---------------------------------------------------------------+
|  NETWORK LAYER (Layer 3)                                      |
|  IPv4: Adds src/dst IP, TTL, protocol, checksum, fragmentation|
|  IPv6: Adds src/dst IP, next header, hop limit                |
|  Packet: [IP Header][TCP Header][HTTP Data]                   |
+---------------------------------------------------------------+
                            | Add Ethernet header
                            V
+---------------------------------------------------------------+
|  DATA LINK LAYER (Layer 2)                                    |
|  Ethernet: Adds src/dst MAC, EtherType, FCS                   |
|  Frame: [Eth Header][IP Header][TCP Header][HTTP Data][FCS]   |
+---------------------------------------------------------------+
                            | Convert to bits
                            V
+---------------------------------------------------------------+
|  PHYSICAL LAYER (Layer 1)                                     |
|  Electrical/optical/radio signals on the wire                 |
+---------------------------------------------------------------+

KEY CONCEPTS:
* Each layer adds its own header (and sometimes trailer)
* Headers contain control information for that layer
* Lower layers treat upper layer data as opaque payload
* Routers operate at Layer 3 (IP), Switches at Layer 2 (MAC)
* Firewalls can inspect Layers 3, 4, and 7
"""
    print(explanation)

def main():
    print("="*70)
    print("PACKET STRUCTURE ANALYSIS DEMO")
    print("="*70)
    print("This demo creates sample packets and analyzes their structure")
    print("without requiring live capture or root privileges.\n")
    
    # Create sample packets
    packets = create_sample_packets()
    
    # Save to PCAP file for later analysis
    output_file = "sample_packets.pcap"
    wrpcap(output_file, packets)
    print(f"\n[+] Saved {len(packets)} sample packets to {output_file}")
    
    # Analyze each packet
    print("\n" + "="*70)
    print("DETAILED PACKET ANALYSIS")
    print("="*70)
    
    for i, pkt in enumerate(packets, 1):
        analyze_packet_structure(pkt, i)
    
    # Explain protocol flow
    explain_protocol_flow()
    
    print("\n[+] Demo complete!")
    print(f"[+] You can analyze the saved PCAP with: python packet_analyzer.py -r {output_file} -v")

if __name__ == "__main__":
    main()